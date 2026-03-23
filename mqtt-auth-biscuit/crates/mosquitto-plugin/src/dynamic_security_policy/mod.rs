use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};
use thiserror::Error;

mod model;
mod mutation;
mod persist;
#[cfg(test)]
use model::{ACL_READ, ACL_SUBSCRIBE, ACL_WRITE};
use model::{
    AccessKind, AclConfig, AclEntry, AclType, DynSecClient, DynSecConfig, DynSecGroup, DynSecRole,
    DynSecState, RoleAclKey, RoleRef, RuntimeRoleAclOverride,
};
use mutation::{
    ControlCommand, ControlCommandKind, ControlMutationDraft, ControlPayload, PersistMutation,
    RetryIntentReducer, RoleAclMutation,
};
pub use mutation::{ControlEnforcementTargets, ControlNotifyEvent};
use persist::apply_persist_mutations;
#[cfg(test)]
use persist::nested_array_missing_or_empty;
#[cfg(test)]
use serde_json::json;

type DynSecResult<T> = Result<T, DynSecError>;
const PENDING_PERSIST_WARN_THRESHOLD: usize = 256;

#[derive(Debug, Error)]
pub enum DynSecError {
    #[error("dynsec {name} lock poisoned")]
    LockPoisoned { name: &'static str },

    #[error("invalid control payload: {source}")]
    InvalidControlPayload {
        #[source]
        source: serde_json::Error,
    },

    #[error("dynsec config read failed: {source}")]
    ConfigRead {
        #[source]
        source: std::io::Error,
    },

    #[error("dynsec config parse failed: {source}")]
    ConfigParse {
        #[source]
        source: serde_json::Error,
    },

    #[error("dynsec config serialize failed: {source}")]
    ConfigSerialize {
        #[source]
        source: serde_json::Error,
    },

    #[error("dynsec config write failed: {source}")]
    ConfigWrite {
        #[source]
        source: std::io::Error,
    },

    #[error("dynsec config schema invalid: missing '{field}'")]
    MissingField { field: String },

    #[error("dynsec config schema invalid: expected '{field}' to be an array")]
    ExpectedArray { field: String },

    #[error("dynsec config root is not an object")]
    RootNotObject,

    #[error("dynsec config persistence blocked by divergent state")]
    PersistenceBlocked,
}

impl DynSecError {
    const fn lock_poisoned(name: &'static str) -> Self {
        Self::LockPoisoned { name }
    }
}

fn lock_mutex<'a, T>(mutex: &'a Mutex<T>, name: &'static str) -> DynSecResult<MutexGuard<'a, T>> {
    mutex.lock().map_err(|_| DynSecError::lock_poisoned(name))
}

fn read_lock<'a, T>(
    rw_lock: &'a RwLock<T>,
    name: &'static str,
) -> DynSecResult<RwLockReadGuard<'a, T>> {
    rw_lock.read().map_err(|_| DynSecError::lock_poisoned(name))
}

fn write_lock<'a, T>(
    rw_lock: &'a RwLock<T>,
    name: &'static str,
) -> DynSecResult<RwLockWriteGuard<'a, T>> {
    rw_lock
        .write()
        .map_err(|_| DynSecError::lock_poisoned(name))
}

#[derive(Debug)]
pub struct DynamicSecurityPolicy {
    config_path: PathBuf,
    reload_interval: Duration,
    control_apply_lock: Mutex<()>,
    last_loaded: Mutex<Option<Instant>>,
    state: RwLock<DynSecState>,
    pending_persist_mutations: Mutex<Vec<PersistMutation>>,
    runtime_disabled_usernames: Mutex<HashSet<String>>,
    runtime_role_acl_overrides: Mutex<HashMap<RoleAclKey, RuntimeRoleAclOverride>>,
}

impl DynamicSecurityPolicy {
    pub fn new(config_path: impl Into<PathBuf>, reload_interval: Duration) -> DynSecResult<Self> {
        let policy = Self {
            config_path: config_path.into(),
            reload_interval,
            control_apply_lock: Mutex::new(()),
            last_loaded: Mutex::new(None),
            state: RwLock::new(DynSecState::default()),
            pending_persist_mutations: Mutex::new(Vec::new()),
            runtime_disabled_usernames: Mutex::new(HashSet::new()),
            runtime_role_acl_overrides: Mutex::new(HashMap::new()),
        };
        policy.reload_if_needed(true)?;
        Ok(policy)
    }

    pub fn check(
        &self,
        username: Option<&str>,
        client_id: Option<&str>,
        topic: &str,
        access: i32,
    ) -> DynSecResult<bool> {
        self.reload_if_needed(false)?;
        let state = read_lock(&self.state, "state")?;
        let is_runtime_disabled = if let Some(name) = username {
            // Keep the lock order consistent with the control path, but drop the
            // runtime-disable mutex before the ACL walk.
            let runtime_disabled = lock_mutex(&self.runtime_disabled_usernames, "runtime disable")?;
            runtime_disabled.contains(name)
        } else {
            false
        };
        if is_runtime_disabled {
            return Ok(false);
        }

        Ok(state_allows_access(
            &state,
            username,
            client_id,
            topic,
            AccessKind::from_access(access),
        ))
    }

    pub fn apply_control_payload(&self, payload: &[u8]) -> DynSecResult<ControlEnforcementTargets> {
        let Some(parsed) = Self::parse_control_payload(payload)? else {
            return Ok(ControlEnforcementTargets::default());
        };

        // **Limitation**: `control_apply_lock` is held for the entire apply_control_payload
        // scope, including file I/O in load_current_control_state and persist_control_mutations.
        // A slow or stalled filesystem will block all concurrent control commands and any
        // reload_if_needed calls. This is a deliberate correctness-over-latency trade-off;
        // the research benchmark environment uses local tmpfs so this is not exercised in
        // normal throughput/latency measurements.
        let _control_guard = lock_mutex(&self.control_apply_lock, "control")?;
        let state = self.load_state_for_control_payload()?;
        let draft = self.build_control_mutation_draft(state, &parsed.commands)?;
        let retry_persist_mutations =
            self.collect_retry_persist_mutations(&parsed.commands, &draft)?;

        let mut targets = self.commit_control_mutation_draft(draft, None)?;
        self.flush_retry_persist_mutations(retry_persist_mutations, &mut targets);
        Ok(targets)
    }

    /// **Limitation**: `reload_is_due` is checked outside `control_apply_lock` to avoid
    /// acquiring the mutex on the hot path when no reload is needed. This means two
    /// concurrent callers can both observe `reload_is_due() == true` and then serialise
    /// on the lock — the second thread will perform a redundant (but harmless) reload
    /// because `reload_if_needed_locked` re-checks the timer under the lock.
    fn reload_if_needed(&self, force: bool) -> DynSecResult<()> {
        if !self.reload_is_due(force)? {
            return Ok(());
        }

        let _control_guard = lock_mutex(&self.control_apply_lock, "control")?;
        self.reload_if_needed_locked(force)
    }

    fn reload_is_due(&self, force: bool) -> DynSecResult<bool> {
        if force {
            return Ok(true);
        }

        let now = Instant::now();
        let reload_due = {
            let last_loaded = lock_mutex(&self.last_loaded, "reload")?;
            !matches!(
                *last_loaded,
                Some(last) if now.duration_since(last) < self.reload_interval
            )
        };

        Ok(reload_due)
    }

    fn reload_if_needed_locked(&self, force: bool) -> DynSecResult<()> {
        let now = Instant::now();
        let mut last_loaded = lock_mutex(&self.last_loaded, "reload")?;

        if !force
            && let Some(last) = *last_loaded
            && now.duration_since(last) < self.reload_interval
        {
            return Ok(());
        }

        let has_valid_cached_state = last_loaded.is_some();
        match self.load_current_control_state() {
            Ok(state) => {
                {
                    let mut state_guard = write_lock(&self.state, "state")?;
                    *state_guard = state;
                }
                *last_loaded = Some(now);
                drop(last_loaded);
            }
            Err(err) if has_valid_cached_state && is_dynsec_load_read_or_parse_error(&err) => {
                return Ok(());
            }
            Err(err) => return Err(err),
        }

        Ok(())
    }

    fn parse_control_payload(payload: &[u8]) -> DynSecResult<Option<ControlPayload>> {
        if payload.is_empty() {
            return Ok(None);
        }

        let parsed: ControlPayload = serde_json::from_slice(payload)
            .map_err(|source| DynSecError::InvalidControlPayload { source })?;
        if parsed.commands.is_empty() {
            return Ok(None);
        }

        Ok(Some(parsed))
    }

    fn load_state_for_control_payload(&self) -> DynSecResult<DynSecState> {
        match self.load_current_control_state() {
            Ok(state) => {
                self.refresh_cached_state(state.clone())?;
                Ok(state)
            }
            Err(err) if is_dynsec_load_read_or_parse_error(&err) => {
                Ok(read_lock(&self.state, "state")?.clone())
            }
            Err(err) => Err(err),
        }
    }

    fn build_control_mutation_draft(
        &self,
        state: DynSecState,
        commands: &[ControlCommand],
    ) -> DynSecResult<ControlMutationDraft> {
        // **Limitation**: The full runtime state, disabled-username set, and role-ACL
        // override map are cloned into the ControlMutationDraft so mutations can be
        // computed without holding the read locks. For large deployments this adds
        // allocation pressure on every control command; acceptable for the bounded
        // entity counts in the research benchmark scenarios.
        let runtime_disabled_usernames =
            lock_mutex(&self.runtime_disabled_usernames, "runtime disable")?.clone();
        let runtime_role_acl_overrides =
            lock_mutex(&self.runtime_role_acl_overrides, "runtime role-acl")?.clone();
        let mut draft = ControlMutationDraft::new(
            state,
            runtime_disabled_usernames,
            runtime_role_acl_overrides,
        );
        for command in commands {
            draft.apply_command(command);
        }
        draft.finalize_notify_events();
        Ok(draft)
    }

    fn collect_retry_persist_mutations(
        &self,
        commands: &[ControlCommand],
        draft: &ControlMutationDraft,
    ) -> DynSecResult<Vec<PersistMutation>> {
        let pending_persist_mutations =
            lock_mutex(&self.pending_persist_mutations, "pending persist")?.clone();
        let current_persist_mutations = draft.persist_mutations.clone();
        let current_persist_repairs = collect_current_persist_repairs(
            commands,
            &draft.state,
            &pending_persist_mutations,
            &current_persist_mutations,
        );

        Ok(build_retry_persist_mutations(
            &pending_persist_mutations,
            &current_persist_repairs,
            &current_persist_mutations,
        ))
    }

    fn flush_retry_persist_mutations(
        &self,
        retry_persist_mutations: Vec<PersistMutation>,
        targets: &mut ControlEnforcementTargets,
    ) {
        if retry_persist_mutations.is_empty() {
            return;
        }

        let Ok(mut pending_guard) = self.pending_persist_mutations.lock() else {
            targets.persist_warning =
                Some(DynSecError::lock_poisoned("pending persist").to_string());
            return;
        };

        // The threshold below detects a persistently broken config file. The queue is
        // already collapsed by RetryIntentReducer, so its size is bounded by the number
        // of distinct (entity, operation) combinations mutated while the file was
        // unwritable — not by raw command count. Exceeding the threshold means many
        // distinct roles/groups/clients have been mutated without any successful flush.
        //
        match self.persist_control_mutations(&retry_persist_mutations) {
            Ok(()) => pending_guard.clear(),
            Err(err) => {
                *pending_guard = retry_persist_mutations;
                if pending_guard.len() >= PENDING_PERSIST_WARN_THRESHOLD {
                    crate::log_info(&format!(
                        "dynsec: pending persist queue has {} unflushed mutations — \
                         config file may be permanently unwritable",
                        pending_guard.len(),
                    ));
                }
                targets.persist_warning = Some(err.to_string());
            }
        }
    }

    fn load_current_control_state(&self) -> DynSecResult<DynSecState> {
        let mut state = self.load_base_control_state()?;
        let replay_summary = self.apply_pending_reload_mutations_best_effort(&mut state)?;
        if replay_summary.blocked > 0 {
            crate::log_debug(&format!(
                "Dynsec pending replay skipped blocked mutations during reload: blocked={} changed={} already_satisfied={}",
                replay_summary.blocked, replay_summary.changed, replay_summary.already_satisfied,
            ));
        }
        self.apply_runtime_role_acl_overrides(&mut state)?;
        Ok(state)
    }

    fn load_base_control_state(&self) -> DynSecResult<DynSecState> {
        let raw = fs::read_to_string(&self.config_path)
            .map_err(|source| DynSecError::ConfigRead { source })?;
        let cfg: DynSecConfig =
            serde_json::from_str(&raw).map_err(|source| DynSecError::ConfigParse { source })?;
        Ok(DynSecState::from_config(cfg))
    }

    fn refresh_cached_state(&self, state: DynSecState) -> DynSecResult<()> {
        {
            let mut state_guard = write_lock(&self.state, "state")?;
            *state_guard = state;
        }
        let mut last_loaded = lock_mutex(&self.last_loaded, "reload")?;
        *last_loaded = Some(Instant::now());
        drop(last_loaded);
        Ok(())
    }

    fn apply_runtime_role_acl_overrides(&self, state: &mut DynSecState) -> DynSecResult<()> {
        let overrides = lock_mutex(&self.runtime_role_acl_overrides, "runtime role-acl")?;
        if overrides.is_empty() {
            return Ok(());
        }

        for (key, value) in overrides.iter() {
            let Some(role) = state.roles.get_mut(&key.rolename) else {
                continue;
            };
            match value {
                RuntimeRoleAclOverride::Remove => {
                    let _ = role.acls.remove_acl_entry(key.acl_type, &key.topic);
                }
                RuntimeRoleAclOverride::Add { priority, allow } => {
                    let _ = role.acls.upsert_acl_entry(AclEntry {
                        acl_type: key.acl_type,
                        topic: key.topic.clone(),
                        allow: *allow,
                        priority: *priority,
                    });
                }
            }
        }
        drop(overrides);
        Ok(())
    }

    fn apply_pending_reload_mutations_best_effort(
        &self,
        state: &mut DynSecState,
    ) -> DynSecResult<PendingReplaySummary> {
        let mut summary = PendingReplaySummary::default();
        {
            let pending = lock_mutex(&self.pending_persist_mutations, "pending persist")?;
            for mutation in pending
                .iter()
                .filter(|mutation| mutation.is_replayed_on_reload())
            {
                match apply_state_persist_mutation(state, mutation) {
                    StateApplyOutcome::Changed => summary.changed += 1,
                    StateApplyOutcome::AlreadySatisfied => summary.already_satisfied += 1,
                    StateApplyOutcome::Blocked => summary.blocked += 1,
                }
            }
        }
        Ok(summary)
    }

    /// **Limitation**: This performs a non-atomic read-modify-write on the JSON config
    /// file. The `control_apply_lock` mutex protects against concurrent writes from
    /// this process, but cannot guard against an external process (e.g. the Mosquitto
    /// Dynamic Security plugin) writing to the same file between our read and write.
    /// Such a race would silently overwrite the external change.
    fn persist_control_mutations(&self, mutations: &[PersistMutation]) -> DynSecResult<()> {
        let mut root = self.read_config_root()?;
        let outcome = apply_persist_mutations(&mut root, mutations)?;

        if outcome.blocked() {
            return Err(DynSecError::PersistenceBlocked);
        }

        if !outcome.changed() {
            return Ok(());
        }

        self.write_config_root(&root)
    }

    fn commit_control_mutation_draft(
        &self,
        draft: ControlMutationDraft,
        persist_warning: Option<String>,
    ) -> DynSecResult<ControlEnforcementTargets> {
        let ControlMutationDraft {
            initial_state: _,
            state: next_state,
            initial_runtime_disabled_usernames: _,
            runtime_disabled_usernames,
            runtime_role_acl_overrides,
            kick_client_ids,
            kick_usernames,
            pending_notify_candidates: _,
            notify_events,
            persist_mutations: _,
            changed,
        } = draft;

        if changed {
            {
                let mut state = write_lock(&self.state, "state")?;
                let mut runtime_disabled =
                    lock_mutex(&self.runtime_disabled_usernames, "runtime disable")?;
                *state = next_state;
                *runtime_disabled = runtime_disabled_usernames;
                drop(runtime_disabled);
                drop(state);
            }
            // The runtime_role_acl_overrides update is in a separate lock scope from
            // state + runtime_disabled above. A concurrent check() call that acquires
            // the state read-lock between these two scopes will see the new state
            // paired with the *old* overrides for that single read. This is safe:
            // control_apply_lock serialises all writers, overrides are baked into the
            // loaded DynSecState by load_current_control_state(), and a stale-override
            // read at worst applies a conservative deny that will self-correct on the
            // next check() after this scope exits.
            {
                let mut overrides =
                    lock_mutex(&self.runtime_role_acl_overrides, "runtime role-acl")?;
                *overrides = runtime_role_acl_overrides;
            }
            let mut last_loaded = lock_mutex(&self.last_loaded, "reload")?;
            *last_loaded = Some(Instant::now());
        }

        let mut kick_client_ids: Vec<String> = kick_client_ids.into_iter().collect();
        let mut kick_usernames: Vec<String> = kick_usernames.into_iter().collect();
        kick_client_ids.sort();
        kick_usernames.sort();
        Ok(ControlEnforcementTargets {
            kick_client_ids,
            kick_usernames,
            notify_events,
            persist_warning,
        })
    }

    fn read_config_root(&self) -> DynSecResult<Value> {
        let raw = fs::read_to_string(&self.config_path)
            .map_err(|source| DynSecError::ConfigRead { source })?;
        serde_json::from_str(&raw).map_err(|source| DynSecError::ConfigParse { source })
    }

    fn write_config_root(&self, root: &Value) -> DynSecResult<()> {
        let serialized = serde_json::to_string_pretty(root)
            .map_err(|source| DynSecError::ConfigSerialize { source })?;
        fs::write(&self.config_path, format!("{serialized}\n"))
            .map_err(|source| DynSecError::ConfigWrite { source })?;
        Ok(())
    }
}

fn state_allows_access(
    state: &DynSecState,
    username: Option<&str>,
    client_id: Option<&str>,
    topic: &str,
    access_kind: AccessKind,
) -> bool {
    let default_allow = state.default_access.allow_for(access_kind);
    let client = username.and_then(|name| state.clients.get(name));

    if let Some(client) = client {
        if client.disabled {
            return false;
        }
        if let (Some(expected), Some(actual)) = (client.client_id.as_deref(), client_id)
            && expected != actual
        {
            return false;
        }
    }

    let mut roles = Vec::new();
    if let Some(client) = client {
        roles.extend(client.roles.iter().cloned());
        for group_ref in &client.groups {
            if let Some(group) = state.groups.get(&group_ref.name) {
                roles.extend(group.roles.iter().cloned());
            }
        }
    } else if let Some(group_name) = state.anonymous_group.as_deref()
        && let Some(group) = state.groups.get(group_name)
    {
        roles.extend(group.roles.iter().cloned());
    }

    roles.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.name.cmp(&b.name))
    });

    for role_ref in roles {
        if let Some(role) = state.roles.get(&role_ref.name)
            && let Some(allow) = role.match_acl(access_kind, topic)
        {
            return allow;
        }
    }

    default_allow
}

fn state_allows_access_with_runtime_disabled(
    state: &DynSecState,
    runtime_disabled_usernames: &HashSet<String>,
    username: Option<&str>,
    client_id: Option<&str>,
    topic: &str,
    access_kind: AccessKind,
) -> bool {
    if let Some(name) = username
        && runtime_disabled_usernames.contains(name)
    {
        return false;
    }

    state_allows_access(state, username, client_id, topic, access_kind)
}

pub fn state_allows_username_access(
    state: &DynSecState,
    runtime_disabled_usernames: &HashSet<String>,
    username: &str,
    topic: &str,
    access_kind: AccessKind,
) -> bool {
    let client_id = state
        .clients
        .get(username)
        .and_then(|client| client.client_id.as_deref());
    state_allows_access_with_runtime_disabled(
        state,
        runtime_disabled_usernames,
        Some(username),
        client_id,
        topic,
        access_kind,
    )
}

const fn is_dynsec_load_read_or_parse_error(err: &DynSecError) -> bool {
    matches!(
        err,
        DynSecError::ConfigRead { .. } | DynSecError::ConfigParse { .. }
    )
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct PendingReplaySummary {
    changed: usize,
    already_satisfied: usize,
    blocked: usize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum StateApplyOutcome {
    Changed,
    AlreadySatisfied,
    Blocked,
}

impl StateApplyOutcome {
    const fn from_changed(changed: bool) -> Self {
        if changed {
            Self::Changed
        } else {
            Self::AlreadySatisfied
        }
    }
}

fn apply_state_persist_mutation(
    state: &mut DynSecState,
    mutation: &PersistMutation,
) -> StateApplyOutcome {
    match mutation {
        PersistMutation::SetClientDisabled { username, disabled } => {
            apply_state_set_client_disabled(state, username, *disabled)
        }
        PersistMutation::CreateRole { rolename, acls } => {
            apply_state_create_role(state, rolename, acls)
        }
        PersistMutation::DeleteRole { rolename } => apply_state_delete_role(state, rolename),
        PersistMutation::CreateGroup { groupname, roles } => {
            apply_state_create_group(state, groupname, roles)
        }
        PersistMutation::DeleteGroup { groupname } => {
            StateApplyOutcome::from_changed(delete_group_from_state(state, groupname))
        }
        PersistMutation::AddGroupClient {
            groupname,
            username,
            priority,
        } => apply_state_add_group_client(state, groupname, username, *priority),
        PersistMutation::RemoveGroupClient {
            groupname,
            username,
        } => apply_state_remove_group_client(state, groupname, username),
        PersistMutation::RoleAcl(RoleAclMutation::Add {
            rolename,
            acltype,
            topic,
            priority,
            allow,
        }) => apply_state_add_role_acl(state, rolename, acltype, topic, *priority, *allow),
        PersistMutation::RoleAcl(RoleAclMutation::Remove {
            rolename,
            acltype,
            topic,
        }) => apply_state_remove_role_acl(state, rolename, acltype, topic),
    }
}

fn apply_state_set_client_disabled(
    state: &mut DynSecState,
    username: &str,
    disabled: bool,
) -> StateApplyOutcome {
    let Some(client) = state.clients.get_mut(username) else {
        return StateApplyOutcome::Blocked;
    };
    if client.disabled == disabled {
        return StateApplyOutcome::AlreadySatisfied;
    }
    client.disabled = disabled;
    StateApplyOutcome::Changed
}

fn apply_state_create_role(
    state: &mut DynSecState,
    rolename: &str,
    acls: &[AclConfig],
) -> StateApplyOutcome {
    if let Some(role) = state.roles.get_mut(rolename) {
        return StateApplyOutcome::from_changed(role.merge_control_acls(acls));
    }
    state.roles.insert(
        rolename.to_string(),
        DynSecRole::from_control_acls(Some(acls.to_vec())),
    );
    StateApplyOutcome::Changed
}

fn apply_state_delete_role(state: &mut DynSecState, rolename: &str) -> StateApplyOutcome {
    let mut changed = state.roles.remove(rolename).is_some();
    for client in state.clients.values_mut() {
        changed |= client.remove_role(rolename);
    }
    for group in state.groups.values_mut() {
        changed |= group.remove_role(rolename);
    }
    StateApplyOutcome::from_changed(changed)
}

fn apply_state_create_group(
    state: &mut DynSecState,
    groupname: &str,
    roles: &[RoleRef],
) -> StateApplyOutcome {
    if let Some(group) = state.groups.get_mut(groupname) {
        return StateApplyOutcome::from_changed(group.merge_control_roles(roles));
    }
    state.groups.insert(
        groupname.to_string(),
        DynSecGroup::from_control_roles(Some(roles.to_vec())),
    );
    StateApplyOutcome::Changed
}

fn apply_state_add_group_client(
    state: &mut DynSecState,
    groupname: &str,
    username: &str,
    priority: i32,
) -> StateApplyOutcome {
    let Some(group) = state.groups.get_mut(groupname) else {
        return StateApplyOutcome::Blocked;
    };
    let mut changed = group.add_client(username, priority);
    let client = state
        .clients
        .entry(username.to_string())
        .or_insert_with(|| DynSecClient::placeholder(username));
    changed |= client.add_group(groupname, priority);
    StateApplyOutcome::from_changed(changed)
}

fn apply_state_remove_group_client(
    state: &mut DynSecState,
    groupname: &str,
    username: &str,
) -> StateApplyOutcome {
    let mut changed = false;
    if let Some(group) = state.groups.get_mut(groupname) {
        changed |= group.remove_client(username);
    }
    if let Some(client) = state.clients.get_mut(username) {
        changed |= client.remove_group(groupname);
    }
    changed |= prune_placeholder_client(state, username);
    StateApplyOutcome::from_changed(changed)
}

fn apply_state_add_role_acl(
    state: &mut DynSecState,
    rolename: &str,
    acltype: &str,
    topic: &str,
    priority: i32,
    allow: bool,
) -> StateApplyOutcome {
    let Some(parsed_acl_type) = AclType::from_control_str(acltype) else {
        return StateApplyOutcome::Blocked;
    };
    let Some(role) = state.roles.get_mut(rolename) else {
        return StateApplyOutcome::Blocked;
    };
    StateApplyOutcome::from_changed(role.acls.upsert_acl_entry(AclEntry {
        acl_type: parsed_acl_type,
        topic: topic.to_string(),
        allow,
        priority,
    }))
}

fn apply_state_remove_role_acl(
    state: &mut DynSecState,
    rolename: &str,
    acltype: &str,
    topic: &str,
) -> StateApplyOutcome {
    let Some(parsed_acl_type) = AclType::from_control_str(acltype) else {
        return StateApplyOutcome::AlreadySatisfied;
    };
    let Some(role) = state.roles.get_mut(rolename) else {
        return StateApplyOutcome::AlreadySatisfied;
    };
    StateApplyOutcome::from_changed(role.acls.remove_acl_entry(parsed_acl_type, topic).is_some())
}

pub fn prune_placeholder_client(state: &mut DynSecState, username: &str) -> bool {
    let should_prune = state
        .clients
        .get(username)
        .is_some_and(DynSecClient::is_prunable_placeholder);
    if !should_prune {
        return false;
    }
    state.clients.remove(username).is_some()
}

pub fn delete_group_from_state(state: &mut DynSecState, groupname: &str) -> bool {
    let removed_group = state.groups.remove(groupname).is_some();
    let clear_anonymous_group = state.anonymous_group.as_deref() == Some(groupname);
    if clear_anonymous_group {
        state.anonymous_group = None;
    }
    let mut changed = removed_group || clear_anonymous_group;
    for client in state.clients.values_mut() {
        changed |= client.remove_group(groupname);
    }
    changed |= prune_unlinked_placeholder_clients(state);
    changed
}

fn prune_unlinked_placeholder_clients(state: &mut DynSecState) -> bool {
    let usernames_to_prune: Vec<String> = state
        .clients
        .iter()
        .filter_map(|(username, client)| {
            if client.is_prunable_placeholder() {
                Some(username.clone())
            } else {
                None
            }
        })
        .collect();
    let mut changed = false;
    for username in usernames_to_prune {
        changed |= state.clients.remove(&username).is_some();
    }
    changed
}

fn collect_current_persist_repairs(
    commands: &[ControlCommand],
    state: &DynSecState,
    pending_mutations: &[PersistMutation],
    current_mutations: &[PersistMutation],
) -> Vec<PersistMutation> {
    let (requested_roles, requested_groups) = collect_requested_create_entities(commands);
    let (needed_roles, needed_groups) = collect_needed_create_repairs(
        pending_mutations,
        current_mutations,
        &requested_roles,
        &requested_groups,
    );
    build_create_repairs(commands, state, &needed_roles, &needed_groups)
}

fn collect_requested_create_entities(
    commands: &[ControlCommand],
) -> (HashSet<String>, HashSet<String>) {
    let mut requested_roles = HashSet::new();
    let mut requested_groups = HashSet::new();

    for command in commands {
        if let Some(rolename) = create_role_name(command) {
            requested_roles.insert(rolename.to_string());
        }
        if let Some(groupname) = create_group_name(command) {
            requested_groups.insert(groupname.to_string());
        }
    }

    (requested_roles, requested_groups)
}

fn collect_needed_create_repairs(
    pending_mutations: &[PersistMutation],
    current_mutations: &[PersistMutation],
    requested_roles: &HashSet<String>,
    requested_groups: &HashSet<String>,
) -> (HashSet<String>, HashSet<String>) {
    let mut needed_roles = HashSet::new();
    let mut needed_groups = HashSet::new();

    for mutation in pending_mutations.iter().chain(current_mutations.iter()) {
        match mutation {
            PersistMutation::AddGroupClient { groupname, .. }
                if requested_groups.contains(groupname) =>
            {
                needed_groups.insert(groupname.clone());
            }
            PersistMutation::RoleAcl(RoleAclMutation::Add { rolename, .. })
                if requested_roles.contains(rolename) =>
            {
                needed_roles.insert(rolename.clone());
            }
            _ => {}
        }
    }

    (needed_roles, needed_groups)
}

fn build_create_repairs(
    commands: &[ControlCommand],
    state: &DynSecState,
    needed_roles: &HashSet<String>,
    needed_groups: &HashSet<String>,
) -> Vec<PersistMutation> {
    let mut repairs = Vec::new();
    let mut emitted_roles = HashSet::new();
    let mut emitted_groups = HashSet::new();

    for command in commands {
        if let Some(rolename) = create_role_name(command) {
            if needed_roles.contains(rolename)
                && emitted_roles.insert(rolename.to_string())
                && let Some(role) = state.roles.get(rolename)
            {
                repairs.push(PersistMutation::CreateRole {
                    rolename: rolename.to_string(),
                    acls: role.to_control_acls(),
                });
            }
            continue;
        }

        let Some(groupname) = create_group_name(command) else {
            continue;
        };
        if needed_groups.contains(groupname)
            && emitted_groups.insert(groupname.to_string())
            && let Some(group) = state.groups.get(groupname)
        {
            repairs.push(PersistMutation::CreateGroup {
                groupname: groupname.to_string(),
                roles: group.to_control_roles(),
            });
        }
    }

    repairs
}

fn create_role_name(command: &ControlCommand) -> Option<&str> {
    matches!(
        ControlCommandKind::parse(&command.command),
        Some(ControlCommandKind::CreateRole)
    )
    .then_some(())?;
    command
        .rolename
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn create_group_name(command: &ControlCommand) -> Option<&str> {
    matches!(
        ControlCommandKind::parse(&command.command),
        Some(ControlCommandKind::CreateGroup)
    )
    .then_some(())?;
    command
        .groupname
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn build_retry_persist_mutations(
    pending_mutations: &[PersistMutation],
    current_persist_repairs: &[PersistMutation],
    current_mutations: &[PersistMutation],
) -> Vec<PersistMutation> {
    let mut combined = Vec::with_capacity(
        pending_mutations.len() + current_persist_repairs.len() + current_mutations.len(),
    );
    combined.extend_from_slice(pending_mutations);
    combined.extend_from_slice(current_persist_repairs);
    combined.extend_from_slice(current_mutations);
    collapse_retry_intents(&combined)
}

fn collapse_retry_intents(mutations: &[PersistMutation]) -> Vec<PersistMutation> {
    let mut reducer = RetryIntentReducer::default();
    for mutation in mutations {
        reducer.apply(mutation);
    }
    reducer.into_persist_mutations()
}

pub fn merge_persist_group_roles(
    existing_roles: &[RoleRef],
    next_roles: &[RoleRef],
) -> Vec<RoleRef> {
    let mut group = DynSecGroup::from_control_roles(Some(existing_roles.to_vec()));
    let _ = group.merge_control_roles(next_roles);
    group.to_control_roles()
}

pub fn merge_persist_role_acls(
    existing_acls: &[AclConfig],
    next_acls: &[AclConfig],
) -> Vec<AclConfig> {
    let mut role = DynSecRole::from_control_acls(Some(existing_acls.to_vec()));
    let _ = role.merge_control_acls(next_acls);
    role.to_control_acls()
}

#[cfg(test)]
mod tests;
