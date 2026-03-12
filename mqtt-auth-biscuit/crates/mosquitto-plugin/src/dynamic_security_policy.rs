use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

// Structural sub-modules (logically part of this module)
#[path = "dyn_sec_model.rs"]
mod dyn_sec_model;
#[path = "dyn_sec_mutation.rs"]
mod dyn_sec_mutation;
use dyn_sec_model::*;
use dyn_sec_mutation::{
    ControlCommand, ControlMutationDraft, ControlPayload, PersistMutation, RetryIntentReducer,
    RoleAclMutation,
};
pub(crate) use dyn_sec_mutation::{ControlEnforcementTargets, ControlNotifyEvent};

#[derive(Debug)]
pub struct DynamicSecurityPolicy {
    config_path: String,
    reload_interval: Duration,
    control_apply_lock: Mutex<()>,
    last_loaded: Mutex<Option<Instant>>,
    state: RwLock<DynSecState>,
    pending_persist_mutations: Mutex<Vec<PersistMutation>>,
    runtime_disabled_usernames: Mutex<HashSet<String>>,
    runtime_role_acl_overrides: Mutex<HashMap<RoleAclKey, RuntimeRoleAclOverride>>,
}

impl DynamicSecurityPolicy {
    pub fn new(config_path: impl Into<String>, reload_interval: Duration) -> Result<Self, String> {
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
    ) -> Result<bool, String> {
        self.reload_if_needed(false)?;
        let state = self
            .state
            .read()
            .map_err(|_| "dynsec state lock poisoned".to_string())?;
        let is_runtime_disabled = if let Some(name) = username {
            // Keep the lock order consistent with the control path, but drop the
            // runtime-disable mutex before the ACL walk.
            let runtime_disabled = self
                .runtime_disabled_usernames
                .lock()
                .map_err(|_| "dynsec runtime disable lock poisoned".to_string())?;
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

    pub fn apply_control_payload(
        &self,
        payload: &[u8],
    ) -> Result<ControlEnforcementTargets, String> {
        if payload.is_empty() {
            return Ok(ControlEnforcementTargets::default());
        }

        let parsed: ControlPayload =
            serde_json::from_slice(payload).map_err(|e| format!("invalid control payload: {e}"))?;
        if parsed.commands.is_empty() {
            return Ok(ControlEnforcementTargets::default());
        }

        // **Limitation**: `control_apply_lock` is held for the entire apply_control_payload
        // scope, including file I/O in load_current_control_state and persist_control_mutations.
        // A slow or stalled filesystem will block all concurrent control commands and any
        // reload_if_needed calls. This is a deliberate correctness-over-latency trade-off;
        // the research benchmark environment uses local tmpfs so this is not exercised in
        // normal throughput/latency measurements.
        let _control_guard = self
            .control_apply_lock
            .lock()
            .map_err(|_| "dynsec control lock poisoned".to_string())?;
        let state = match self.load_current_control_state() {
            Ok(state) => {
                self.refresh_cached_state(state.clone())?;
                state
            }
            Err(err) if is_dynsec_load_read_or_parse_error(&err) => self
                .state
                .read()
                .map_err(|_| "dynsec state lock poisoned".to_string())?
                .clone(),
            Err(err) => return Err(err),
        };

        // **Limitation**: The full runtime state, disabled-username set, and role-ACL
        // override map are cloned into the ControlMutationDraft so mutations can be
        // computed without holding the read locks. For large deployments this adds
        // allocation pressure on every control command; acceptable for the bounded
        // entity counts in the research benchmark scenarios.
        let draft = {
            let runtime_disabled_usernames = self
                .runtime_disabled_usernames
                .lock()
                .map_err(|_| "dynsec runtime disable lock poisoned".to_string())?
                .clone();
            let runtime_role_acl_overrides = self
                .runtime_role_acl_overrides
                .lock()
                .map_err(|_| "dynsec runtime role-acl lock poisoned".to_string())?
                .clone();
            let mut draft = ControlMutationDraft::new(
                state,
                runtime_disabled_usernames,
                runtime_role_acl_overrides,
            );
            for cmd in &parsed.commands {
                draft.apply_command(cmd);
            }
            draft.finalize_notify_events();
            draft
        };

        let pending_persist_mutations = self
            .pending_persist_mutations
            .lock()
            .map_err(|_| "dynsec pending persist lock poisoned".to_string())?
            .clone();
        let current_persist_mutations = draft.persist_mutations.clone();
        let current_persist_repairs = collect_current_persist_repairs(
            &parsed.commands,
            &draft.state,
            &pending_persist_mutations,
            &current_persist_mutations,
        );
        let retry_persist_mutations = build_retry_persist_mutations(
            &pending_persist_mutations,
            &current_persist_repairs,
            &current_persist_mutations,
        );

        let mut targets = self.commit_control_mutation_draft(draft, None)?;
        if retry_persist_mutations.is_empty() {
            return Ok(targets);
        }

        let mut pending_guard = match self.pending_persist_mutations.lock() {
            Ok(guard) => guard,
            Err(_) => {
                targets.persist_warning = Some("dynsec pending persist lock poisoned".to_string());
                return Ok(targets);
            }
        };

        // The threshold below detects a persistently broken config file. The queue is
        // already collapsed by RetryIntentReducer, so its size is bounded by the number
        // of distinct (entity, operation) combinations mutated while the file was
        // unwritable — not by raw command count. Exceeding the threshold means many
        // distinct roles/groups/clients have been mutated without any successful flush.
        //
        // **Limitation**: The queue is not hard-capped. Under a permanently unwritable
        // config file with a sustained stream of distinct structural mutations, memory
        // usage grows without bound. In the research benchmark environment the number
        // of distinct entities is small and bounded by scenario design, so this does
        // not manifest in practice.
        const PENDING_PERSIST_WARN_THRESHOLD: usize = 256;

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
                targets.persist_warning = Some(err);
            }
        }

        Ok(targets)
    }

    /// **Limitation**: `reload_is_due` is checked outside `control_apply_lock` to avoid
    /// acquiring the mutex on the hot path when no reload is needed. This means two
    /// concurrent callers can both observe `reload_is_due() == true` and then serialise
    /// on the lock — the second thread will perform a redundant (but harmless) reload
    /// because `reload_if_needed_locked` re-checks the timer under the lock.
    fn reload_if_needed(&self, force: bool) -> Result<(), String> {
        if !self.reload_is_due(force)? {
            return Ok(());
        }

        let _control_guard = self
            .control_apply_lock
            .lock()
            .map_err(|_| "dynsec control lock poisoned".to_string())?;
        self.reload_if_needed_locked(force)
    }

    fn reload_is_due(&self, force: bool) -> Result<bool, String> {
        if force {
            return Ok(true);
        }

        let now = Instant::now();
        let last_loaded = self
            .last_loaded
            .lock()
            .map_err(|_| "dynsec reload lock poisoned".to_string())?;

        if let Some(last) = *last_loaded
            && now.duration_since(last) < self.reload_interval
        {
            return Ok(false);
        }

        Ok(true)
    }

    fn reload_if_needed_locked(&self, force: bool) -> Result<(), String> {
        let now = Instant::now();
        let mut last_loaded = self
            .last_loaded
            .lock()
            .map_err(|_| "dynsec reload lock poisoned".to_string())?;

        if !force
            && let Some(last) = *last_loaded
            && now.duration_since(last) < self.reload_interval
        {
            return Ok(());
        }

        let has_valid_cached_state = last_loaded.is_some();
        match self.load_current_control_state() {
            Ok(state) => {
                let mut guard = self
                    .state
                    .write()
                    .map_err(|_| "dynsec state lock poisoned".to_string())?;
                *guard = state;
                *last_loaded = Some(now);
            }
            Err(err) if has_valid_cached_state && is_dynsec_load_read_or_parse_error(&err) => {
                return Ok(());
            }
            Err(err) => return Err(err),
        }

        Ok(())
    }

    fn load_current_control_state(&self) -> Result<DynSecState, String> {
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

    fn load_base_control_state(&self) -> Result<DynSecState, String> {
        let raw = fs::read_to_string(&self.config_path)
            .map_err(|e| format!("dynsec config read failed: {e}"))?;
        let cfg: DynSecConfig =
            serde_json::from_str(&raw).map_err(|e| format!("dynsec config parse failed: {e}"))?;
        Ok(DynSecState::from_config(cfg))
    }

    fn refresh_cached_state(&self, state: DynSecState) -> Result<(), String> {
        let mut guard = self
            .state
            .write()
            .map_err(|_| "dynsec state lock poisoned".to_string())?;
        *guard = state;
        let mut last_loaded = self
            .last_loaded
            .lock()
            .map_err(|_| "dynsec reload lock poisoned".to_string())?;
        *last_loaded = Some(Instant::now());
        Ok(())
    }

    fn apply_runtime_role_acl_overrides(&self, state: &mut DynSecState) -> Result<(), String> {
        let overrides = self
            .runtime_role_acl_overrides
            .lock()
            .map_err(|_| "dynsec runtime role-acl lock poisoned".to_string())?;
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
        Ok(())
    }

    fn apply_pending_reload_mutations_best_effort(
        &self,
        state: &mut DynSecState,
    ) -> Result<PendingReplaySummary, String> {
        let mut summary = PendingReplaySummary::default();
        let pending = self
            .pending_persist_mutations
            .lock()
            .map_err(|_| "dynsec pending persist lock poisoned".to_string())?;
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
        Ok(summary)
    }

    /// **Limitation**: This performs a non-atomic read-modify-write on the JSON config
    /// file. The `control_apply_lock` mutex protects against concurrent writes from
    /// this process, but cannot guard against an external process (e.g. the Mosquitto
    /// Dynamic Security plugin) writing to the same file between our read and write.
    /// Such a race would silently overwrite the external change.
    fn persist_control_mutations(&self, mutations: &[PersistMutation]) -> Result<(), String> {
        let raw = fs::read_to_string(&self.config_path)
            .map_err(|e| format!("dynsec config read failed: {e}"))?;
        let mut root: Value =
            serde_json::from_str(&raw).map_err(|e| format!("dynsec config parse failed: {e}"))?;

        let mut changed = false;
        let mut blocked = false;
        for mutation in mutations {
            let outcome = apply_persist_mutation(&mut root, mutation)?;
            changed |= outcome.changed();
            blocked |= outcome.blocked();
        }

        if blocked {
            return Err("dynsec config persistence blocked by divergent state".to_string());
        }

        if !changed {
            return Ok(());
        }

        let serialized = serde_json::to_string_pretty(&root)
            .map_err(|e| format!("dynsec config serialize failed: {e}"))?;
        fs::write(&self.config_path, format!("{serialized}\n"))
            .map_err(|e| format!("dynsec config write failed: {e}"))?;
        Ok(())
    }

    fn commit_control_mutation_draft(
        &self,
        draft: ControlMutationDraft,
        persist_warning: Option<String>,
    ) -> Result<ControlEnforcementTargets, String> {
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
                let mut state = self
                    .state
                    .write()
                    .map_err(|_| "dynsec state lock poisoned".to_string())?;
                let mut runtime_disabled = self
                    .runtime_disabled_usernames
                    .lock()
                    .map_err(|_| "dynsec runtime disable lock poisoned".to_string())?;
                *state = next_state;
                *runtime_disabled = runtime_disabled_usernames;
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
                let mut overrides = self
                    .runtime_role_acl_overrides
                    .lock()
                    .map_err(|_| "dynsec runtime role-acl lock poisoned".to_string())?;
                *overrides = runtime_role_acl_overrides;
            }
            let mut last_loaded = self
                .last_loaded
                .lock()
                .map_err(|_| "dynsec reload lock poisoned".to_string())?;
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

pub(crate) fn state_allows_username_access(
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

fn is_dynsec_load_read_or_parse_error(err: &str) -> bool {
    err.starts_with("dynsec config read failed:") || err.starts_with("dynsec config parse failed:")
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
            let Some(client) = state.clients.get_mut(username) else {
                return StateApplyOutcome::Blocked;
            };
            if client.disabled == *disabled {
                return StateApplyOutcome::AlreadySatisfied;
            }
            client.disabled = *disabled;
            StateApplyOutcome::Changed
        }
        PersistMutation::CreateRole { rolename, acls } => {
            if let Some(role) = state.roles.get_mut(rolename) {
                return StateApplyOutcome::from_changed(role.merge_control_acls(acls));
            }
            state.roles.insert(
                rolename.clone(),
                DynSecRole::from_control_acls(Some(acls.clone())),
            );
            StateApplyOutcome::Changed
        }
        PersistMutation::DeleteRole { rolename } => {
            let mut changed = state.roles.remove(rolename).is_some();
            for client in state.clients.values_mut() {
                changed |= client.remove_role(rolename);
            }
            for group in state.groups.values_mut() {
                changed |= group.remove_role(rolename);
            }
            StateApplyOutcome::from_changed(changed)
        }
        PersistMutation::CreateGroup { groupname, roles } => {
            if let Some(group) = state.groups.get_mut(groupname) {
                return StateApplyOutcome::from_changed(group.merge_control_roles(roles));
            }
            state.groups.insert(
                groupname.clone(),
                DynSecGroup::from_control_roles(Some(roles.clone())),
            );
            StateApplyOutcome::Changed
        }
        PersistMutation::DeleteGroup { groupname } => {
            StateApplyOutcome::from_changed(delete_group_from_state(state, groupname))
        }
        PersistMutation::AddGroupClient {
            groupname,
            username,
            priority,
        } => {
            let Some(group) = state.groups.get_mut(groupname) else {
                return StateApplyOutcome::Blocked;
            };
            let mut changed = group.add_client(username, *priority);
            let client = state
                .clients
                .entry(username.clone())
                .or_insert_with(|| DynSecClient::placeholder(username));
            changed |= client.add_group(groupname, *priority);
            StateApplyOutcome::from_changed(changed)
        }
        PersistMutation::RemoveGroupClient {
            groupname,
            username,
        } => {
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
        PersistMutation::RoleAcl(RoleAclMutation::Add {
            rolename,
            acltype,
            topic,
            priority,
            allow,
        }) => {
            let Some(acl_type) = AclType::from_control_str(acltype) else {
                return StateApplyOutcome::Blocked;
            };
            let Some(role) = state.roles.get_mut(rolename) else {
                return StateApplyOutcome::Blocked;
            };
            StateApplyOutcome::from_changed(role.acls.upsert_acl_entry(AclEntry {
                acl_type,
                topic: topic.clone(),
                allow: *allow,
                priority: *priority,
            }))
        }
        PersistMutation::RoleAcl(RoleAclMutation::Remove {
            rolename,
            acltype,
            topic,
        }) => {
            let Some(acl_type) = AclType::from_control_str(acltype) else {
                return StateApplyOutcome::AlreadySatisfied;
            };
            let Some(role) = state.roles.get_mut(rolename) else {
                return StateApplyOutcome::AlreadySatisfied;
            };
            StateApplyOutcome::from_changed(role.acls.remove_acl_entry(acl_type, topic).is_some())
        }
    }
}

pub(crate) fn prune_placeholder_client(state: &mut DynSecState, username: &str) -> bool {
    let should_prune = state
        .clients
        .get(username)
        .is_some_and(DynSecClient::is_prunable_placeholder);
    if !should_prune {
        return false;
    }
    state.clients.remove(username).is_some()
}

pub(crate) fn delete_group_from_state(state: &mut DynSecState, groupname: &str) -> bool {
    let mut changed = state.groups.remove(groupname).is_some();
    if state.anonymous_group.as_deref() == Some(groupname) {
        state.anonymous_group = None;
        changed = true;
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistApplyOutcome {
    Changed,
    AlreadySatisfied,
    Blocked,
}

impl PersistApplyOutcome {
    const fn from_changed(changed: bool) -> Self {
        if changed {
            Self::Changed
        } else {
            Self::AlreadySatisfied
        }
    }

    const fn changed(self) -> bool {
        matches!(self, Self::Changed)
    }

    const fn blocked(self) -> bool {
        matches!(self, Self::Blocked)
    }
}

fn apply_persist_mutation(
    root: &mut Value,
    mutation: &PersistMutation,
) -> Result<PersistApplyOutcome, String> {
    match mutation {
        PersistMutation::SetClientDisabled { username, disabled } => {
            let clients = ensure_array(root, "clients")?;
            let mut changed = false;
            let mut found = false;
            for client in &mut *clients {
                let Some(current_username) = client.get("username").and_then(Value::as_str) else {
                    continue;
                };
                if current_username == username {
                    found = true;
                    let current_disabled = client
                        .get("disabled")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if current_disabled != *disabled {
                        client["disabled"] = Value::Bool(*disabled);
                        changed = true;
                    }
                }
            }
            if !found && *disabled {
                changed |= persist_disabled_placeholder_client(clients, username);
            }
            Ok(PersistApplyOutcome::from_changed(changed))
        }
        PersistMutation::CreateRole { rolename, acls } => {
            let roles = ensure_array(root, "roles")?;
            if let Some(role) = roles.iter_mut().find(|role| {
                role.get("rolename").and_then(Value::as_str) == Some(rolename.as_str())
            }) {
                let mut changed = false;
                for acl in acls {
                    changed |= upsert_acl_ref(role, acl)?.changed();
                }
                return Ok(PersistApplyOutcome::from_changed(changed));
            }

            let mut role = json!({ "rolename": rolename });
            if !acls.is_empty() {
                role["acls"] = Value::Array(acls.iter().map(acl_to_value).collect());
            }
            roles.push(role);
            Ok(PersistApplyOutcome::Changed)
        }
        PersistMutation::DeleteRole { rolename } => {
            let mut changed = false;
            if let Some(roles) = get_array_field(root, "roles")? {
                let before_len = roles.len();
                roles.retain(|role| {
                    role.get("rolename").and_then(Value::as_str) != Some(rolename.as_str())
                });
                changed |= roles.len() != before_len;
            }
            if let Some(groups) = get_array_field(root, "groups")? {
                for group in groups {
                    changed |= remove_named_ref(group, "roles", "rolename", rolename)?.changed();
                }
            }
            if let Some(clients) = get_array_field(root, "clients")? {
                for client in clients {
                    changed |= remove_named_ref(client, "roles", "rolename", rolename)?.changed();
                }
            }
            Ok(PersistApplyOutcome::from_changed(changed))
        }
        PersistMutation::CreateGroup { groupname, roles } => {
            let groups = ensure_array(root, "groups")?;
            if let Some(group) = groups.iter_mut().find(|group| {
                group.get("groupname").and_then(Value::as_str) == Some(groupname.as_str())
            }) {
                let mut changed = false;
                for role in roles {
                    changed |= upsert_named_priority_ref(
                        group,
                        "roles",
                        "rolename",
                        &role.rolename,
                        role.priority.unwrap_or(-1),
                    )?
                    .changed();
                }
                return Ok(PersistApplyOutcome::from_changed(changed));
            }

            let mut group = json!({ "groupname": groupname });
            if !roles.is_empty() {
                group["roles"] = Value::Array(roles.iter().map(role_ref_to_value).collect());
            }
            groups.push(group);
            Ok(PersistApplyOutcome::Changed)
        }
        PersistMutation::DeleteGroup { groupname } => {
            let mut changed = false;
            if let Some(groups) = get_array_field(root, "groups")? {
                let before_len = groups.len();
                groups.retain(|group| {
                    group.get("groupname").and_then(Value::as_str) != Some(groupname.as_str())
                });
                changed |= groups.len() != before_len;
            }
            if let Some(clients) = get_array_field(root, "clients")? {
                let mut index = 0;
                while index < clients.len() {
                    changed |=
                        remove_named_ref(&mut clients[index], "groups", "groupname", groupname)?
                            .changed();
                    if is_prunable_persisted_placeholder_client(&clients[index])? {
                        clients.remove(index);
                        changed = true;
                        continue;
                    }
                    index += 1;
                }
            }
            if root.get("anonymousGroup").and_then(Value::as_str) == Some(groupname.as_str()) {
                let object = root
                    .as_object_mut()
                    .ok_or_else(|| "dynsec config root is not an object".to_string())?;
                changed |= object.remove("anonymousGroup").is_some();
            }
            Ok(PersistApplyOutcome::from_changed(changed))
        }
        PersistMutation::AddGroupClient {
            groupname,
            username,
            priority,
        } => {
            let mut changed = false;

            {
                let Some(groups) = get_array_field(root, "groups")? else {
                    return Ok(PersistApplyOutcome::Blocked);
                };
                let Some(group) = groups.iter_mut().find(|group| {
                    group.get("groupname").and_then(Value::as_str) == Some(groupname.as_str())
                }) else {
                    return Ok(PersistApplyOutcome::Blocked);
                };

                changed |=
                    upsert_named_priority_ref(group, "clients", "username", username, *priority)?
                        .changed();
            }

            let Some(clients) = get_array_field(root, "clients")? else {
                return Ok(PersistApplyOutcome::from_changed(changed));
            };
            if let Some(client) = clients.iter_mut().find(|client| {
                client.get("username").and_then(Value::as_str) == Some(username.as_str())
            }) {
                changed |=
                    upsert_named_priority_ref(client, "groups", "groupname", groupname, *priority)?
                        .changed();
            }

            Ok(PersistApplyOutcome::from_changed(changed))
        }
        PersistMutation::RemoveGroupClient {
            groupname,
            username,
        } => {
            let mut changed = false;
            if let Some(groups) = get_array_field(root, "groups")? {
                for group in groups {
                    let Some(current_groupname) = group.get("groupname").and_then(Value::as_str)
                    else {
                        continue;
                    };
                    if current_groupname == groupname {
                        changed |=
                            remove_named_ref(group, "clients", "username", username)?.changed();
                    }
                }
            }
            if let Some(clients) = get_array_field(root, "clients")? {
                for client in &mut *clients {
                    let Some(current_username) = client.get("username").and_then(Value::as_str)
                    else {
                        continue;
                    };
                    if current_username == username {
                        changed |=
                            remove_named_ref(client, "groups", "groupname", groupname)?.changed();
                    }
                }
                changed |= prune_persisted_placeholder_client(clients, username)?.changed();
            }
            Ok(PersistApplyOutcome::from_changed(changed))
        }
        PersistMutation::RoleAcl(RoleAclMutation::Add {
            rolename,
            acltype,
            topic,
            priority,
            allow,
        }) => {
            let Some(roles) = get_array_field(root, "roles")? else {
                return Ok(PersistApplyOutcome::Blocked);
            };

            for role in roles {
                let Some(current_rolename) = role.get("rolename").and_then(Value::as_str) else {
                    continue;
                };
                if current_rolename != rolename {
                    continue;
                }
                let acls = ensure_nested_array(role, "acls")?;
                for acl in acls.iter_mut() {
                    let acl_acltype = acl.get("acltype").and_then(Value::as_str);
                    let acl_topic = acl.get("topic").and_then(Value::as_str);
                    if acl_acltype == Some(acltype.as_str()) && acl_topic == Some(topic.as_str()) {
                        let current_priority =
                            acl.get("priority").and_then(Value::as_i64).unwrap_or(0);
                        let current_allow =
                            acl.get("allow").and_then(Value::as_bool).unwrap_or(false);
                        if current_priority == i64::from(*priority) && current_allow == *allow {
                            return Ok(PersistApplyOutcome::AlreadySatisfied);
                        }
                        acl["priority"] = Value::Number((*priority).into());
                        acl["allow"] = Value::Bool(*allow);
                        return Ok(PersistApplyOutcome::Changed);
                    }
                }
                acls.push(json!({
                    "acltype": acltype,
                    "topic": topic,
                    "priority": priority,
                    "allow": allow,
                }));
                return Ok(PersistApplyOutcome::Changed);
            }
            Ok(PersistApplyOutcome::Blocked)
        }
        PersistMutation::RoleAcl(RoleAclMutation::Remove {
            rolename,
            acltype,
            topic,
        }) => {
            let Some(roles) = get_array_field(root, "roles")? else {
                return Ok(PersistApplyOutcome::AlreadySatisfied);
            };

            let mut changed = false;
            for role in roles {
                let Some(current_rolename) = role.get("rolename").and_then(Value::as_str) else {
                    continue;
                };
                if current_rolename != rolename {
                    continue;
                }
                if let Some(acls) = get_nested_array_field(role, "acls")? {
                    let before_len = acls.len();
                    acls.retain(|acl| {
                        let acl_acltype = acl.get("acltype").and_then(Value::as_str);
                        let acl_topic = acl.get("topic").and_then(Value::as_str);
                        !(acl_acltype == Some(acltype.as_str())
                            && acl_topic == Some(topic.as_str()))
                    });
                    changed |= acls.len() != before_len;
                }
            }
            Ok(PersistApplyOutcome::from_changed(changed))
        }
    }
}

fn ensure_array<'a>(root: &'a mut Value, key: &str) -> Result<&'a mut Vec<Value>, String> {
    if root.get(key).is_none() {
        root[key] = Value::Array(Vec::new());
    }
    let Some(value) = root.get_mut(key) else {
        return Err(format!("dynsec config schema invalid: missing '{key}'"));
    };
    expect_array(value, key)
}

fn collect_current_persist_repairs(
    commands: &[ControlCommand],
    state: &DynSecState,
    pending_mutations: &[PersistMutation],
    current_mutations: &[PersistMutation],
) -> Vec<PersistMutation> {
    let mut requested_roles = HashSet::new();
    let mut requested_groups = HashSet::new();
    for cmd in commands {
        match cmd.command.trim() {
            "createRole" => {
                let Some(rolename) = cmd
                    .rolename
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                requested_roles.insert(rolename.to_string());
            }
            "createGroup" => {
                let Some(groupname) = cmd
                    .groupname
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                requested_groups.insert(groupname.to_string());
            }
            _ => {}
        }
    }

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

    let mut repairs = Vec::new();
    let mut emitted_roles = HashSet::new();
    let mut emitted_groups = HashSet::new();
    for cmd in commands {
        match cmd.command.trim() {
            "createRole" => {
                let Some(rolename) = cmd
                    .rolename
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                if !needed_roles.contains(rolename) || !emitted_roles.insert(rolename.to_string()) {
                    continue;
                }
                let Some(role) = state.roles.get(rolename) else {
                    continue;
                };
                repairs.push(PersistMutation::CreateRole {
                    rolename: rolename.to_string(),
                    acls: role.to_control_acls(),
                });
            }
            "createGroup" => {
                let Some(groupname) = cmd
                    .groupname
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                else {
                    continue;
                };
                if !needed_groups.contains(groupname)
                    || !emitted_groups.insert(groupname.to_string())
                {
                    continue;
                }
                let Some(group) = state.groups.get(groupname) else {
                    continue;
                };
                repairs.push(PersistMutation::CreateGroup {
                    groupname: groupname.to_string(),
                    roles: group.to_control_roles(),
                });
            }
            _ => {}
        }
    }
    repairs
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

pub(crate) fn merge_persist_group_roles(
    existing_roles: &[RoleRef],
    next_roles: &[RoleRef],
) -> Vec<RoleRef> {
    let mut group = DynSecGroup::from_control_roles(Some(existing_roles.to_vec()));
    let _ = group.merge_control_roles(next_roles);
    group.to_control_roles()
}

pub(crate) fn merge_persist_role_acls(
    existing_acls: &[AclConfig],
    next_acls: &[AclConfig],
) -> Vec<AclConfig> {
    let mut role = DynSecRole::from_control_acls(Some(existing_acls.to_vec()));
    let _ = role.merge_control_acls(next_acls);
    role.to_control_acls()
}

fn get_array_field<'a>(
    root: &'a mut Value,
    key: &str,
) -> Result<Option<&'a mut Vec<Value>>, String> {
    let Some(value) = root.get_mut(key) else {
        return Ok(None);
    };
    expect_array(value, key).map(Some)
}

fn ensure_nested_array<'a>(
    parent: &'a mut Value,
    field: &str,
) -> Result<&'a mut Vec<Value>, String> {
    if parent.get(field).is_none() {
        parent[field] = Value::Array(Vec::new());
    }
    let Some(value) = parent.get_mut(field) else {
        return Err(format!("dynsec config schema invalid: missing '{field}'"));
    };
    expect_array(value, field)
}

fn get_nested_array_field<'a>(
    parent: &'a mut Value,
    field: &str,
) -> Result<Option<&'a mut Vec<Value>>, String> {
    let Some(value) = parent.get_mut(field) else {
        return Ok(None);
    };
    expect_array(value, field).map(Some)
}

fn expect_array<'a>(value: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>, String> {
    value
        .as_array_mut()
        .ok_or_else(|| format!("dynsec config schema invalid: expected '{field}' to be an array"))
}

fn remove_named_ref(
    parent: &mut Value,
    field: &str,
    name_field: &str,
    target: &str,
) -> Result<PersistApplyOutcome, String> {
    let Some(list) = get_nested_array_field(parent, field)? else {
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    };
    let before_len = list.len();
    list.retain(|entry| entry.get(name_field).and_then(Value::as_str) != Some(target));
    Ok(PersistApplyOutcome::from_changed(list.len() != before_len))
}

fn prune_persisted_placeholder_client(
    clients: &mut Vec<Value>,
    username: &str,
) -> Result<PersistApplyOutcome, String> {
    let Some(index) = clients
        .iter()
        .position(|client| client.get("username").and_then(Value::as_str) == Some(username))
    else {
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    };

    if !is_prunable_persisted_placeholder_client(&clients[index])? {
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    }

    clients.remove(index);
    Ok(PersistApplyOutcome::Changed)
}

fn persist_disabled_placeholder_client(clients: &mut Vec<Value>, username: &str) -> bool {
    // Disabled synthetic users must remain durable even after their final
    // group reference is removed, so persist a minimal stub.
    clients.push(json!({
        "username": username,
        "disabled": true,
    }));
    true
}

fn is_prunable_persisted_placeholder_client(client: &Value) -> Result<bool, String> {
    if client.get("username").and_then(Value::as_str).is_none() {
        return Ok(false);
    }

    let has_client_id = client
        .get("clientid")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let roles_empty = nested_array_missing_or_empty(client, "roles")?;
    let groups_empty = nested_array_missing_or_empty(client, "groups")?;
    let disabled = client
        .get("disabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(!has_client_id && roles_empty && groups_empty && !disabled)
}

fn nested_array_missing_or_empty(parent: &Value, field: &str) -> Result<bool, String> {
    let Some(value) = parent.get(field) else {
        return Ok(true);
    };
    let Some(array) = value.as_array() else {
        return Err(format!(
            "dynsec config schema invalid: expected '{field}' to be an array"
        ));
    };
    Ok(array.is_empty())
}

fn upsert_named_priority_ref(
    parent: &mut Value,
    field: &str,
    name_field: &str,
    target: &str,
    priority: i32,
) -> Result<PersistApplyOutcome, String> {
    let list = ensure_nested_array(parent, field)?;

    for entry in list.iter_mut() {
        let Some(current_target) = entry.get(name_field).and_then(Value::as_str) else {
            continue;
        };
        if current_target != target {
            continue;
        }

        let current_priority = entry.get("priority").and_then(Value::as_i64).unwrap_or(-1);
        if current_priority != i64::from(priority) {
            entry["priority"] = Value::Number(priority.into());
            return Ok(PersistApplyOutcome::Changed);
        }
        return Ok(PersistApplyOutcome::AlreadySatisfied);
    }

    list.push(json!({
        name_field: target,
        "priority": priority,
    }));
    Ok(PersistApplyOutcome::Changed)
}

fn upsert_acl_ref(parent: &mut Value, acl: &AclConfig) -> Result<PersistApplyOutcome, String> {
    let acls = ensure_nested_array(parent, "acls")?;

    for entry in acls.iter_mut() {
        let current_acltype = entry.get("acltype").and_then(Value::as_str);
        let current_topic = entry.get("topic").and_then(Value::as_str);
        if current_acltype != Some(acl.acltype.as_str())
            || current_topic != Some(acl.topic.as_str())
        {
            continue;
        }

        let current_priority = entry.get("priority").and_then(Value::as_i64);
        let current_allow = entry.get("allow").and_then(Value::as_bool);
        let next_priority = acl.priority.map(i64::from);
        let next_allow = acl.allow;
        if current_priority == next_priority && current_allow == next_allow {
            return Ok(PersistApplyOutcome::AlreadySatisfied);
        }

        if let Some(priority) = acl.priority {
            entry["priority"] = Value::Number(priority.into());
        } else {
            let _ = entry.as_object_mut().map(|obj| obj.remove("priority"));
        }
        if let Some(allow) = acl.allow {
            entry["allow"] = Value::Bool(allow);
        } else {
            let _ = entry.as_object_mut().map(|obj| obj.remove("allow"));
        }
        return Ok(PersistApplyOutcome::Changed);
    }

    acls.push(acl_to_value(acl));
    Ok(PersistApplyOutcome::Changed)
}

fn role_ref_to_value(role: &RoleRef) -> Value {
    let mut out = json!({ "rolename": role.rolename });
    if let Some(priority) = role.priority {
        out["priority"] = Value::Number(priority.into());
    }
    out
}

fn acl_to_value(acl: &AclConfig) -> Value {
    let mut out = json!({
        "acltype": acl.acltype,
        "topic": acl.topic,
    });
    if let Some(priority) = acl.priority {
        out["priority"] = Value::Number(priority.into());
    }
    if let Some(allow) = acl.allow {
        out["allow"] = Value::Bool(allow);
    }
    out
}

#[cfg(test)]
#[path = "dynamic_security_policy_tests.rs"]
mod tests;
