use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

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

fn state_allows_username_access(
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

fn prune_placeholder_client(state: &mut DynSecState, username: &str) -> bool {
    let should_prune = state
        .clients
        .get(username)
        .is_some_and(DynSecClient::is_prunable_placeholder);
    if !should_prune {
        return false;
    }
    state.clients.remove(username).is_some()
}

fn delete_group_from_state(state: &mut DynSecState, groupname: &str) -> bool {
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

fn merge_persist_group_roles(existing_roles: &[RoleRef], next_roles: &[RoleRef]) -> Vec<RoleRef> {
    let mut group = DynSecGroup::from_control_roles(Some(existing_roles.to_vec()));
    let _ = group.merge_control_roles(next_roles);
    group.to_control_roles()
}

fn merge_persist_role_acls(existing_acls: &[AclConfig], next_acls: &[AclConfig]) -> Vec<AclConfig> {
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

#[derive(Debug, Clone, Deserialize)]
struct ControlPayload {
    #[serde(default)]
    commands: Vec<ControlCommand>,
}

#[derive(Debug, Clone, Deserialize)]
struct ControlCommand {
    command: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    groupname: Option<String>,
    #[serde(default)]
    rolename: Option<String>,
    #[serde(default)]
    roles: Option<Vec<RoleRef>>,
    #[serde(default)]
    acls: Option<Vec<AclConfig>>,
    #[serde(default)]
    acltype: Option<String>,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    priority: Option<i32>,
    #[serde(default)]
    allow: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlEnforcementTargets {
    pub kick_client_ids: Vec<String>,
    pub kick_usernames: Vec<String>,
    pub notify_events: Vec<ControlNotifyEvent>,
    pub persist_warning: Option<String>,
}

#[derive(Debug, Clone)]
struct ControlMutationDraft {
    // Notify events are computed as a net revocation diff across the whole payload.
    initial_state: DynSecState,
    state: DynSecState,
    initial_runtime_disabled_usernames: HashSet<String>,
    runtime_disabled_usernames: HashSet<String>,
    runtime_role_acl_overrides: HashMap<RoleAclKey, RuntimeRoleAclOverride>,
    kick_client_ids: HashSet<String>,
    kick_usernames: HashSet<String>,
    pending_notify_candidates: Vec<PendingNotifyCandidate>,
    notify_events: Vec<ControlNotifyEvent>,
    persist_mutations: Vec<PersistMutation>,
    changed: bool,
}

impl ControlMutationDraft {
    fn new(
        state: DynSecState,
        runtime_disabled_usernames: HashSet<String>,
        runtime_role_acl_overrides: HashMap<RoleAclKey, RuntimeRoleAclOverride>,
    ) -> Self {
        Self {
            initial_state: state.clone(),
            state,
            initial_runtime_disabled_usernames: runtime_disabled_usernames.clone(),
            runtime_disabled_usernames,
            runtime_role_acl_overrides,
            kick_client_ids: HashSet::new(),
            kick_usernames: HashSet::new(),
            pending_notify_candidates: Vec::new(),
            notify_events: Vec::new(),
            persist_mutations: Vec::new(),
            changed: false,
        }
    }

    fn apply_command(&mut self, cmd: &ControlCommand) {
        let command = cmd.command.as_str();
        if command == "disableClient" || command == "enableClient" {
            self.apply_client_disable_command(command, cmd);
            return;
        }

        if command == "createRole" {
            let Some(rolename) = cmd
                .rolename
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return;
            };

            if self.state.roles.contains_key(rolename) {
                return;
            }

            self.state.roles.insert(
                rolename.to_string(),
                DynSecRole::from_control_acls(cmd.acls.clone()),
            );
            self.persist_mutations.push(PersistMutation::CreateRole {
                rolename: rolename.to_string(),
                acls: cmd.acls.clone().unwrap_or_default(),
            });
            self.changed = true;
            return;
        }

        if command == "deleteRole" {
            let Some(rolename) = cmd
                .rolename
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return;
            };

            if self.state.roles.remove(rolename).is_none() {
                return;
            }
            for client in self.state.clients.values_mut() {
                client.remove_role(rolename);
            }
            for group in self.state.groups.values_mut() {
                group.remove_role(rolename);
            }
            let before_len = self.runtime_role_acl_overrides.len();
            self.runtime_role_acl_overrides
                .retain(|key, _| key.rolename != rolename);
            self.changed |= self.runtime_role_acl_overrides.len() != before_len;
            self.persist_mutations.push(PersistMutation::DeleteRole {
                rolename: rolename.to_string(),
            });
            self.queue_role_publish_receive_revocation_candidates(command, rolename, None);
            self.changed = true;
            return;
        }

        if command == "createGroup" {
            let Some(groupname) = cmd
                .groupname
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return;
            };

            if self.state.groups.contains_key(groupname) {
                return;
            }

            self.state.groups.insert(
                groupname.to_string(),
                DynSecGroup::from_control_roles(cmd.roles.clone()),
            );
            self.persist_mutations.push(PersistMutation::CreateGroup {
                groupname: groupname.to_string(),
                roles: cmd.roles.clone().unwrap_or_default(),
            });
            self.changed = true;
            return;
        }

        if command == "deleteGroup" {
            let Some(groupname) = cmd
                .groupname
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return;
            };

            if !delete_group_from_state(&mut self.state, groupname) {
                return;
            }
            self.persist_mutations.push(PersistMutation::DeleteGroup {
                groupname: groupname.to_string(),
            });
            self.queue_group_publish_receive_revocation_candidates(command, groupname, None);
            self.changed = true;
            return;
        }

        if command == "addGroupClient" || command == "removeGroupClient" {
            self.apply_group_client_command(command, cmd);
            return;
        }

        if command == "removeRoleACL" || command == "addRoleACL" {
            self.apply_role_acl_command(command, cmd);
        }
    }

    fn apply_client_disable_command(&mut self, command: &str, cmd: &ControlCommand) {
        let Some(username) = cmd
            .username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        if command == "enableClient" {
            self.persist_mutations
                .push(PersistMutation::SetClientDisabled {
                    username: username.to_string(),
                    disabled: false,
                });
        }

        let Some(client) = self.state.clients.get_mut(username) else {
            if command == "enableClient" {
                self.changed |= self.runtime_disabled_usernames.remove(username);
            }
            return;
        };

        if command == "disableClient" {
            if client.disabled {
                return;
            }
            client.disabled = true;
            self.changed = true;
            self.persist_mutations
                .push(PersistMutation::SetClientDisabled {
                    username: username.to_string(),
                    disabled: true,
                });
            self.changed |= self.runtime_disabled_usernames.insert(username.to_string());
            self.kick_usernames.insert(username.to_string());
            if let Some(client_id) = client.client_id.as_ref() {
                self.kick_client_ids.insert(client_id.clone());
            }
            return;
        }

        let was_disabled = client.disabled;
        client.disabled = false;
        self.changed |= was_disabled;
        self.changed |= self.runtime_disabled_usernames.remove(username);
        self.kick_usernames.remove(username);
        if was_disabled && let Some(client_id) = client.client_id.as_ref() {
            self.kick_client_ids.remove(client_id);
        }
    }

    fn apply_group_client_command(&mut self, command: &str, cmd: &ControlCommand) {
        let Some(groupname) = cmd
            .groupname
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(username) = cmd
            .username
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        let mut changed = false;
        if command == "addGroupClient" {
            let priority = cmd.priority.unwrap_or(0);
            let Some(group) = self.state.groups.get_mut(groupname) else {
                return;
            };
            changed |= group.add_client(username, priority);
            let client = self
                .state
                .clients
                .entry(username.to_string())
                .or_insert_with(|| DynSecClient::placeholder(username));
            changed |= client.add_group(groupname, priority);
            if changed {
                self.persist_mutations
                    .push(PersistMutation::AddGroupClient {
                        groupname: groupname.to_string(),
                        username: username.to_string(),
                        priority,
                    });
            }
        } else {
            if let Some(group) = self.state.groups.get_mut(groupname) {
                changed |= group.remove_client(username);
            }
            if let Some(client) = self.state.clients.get_mut(username) {
                changed |= client.remove_group(groupname);
            }
            changed |= self.prune_placeholder_client(username);
            if changed {
                self.persist_mutations
                    .push(PersistMutation::RemoveGroupClient {
                        groupname: groupname.to_string(),
                        username: username.to_string(),
                    });
                self.queue_group_publish_receive_revocation_candidates(
                    command,
                    groupname,
                    Some(username),
                );
            }
        }
        self.changed |= changed;
    }

    fn prune_placeholder_client(&mut self, username: &str) -> bool {
        prune_placeholder_client(&mut self.state, username)
    }

    fn queue_role_publish_receive_revocation_candidates(
        &mut self,
        command: &str,
        rolename: &str,
        usernames: Option<Vec<String>>,
    ) {
        let Some(role) = self.initial_state.roles.get(rolename) else {
            return;
        };
        let usernames =
            usernames.unwrap_or_else(|| role_member_usernames(&self.initial_state, rolename));
        if usernames.is_empty() {
            return;
        }

        let topics: Vec<String> = role
            .acls
            .publish_c_recv
            .iter()
            .filter(|acl| acl.allow && !acl.topic.starts_with("$CONTROL/"))
            .map(|acl| acl.topic.clone())
            .collect();
        for topic in topics {
            self.queue_publish_receive_revocation_candidate(command, rolename, &topic, &usernames);
        }
    }

    fn queue_group_publish_receive_revocation_candidates(
        &mut self,
        command: &str,
        groupname: &str,
        username: Option<&str>,
    ) {
        let Some(group) = self.initial_state.groups.get(groupname) else {
            return;
        };
        let usernames = username
            .map(|value| vec![value.to_string()])
            .unwrap_or_else(|| group_member_usernames(&self.initial_state, groupname));
        if usernames.is_empty() {
            return;
        }

        let role_names: Vec<String> = group
            .roles
            .iter()
            .map(|role_ref| role_ref.name.clone())
            .collect();
        for role_name in role_names {
            self.queue_role_publish_receive_revocation_candidates(
                command,
                &role_name,
                Some(usernames.clone()),
            );
        }
    }

    fn queue_publish_receive_revocation_candidate(
        &mut self,
        command: &str,
        rolename: &str,
        topic: &str,
        candidate_usernames: &[String],
    ) {
        let usernames =
            self.usernames_with_initial_publish_receive_access(candidate_usernames, topic);
        if usernames.is_empty() {
            return;
        }

        self.pending_notify_candidates.push(PendingNotifyCandidate {
            command: command.to_string(),
            rolename: rolename.to_string(),
            topic: topic.to_string(),
            usernames,
        });
    }

    fn usernames_with_initial_publish_receive_access(
        &self,
        candidate_usernames: &[String],
        topic: &str,
    ) -> Vec<String> {
        let mut usernames = Vec::new();
        for username in candidate_usernames {
            let had_access = state_allows_username_access(
                &self.initial_state,
                &self.initial_runtime_disabled_usernames,
                username,
                topic,
                AccessKind::PublishReceive,
            );
            if had_access {
                usernames.push(username.clone());
            }
        }
        usernames.sort();
        usernames.dedup();
        usernames
    }

    fn finalize_notify_events(&mut self) {
        // Emit read-policy notifications only for access lost in the final payload state.
        let mut aggregated_usernames: HashMap<NotifyEventKey, Vec<String>> = HashMap::new();
        for candidate in &self.pending_notify_candidates {
            let mut usernames: Vec<String> = candidate
                .usernames
                .iter()
                .filter(|username| {
                    !state_allows_username_access(
                        &self.state,
                        &self.runtime_disabled_usernames,
                        username,
                        &candidate.topic,
                        AccessKind::PublishReceive,
                    )
                })
                .cloned()
                .collect();
            if usernames.is_empty() {
                continue;
            }
            usernames.sort();
            usernames.dedup();
            aggregated_usernames
                .entry(NotifyEventKey::from_candidate(candidate))
                .or_default()
                .extend(usernames);
        }
        let mut notify_events: Vec<ControlNotifyEvent> = aggregated_usernames
            .into_iter()
            .map(|(key, mut usernames)| {
                usernames.sort();
                usernames.dedup();
                ControlNotifyEvent {
                    command: key.command,
                    rolename: Some(key.rolename),
                    acltype: Some("publishClientReceive".to_string()),
                    topic: Some(key.topic),
                    usernames,
                }
            })
            .collect();
        notify_events.sort_by(|a, b| {
            a.command
                .cmp(&b.command)
                .then_with(|| a.rolename.cmp(&b.rolename))
                .then_with(|| a.topic.cmp(&b.topic))
        });
        self.notify_events = notify_events;
        self.pending_notify_candidates.clear();
    }

    fn apply_role_acl_command(&mut self, command: &str, cmd: &ControlCommand) {
        let Some(rolename) = cmd
            .rolename
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(acltype) = cmd
            .acltype
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(topic) = cmd
            .topic
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(acl_type) = AclType::from_control_str(acltype) else {
            return;
        };

        let Some(role) = self.state.roles.get_mut(rolename) else {
            return;
        };

        if command == "removeRoleACL" {
            let removed_acl = role.acls.remove_acl_entry(acl_type, topic);
            if let Some(removed_acl) = removed_acl {
                self.changed = true;
                self.persist_mutations
                    .push(PersistMutation::RoleAcl(RoleAclMutation::Remove {
                        rolename: rolename.to_string(),
                        acltype: acltype.to_string(),
                        topic: topic.to_string(),
                    }));
                self.runtime_role_acl_overrides.insert(
                    RoleAclKey::new(rolename, acl_type, topic),
                    RuntimeRoleAclOverride::Remove,
                );
                if removed_acl.allow
                    && removed_acl.acl_type == AclType::PublishClientReceive
                    && !removed_acl.topic.starts_with("$CONTROL/")
                {
                    let usernames = role_member_usernames(&self.initial_state, rolename);
                    self.queue_publish_receive_revocation_candidate(
                        command, rolename, topic, &usernames,
                    );
                }
            }
            return;
        }

        let allow = cmd.allow.unwrap_or(false);
        let priority = cmd.priority.unwrap_or(0);
        let changed = role.acls.upsert_acl_entry(AclEntry {
            acl_type,
            topic: topic.to_string(),
            allow,
            priority,
        });
        if !changed {
            return;
        }

        self.changed = true;
        self.persist_mutations
            .push(PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: rolename.to_string(),
                acltype: acltype.to_string(),
                topic: topic.to_string(),
                priority,
                allow,
            }));
        self.runtime_role_acl_overrides.insert(
            RoleAclKey::new(rolename, acl_type, topic),
            RuntimeRoleAclOverride::Add { priority, allow },
        );
        if !allow && acl_type == AclType::PublishClientReceive && !topic.starts_with("$CONTROL/") {
            let usernames = role_member_usernames(&self.initial_state, rolename);
            self.queue_publish_receive_revocation_candidate(command, rolename, topic, &usernames);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlNotifyEvent {
    pub command: String,
    pub rolename: Option<String>,
    pub acltype: Option<String>,
    pub topic: Option<String>,
    pub usernames: Vec<String>,
}

#[derive(Debug, Clone)]
struct PendingNotifyCandidate {
    command: String,
    rolename: String,
    topic: String,
    usernames: Vec<String>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NotifyEventKey {
    command: String,
    rolename: String,
    topic: String,
}

impl NotifyEventKey {
    fn from_candidate(candidate: &PendingNotifyCandidate) -> Self {
        Self {
            command: candidate.command.clone(),
            rolename: candidate.rolename.clone(),
            topic: candidate.topic.clone(),
        }
    }
}

#[derive(Debug, Clone)]
enum RoleAclMutation {
    Add {
        rolename: String,
        acltype: String,
        topic: String,
        priority: i32,
        allow: bool,
    },
    Remove {
        rolename: String,
        acltype: String,
        topic: String,
    },
}

#[derive(Debug, Clone)]
enum PersistMutation {
    SetClientDisabled {
        username: String,
        disabled: bool,
    },
    CreateRole {
        rolename: String,
        acls: Vec<AclConfig>,
    },
    DeleteRole {
        rolename: String,
    },
    CreateGroup {
        groupname: String,
        roles: Vec<RoleRef>,
    },
    DeleteGroup {
        groupname: String,
    },
    AddGroupClient {
        groupname: String,
        username: String,
        priority: i32,
    },
    RemoveGroupClient {
        groupname: String,
        username: String,
    },
    RoleAcl(RoleAclMutation),
}

impl PersistMutation {
    /// Returns whether this mutation should be replayed against freshly-loaded state
    /// during a config reload while the pending queue is non-empty.
    ///
    /// **Limitation**: `RoleAcl` variants return `false` — they are *not* replayed on
    /// reload. Instead, the `runtime_role_acl_overrides` map covers them at check-time.
    /// The two mechanisms can diverge: if a pending `addRoleACL` has not been flushed
    /// and a subsequent `deleteRole` removes the runtime override, the ACL change is
    /// lost from both the file and the override map. This is acceptable because the
    /// `deleteRole` semantics intentionally discard all ACLs for that role, and the
    /// pending persist queue's RetryIntentReducer will also drop orphaned ACL intents
    /// when it sees the role deletion.
    const fn is_replayed_on_reload(&self) -> bool {
        matches!(
            self,
            Self::SetClientDisabled { .. }
                | Self::CreateRole { .. }
                | Self::DeleteRole { .. }
                | Self::CreateGroup { .. }
                | Self::DeleteGroup { .. }
                | Self::AddGroupClient { .. }
                | Self::RemoveGroupClient { .. }
        )
    }
}

#[derive(Debug, Clone)]
enum PendingRoleLifecycle {
    Create { acls: Vec<AclConfig> },
    Delete,
    DeleteThenCreate { acls: Vec<AclConfig> },
}

#[derive(Debug, Clone)]
enum PendingGroupLifecycle {
    Create { roles: Vec<RoleRef> },
    Delete,
    DeleteThenCreate { roles: Vec<RoleRef> },
}

impl PendingRoleLifecycle {
    fn create_acls(&self) -> Option<&[AclConfig]> {
        match self {
            Self::Create { acls } | Self::DeleteThenCreate { acls } => Some(acls),
            Self::Delete => None,
        }
    }

    fn requires_delete_persist(&self) -> bool {
        matches!(self, Self::Delete | Self::DeleteThenCreate { .. })
    }

    fn is_delete_only(&self) -> bool {
        matches!(self, Self::Delete)
    }
}

impl PendingGroupLifecycle {
    fn create_roles(&self) -> Option<&[RoleRef]> {
        match self {
            Self::Create { roles } | Self::DeleteThenCreate { roles } => Some(roles),
            Self::Delete => None,
        }
    }

    fn requires_delete_persist(&self) -> bool {
        matches!(self, Self::Delete | Self::DeleteThenCreate { .. })
    }

    fn is_delete_only(&self) -> bool {
        matches!(self, Self::Delete)
    }
}

#[derive(Debug, Clone, Copy)]
enum PendingGroupClientMutation {
    Add { priority: i32 },
    Remove,
}

#[derive(Debug, Clone, Copy)]
enum PendingRoleAclMutation {
    Add { priority: i32, allow: bool },
    Remove,
}

#[derive(Debug, Default)]
struct RetryIntentReducer {
    client_disabled: BTreeMap<String, bool>,
    roles: BTreeMap<String, PendingRoleLifecycle>,
    groups: BTreeMap<String, PendingGroupLifecycle>,
    group_clients: BTreeMap<(String, String), PendingGroupClientMutation>,
    role_acls: BTreeMap<(String, String, String), PendingRoleAclMutation>,
}

impl RetryIntentReducer {
    fn apply(&mut self, mutation: &PersistMutation) {
        match mutation {
            PersistMutation::SetClientDisabled { username, disabled } => {
                self.client_disabled.insert(username.clone(), *disabled);
            }
            PersistMutation::CreateRole { rolename, acls } => {
                self.apply_role_create(rolename, acls)
            }
            PersistMutation::DeleteRole { rolename } => self.apply_role_delete(rolename),
            PersistMutation::CreateGroup {
                groupname,
                roles: role_refs,
            } => self.apply_group_create(groupname, role_refs),
            PersistMutation::DeleteGroup { groupname } => self.apply_group_delete(groupname),
            PersistMutation::AddGroupClient {
                groupname,
                username,
                priority,
            } => self.apply_group_client_intent(
                groupname,
                username,
                PendingGroupClientMutation::Add {
                    priority: *priority,
                },
            ),
            PersistMutation::RemoveGroupClient {
                groupname,
                username,
            } => self.apply_group_client_intent(
                groupname,
                username,
                PendingGroupClientMutation::Remove,
            ),
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename,
                acltype,
                topic,
                priority,
                allow,
            }) => self.apply_role_acl_intent(
                rolename,
                acltype,
                topic,
                PendingRoleAclMutation::Add {
                    priority: *priority,
                    allow: *allow,
                },
            ),
            PersistMutation::RoleAcl(RoleAclMutation::Remove {
                rolename,
                acltype,
                topic,
            }) => {
                self.apply_role_acl_intent(rolename, acltype, topic, PendingRoleAclMutation::Remove)
            }
        }
    }

    fn apply_role_create(&mut self, rolename: &str, acls: &[AclConfig]) {
        let merged_acls = match self.roles.remove(rolename) {
            Some(PendingRoleLifecycle::Create { acls: existing }) => PendingRoleLifecycle::Create {
                acls: merge_persist_role_acls(&existing, acls),
            },
            Some(PendingRoleLifecycle::Delete) => PendingRoleLifecycle::DeleteThenCreate {
                acls: acls.to_vec(),
            },
            Some(PendingRoleLifecycle::DeleteThenCreate { acls: existing }) => {
                PendingRoleLifecycle::DeleteThenCreate {
                    acls: merge_persist_role_acls(&existing, acls),
                }
            }
            None => PendingRoleLifecycle::Create {
                acls: acls.to_vec(),
            },
        };
        self.roles.insert(rolename.to_string(), merged_acls);
    }

    fn apply_role_delete(&mut self, rolename: &str) {
        self.roles
            .insert(rolename.to_string(), PendingRoleLifecycle::Delete);
        self.role_acls
            .retain(|(current_role, _, _), _| current_role != rolename);
    }

    fn apply_group_create(&mut self, groupname: &str, roles: &[RoleRef]) {
        let merged_roles = match self.groups.remove(groupname) {
            Some(PendingGroupLifecycle::Create {
                roles: existing_roles,
            }) => PendingGroupLifecycle::Create {
                roles: merge_persist_group_roles(&existing_roles, roles),
            },
            Some(PendingGroupLifecycle::Delete) => PendingGroupLifecycle::DeleteThenCreate {
                roles: roles.to_vec(),
            },
            Some(PendingGroupLifecycle::DeleteThenCreate {
                roles: existing_roles,
            }) => PendingGroupLifecycle::DeleteThenCreate {
                roles: merge_persist_group_roles(&existing_roles, roles),
            },
            None => PendingGroupLifecycle::Create {
                roles: roles.to_vec(),
            },
        };
        self.groups.insert(groupname.to_string(), merged_roles);
    }

    fn apply_group_delete(&mut self, groupname: &str) {
        self.groups
            .insert(groupname.to_string(), PendingGroupLifecycle::Delete);
        self.group_clients
            .retain(|(current_group, _), _| current_group != groupname);
    }

    fn apply_group_client_intent(
        &mut self,
        groupname: &str,
        username: &str,
        mutation: PendingGroupClientMutation,
    ) {
        self.group_clients
            .insert((groupname.to_string(), username.to_string()), mutation);
    }

    fn apply_role_acl_intent(
        &mut self,
        rolename: &str,
        acltype: &str,
        topic: &str,
        mutation: PendingRoleAclMutation,
    ) {
        self.role_acls.insert(
            (rolename.to_string(), acltype.to_string(), topic.to_string()),
            mutation,
        );
    }

    fn into_persist_mutations(self) -> Vec<PersistMutation> {
        let RetryIntentReducer {
            client_disabled,
            roles,
            groups,
            group_clients,
            role_acls,
        } = self;

        let mut collapsed = Vec::new();

        // Order matters: persist cleanup deletes before recreate, then emit
        // dependent membership / ACL intents so disk state converges to the
        // already-applied runtime state.
        Self::emit_delete_cleanup_phase(&mut collapsed, &groups, &roles);
        Self::emit_create_phase(&mut collapsed, &roles, &groups);
        Self::emit_membership_add_phase(&mut collapsed, &groups, &group_clients);
        Self::emit_runtime_disable_phase(&mut collapsed, client_disabled);
        Self::emit_role_acl_add_phase(&mut collapsed, &roles, &role_acls);
        Self::emit_membership_remove_phase(&mut collapsed, &groups, &group_clients);
        Self::emit_role_acl_remove_phase(&mut collapsed, &roles, &role_acls);

        collapsed
    }

    fn emit_delete_cleanup_phase(
        collapsed: &mut Vec<PersistMutation>,
        groups: &BTreeMap<String, PendingGroupLifecycle>,
        roles: &BTreeMap<String, PendingRoleLifecycle>,
    ) {
        for (groupname, lifecycle) in groups {
            if lifecycle.requires_delete_persist() {
                collapsed.push(PersistMutation::DeleteGroup {
                    groupname: groupname.clone(),
                });
            }
        }

        for (rolename, lifecycle) in roles {
            if lifecycle.requires_delete_persist() {
                collapsed.push(PersistMutation::DeleteRole {
                    rolename: rolename.clone(),
                });
            }
        }
    }

    fn emit_create_phase(
        collapsed: &mut Vec<PersistMutation>,
        roles: &BTreeMap<String, PendingRoleLifecycle>,
        groups: &BTreeMap<String, PendingGroupLifecycle>,
    ) {
        for (rolename, lifecycle) in roles {
            if let Some(acls) = lifecycle.create_acls() {
                collapsed.push(PersistMutation::CreateRole {
                    rolename: rolename.clone(),
                    acls: acls.to_vec(),
                });
            }
        }

        for (groupname, lifecycle) in groups {
            if let Some(roles) = lifecycle.create_roles() {
                collapsed.push(PersistMutation::CreateGroup {
                    groupname: groupname.clone(),
                    roles: roles.to_vec(),
                });
            }
        }
    }

    fn emit_membership_add_phase(
        collapsed: &mut Vec<PersistMutation>,
        groups: &BTreeMap<String, PendingGroupLifecycle>,
        group_clients: &BTreeMap<(String, String), PendingGroupClientMutation>,
    ) {
        for ((groupname, username), mutation) in group_clients {
            if groups
                .get(groupname)
                .is_some_and(PendingGroupLifecycle::is_delete_only)
            {
                continue;
            }
            if let PendingGroupClientMutation::Add { priority } = mutation {
                collapsed.push(PersistMutation::AddGroupClient {
                    groupname: groupname.clone(),
                    username: username.clone(),
                    priority: *priority,
                });
            }
        }
    }

    fn emit_runtime_disable_phase(
        collapsed: &mut Vec<PersistMutation>,
        client_disabled: BTreeMap<String, bool>,
    ) {
        for (username, disabled) in client_disabled {
            collapsed.push(PersistMutation::SetClientDisabled { username, disabled });
        }
    }

    fn emit_role_acl_add_phase(
        collapsed: &mut Vec<PersistMutation>,
        roles: &BTreeMap<String, PendingRoleLifecycle>,
        role_acls: &BTreeMap<(String, String, String), PendingRoleAclMutation>,
    ) {
        for ((rolename, acltype, topic), mutation) in role_acls {
            if roles
                .get(rolename)
                .is_some_and(PendingRoleLifecycle::is_delete_only)
            {
                continue;
            }
            if let PendingRoleAclMutation::Add { priority, allow } = mutation {
                collapsed.push(PersistMutation::RoleAcl(RoleAclMutation::Add {
                    rolename: rolename.clone(),
                    acltype: acltype.clone(),
                    topic: topic.clone(),
                    priority: *priority,
                    allow: *allow,
                }));
            }
        }
    }

    fn emit_membership_remove_phase(
        collapsed: &mut Vec<PersistMutation>,
        groups: &BTreeMap<String, PendingGroupLifecycle>,
        group_clients: &BTreeMap<(String, String), PendingGroupClientMutation>,
    ) {
        for ((groupname, username), mutation) in group_clients {
            if groups
                .get(groupname)
                .is_some_and(PendingGroupLifecycle::is_delete_only)
            {
                continue;
            }
            if matches!(mutation, PendingGroupClientMutation::Remove) {
                collapsed.push(PersistMutation::RemoveGroupClient {
                    groupname: groupname.clone(),
                    username: username.clone(),
                });
            }
        }
    }

    fn emit_role_acl_remove_phase(
        collapsed: &mut Vec<PersistMutation>,
        roles: &BTreeMap<String, PendingRoleLifecycle>,
        role_acls: &BTreeMap<(String, String, String), PendingRoleAclMutation>,
    ) {
        for ((rolename, acltype, topic), mutation) in role_acls {
            if roles
                .get(rolename)
                .is_some_and(PendingRoleLifecycle::is_delete_only)
            {
                continue;
            }
            if matches!(mutation, PendingRoleAclMutation::Remove) {
                collapsed.push(PersistMutation::RoleAcl(RoleAclMutation::Remove {
                    rolename: rolename.clone(),
                    acltype: acltype.clone(),
                    topic: topic.clone(),
                }));
            }
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RoleAclKey {
    rolename: String,
    acl_type: AclType,
    topic: String,
}

impl RoleAclKey {
    fn new(rolename: &str, acl_type: AclType, topic: &str) -> Self {
        Self {
            rolename: rolename.to_string(),
            acl_type,
            topic: topic.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
enum RuntimeRoleAclOverride {
    Remove,
    Add { priority: i32, allow: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessKind {
    PublishSend,
    PublishReceive,
    Subscribe,
    Unsubscribe,
    Unknown,
}

impl AccessKind {
    const fn from_access(access: i32) -> Self {
        if (access & ACL_WRITE) != 0 {
            Self::PublishSend
        } else if (access & ACL_SUBSCRIBE) != 0 {
            Self::Subscribe
        } else if (access & ACL_UNSUBSCRIBE) != 0 {
            Self::Unsubscribe
        } else if (access & ACL_READ) != 0 {
            Self::PublishReceive
        } else {
            Self::Unknown
        }
    }
}

const ACL_READ: i32 = 0x01;
const ACL_WRITE: i32 = 0x02;
const ACL_SUBSCRIBE: i32 = 0x04;
const ACL_UNSUBSCRIBE: i32 = 0x08;

#[derive(Debug, Clone, Default)]
struct DynSecState {
    clients: HashMap<String, DynSecClient>,
    groups: HashMap<String, DynSecGroup>,
    roles: HashMap<String, DynSecRole>,
    default_access: DefaultAclAccess,
    anonymous_group: Option<String>,
}

impl DynSecState {
    fn from_config(cfg: DynSecConfig) -> Self {
        let mut roles = HashMap::new();
        if let Some(list) = cfg.roles {
            for role in list {
                roles.insert(role.rolename.clone(), DynSecRole::from_config(role));
            }
        }

        let mut groups = HashMap::new();
        if let Some(list) = cfg.groups {
            for group in list {
                groups.insert(group.groupname.clone(), DynSecGroup::from_config(group));
            }
        }

        let mut clients = HashMap::new();
        if let Some(list) = cfg.clients {
            for client in list {
                clients.insert(client.username.clone(), DynSecClient::from_config(client));
            }
        }

        for (group_name, group) in &groups {
            for client_ref in &group.clients {
                let entry = clients
                    .entry(client_ref.name.clone())
                    .or_insert_with(|| DynSecClient::placeholder(&client_ref.name));
                merge_name_priority_by_max(&mut entry.groups, group_name, client_ref.priority);
            }
        }

        Self {
            clients,
            groups,
            roles,
            default_access: DefaultAclAccess::from_config(cfg.default_acl_access),
            anonymous_group: cfg.anonymous_group,
        }
    }
}

fn role_member_usernames(state: &DynSecState, rolename: &str) -> Vec<String> {
    let mut usernames = HashSet::new();
    for (username, client) in &state.clients {
        let has_direct_role = client.roles.iter().any(|role| role.name == rolename);
        let has_group_role = client.groups.iter().any(|group_ref| {
            state
                .groups
                .get(&group_ref.name)
                .is_some_and(|group| group.roles.iter().any(|role| role.name == rolename))
        });
        if has_direct_role || has_group_role {
            usernames.insert(username.clone());
        }
    }
    let mut out: Vec<String> = usernames.into_iter().collect();
    out.sort();
    out
}

fn group_member_usernames(state: &DynSecState, groupname: &str) -> Vec<String> {
    let mut usernames = HashSet::new();
    if let Some(group) = state.groups.get(groupname) {
        for client_ref in &group.clients {
            usernames.insert(client_ref.name.clone());
        }
    }
    for (username, client) in &state.clients {
        if client
            .groups
            .iter()
            .any(|group_ref| group_ref.name == groupname)
        {
            usernames.insert(username.clone());
        }
    }
    let mut out: Vec<String> = usernames.into_iter().collect();
    out.sort();
    out
}

#[derive(Debug, Clone)]
struct DynSecClient {
    client_id: Option<String>,
    roles: Vec<NamePriority>,
    groups: Vec<NamePriority>,
    disabled: bool,
    synthetic: bool,
}

impl DynSecClient {
    fn from_config(cfg: ClientConfig) -> Self {
        let roles = NamePriority::from_role_refs(cfg.roles);
        let groups = NamePriority::from_group_refs(cfg.groups);
        Self {
            client_id: cfg.client_id,
            roles,
            groups,
            disabled: cfg.disabled.unwrap_or(false),
            synthetic: false,
        }
    }

    fn placeholder(_username: &str) -> Self {
        Self {
            client_id: None,
            roles: Vec::new(),
            groups: Vec::new(),
            disabled: false,
            synthetic: true,
        }
    }

    fn add_group(&mut self, group_name: &str, priority: i32) -> bool {
        upsert_name_priority(&mut self.groups, group_name, priority)
    }

    fn remove_group(&mut self, group_name: &str) -> bool {
        remove_name_priority(&mut self.groups, group_name)
    }

    fn remove_role(&mut self, rolename: &str) -> bool {
        remove_name_priority(&mut self.roles, rolename)
    }

    fn is_prunable_placeholder(&self) -> bool {
        self.synthetic
            && self.client_id.is_none()
            && self.roles.is_empty()
            && self.groups.is_empty()
            && !self.disabled
    }
}

#[derive(Debug, Clone)]
struct DynSecGroup {
    roles: Vec<NamePriority>,
    clients: Vec<NamePriority>,
}

impl DynSecGroup {
    fn from_config(cfg: GroupConfig) -> Self {
        Self {
            roles: NamePriority::from_role_refs(cfg.roles),
            clients: NamePriority::from_client_refs(cfg.clients),
        }
    }

    fn from_control_roles(roles: Option<Vec<RoleRef>>) -> Self {
        Self {
            roles: NamePriority::from_role_refs(roles),
            clients: Vec::new(),
        }
    }

    fn add_client(&mut self, username: &str, priority: i32) -> bool {
        upsert_name_priority(&mut self.clients, username, priority)
    }

    fn remove_client(&mut self, username: &str) -> bool {
        remove_name_priority(&mut self.clients, username)
    }

    fn remove_role(&mut self, rolename: &str) -> bool {
        remove_name_priority(&mut self.roles, rolename)
    }

    fn merge_control_roles(&mut self, roles: &[RoleRef]) -> bool {
        let mut changed = false;
        for role in roles {
            changed |=
                upsert_name_priority(&mut self.roles, &role.rolename, role.priority.unwrap_or(-1));
        }
        changed
    }

    fn to_control_roles(&self) -> Vec<RoleRef> {
        self.roles
            .iter()
            .map(|role| RoleRef {
                rolename: role.name.clone(),
                priority: Some(role.priority),
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
struct DynSecRole {
    acls: DynSecAcls,
}

impl DynSecRole {
    fn from_config(cfg: RoleConfig) -> Self {
        let mut acls = DynSecAcls::default();
        if let Some(list) = cfg.acls {
            for acl in list {
                acls.add_acl(acl);
            }
        }
        acls.sort();
        Self { acls }
    }

    fn from_control_acls(acls: Option<Vec<AclConfig>>) -> Self {
        let mut dynsec_acls = DynSecAcls::default();
        if let Some(list) = acls {
            for acl in list {
                dynsec_acls.add_acl(acl);
            }
        }
        dynsec_acls.sort();
        Self { acls: dynsec_acls }
    }

    fn match_acl(&self, access: AccessKind, topic: &str) -> Option<bool> {
        match access {
            AccessKind::PublishSend => match_acl_publish(&self.acls.publish_c_send, topic),
            AccessKind::PublishReceive => match_acl_publish(&self.acls.publish_c_recv, topic),
            AccessKind::Subscribe => match_acl_literal(&self.acls.subscribe_literal, topic)
                .or_else(|| match_acl_sub(&self.acls.subscribe_pattern, topic)),
            AccessKind::Unsubscribe => match_acl_literal(&self.acls.unsubscribe_literal, topic)
                .or_else(|| match_acl_sub(&self.acls.unsubscribe_pattern, topic)),
            AccessKind::Unknown => None,
        }
    }

    fn merge_control_acls(&mut self, acls: &[AclConfig]) -> bool {
        let mut changed = false;
        for acl in acls {
            changed |= self
                .acls
                .upsert_acl_entry(AclEntry::from_config(acl.clone()));
        }
        changed
    }

    fn to_control_acls(&self) -> Vec<AclConfig> {
        self.acls.to_control_configs()
    }
}

#[derive(Debug, Clone, Default)]
struct DynSecAcls {
    publish_c_send: Vec<AclEntry>,
    publish_c_recv: Vec<AclEntry>,
    subscribe_literal: HashMap<String, AclEntry>,
    subscribe_pattern: Vec<AclEntry>,
    unsubscribe_literal: HashMap<String, AclEntry>,
    unsubscribe_pattern: Vec<AclEntry>,
}

impl DynSecAcls {
    fn add_acl(&mut self, cfg: AclConfig) {
        let acl = AclEntry::from_config(cfg);
        match acl.acl_type {
            AclType::PublishClientSend => self.publish_c_send.push(acl),
            AclType::PublishClientReceive => self.publish_c_recv.push(acl),
            AclType::SubscribeLiteral => insert_literal_acl(&mut self.subscribe_literal, acl),
            AclType::SubscribePattern => self.subscribe_pattern.push(acl),
            AclType::UnsubscribeLiteral => insert_literal_acl(&mut self.unsubscribe_literal, acl),
            AclType::UnsubscribePattern => self.unsubscribe_pattern.push(acl),
            AclType::SubscribeGeneric => {}
            AclType::UnsubscribeGeneric => {}
        }
    }

    fn sort(&mut self) {
        sort_acl_list(&mut self.publish_c_send);
        sort_acl_list(&mut self.publish_c_recv);
        sort_acl_list(&mut self.subscribe_pattern);
        sort_acl_list(&mut self.unsubscribe_pattern);
    }

    fn remove_acl_entry(&mut self, acl_type: AclType, topic: &str) -> Option<AclEntry> {
        match acl_type {
            AclType::PublishClientSend => remove_acl_from_vec(&mut self.publish_c_send, topic),
            AclType::PublishClientReceive => remove_acl_from_vec(&mut self.publish_c_recv, topic),
            AclType::SubscribeLiteral => self.subscribe_literal.remove(topic),
            AclType::SubscribePattern => remove_acl_from_vec(&mut self.subscribe_pattern, topic),
            AclType::UnsubscribeLiteral => self.unsubscribe_literal.remove(topic),
            AclType::UnsubscribePattern => {
                remove_acl_from_vec(&mut self.unsubscribe_pattern, topic)
            }
            AclType::SubscribeGeneric | AclType::UnsubscribeGeneric => None,
        }
    }

    fn upsert_acl_entry(&mut self, acl: AclEntry) -> bool {
        match acl.acl_type {
            AclType::PublishClientSend => upsert_acl_in_vec(&mut self.publish_c_send, acl),
            AclType::PublishClientReceive => upsert_acl_in_vec(&mut self.publish_c_recv, acl),
            AclType::SubscribeLiteral => {
                upsert_acl_in_literal_map(&mut self.subscribe_literal, acl)
            }
            AclType::SubscribePattern => upsert_acl_in_vec(&mut self.subscribe_pattern, acl),
            AclType::UnsubscribeLiteral => {
                upsert_acl_in_literal_map(&mut self.unsubscribe_literal, acl)
            }
            AclType::UnsubscribePattern => upsert_acl_in_vec(&mut self.unsubscribe_pattern, acl),
            AclType::SubscribeGeneric | AclType::UnsubscribeGeneric => false,
        }
    }

    fn to_control_configs(&self) -> Vec<AclConfig> {
        let mut out = Vec::new();
        out.extend(self.publish_c_send.iter().map(AclEntry::to_control_config));
        out.extend(self.publish_c_recv.iter().map(AclEntry::to_control_config));

        let mut subscribe_literal: Vec<_> = self.subscribe_literal.values().collect();
        subscribe_literal.sort_by(|left, right| left.topic.cmp(&right.topic));
        out.extend(
            subscribe_literal
                .into_iter()
                .map(AclEntry::to_control_config),
        );

        out.extend(
            self.subscribe_pattern
                .iter()
                .map(AclEntry::to_control_config),
        );

        let mut unsubscribe_literal: Vec<_> = self.unsubscribe_literal.values().collect();
        unsubscribe_literal.sort_by(|left, right| left.topic.cmp(&right.topic));
        out.extend(
            unsubscribe_literal
                .into_iter()
                .map(AclEntry::to_control_config),
        );

        out.extend(
            self.unsubscribe_pattern
                .iter()
                .map(AclEntry::to_control_config),
        );
        out
    }
}

#[derive(Debug, Clone)]
struct AclEntry {
    acl_type: AclType,
    topic: String,
    allow: bool,
    priority: i32,
}

impl AclEntry {
    fn from_config(cfg: AclConfig) -> Self {
        let acl_type = AclType::from_str(&cfg.acltype);
        Self {
            acl_type,
            topic: cfg.topic,
            allow: cfg.allow.unwrap_or(false),
            priority: cfg.priority.unwrap_or(0),
        }
    }

    fn to_control_config(&self) -> AclConfig {
        AclConfig {
            acltype: self.acl_type.as_str().to_string(),
            topic: self.topic.clone(),
            priority: Some(self.priority),
            allow: Some(self.allow),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AclType {
    PublishClientSend,
    PublishClientReceive,
    SubscribeLiteral,
    SubscribePattern,
    UnsubscribeLiteral,
    UnsubscribePattern,
    SubscribeGeneric,
    UnsubscribeGeneric,
}

impl AclType {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::PublishClientSend => "publishClientSend",
            Self::PublishClientReceive => "publishClientReceive",
            Self::SubscribeLiteral => "subscribeLiteral",
            Self::SubscribePattern => "subscribePattern",
            Self::UnsubscribeLiteral => "unsubscribeLiteral",
            Self::UnsubscribePattern => "unsubscribePattern",
            Self::SubscribeGeneric => "subscribe",
            Self::UnsubscribeGeneric => "unsubscribe",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "publishClientSend" => Self::PublishClientSend,
            "publishClientReceive" => Self::PublishClientReceive,
            "subscribeLiteral" => Self::SubscribeLiteral,
            "subscribePattern" => Self::SubscribePattern,
            "unsubscribeLiteral" => Self::UnsubscribeLiteral,
            "unsubscribePattern" => Self::UnsubscribePattern,
            "subscribe" => Self::SubscribeGeneric,
            "unsubscribe" => Self::UnsubscribeGeneric,
            _ => {
                eprintln!("dynsec: unknown acltype '{value}', defaulting to subscribe");
                Self::SubscribeGeneric
            }
        }
    }

    fn from_control_str(value: &str) -> Option<Self> {
        match value {
            "publishClientSend" => Some(Self::PublishClientSend),
            "publishClientReceive" => Some(Self::PublishClientReceive),
            "subscribeLiteral" => Some(Self::SubscribeLiteral),
            "subscribePattern" => Some(Self::SubscribePattern),
            "unsubscribeLiteral" => Some(Self::UnsubscribeLiteral),
            "unsubscribePattern" => Some(Self::UnsubscribePattern),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct DefaultAclAccess {
    publish_client_send: bool,
    publish_client_receive: bool,
    subscribe: bool,
    unsubscribe: bool,
}

impl DefaultAclAccess {
    fn from_config(cfg: Option<DefaultAclAccessConfig>) -> Self {
        if let Some(cfg) = cfg {
            Self {
                publish_client_send: cfg.publish_client_send.unwrap_or(false),
                publish_client_receive: cfg.publish_client_receive.unwrap_or(false),
                subscribe: cfg.subscribe.unwrap_or(false),
                unsubscribe: cfg.unsubscribe.unwrap_or(false),
            }
        } else {
            eprintln!("dynsec: missing defaultACLAccess; defaulting to all deny");
            Self {
                publish_client_send: false,
                publish_client_receive: false,
                subscribe: false,
                unsubscribe: false,
            }
        }
    }

    const fn allow_for(&self, access: AccessKind) -> bool {
        match access {
            AccessKind::PublishSend => self.publish_client_send,
            AccessKind::PublishReceive => self.publish_client_receive,
            AccessKind::Subscribe => self.subscribe,
            AccessKind::Unsubscribe => self.unsubscribe,
            AccessKind::Unknown => false,
        }
    }
}

#[derive(Debug, Clone)]
struct NamePriority {
    name: String,
    priority: i32,
}

impl NamePriority {
    fn new(name: &str, priority: i32) -> Self {
        Self {
            name: name.to_string(),
            priority,
        }
    }

    fn from_role_refs(list: Option<Vec<RoleRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.rolename, entry.priority.unwrap_or(-1)))
            .collect()
    }

    fn from_group_refs(list: Option<Vec<GroupRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.groupname, entry.priority.unwrap_or(-1)))
            .collect()
    }

    fn from_client_refs(list: Option<Vec<ClientRef>>) -> Vec<Self> {
        list.unwrap_or_default()
            .into_iter()
            .map(|entry| Self::new(&entry.username, entry.priority.unwrap_or(-1)))
            .collect()
    }
}

fn upsert_name_priority(list: &mut Vec<NamePriority>, name: &str, priority: i32) -> bool {
    if let Some(existing) = list.iter_mut().find(|entry| entry.name == name) {
        if priority != existing.priority {
            existing.priority = priority;
            return true;
        }
        return false;
    }
    list.push(NamePriority::new(name, priority));
    true
}

fn merge_name_priority_by_max(list: &mut Vec<NamePriority>, name: &str, priority: i32) -> bool {
    if let Some(existing) = list.iter_mut().find(|entry| entry.name == name) {
        if priority > existing.priority {
            existing.priority = priority;
            return true;
        }
        return false;
    }
    list.push(NamePriority::new(name, priority));
    true
}

fn remove_name_priority(list: &mut Vec<NamePriority>, name: &str) -> bool {
    let Some(idx) = list.iter().position(|entry| entry.name == name) else {
        return false;
    };
    list.remove(idx);
    true
}

#[derive(Debug, Clone, Deserialize)]
struct DynSecConfig {
    clients: Option<Vec<ClientConfig>>,
    groups: Option<Vec<GroupConfig>>,
    roles: Option<Vec<RoleConfig>>,
    #[serde(rename = "defaultACLAccess")]
    default_acl_access: Option<DefaultAclAccessConfig>,
    #[serde(rename = "anonymousGroup")]
    anonymous_group: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientConfig {
    username: String,
    #[serde(rename = "clientid")]
    client_id: Option<String>,
    roles: Option<Vec<RoleRef>>,
    groups: Option<Vec<GroupRef>>,
    disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct GroupConfig {
    groupname: String,
    roles: Option<Vec<RoleRef>>,
    clients: Option<Vec<ClientRef>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RoleConfig {
    rolename: String,
    acls: Option<Vec<AclConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RoleRef {
    rolename: String,
    priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct GroupRef {
    groupname: String,
    priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClientRef {
    username: String,
    priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
struct AclConfig {
    #[serde(rename = "acltype")]
    acltype: String,
    topic: String,
    priority: Option<i32>,
    allow: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct DefaultAclAccessConfig {
    #[serde(rename = "publishClientSend")]
    publish_client_send: Option<bool>,
    #[serde(rename = "publishClientReceive")]
    publish_client_receive: Option<bool>,
    subscribe: Option<bool>,
    unsubscribe: Option<bool>,
}

fn match_acl_publish(acls: &[AclEntry], topic: &str) -> Option<bool> {
    for acl in acls {
        if topic_match_sub(&acl.topic, topic) {
            return Some(acl.allow);
        }
    }
    None
}

fn match_acl_literal(acls: &HashMap<String, AclEntry>, topic: &str) -> Option<bool> {
    acls.get(topic).map(|acl| acl.allow)
}

fn match_acl_sub(acls: &[AclEntry], topic: &str) -> Option<bool> {
    for acl in acls {
        if sub_match_sub(&acl.topic, topic) {
            return Some(acl.allow);
        }
    }
    None
}

fn insert_literal_acl(map: &mut HashMap<String, AclEntry>, acl: AclEntry) {
    let entry = map.entry(acl.topic.clone()).or_insert(acl.clone());
    if acl.priority > entry.priority {
        *entry = acl;
    }
}

fn upsert_acl_in_literal_map(map: &mut HashMap<String, AclEntry>, acl: AclEntry) -> bool {
    if let Some(existing) = map.get_mut(&acl.topic) {
        if existing.allow == acl.allow && existing.priority == acl.priority {
            return false;
        }
        *existing = acl;
        true
    } else {
        map.insert(acl.topic.clone(), acl);
        true
    }
}

fn upsert_acl_in_vec(list: &mut Vec<AclEntry>, acl: AclEntry) -> bool {
    if let Some(existing) = list.iter_mut().find(|entry| entry.topic == acl.topic) {
        if existing.allow == acl.allow && existing.priority == acl.priority {
            return false;
        }
        *existing = acl;
    } else {
        list.push(acl);
    }
    sort_acl_list(list);
    true
}

fn remove_acl_from_vec(list: &mut Vec<AclEntry>, topic: &str) -> Option<AclEntry> {
    let idx = list.iter().position(|entry| entry.topic == topic)?;
    Some(list.remove(idx))
}

fn sort_acl_list(list: &mut [AclEntry]) {
    list.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.topic.cmp(&b.topic))
    });
}

fn topic_match_sub(filter: &str, topic: &str) -> bool {
    sub_match_sub(filter, topic)
}

fn sub_match_sub(filter: &str, topic: &str) -> bool {
    if filter == "#" {
        return true;
    }

    let filter_parts: Vec<&str> = filter.split('/').collect();
    let topic_parts: Vec<&str> = topic.split('/').collect();
    let mut i = 0;

    while i < filter_parts.len() {
        let fp = filter_parts[i];
        if fp == "#" {
            return true;
        }
        if i >= topic_parts.len() {
            return false;
        }
        if fp != "+" && fp != topic_parts[i] {
            return false;
        }
        i += 1;
    }

    i == topic_parts.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;

    static DYNSEC_TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn write_test_dynsec_config() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dynsec-control-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "roles": [{"rolename": "ctrl", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [],
  "roles": [
    {
      "rolename": "ctrl",
      "acls": [
        {
          "acltype": "publishClientSend",
          "topic": "$CONTROL/dynamic-security/v1",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("test dynsec config must be writable");
        path.to_string_lossy().into_owned()
    }

    fn set_client_disabled(path: &str, username: &str, disabled: bool) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
        if let Some(clients) = root.get_mut("clients").and_then(Value::as_array_mut) {
            for client in clients {
                let Some(current_username) = client.get("username").and_then(Value::as_str) else {
                    continue;
                };
                if current_username == username {
                    client["disabled"] = Value::Bool(disabled);
                }
            }
        }
        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn restore_fanout_reader_publish_receive_acl(path: &str) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
        if let Some(roles) = root.get_mut("roles").and_then(Value::as_array_mut) {
            for role in roles {
                let Some(current_rolename) = role.get("rolename").and_then(Value::as_str) else {
                    continue;
                };
                if current_rolename != "fanout_reader" {
                    continue;
                }

                if role.get("acls").is_none() {
                    role["acls"] = Value::Array(Vec::new());
                }
                let Some(acls) = role.get_mut("acls").and_then(Value::as_array_mut) else {
                    continue;
                };

                let mut already_present = false;
                for acl in acls.iter() {
                    let acltype = acl.get("acltype").and_then(Value::as_str);
                    let topic = acl.get("topic").and_then(Value::as_str);
                    if acltype == Some("publishClientReceive") && topic == Some("fanout/broadcast")
                    {
                        already_present = true;
                        break;
                    }
                }
                if !already_present {
                    acls.push(json!({
                        "acltype": "publishClientReceive",
                        "topic": "fanout/broadcast",
                        "priority": 0,
                        "allow": true
                    }));
                }
            }
        }

        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn remove_group_from_dynsec_file(path: &str, groupname: &str) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
        if let Some(groups) = root.get_mut("groups").and_then(Value::as_array_mut) {
            groups
                .retain(|group| group.get("groupname").and_then(Value::as_str) != Some(groupname));
        }
        if let Some(clients) = root.get_mut("clients").and_then(Value::as_array_mut) {
            for client in clients {
                if let Some(group_refs) = client.get_mut("groups").and_then(Value::as_array_mut) {
                    group_refs.retain(|group| {
                        group.get("groupname").and_then(Value::as_str) != Some(groupname)
                    });
                }
            }
        }
        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn remove_group_definition_from_dynsec_file(path: &str, groupname: &str) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
        if let Some(groups) = root.get_mut("groups").and_then(Value::as_array_mut) {
            groups
                .retain(|group| group.get("groupname").and_then(Value::as_str) != Some(groupname));
        }
        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn remove_role_from_dynsec_file(path: &str, rolename: &str) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
        if let Some(roles) = root.get_mut("roles").and_then(Value::as_array_mut) {
            roles.retain(|role| role.get("rolename").and_then(Value::as_str) != Some(rolename));
        }
        if let Some(groups) = root.get_mut("groups").and_then(Value::as_array_mut) {
            for group in groups {
                if let Some(role_refs) = group.get_mut("roles").and_then(Value::as_array_mut) {
                    role_refs.retain(|role| {
                        role.get("rolename").and_then(Value::as_str) != Some(rolename)
                    });
                }
            }
        }
        if let Some(clients) = root.get_mut("clients").and_then(Value::as_array_mut) {
            for client in clients {
                if let Some(role_refs) = client.get_mut("roles").and_then(Value::as_array_mut) {
                    role_refs.retain(|role| {
                        role.get("rolename").and_then(Value::as_str) != Some(rolename)
                    });
                }
            }
        }
        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn remove_role_definition_from_dynsec_file(path: &str, rolename: &str) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
        if let Some(roles) = root.get_mut("roles").and_then(Value::as_array_mut) {
            roles.retain(|role| role.get("rolename").and_then(Value::as_str) != Some(rolename));
        }
        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn write_invalid_json(path: &str) {
        fs::write(path, "{ invalid json").expect("test dynsec config should be writable");
    }

    fn write_test_dynsec_config_without_client_id() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dynsec-control-no-clientid-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "roles": [{"rolename": "ctrl", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [],
  "roles": [
    {
      "rolename": "ctrl",
      "acls": [
        {
          "acltype": "publishClientSend",
          "topic": "$CONTROL/dynamic-security/v1",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("test dynsec config must be writable");
        path.to_string_lossy().into_owned()
    }

    fn write_test_dynsec_notify_config() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dynsec-control-notify-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "roles": [{"rolename": "fanout_reader", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [],
  "roles": [
    {
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("test dynsec notify config must be writable");
        path.to_string_lossy().into_owned()
    }

    fn write_test_dynsec_client_side_group_notify_config() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("dynsec-control-client-group-notify-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "groups": [{"groupname": "fanout", "priority": 0}],
      "disabled": false
    }
  ],
  "groups": [
    {
      "groupname": "fanout",
      "roles": [{"rolename": "fanout_reader", "priority": 0}]
    }
  ],
  "roles": [
    {
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("test dynsec client-group notify config must be writable");
        path.to_string_lossy().into_owned()
    }

    fn write_test_dynsec_overlap_notify_config() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("dynsec-control-overlap-notify-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "groups": [
        {"groupname": "fanout", "priority": 0},
        {"groupname": "backup", "priority": 10}
      ],
      "disabled": false
    }
  ],
  "groups": [
    {
      "groupname": "fanout",
      "roles": [{"rolename": "fanout_reader", "priority": 0}],
      "clients": [{"username": "test_user", "priority": 0}]
    },
    {
      "groupname": "backup",
      "roles": [{"rolename": "backup_reader", "priority": 0}],
      "clients": [{"username": "test_user", "priority": 10}]
    }
  ],
  "roles": [
    {
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": true
        }
      ]
    },
    {
      "rolename": "backup_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("test dynsec overlap notify config must be writable");
        path.to_string_lossy().into_owned()
    }

    fn write_test_dynsec_anonymous_config() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dynsec-control-anon-{unique}.json"));
        let config = r#"{
  "clients": [],
  "groups": [
    {
      "groupname": "anonymous",
      "roles": [{"rolename": "anonymous_reader", "priority": 0}],
      "clients": []
    }
  ],
  "roles": [
    {
      "rolename": "anonymous_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "public/announce",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  },
  "anonymousGroup": "anonymous"
}"#;
        fs::write(&path, config).expect("test dynsec anonymous config must be writable");
        path.to_string_lossy().into_owned()
    }

    fn write_test_dynsec_conflicting_membership_priority_config() -> String {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("dynsec-control-merge-priority-{unique}.json"));
        let config = r#"{
  "clients": [
    {
      "username": "test_user",
      "clientid": "test_client",
      "groups": [
        {"groupname": "high_deny", "priority": 10},
        {"groupname": "low_allow", "priority": 5}
      ],
      "disabled": false
    }
  ],
  "groups": [
    {
      "groupname": "high_deny",
      "roles": [{"rolename": "deny_reader", "priority": 0}],
      "clients": [{"username": "test_user", "priority": 1}]
    },
    {
      "groupname": "low_allow",
      "roles": [{"rolename": "allow_reader", "priority": 0}],
      "clients": []
    }
  ],
  "roles": [
    {
      "rolename": "deny_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": false
        }
      ]
    },
    {
      "rolename": "allow_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 0,
          "allow": true
        }
      ]
    }
  ],
  "defaultACLAccess": {
    "publishClientSend": false,
    "publishClientReceive": false,
    "subscribe": false,
    "unsubscribe": false
  }
}"#;
        fs::write(&path, config).expect("test dynsec priority config must be writable");
        path.to_string_lossy().into_owned()
    }

    fn add_external_group_grant(path: &str, groupname: &str, rolename: &str, topic: &str) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");

        let roles = root["roles"]
            .as_array_mut()
            .expect("roles should be an array");
        roles.push(json!({
            "rolename": rolename,
            "acls": [
                {
                    "acltype": "publishClientReceive",
                    "topic": topic,
                    "priority": 0,
                    "allow": true
                }
            ]
        }));

        let groups = root["groups"]
            .as_array_mut()
            .expect("groups should be an array");
        groups.push(json!({
            "groupname": groupname,
            "roles": [{"rolename": rolename, "priority": 0}],
            "clients": [{"username": "test_user", "priority": 0}]
        }));

        let clients = root["clients"]
            .as_array_mut()
            .expect("clients should be an array");
        let client = clients
            .iter_mut()
            .find(|entry| entry["username"].as_str() == Some("test_user"))
            .expect("test_user client should exist");
        client["groups"] = Value::Array(vec![json!({
            "groupname": groupname,
            "priority": 0
        })]);

        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn replace_dynsec_file_with_directory(path: &str) -> String {
        let original = fs::read_to_string(path).expect("test dynsec config should be readable");
        fs::remove_file(path).expect("test dynsec config should be removable");
        fs::create_dir(path).expect("test dynsec config path should become a directory");
        original
    }

    fn restore_dynsec_file(path: &str, original: &str) {
        let dynsec_path = Path::new(path);
        if dynsec_path.is_dir() {
            fs::remove_dir(dynsec_path).expect("test dynsec config directory should be removable");
        } else if dynsec_path.exists() {
            fs::remove_file(dynsec_path).expect("test dynsec config file should be removable");
        }
        fs::write(dynsec_path, original).expect("test dynsec config should be restorable");
    }

    #[cfg(unix)]
    fn set_dynsec_file_mode(path: &str, mode: u32) -> u32 {
        let mut permissions = fs::metadata(path)
            .expect("test dynsec config metadata should be readable")
            .permissions();
        let original_mode = permissions.mode();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions).expect("test dynsec config permissions should set");
        original_mode
    }

    fn set_top_level_field_to_object(path: &str, field: &str) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");
        root[field] = json!({ "broken": true });
        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn set_stub_group_grant(path: &str, groupname: &str, rolename: &str) {
        let raw = fs::read_to_string(path).expect("test dynsec config should be readable");
        let mut root: Value = serde_json::from_str(&raw).expect("test dynsec config should parse");

        let roles = root["roles"]
            .as_array_mut()
            .expect("roles should be an array");
        roles.push(json!({
            "rolename": rolename,
            "acls": []
        }));

        let groups = root["groups"]
            .as_array_mut()
            .expect("groups should be an array");
        groups.push(json!({
            "groupname": groupname,
            "roles": [],
            "clients": []
        }));

        let serialized =
            serde_json::to_string_pretty(&root).expect("test dynsec config should serialize");
        fs::write(path, format!("{serialized}\n")).expect("test dynsec config should be writable");
    }

    fn group_grant_payload() -> &'static [u8] {
        br#"{
  "commands": [
    {
      "command": "createRole",
      "rolename": "fanout_reader",
      "acls": [
        {
          "acltype": "subscribeLiteral",
          "topic": "fanout/broadcast",
          "priority": 1,
          "allow": true
        },
        {
          "acltype": "publishClientReceive",
          "topic": "fanout/broadcast",
          "priority": 1,
          "allow": true
        }
      ]
    },
    {
      "command": "createGroup",
      "groupname": "fanout",
      "roles": [
        {"rolename": "fanout_reader", "priority": 5}
      ]
    },
    {
      "command": "addGroupClient",
      "groupname": "fanout",
      "username": "test_user",
      "priority": 7
    }
  ]
}"#
    }

    fn anonymous_placeholder_group_payload() -> &'static [u8] {
        br#"{
  "commands": [
    {
      "command": "createRole",
      "rolename": "private_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "private/announce",
          "priority": 0,
          "allow": true
        }
      ]
    },
    {
      "command": "createGroup",
      "groupname": "private",
      "roles": [
        {"rolename": "private_reader", "priority": 0}
      ]
    },
    {
      "command": "addGroupClient",
      "groupname": "private",
      "username": "ghost",
      "priority": 0
    }
  ]
}"#
    }

    fn assert_persisted_disabled_placeholder_client(path: &str, username: &str) {
        let raw = fs::read_to_string(path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let clients = root["clients"]
            .as_array()
            .expect("clients should be an array");
        let client = clients
            .iter()
            .find(|client| client["username"].as_str() == Some(username))
            .expect("disabled placeholder client should be persisted");
        assert_eq!(client["disabled"].as_bool(), Some(true));
        assert!(client.get("clientid").is_none());
        assert!(nested_array_missing_or_empty(client, "roles").expect("roles should be valid"));
        assert!(nested_array_missing_or_empty(client, "groups").expect("groups should be valid"));
    }

    #[test]
    fn apply_control_payload_disable_client_marks_user_disabled_and_returns_client_id() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");
        assert_eq!(targets.kick_client_ids, vec!["test_client".to_string()]);
        assert_eq!(targets.kick_usernames, vec!["test_user".to_string()]);
        assert!(targets.notify_events.is_empty());
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_ignores_non_disable_commands() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"listRoles"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_rejects_invalid_json() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let err = policy
            .apply_control_payload(br#"{"commands":[{"command":"disableClient"}"#)
            .expect_err("invalid payload should fail");
        assert!(err.contains("invalid control payload"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_returns_username_when_client_id_missing() {
        let path = write_test_dynsec_config_without_client_id();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert_eq!(targets.kick_usernames, vec!["test_user".to_string()]);
        assert!(targets.notify_events.is_empty());

        // Runtime disable overlay must continue denying even after config reloads.
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("another_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_enable_client_clears_runtime_disable_overlay() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let disable_payload =
            br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
        let disable_targets = policy
            .apply_control_payload(disable_payload)
            .expect("disable payload should apply");
        assert_eq!(
            disable_targets.kick_client_ids,
            vec!["test_client".to_string()]
        );
        assert_eq!(
            disable_targets.kick_usernames,
            vec!["test_user".to_string()]
        );
        assert!(disable_targets.notify_events.is_empty());
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let enable_payload = br#"{"commands":[{"command":"enableClient","username":"test_user"}]}"#;
        let enable_targets = policy
            .apply_control_payload(enable_payload)
            .expect("enable payload should apply");
        assert!(enable_targets.kick_client_ids.is_empty());
        assert!(enable_targets.kick_usernames.is_empty());
        assert!(enable_targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_disable_then_enable_same_payload_has_no_kick_targets() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        let payload = br#"{
            "commands":[
                {"command":"disableClient","username":"test_user"},
                {"command":"enableClient","username":"test_user"}
            ]
        }"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_enable_client_clears_overlay_even_if_state_already_enabled() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let disable_payload =
            br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#;
        policy
            .apply_control_payload(disable_payload)
            .expect("disable payload should apply");

        // Simulate a state overlay mismatch by externally setting the file back to enabled.
        set_client_disabled(&path, "test_user", false);
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let enable_payload = br#"{"commands":[{"command":"enableClient","username":"test_user"}]}"#;
        let targets = policy
            .apply_control_payload(enable_payload)
            .expect("enable payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_create_role_group_and_membership_grants_access_after_reload() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let targets = policy
            .apply_control_payload(group_grant_payload())
            .expect("create payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert!(targets.notify_events.is_empty());

        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_SUBSCRIBE
                )
                .expect("policy check should succeed")
        );
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_SUBSCRIBE
                )
                .expect("policy check should succeed")
        );
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_remove_group_client_revokes_group_access_after_reload() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");
        policy
            .apply_control_payload(group_grant_payload())
            .expect("create payload should apply");

        let payload =
            br#"{"commands":[{"command":"removeGroupClient","groupname":"fanout","username":"test_user"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("remove payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        let event = &targets.notify_events[0];
        assert_eq!(event.command, "removeGroupClient");
        assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
        assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
        assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
        assert_eq!(event.usernames, vec!["test_user".to_string()]);
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_SUBSCRIBE
                )
                .expect("policy check should succeed")
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_remove_group_client_prunes_placeholder_and_restores_anonymous_fallback()
     {
        let path = write_test_dynsec_anonymous_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");
        policy
            .apply_control_payload(anonymous_placeholder_group_payload())
            .expect("create payload should apply");

        assert!(
            !policy
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "public/announce",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let payload =
            br#"{"commands":[{"command":"removeGroupClient","groupname":"private","username":"ghost"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("remove payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        let event = &targets.notify_events[0];
        assert_eq!(event.command, "removeGroupClient");
        assert_eq!(event.rolename.as_deref(), Some("private_reader"));
        assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
        assert_eq!(event.topic.as_deref(), Some("private/announce"));
        assert_eq!(event.usernames, vec!["ghost".to_string()]);

        let state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        assert!(!state.clients.contains_key("ghost"));
        drop(state);

        assert!(
            policy
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "public/announce",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_group_revokes_group_access_after_reload() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");
        policy
            .apply_control_payload(group_grant_payload())
            .expect("create payload should apply");

        let payload = br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("delete payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        let event = &targets.notify_events[0];
        assert_eq!(event.command, "deleteGroup");
        assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
        assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
        assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
        assert_eq!(event.usernames, vec!["test_user".to_string()]);
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let groups = root["groups"]
            .as_array()
            .expect("groups should be an array");
        assert!(groups.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_group_prunes_placeholders_and_restores_anonymous_fallback() {
        let path = write_test_dynsec_anonymous_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");
        policy
            .apply_control_payload(anonymous_placeholder_group_payload())
            .expect("create payload should apply");

        let payload = br#"{"commands":[{"command":"deleteGroup","groupname":"private"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("delete payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        let event = &targets.notify_events[0];
        assert_eq!(event.command, "deleteGroup");
        assert_eq!(event.rolename.as_deref(), Some("private_reader"));
        assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
        assert_eq!(event.topic.as_deref(), Some("private/announce"));
        assert_eq!(event.usernames, vec!["ghost".to_string()]);

        let state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        assert!(!state.clients.contains_key("ghost"));
        drop(state);

        assert!(
            policy
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "public/announce",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_anonymous_group_clears_anonymous_binding() {
        let path = write_test_dynsec_anonymous_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        assert!(
            policy
                .check(None, None, "public/announce", ACL_READ)
                .expect("anonymous policy check should succeed")
        );

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"anonymous"}]}"#,
            )
            .expect("delete payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());

        let state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        assert!(!state.groups.contains_key("anonymous"));
        assert_eq!(state.anonymous_group, None);
        drop(state);

        assert!(
            !policy
                .check(None, None, "public/announce", ACL_READ)
                .expect("anonymous policy check should succeed")
        );

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        assert!(root.get("anonymousGroup").is_none());

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(None, None, "public/announce", ACL_READ)
                .expect("anonymous policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_role_cleans_group_references_after_reload() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");
        policy
            .apply_control_payload(group_grant_payload())
            .expect("create payload should apply");

        let payload = br#"{"commands":[{"command":"deleteRole","rolename":"fanout_reader"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("delete payload should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        let event = &targets.notify_events[0];
        assert_eq!(event.command, "deleteRole");
        assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
        assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
        assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
        assert_eq!(event.usernames, vec!["test_user".to_string()]);
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let roles = root["roles"].as_array().expect("roles should be an array");
        assert_eq!(roles.len(), 1);
        let group_roles = root["groups"][0]["roles"]
            .as_array()
            .expect("group roles should be an array");
        assert!(group_roles.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_add_group_client_updates_existing_priority_and_persists() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");
        policy
            .apply_control_payload(group_grant_payload())
            .expect("create payload should apply");

        let payload =
            br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"test_user","priority":1}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("priority update should apply");
        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert!(targets.notify_events.is_empty());

        let state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        let client_group = state
            .clients
            .get("test_user")
            .and_then(|client| client.groups.iter().find(|group| group.name == "fanout"))
            .expect("client should keep fanout membership");
        assert_eq!(client_group.priority, 1);
        let group_client = state
            .groups
            .get("fanout")
            .and_then(|group| {
                group
                    .clients
                    .iter()
                    .find(|client| client.name == "test_user")
            })
            .expect("group should keep test_user membership");
        assert_eq!(group_client.priority, 1);
        drop(state);

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let groups = root["groups"]
            .as_array()
            .expect("groups should be an array");
        let fanout_group = groups
            .iter()
            .find(|group| group["groupname"].as_str() == Some("fanout"))
            .expect("fanout group should exist");
        let clients = fanout_group["clients"]
            .as_array()
            .expect("group clients should be an array");
        let test_user = clients
            .iter()
            .find(|entry| entry["username"].as_str() == Some("test_user"))
            .expect("test_user client ref should exist");
        assert_eq!(test_user["priority"].as_i64(), Some(1));
        let test_user_groups = root["clients"][0]["groups"]
            .as_array()
            .expect("client groups should be an array");
        let fanout_membership = test_user_groups
            .iter()
            .find(|entry| entry["groupname"].as_str() == Some("fanout"))
            .expect("fanout group ref should exist");
        assert_eq!(fanout_membership["priority"].as_i64(), Some(1));

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        let reloaded_state = reloaded
            .state
            .read()
            .expect("dynsec state lock should succeed");
        let reloaded_group = reloaded_state
            .clients
            .get("test_user")
            .and_then(|client| client.groups.iter().find(|group| group.name == "fanout"))
            .expect("reloaded client should keep fanout membership");
        assert_eq!(reloaded_group.priority, 1);
        drop(reloaded_state);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_persist_failure_returns_warning_and_keeps_structural_mutations_live() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let targets = policy
            .apply_control_payload(group_grant_payload())
            .expect("persist failure should still apply runtime mutations");
        assert!(
            targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("dynsec config read failed"))
        );
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        policy
            .reload_if_needed(true)
            .expect("forced reload should preserve pending structural mutations");
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn check_fast_path_does_not_wait_on_control_apply_lock_when_reload_is_fresh() {
        let path = write_test_dynsec_config();
        let policy = Arc::new(
            DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
                .expect("policy must load"),
        );
        let control_guard = policy
            .control_apply_lock
            .lock()
            .expect("control lock should succeed");
        let (tx, rx) = mpsc::channel();
        let thread_policy = Arc::clone(&policy);

        let handle = thread::spawn(move || {
            let result = thread_policy.check(
                Some("test_user"),
                Some("test_client"),
                "$CONTROL/dynamic-security/v1",
                ACL_WRITE,
            );
            tx.send(result).expect("channel send should succeed");
        });

        let result = rx
            .recv_timeout(Duration::from_millis(200))
            .expect("fresh check should not block on control lock");
        assert!(result.expect("policy check should succeed"));

        drop(control_guard);
        handle.join().expect("check thread should join");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_persist_failure_returns_warning_and_keeps_runtime_disable_overlay_live()
     {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#,
            )
            .expect("persist failure should still apply runtime disable");
        assert!(
            targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("dynsec config read failed"))
        );
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        policy
            .reload_if_needed(true)
            .expect("forced reload should preserve runtime disable overlay");
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_persist_failure_returns_warning_and_keeps_runtime_enable_live() {
        let path = write_test_dynsec_config();
        set_client_disabled(&path, "test_user", true);
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"enableClient","username":"test_user"}]}"#,
            )
            .expect("persist failure should still apply runtime enable");
        assert!(
            targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("dynsec config read failed"))
        );
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        policy
            .reload_if_needed(true)
            .expect("forced reload should preserve runtime enable");
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_persist_failure_returns_warning_and_keeps_role_acl_overrides_live() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"addRoleACL","rolename":"ctrl","acltype":"publishClientReceive","topic":"fanout/broadcast","priority":1,"allow":true}]}"#)
            .expect("persist failure should still apply role ACL overrides");
        assert!(
            targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("dynsec config read failed"))
        );
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        policy
            .reload_if_needed(true)
            .expect("forced reload should preserve runtime role ACL overrides");
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_schema_invalid_persist_keeps_pending_structural_mutations() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
        set_top_level_field_to_object(&path, "groups");

        let targets = policy
            .apply_control_payload(group_grant_payload())
            .expect("schema-invalid persist should still apply runtime mutations");
        assert!(
            targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("expected 'groups' to be an array"))
        );
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        assert!(
            !policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        restore_dynsec_file(&path, &original);
        policy
            .reload_if_needed(true)
            .expect("forced reload should preserve pending structural mutations");
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_schema_invalid_persist_keeps_pending_runtime_disable() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
        set_top_level_field_to_object(&path, "clients");

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"disableClient","username":"test_user"}]}"#,
            )
            .expect("schema-invalid persist should still apply runtime disable");
        assert!(
            targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("expected 'clients' to be an array"))
        );
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );
        assert!(
            !policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        restore_dynsec_file(&path, &original);
        policy
            .reload_if_needed(true)
            .expect("forced reload should preserve pending runtime disable");
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_retries_pending_persist_mutations_on_later_success() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(group_grant_payload())
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        let retry_targets = policy
            .apply_control_payload(group_grant_payload())
            .expect("later control command should retry pending persistence");
        assert!(retry_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_keeps_pending_add_group_client_when_retry_is_blocked() {
        let path = write_test_dynsec_client_side_group_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"ghost","priority":5}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());
        assert!(
            policy
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        remove_group_from_dynsec_file(&path, "fanout");

        let retry_targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
            .expect("retry should keep runtime changes live");
        assert!(
            retry_targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("blocked by divergent state"))
        );
        assert!(
            !policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );
        assert!(
            !policy
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should follow fresh file state on replay failure")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_keeps_pending_role_acl_add_when_retry_is_blocked() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":0,"allow":true}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_SUBSCRIBE
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        remove_role_from_dynsec_file(&path, "fanout_reader");

        let retry_targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
            .expect("retry should keep runtime changes live");
        assert!(
            retry_targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("blocked by divergent state"))
        );
        assert!(
            !policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_current_create_group_repairs_pending_add_group_client_retry() {
        let path = write_test_dynsec_client_side_group_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"ghost","priority":5}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());

        restore_dynsec_file(&path, &original);
        remove_group_from_dynsec_file(&path, "fanout");

        let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"fanout","roles":[{"rolename":"fanout_reader","priority":0}]}]}"#,
            )
            .expect("repair payload should apply");
        assert!(repair_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed after durable repair")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_current_create_role_repairs_pending_role_acl_retry() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":0,"allow":true}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());

        restore_dynsec_file(&path, &original);
        remove_role_definition_from_dynsec_file(&path, "fanout_reader");

        let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":0,"allow":true}]}]}"#,
            )
            .expect("repair payload should apply");
        assert!(repair_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_SUBSCRIBE
                )
                .expect("policy check should succeed after durable repair")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn collapse_retry_intents_drops_superseded_group_client_add_before_delete_group() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
                priority: 5,
            },
            PersistMutation::DeleteGroup {
                groupname: "fanout".to_string(),
            },
        ]);

        assert_eq!(collapsed.len(), 1);
        assert!(matches!(
            collapsed.as_slice(),
            [PersistMutation::DeleteGroup { groupname }] if groupname == "fanout"
        ));
    }

    #[test]
    fn collapse_retry_intents_drops_superseded_role_acl_add_before_delete_role() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: "fanout_reader".to_string(),
                acltype: "subscribeLiteral".to_string(),
                topic: "fanout/broadcast".to_string(),
                priority: 0,
                allow: true,
            }),
            PersistMutation::DeleteRole {
                rolename: "fanout_reader".to_string(),
            },
        ]);

        assert_eq!(collapsed.len(), 1);
        assert!(matches!(
            collapsed.as_slice(),
            [PersistMutation::DeleteRole { rolename }] if rolename == "fanout_reader"
        ));
    }

    #[test]
    fn collapse_retry_intents_keeps_only_latest_group_client_intent() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
                priority: 1,
            },
            PersistMutation::RemoveGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
            },
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
                priority: 7,
            },
        ]);

        assert_eq!(collapsed.len(), 1);
        assert!(matches!(
            collapsed.as_slice(),
            [PersistMutation::AddGroupClient {
                groupname,
                username,
                priority
            }] if groupname == "fanout" && username == "ghost" && *priority == 7
        ));
    }

    #[test]
    fn collapse_retry_intents_create_group_then_delete_then_recreate_keeps_delete_cleanup() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::CreateGroup {
                groupname: "fanout".to_string(),
                roles: vec![RoleRef {
                    rolename: "reader".to_string(),
                    priority: Some(0),
                }],
            },
            PersistMutation::DeleteGroup {
                groupname: "fanout".to_string(),
            },
            PersistMutation::CreateGroup {
                groupname: "fanout".to_string(),
                roles: vec![RoleRef {
                    rolename: "writer".to_string(),
                    priority: Some(5),
                }],
            },
        ]);

        assert!(matches!(
            collapsed.as_slice(),
            [
                PersistMutation::DeleteGroup { groupname: deleted_group },
                PersistMutation::CreateGroup { groupname, roles }
            ] if deleted_group == "fanout"
                && groupname == "fanout"
                && roles.len() == 1
                && roles[0].rolename == "writer"
                && roles[0].priority == Some(5)
        ));
    }

    #[test]
    fn collapse_retry_intents_create_role_then_delete_then_recreate_keeps_delete_cleanup() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::CreateRole {
                rolename: "fanout_reader".to_string(),
                acls: vec![AclConfig {
                    acltype: "subscribeLiteral".to_string(),
                    topic: "fanout/old".to_string(),
                    priority: Some(0),
                    allow: Some(true),
                }],
            },
            PersistMutation::DeleteRole {
                rolename: "fanout_reader".to_string(),
            },
            PersistMutation::CreateRole {
                rolename: "fanout_reader".to_string(),
                acls: vec![AclConfig {
                    acltype: "subscribeLiteral".to_string(),
                    topic: "fanout/new".to_string(),
                    priority: Some(2),
                    allow: Some(true),
                }],
            },
        ]);

        assert!(matches!(
            collapsed.as_slice(),
            [
                PersistMutation::DeleteRole { rolename: deleted_role },
                PersistMutation::CreateRole { rolename, acls }
            ] if deleted_role == "fanout_reader"
                && rolename == "fanout_reader"
                && acls.len() == 1
                && acls[0].topic == "fanout/new"
                && acls[0].priority == Some(2)
        ));
    }

    #[test]
    fn collapse_retry_intents_delete_group_then_create_group_keeps_recreated_membership() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::DeleteGroup {
                groupname: "fanout".to_string(),
            },
            PersistMutation::CreateGroup {
                groupname: "fanout".to_string(),
                roles: vec![RoleRef {
                    rolename: "reader".to_string(),
                    priority: Some(0),
                }],
            },
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
                priority: 3,
            },
        ]);

        assert!(matches!(
            collapsed.as_slice(),
            [
                PersistMutation::DeleteGroup { groupname: deleted_group },
                PersistMutation::CreateGroup { groupname, .. },
                PersistMutation::AddGroupClient {
                    groupname: add_group,
                    username,
                    priority
                }
            ] if deleted_group == "fanout"
                && groupname == "fanout"
                && add_group == "fanout"
                && username == "ghost"
                && *priority == 3
        ));
    }

    #[test]
    fn collapse_retry_intents_delete_role_then_create_role_keeps_recreated_acl_add() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::DeleteRole {
                rolename: "fanout_reader".to_string(),
            },
            PersistMutation::CreateRole {
                rolename: "fanout_reader".to_string(),
                acls: vec![AclConfig {
                    acltype: "publishClientReceive".to_string(),
                    topic: "fanout/base".to_string(),
                    priority: Some(0),
                    allow: Some(true),
                }],
            },
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: "fanout_reader".to_string(),
                acltype: "subscribeLiteral".to_string(),
                topic: "fanout/extra".to_string(),
                priority: 4,
                allow: true,
            }),
        ]);

        assert!(matches!(
            collapsed.as_slice(),
            [
                PersistMutation::DeleteRole { rolename: deleted_role },
                PersistMutation::CreateRole { rolename, .. },
                PersistMutation::RoleAcl(RoleAclMutation::Add {
                    rolename: acl_role,
                    acltype,
                    topic,
                    priority,
                    allow
                })
            ] if deleted_role == "fanout_reader"
                && rolename == "fanout_reader"
                && acl_role == "fanout_reader"
                && acltype == "subscribeLiteral"
                && topic == "fanout/extra"
                && *priority == 4
                && *allow
        ));
    }

    #[test]
    fn collapse_retry_intents_emits_delete_before_recreate_and_dependents() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::DeleteGroup {
                groupname: "fanout".to_string(),
            },
            PersistMutation::CreateGroup {
                groupname: "fanout".to_string(),
                roles: vec![RoleRef {
                    rolename: "reader".to_string(),
                    priority: Some(0),
                }],
            },
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
                priority: 3,
            },
            PersistMutation::SetClientDisabled {
                username: "ghost".to_string(),
                disabled: true,
            },
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: "reader".to_string(),
                acltype: "subscribeLiteral".to_string(),
                topic: "fanout/extra".to_string(),
                priority: 4,
                allow: true,
            }),
            PersistMutation::RemoveGroupClient {
                groupname: "fanout".to_string(),
                username: "other".to_string(),
            },
            PersistMutation::RoleAcl(RoleAclMutation::Remove {
                rolename: "reader".to_string(),
                acltype: "subscribeLiteral".to_string(),
                topic: "fanout/old".to_string(),
            }),
        ]);

        assert!(matches!(
            collapsed.as_slice(),
            [
                PersistMutation::DeleteGroup { groupname: deleted_group },
                PersistMutation::CreateGroup { groupname: created_group, .. },
                PersistMutation::AddGroupClient { groupname: added_group, username: added_user, priority: added_priority },
                PersistMutation::SetClientDisabled { username: disabled_user, disabled },
                PersistMutation::RoleAcl(RoleAclMutation::Add {
                    rolename: added_role,
                    acltype: added_acltype,
                    topic: added_topic,
                    priority: added_acl_priority,
                    allow: added_allow
                }),
                PersistMutation::RemoveGroupClient { groupname: removed_group, username: removed_user },
                PersistMutation::RoleAcl(RoleAclMutation::Remove {
                    rolename: removed_role,
                    acltype: removed_acltype,
                    topic: removed_topic
                })
            ] if deleted_group == "fanout"
                && created_group == "fanout"
                && added_group == "fanout"
                && added_user == "ghost"
                && *added_priority == 3
                && disabled_user == "ghost"
                && *disabled
                && added_role == "reader"
                && added_acltype == "subscribeLiteral"
                && added_topic == "fanout/extra"
                && *added_acl_priority == 4
                && *added_allow
                && removed_group == "fanout"
                && removed_user == "other"
                && removed_role == "reader"
                && removed_acltype == "subscribeLiteral"
                && removed_topic == "fanout/old"
        ));
    }

    #[test]
    fn collapse_retry_intents_skips_dependents_only_for_delete_not_delete_then_create() {
        let delete_only = collapse_retry_intents(&[
            PersistMutation::DeleteGroup {
                groupname: "fanout".to_string(),
            },
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
                priority: 3,
            },
        ]);
        assert!(matches!(
            delete_only.as_slice(),
            [PersistMutation::DeleteGroup { groupname }] if groupname == "fanout"
        ));

        let recreated = collapse_retry_intents(&[
            PersistMutation::DeleteGroup {
                groupname: "fanout".to_string(),
            },
            PersistMutation::CreateGroup {
                groupname: "fanout".to_string(),
                roles: vec![RoleRef {
                    rolename: "reader".to_string(),
                    priority: Some(0),
                }],
            },
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
                priority: 3,
            },
        ]);
        assert!(matches!(
            recreated.as_slice(),
            [
                PersistMutation::DeleteGroup { groupname: deleted_group },
                PersistMutation::CreateGroup { groupname: created_group, .. },
                PersistMutation::AddGroupClient { groupname: added_group, username, priority }
            ] if deleted_group == "fanout"
                && created_group == "fanout"
                && added_group == "fanout"
                && username == "ghost"
                && *priority == 3
        ));
    }

    #[test]
    fn collapse_retry_intents_create_group_then_delete_drops_intermediate_membership_intents() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::CreateGroup {
                groupname: "fanout".to_string(),
                roles: vec![RoleRef {
                    rolename: "reader".to_string(),
                    priority: Some(0),
                }],
            },
            PersistMutation::AddGroupClient {
                groupname: "fanout".to_string(),
                username: "ghost".to_string(),
                priority: 5,
            },
            PersistMutation::DeleteGroup {
                groupname: "fanout".to_string(),
            },
        ]);

        assert!(matches!(
            collapsed.as_slice(),
            [PersistMutation::DeleteGroup { groupname }] if groupname == "fanout"
        ));
    }

    #[test]
    fn collapse_retry_intents_create_role_then_delete_drops_intermediate_acl_intents() {
        let collapsed = collapse_retry_intents(&[
            PersistMutation::CreateRole {
                rolename: "fanout_reader".to_string(),
                acls: vec![AclConfig {
                    acltype: "publishClientReceive".to_string(),
                    topic: "fanout/base".to_string(),
                    priority: Some(0),
                    allow: Some(true),
                }],
            },
            PersistMutation::RoleAcl(RoleAclMutation::Add {
                rolename: "fanout_reader".to_string(),
                acltype: "subscribeLiteral".to_string(),
                topic: "fanout/extra".to_string(),
                priority: 4,
                allow: true,
            }),
            PersistMutation::DeleteRole {
                rolename: "fanout_reader".to_string(),
            },
        ]);

        assert!(matches!(
            collapsed.as_slice(),
            [PersistMutation::DeleteRole { rolename }] if rolename == "fanout_reader"
        ));
    }

    #[test]
    fn apply_control_payload_recreate_group_after_failed_delete_cleans_stale_memberships() {
        let path = write_test_dynsec_client_side_group_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("runtime state should reflect deleted group")
        );

        restore_dynsec_file(&path, &original);
        remove_group_definition_from_dynsec_file(&path, "fanout");

        let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"fanout","roles":[{"rolename":"fanout_reader","priority":0}]}]}"#,
            )
            .expect("recreate payload should converge pending persistence");
        assert!(repair_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let client = root["clients"]
            .as_array()
            .and_then(|clients| {
                clients
                    .iter()
                    .find(|entry| entry["username"].as_str() == Some("test_user"))
            })
            .expect("test_user client should exist");
        let groups = client["groups"]
            .as_array()
            .expect("client groups should be an array");
        assert!(
            groups
                .iter()
                .all(|group| group["groupname"].as_str() != Some("fanout"))
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("reload should not regain stale membership access")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_recreate_role_after_failed_delete_cleans_stale_bindings() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteRole","rolename":"fanout_reader"}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("runtime state should reflect deleted role")
        );

        restore_dynsec_file(&path, &original);
        remove_role_definition_from_dynsec_file(&path, "fanout_reader");

        let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"publishClientReceive","topic":"fanout/new","priority":0,"allow":true}]}]}"#,
            )
            .expect("recreate payload should converge pending persistence");
        assert!(repair_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let client = root["clients"]
            .as_array()
            .and_then(|clients| {
                clients
                    .iter()
                    .find(|entry| entry["username"].as_str() == Some("test_user"))
            })
            .expect("test_user client should exist");
        let roles = client["roles"]
            .as_array()
            .expect("client roles should be an array");
        assert!(
            roles
                .iter()
                .all(|role| role["rolename"].as_str() != Some("fanout_reader"))
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/new",
                    ACL_READ
                )
                .expect("reload should not regain stale role access")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_group_clears_superseded_pending_add_group_client() {
        let path = write_test_dynsec_client_side_group_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"ghost","priority":5}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());

        restore_dynsec_file(&path, &original);

        let delete_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#,
            )
            .expect("delete payload should converge pending persistence");
        assert!(delete_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed after durable delete")
        );

        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn apply_control_payload_create_group_repair_stays_pending_after_write_failure() {
        let path = write_test_dynsec_client_side_group_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addGroupClient","groupname":"fanout","username":"ghost","priority":5}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());

        restore_dynsec_file(&path, &original);
        remove_group_from_dynsec_file(&path, "fanout");

        let original_mode = set_dynsec_file_mode(&path, 0o444);
        let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"fanout","roles":[{"rolename":"fanout_reader","priority":0}]}]}"#,
            )
            .expect("repair payload should keep runtime changes on write failure");
        let _ = set_dynsec_file_mode(&path, original_mode);

        assert!(
            repair_targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("dynsec config write failed"))
        );
        let pending = policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .clone();
        assert_eq!(pending.len(), 2);
        assert!(matches!(
            pending.as_slice(),
            [
                PersistMutation::CreateGroup { groupname, .. },
                PersistMutation::AddGroupClient {
                    groupname: add_group,
                    username,
                    priority
                }
            ] if groupname == "fanout"
                && add_group == "fanout"
                && username == "ghost"
                && *priority == 5
        ));

        let retry_targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
            .expect("later control command should retry pending persistence");
        assert!(retry_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed after durable retry")
        );

        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn apply_control_payload_create_role_repair_stays_pending_after_write_failure() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":0,"allow":true}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());

        restore_dynsec_file(&path, &original);
        remove_role_definition_from_dynsec_file(&path, "fanout_reader");

        let original_mode = set_dynsec_file_mode(&path, 0o444);
        let repair_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":0,"allow":true}]}]}"#,
            )
            .expect("repair payload should keep runtime changes on write failure");
        let _ = set_dynsec_file_mode(&path, original_mode);

        assert!(
            repair_targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("dynsec config write failed"))
        );
        let pending = policy
            .pending_persist_mutations
            .lock()
            .expect("pending persist lock should succeed")
            .clone();
        assert_eq!(pending.len(), 2);
        assert!(matches!(
            pending.as_slice(),
            [
                PersistMutation::CreateRole { rolename, .. },
                PersistMutation::RoleAcl(RoleAclMutation::Add {
                    rolename: acl_role,
                    acltype,
                    topic,
                    priority,
                    allow
                })
            ] if rolename == "fanout_reader"
                && acl_role == "fanout_reader"
                && acltype == "subscribeLiteral"
                && topic == "fanout/broadcast"
                && *priority == 0
                && *allow
        ));

        let retry_targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
            .expect("later control command should retry pending persistence");
        assert!(retry_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_SUBSCRIBE
                )
                .expect("policy check should succeed after durable retry")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_duplicate_create_role_does_not_persist_new_acls() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let raw_before = fs::read_to_string(&path).expect("test dynsec config should be readable");

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"subscribeLiteral","topic":"fanout/broadcast","priority":0,"allow":true}]}]}"#,
            )
            .expect("duplicate createRole should be a no-op");
        assert!(targets.persist_warning.is_none());
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_SUBSCRIBE
                )
                .expect("duplicate createRole must not change live auth")
        );

        let raw_after = fs::read_to_string(&path).expect("test dynsec config should be readable");
        assert_eq!(raw_before, raw_after);

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_SUBSCRIBE
                )
                .expect("duplicate createRole must not change durable auth")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_duplicate_create_group_does_not_persist_new_roles() {
        let path = write_test_dynsec_client_side_group_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let raw_before = fs::read_to_string(&path).expect("test dynsec config should be readable");

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"fanout","roles":[{"rolename":"backup_reader","priority":5}]}]}"#,
            )
            .expect("duplicate createGroup should be a no-op");
        assert!(targets.persist_warning.is_none());

        let raw_after = fs::read_to_string(&path).expect("test dynsec config should be readable");
        assert_eq!(raw_before, raw_after);

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("duplicate createGroup must preserve durable auth")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_retries_schema_invalid_pending_mutations_after_repair() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
        set_top_level_field_to_object(&path, "groups");

        let first_targets = policy
            .apply_control_payload(group_grant_payload())
            .expect("schema-invalid persist should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());

        restore_dynsec_file(&path, &original);
        let retry_targets = policy
            .apply_control_payload(group_grant_payload())
            .expect("later control command should retry pending persistence");
        assert!(retry_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn check_preserves_cached_state_across_read_reload_failures() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        {
            let mut last_loaded = policy
                .last_loaded
                .lock()
                .expect("reload lock should succeed");
            *last_loaded = Some(Instant::now() - Duration::from_secs(120));
        }

        let last_loaded_before_failure = policy
            .last_loaded
            .lock()
            .expect("reload lock should succeed")
            .expect("last_loaded should be set before reload failure");
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should keep cached state on read failure")
        );
        let last_loaded_after_failure = policy
            .last_loaded
            .lock()
            .expect("reload lock should succeed")
            .expect("last_loaded should stay populated after fallback");
        assert_eq!(last_loaded_after_failure, last_loaded_before_failure);

        restore_dynsec_file(&path, &original);
        set_client_disabled(&path, "test_user", true);
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("repaired file should be retried on the next check")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn new_fails_when_dynsec_file_is_missing() {
        let unique = DYNSEC_TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("dynsec-missing-startup-{unique}.json"))
            .to_string_lossy()
            .into_owned();

        let err = DynamicSecurityPolicy::new(path, Duration::from_secs(60))
            .expect_err("missing dynsec file must fail startup");
        assert!(err.contains("dynsec config read failed"));
    }

    #[test]
    fn new_fails_when_dynsec_file_is_malformed() {
        let path = write_test_dynsec_config();
        write_invalid_json(&path);

        let err = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect_err("malformed dynsec file must fail startup");
        assert!(err.contains("dynsec config parse failed"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn forced_reload_falls_back_only_after_a_valid_load_exists() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let last_loaded_before_failure = policy
            .last_loaded
            .lock()
            .expect("reload lock should succeed")
            .expect("last_loaded should be set after initial load");
        let original = replace_dynsec_file_with_directory(&path);

        policy
            .reload_if_needed(true)
            .expect("forced reload should keep cached state after a valid load");
        let last_loaded_after_failure = policy
            .last_loaded
            .lock()
            .expect("reload lock should succeed")
            .expect("last_loaded should stay populated after fallback");
        assert_eq!(last_loaded_after_failure, last_loaded_before_failure);
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("cached state should remain usable after forced fallback")
        );

        restore_dynsec_file(&path, &original);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn forced_reload_uses_fresh_disk_state_when_pending_replay_blocks() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        {
            let mut pending = policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed");
            pending.push(PersistMutation::AddGroupClient {
                groupname: "missing_group".to_string(),
                username: "ghost".to_string(),
                priority: 5,
            });
        }

        set_client_disabled(&path, "test_user", true);
        crate::reset_debug_logs();
        policy
            .reload_if_needed(true)
            .expect("forced reload should absorb fresh disk state even when pending replay blocks");
        let logs = crate::debug_logs_snapshot();
        assert!(logs.iter().any(|entry| {
            entry.contains(
                "Dynsec pending replay skipped blocked mutations during reload: blocked=1 changed=0 already_satisfied=0",
            )
        }));

        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_uses_fresh_disk_state_when_pending_replay_blocks() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        {
            let mut pending = policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed");
            pending.push(PersistMutation::AddGroupClient {
                groupname: "missing_group".to_string(),
                username: "ghost".to_string(),
                priority: 5,
            });
        }

        set_client_disabled(&path, "test_user", true);
        crate::reset_debug_logs();
        let targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
            .expect("control refresh should still succeed when pending replay blocks");
        let logs = crate::debug_logs_snapshot();
        assert!(logs.iter().any(|entry| {
            entry.contains(
                "Dynsec pending replay skipped blocked mutations during reload: blocked=1 changed=0 already_satisfied=0",
            )
        }));
        assert!(
            targets
                .persist_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("blocked by divergent state"))
        );
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn forced_reload_does_not_log_blocked_pending_replay_summary_without_blocked_mutations() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        {
            let mut pending = policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed");
            pending.push(PersistMutation::SetClientDisabled {
                username: "test_user".to_string(),
                disabled: true,
            });
        }

        crate::reset_debug_logs();
        policy
            .reload_if_needed(true)
            .expect("forced reload should replay clean pending mutations without blocked summary");
        let logs = crate::debug_logs_snapshot();
        assert!(logs.iter().all(|entry| {
            !entry.contains("Dynsec pending replay skipped blocked mutations during reload:")
        }));
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn forced_reload_applies_later_pending_replayable_mutations_after_earlier_blocked_replay() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        {
            let mut pending = policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed");
            pending.extend([
                PersistMutation::AddGroupClient {
                    groupname: "missing_group".to_string(),
                    username: "ghost".to_string(),
                    priority: 5,
                },
                PersistMutation::SetClientDisabled {
                    username: "test_user".to_string(),
                    disabled: true,
                },
            ]);
        }

        policy
            .reload_if_needed(true)
            .expect("forced reload should continue replay after a blocked mutation");

        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn check_preserves_cached_state_across_parse_reload_failures() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
        write_invalid_json(&path);

        {
            let mut last_loaded = policy
                .last_loaded
                .lock()
                .expect("reload lock should succeed");
            *last_loaded = Some(Instant::now() - Duration::from_secs(120));
        }

        let last_loaded_before_failure = policy
            .last_loaded
            .lock()
            .expect("reload lock should succeed")
            .expect("last_loaded should be set before reload failure");
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("policy check should keep cached state on parse failure")
        );
        let last_loaded_after_failure = policy
            .last_loaded
            .lock()
            .expect("reload lock should succeed")
            .expect("last_loaded should stay populated after fallback");
        assert_eq!(last_loaded_after_failure, last_loaded_before_failure);

        restore_dynsec_file(&path, &original);
        set_client_disabled(&path, "test_user", true);
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "$CONTROL/dynamic-security/v1",
                    ACL_WRITE
                )
                .expect("repaired file should be retried on the next check")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_valid_noop_persist_clears_pending_mutations() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        policy
            .apply_control_payload(group_grant_payload())
            .expect("initial payload should persist");

        {
            let mut pending = policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed");
            pending.extend([
                PersistMutation::CreateRole {
                    rolename: "fanout_reader".to_string(),
                    acls: vec![
                        AclConfig {
                            acltype: "subscribeLiteral".to_string(),
                            topic: "fanout/broadcast".to_string(),
                            priority: Some(1),
                            allow: Some(true),
                        },
                        AclConfig {
                            acltype: "publishClientReceive".to_string(),
                            topic: "fanout/broadcast".to_string(),
                            priority: Some(1),
                            allow: Some(true),
                        },
                    ],
                },
                PersistMutation::CreateGroup {
                    groupname: "fanout".to_string(),
                    roles: vec![RoleRef {
                        rolename: "fanout_reader".to_string(),
                        priority: Some(5),
                    }],
                },
                PersistMutation::AddGroupClient {
                    groupname: "fanout".to_string(),
                    username: "test_user".to_string(),
                    priority: 7,
                },
            ]);
        }

        let targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
            .expect("noop control payload should still flush pending persistence");
        assert!(targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_disable_placeholder_client_persists_disabled_state() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        policy
            .apply_control_payload(
                br#"{
  "commands": [
    {
      "command": "createRole",
      "rolename": "synthetic_reader",
      "acls": [
        {
          "acltype": "publishClientReceive",
          "topic": "synthetic/broadcast",
          "priority": 1,
          "allow": true
        }
      ]
    },
    {
      "command": "createGroup",
      "groupname": "synthetic",
      "roles": [
        {"rolename": "synthetic_reader", "priority": 1}
      ]
    },
    {
      "command": "addGroupClient",
      "groupname": "synthetic",
      "username": "ghost",
      "priority": 1
    }
  ]
}"#,
            )
            .expect("synthetic grant payload should apply");
        assert!(
            policy
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "synthetic/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        policy
            .apply_control_payload(
                br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#,
            )
            .expect("disable payload should apply");
        assert!(
            !policy
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "synthetic/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        assert_persisted_disabled_placeholder_client(&path, "ghost");

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "synthetic/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pending_disable_placeholder_survives_remove_group_client_retry() {
        let path = write_test_dynsec_anonymous_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        policy
            .apply_control_payload(anonymous_placeholder_group_payload())
            .expect("create payload should apply");
        let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
        replace_dynsec_file_with_directory(&path);

        let disable_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#,
            )
            .expect("disable payload should apply despite persist failure");
        assert!(disable_targets.persist_warning.is_some());
        assert!(
            !policy
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "private/announce",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        let retry_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"removeGroupClient","groupname":"private","username":"ghost"}]}"#,
            )
            .expect("remove payload should durably preserve disabled placeholder");
        assert!(retry_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );
        assert_persisted_disabled_placeholder_client(&path, "ghost");

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "private/announce",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pending_disable_placeholder_survives_delete_group_retry() {
        let path = write_test_dynsec_anonymous_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");

        policy
            .apply_control_payload(anonymous_placeholder_group_payload())
            .expect("create payload should apply");
        let original = fs::read_to_string(&path).expect("test dynsec config should be readable");
        replace_dynsec_file_with_directory(&path);

        let disable_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#,
            )
            .expect("disable payload should apply despite persist failure");
        assert!(disable_targets.persist_warning.is_some());

        restore_dynsec_file(&path, &original);
        let retry_targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"private"}]}"#,
            )
            .expect("delete payload should durably preserve disabled placeholder");
        assert!(retry_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );
        assert_persisted_disabled_placeholder_client(&path, "ghost");

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "private/announce",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn remove_group_client_prunes_persisted_placeholder_and_restores_anonymous_fallback_after_reload()
     {
        let path = write_test_dynsec_anonymous_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        policy
            .apply_control_payload(anonymous_placeholder_group_payload())
            .expect("create payload should apply");
        policy
            .apply_control_payload(
                br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#,
            )
            .expect("disable payload should apply");
        policy
            .apply_control_payload(
                br#"{"commands":[{"command":"enableClient","username":"ghost"}]}"#,
            )
            .expect("enable payload should apply");
        policy
            .apply_control_payload(
                br#"{"commands":[{"command":"removeGroupClient","groupname":"private","username":"ghost"}]}"#,
            )
            .expect("remove payload should apply");

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let clients = root["clients"]
            .as_array()
            .expect("clients should be an array");
        assert!(
            clients
                .iter()
                .all(|client| client["username"].as_str() != Some("ghost"))
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "public/announce",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn default_docker_dynsec_fixture_keeps_dynsec_client_1_pinned_to_client_1() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docker/dynamic-security.json");
        let raw = fs::read_to_string(&path).expect("docker dynsec fixture should be readable");
        let root: Value = serde_json::from_str(&raw).expect("docker dynsec fixture should parse");
        let clients = root["clients"]
            .as_array()
            .expect("clients should be an array");
        let dynsec_client = clients
            .iter()
            .find(|client| client["username"].as_str() == Some("dynsec_client_1"))
            .expect("dynsec_client_1 should exist in the default docker fixture");
        assert_eq!(dynsec_client["clientid"].as_str(), Some("client_1"));
    }

    #[test]
    fn delete_group_prunes_persisted_placeholder_and_restores_anonymous_fallback_after_reload() {
        let path = write_test_dynsec_anonymous_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        policy
            .apply_control_payload(anonymous_placeholder_group_payload())
            .expect("create payload should apply");
        policy
            .apply_control_payload(
                br#"{"commands":[{"command":"disableClient","username":"ghost"}]}"#,
            )
            .expect("disable payload should apply");
        policy
            .apply_control_payload(
                br#"{"commands":[{"command":"enableClient","username":"ghost"}]}"#,
            )
            .expect("enable payload should apply");
        policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"private"}]}"#,
            )
            .expect("delete payload should apply");

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let clients = root["clients"]
            .as_array()
            .expect("clients should be an array");
        assert!(
            clients
                .iter()
                .all(|client| client["username"].as_str() != Some("ghost"))
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("ghost"),
                    Some("ghost_client"),
                    "public/announce",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pending_delete_anonymous_group_clears_anonymous_binding_on_reload() {
        let path = write_test_dynsec_anonymous_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"anonymous"}]}"#,
            )
            .expect("persist failure should still apply runtime mutations");
        assert!(targets.persist_warning.is_some());
        assert!(
            !policy
                .check(None, None, "public/announce", ACL_READ)
                .expect("anonymous policy check should succeed")
        );

        restore_dynsec_file(&path, &original);
        policy
            .reload_if_needed(true)
            .expect("forced reload should replay pending anonymous delete");

        let state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        assert!(!state.groups.contains_key("anonymous"));
        assert_eq!(state.anonymous_group, None);
        drop(state);

        assert!(
            !policy
                .check(None, None, "public/announce", ACL_READ)
                .expect("anonymous policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pending_create_mutations_merge_into_stub_objects_on_reload_and_retry() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        let original = replace_dynsec_file_with_directory(&path);

        let first_targets = policy
            .apply_control_payload(group_grant_payload())
            .expect("persist failure should still apply runtime mutations");
        assert!(first_targets.persist_warning.is_some());

        restore_dynsec_file(&path, &original);
        set_stub_group_grant(&path, "fanout", "fanout_reader");

        policy
            .reload_if_needed(true)
            .expect("forced reload should merge pending create payloads into stub objects");
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        let role = state
            .roles
            .get("fanout_reader")
            .expect("fanout_reader role should exist");
        assert_eq!(
            role.match_acl(AccessKind::PublishReceive, "fanout/broadcast"),
            Some(true)
        );
        let group = state
            .groups
            .get("fanout")
            .expect("fanout group should exist");
        assert!(group.roles.iter().any(|role| role.name == "fanout_reader"));
        drop(state);

        let retry_targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"listRoles"}]}"#)
            .expect("later control command should retry pending persistence");
        assert!(retry_targets.persist_warning.is_none());
        assert!(
            policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed")
                .is_empty()
        );

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let role = root["roles"]
            .as_array()
            .and_then(|roles| {
                roles
                    .iter()
                    .find(|role| role["rolename"].as_str() == Some("fanout_reader"))
            })
            .expect("fanout_reader role should be persisted");
        let role_acls = role["acls"]
            .as_array()
            .expect("role acls should be an array");
        assert!(role_acls.iter().any(|acl| {
            acl["acltype"].as_str() == Some("publishClientReceive")
                && acl["topic"].as_str() == Some("fanout/broadcast")
                && acl["allow"].as_bool() == Some(true)
        }));
        let group = root["groups"]
            .as_array()
            .and_then(|groups| {
                groups
                    .iter()
                    .find(|group| group["groupname"].as_str() == Some("fanout"))
            })
            .expect("fanout group should be persisted");
        let group_roles = group["roles"]
            .as_array()
            .expect("group roles should be an array");
        assert!(group_roles.iter().any(|role| {
            role["rolename"].as_str() == Some("fanout_reader")
                && role["priority"].as_i64() == Some(5)
        }));

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn from_config_keeps_highest_priority_for_duplicate_group_memberships() {
        let path = write_test_dynsec_conflicting_membership_priority_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        let membership = state
            .clients
            .get("test_user")
            .and_then(|client| client.groups.iter().find(|group| group.name == "high_deny"))
            .expect("client should keep duplicated high_deny membership");
        assert_eq!(membership.priority, 10);
        drop(state);

        policy
            .reload_if_needed(true)
            .expect("forced reload should preserve max-priority merge semantics");
        let reloaded_state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        let reloaded_membership = reloaded_state
            .clients
            .get("test_user")
            .and_then(|client| client.groups.iter().find(|group| group.name == "high_deny"))
            .expect("client should keep duplicated high_deny membership after reload");
        assert_eq!(reloaded_membership.priority, 10);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn reload_keeps_acl_changes_for_pending_created_roles() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        {
            let mut pending = policy
                .pending_persist_mutations
                .lock()
                .expect("pending persist lock should succeed");
            pending.extend([
                PersistMutation::CreateRole {
                    rolename: "ephemeral_reader".to_string(),
                    acls: Vec::new(),
                },
                PersistMutation::CreateGroup {
                    groupname: "ephemeral".to_string(),
                    roles: vec![RoleRef {
                        rolename: "ephemeral_reader".to_string(),
                        priority: Some(5),
                    }],
                },
                PersistMutation::AddGroupClient {
                    groupname: "ephemeral".to_string(),
                    username: "test_user".to_string(),
                    priority: 7,
                },
            ]);
        }
        {
            let mut overrides = policy
                .runtime_role_acl_overrides
                .lock()
                .expect("runtime role-acl lock should succeed");
            overrides.insert(
                RoleAclKey::new(
                    "ephemeral_reader",
                    AclType::PublishClientReceive,
                    "ephemeral/broadcast",
                ),
                RuntimeRoleAclOverride::Add {
                    priority: 1,
                    allow: true,
                },
            );
        }

        policy
            .reload_if_needed(true)
            .expect("forced reload should preserve ACL changes on pending-created roles");
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "ephemeral/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let reloaded = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("reloaded policy must load");
        assert!(
            !reloaded
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "ephemeral/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_group_uses_current_file_state_within_reload_interval() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        add_external_group_grant(
            &path,
            "external_fanout",
            "external_reader",
            "external/broadcast",
        );

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"external_fanout"}]}"#,
            )
            .expect("delete payload should apply");

        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        assert_eq!(targets.notify_events[0].command, "deleteGroup");
        assert_eq!(
            targets.notify_events[0].usernames,
            vec!["test_user".to_string()]
        );
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "external/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let raw = fs::read_to_string(&path).expect("dynsec config should be readable");
        let root: Value = serde_json::from_str(&raw).expect("dynsec config should parse");
        let groups = root["groups"]
            .as_array()
            .expect("groups should be an array");
        assert!(
            groups
                .iter()
                .all(|group| group["groupname"].as_str() != Some("external_fanout"))
        );
        let clients = root["clients"]
            .as_array()
            .expect("clients should be an array");
        let client = clients
            .iter()
            .find(|entry| entry["username"].as_str() == Some("test_user"))
            .expect("test_user client should exist");
        let memberships = client["groups"]
            .as_array()
            .expect("client groups should be an array");
        assert!(
            memberships
                .iter()
                .all(|entry| entry["groupname"].as_str() != Some("external_fanout"))
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_create_group_uses_current_file_state_within_reload_interval() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(60))
            .expect("policy must load");
        add_external_group_grant(
            &path,
            "external_fanout",
            "external_reader",
            "external/broadcast",
        );

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"createGroup","groupname":"external_fanout","roles":[]}]}"#,
            )
            .expect("create payload should apply");

        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "external/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );

        let state = policy
            .state
            .read()
            .expect("dynsec state lock should succeed");
        let group = state
            .groups
            .get("external_fanout")
            .expect("external_fanout group should exist");
        assert_eq!(group.roles.len(), 1);
        assert_eq!(group.roles[0].name, "external_reader");
        drop(state);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_group_notifies_client_side_only_members() {
        let path = write_test_dynsec_client_side_group_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#,
            )
            .expect("delete payload should apply");

        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        let event = &targets.notify_events[0];
        assert_eq!(event.command, "deleteGroup");
        assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
        assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
        assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
        assert_eq!(event.usernames, vec!["test_user".to_string()]);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_remove_role_acl_emits_notify_event() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");

        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        let event = &targets.notify_events[0];
        assert_eq!(event.command, "removeRoleACL");
        assert_eq!(event.rolename.as_deref(), Some("fanout_reader"));
        assert_eq!(event.acltype.as_deref(), Some("publishClientReceive"));
        assert_eq!(event.topic.as_deref(), Some("fanout/broadcast"));
        assert_eq!(event.usernames, vec!["test_user".to_string()]);

        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_add_deny_role_acl_emits_notify_event() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast","priority":10,"allow":false}]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");

        assert!(targets.kick_client_ids.is_empty());
        assert!(targets.kick_usernames.is_empty());
        assert_eq!(targets.notify_events.len(), 1);
        let event = &targets.notify_events[0];
        assert_eq!(event.command, "addRoleACL");
        assert_eq!(event.usernames, vec!["test_user".to_string()]);

        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_role_skips_notify_when_access_remains_allowed() {
        let path = write_test_dynsec_overlap_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteRole","rolename":"fanout_reader"}]}"#,
            )
            .expect("delete payload should apply");

        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_delete_group_skips_notify_when_access_remains_allowed() {
        let path = write_test_dynsec_overlap_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"deleteGroup","groupname":"fanout"}]}"#,
            )
            .expect("delete payload should apply");

        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_remove_group_client_skips_notify_when_access_remains_allowed() {
        let path = write_test_dynsec_overlap_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let targets = policy
            .apply_control_payload(
                br#"{"commands":[{"command":"removeGroupClient","groupname":"fanout","username":"test_user"}]}"#,
            )
            .expect("remove payload should apply");

        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_remove_role_acl_skips_notify_when_access_remains_allowed() {
        let path = write_test_dynsec_overlap_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"}]}"#)
            .expect("control payload should apply");

        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_add_deny_role_acl_skips_notify_when_access_remains_allowed() {
        let path = write_test_dynsec_overlap_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let targets = policy
            .apply_control_payload(br#"{"commands":[{"command":"addRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast","priority":10,"allow":false}]}"#)
            .expect("control payload should apply");

        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_group_churn_same_payload_skips_notify_when_access_never_changes() {
        let path = write_test_dynsec_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let payload = br#"{"commands":[
            {"command":"createRole","rolename":"fanout_reader","acls":[{"acltype":"publishClientReceive","topic":"fanout/broadcast","priority":0,"allow":true}]},
            {"command":"createGroup","groupname":"fanout","roles":[{"rolename":"fanout_reader","priority":0}]},
            {"command":"addGroupClient","groupname":"fanout","username":"test_user","priority":0},
            {"command":"removeGroupClient","groupname":"fanout","username":"test_user"},
            {"command":"deleteGroup","groupname":"fanout"},
            {"command":"deleteRole","rolename":"fanout_reader"}
        ]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");

        assert!(targets.notify_events.is_empty());
        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn apply_control_payload_remove_role_acl_then_restore_same_payload_skips_notify() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let payload = br#"{"commands":[
            {"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"},
            {"command":"addRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast","priority":0,"allow":true}
        ]}"#;
        let targets = policy
            .apply_control_payload(payload)
            .expect("control payload should apply");

        assert!(targets.notify_events.is_empty());
        assert!(
            policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn remove_role_acl_overlay_survives_stale_file_reload() {
        let path = write_test_dynsec_notify_config();
        let policy = DynamicSecurityPolicy::new(path.clone(), Duration::from_secs(0))
            .expect("policy must load");

        let payload = br#"{"commands":[{"command":"removeRoleACL","rolename":"fanout_reader","acltype":"publishClientReceive","topic":"fanout/broadcast"}]}"#;
        policy
            .apply_control_payload(payload)
            .expect("control payload should apply");

        // Simulate stale file state that still contains the removed ACL.
        restore_fanout_reader_publish_receive_acl(&path);

        assert!(
            !policy
                .check(
                    Some("test_user"),
                    Some("test_client"),
                    "fanout/broadcast",
                    ACL_READ
                )
                .expect("policy check should succeed")
        );
        let _ = fs::remove_file(path);
    }
}
