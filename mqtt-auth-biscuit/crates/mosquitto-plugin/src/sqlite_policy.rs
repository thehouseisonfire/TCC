use rusqlite::{Connection, params};

const ACL_READ: i32 = 0x01;
const ACL_WRITE: i32 = 0x02;
const ACL_SUBSCRIBE: i32 = 0x04;
const ACL_CONTROL: i32 = 0x08;

pub struct SqlitePolicy {
    conn: Connection,
}

impl SqlitePolicy {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("sqlite open failed: {e}"))?;
        let policy = Self { conn };
        policy.init_schema()?;
        Ok(policy)
    }

    fn init_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE IF NOT EXISTS users(
                    client_id TEXT PRIMARY KEY
                 );
                 CREATE TABLE IF NOT EXISTS roles(
                    role_name TEXT PRIMARY KEY
                 );
                 CREATE TABLE IF NOT EXISTS user_roles(
                    client_id TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 100,
                    PRIMARY KEY(client_id, role_name),
                    FOREIGN KEY(client_id) REFERENCES users(client_id) ON DELETE CASCADE,
                    FOREIGN KEY(role_name) REFERENCES roles(role_name) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS role_acls(
                    role_name TEXT NOT NULL,
                    topic_filter TEXT NOT NULL,
                    access INTEGER NOT NULL,
                    PRIMARY KEY(role_name, topic_filter, access),
                    FOREIGN KEY(role_name) REFERENCES roles(role_name) ON DELETE CASCADE
                 );
                 CREATE TABLE IF NOT EXISTS role_deny_acls(
                    role_name TEXT NOT NULL,
                    topic_filter TEXT NOT NULL,
                    access INTEGER NOT NULL,
                    PRIMARY KEY(role_name, topic_filter, access),
                    FOREIGN KEY(role_name) REFERENCES roles(role_name) ON DELETE CASCADE
                 );
                 CREATE INDEX IF NOT EXISTS idx_user_roles_client ON user_roles(client_id);
                 CREATE INDEX IF NOT EXISTS idx_role_acls_lookup ON role_acls(role_name, access);
                 CREATE INDEX IF NOT EXISTS idx_role_deny_acls_lookup ON role_deny_acls(role_name, access);
                 CREATE TABLE IF NOT EXISTS acl(
                    client_id TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    access INTEGER NOT NULL,
                    PRIMARY KEY(client_id, topic, access)
                 );",
            )
            .map_err(|e| format!("sqlite schema init failed: {e}"))?;
        self.ensure_user_roles_priority_column()?;
        Ok(())
    }

    fn ensure_user_roles_priority_column(&self) -> Result<(), String> {
        let mut stmt = self
            .conn
            .prepare("PRAGMA table_info(user_roles)")
            .map_err(|e| format!("sqlite user_roles introspection prepare failed: {e}"))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| format!("sqlite user_roles introspection query failed: {e}"))?;

        let mut has_priority = false;
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("sqlite user_roles introspection row failed: {e}"))?
        {
            let name: String = row
                .get(1)
                .map_err(|e| format!("sqlite user_roles column decode failed: {e}"))?;
            if name == "priority" {
                has_priority = true;
                break;
            }
        }

        if !has_priority {
            self.conn
                .execute(
                    "ALTER TABLE user_roles ADD COLUMN priority INTEGER NOT NULL DEFAULT 100",
                    [],
                )
                .map_err(|e| format!("sqlite add user_roles.priority failed: {e}"))?;
        }
        Ok(())
    }

    pub fn check(&self, client_id: &str, topic: &str, access: i32) -> Result<bool, String> {
        if let Some(allowed) = self.check_rbac(client_id, topic, access)? {
            return Ok(allowed);
        }

        self.check_legacy_acl(client_id, topic, access)
    }

    fn check_rbac(
        &self,
        client_id: &str,
        topic: &str,
        access: i32,
    ) -> Result<Option<bool>, String> {
        let has_roles = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM users u
                    JOIN user_roles ur ON ur.client_id = u.client_id
                    WHERE u.client_id = ?1
                    LIMIT 1
                )",
                params![client_id],
                |row| row.get::<_, i64>(0),
            )
            .map(|exists| exists != 0)
            .map_err(|e| format!("sqlite role presence query failed: {e}"))?;

        if !has_roles {
            return Ok(None);
        }

        let mut stmt = self
            .conn
            .prepare(
                "SELECT 'allow' AS effect, ra.topic_filter, ur.priority
                 FROM users u
                 JOIN user_roles ur ON ur.client_id = u.client_id
                 JOIN role_acls ra ON ra.role_name = ur.role_name
                 WHERE u.client_id = ?1
                   AND ra.access = ?2
                 UNION ALL
                 SELECT 'deny' AS effect, rd.topic_filter, ur.priority
                 FROM users u
                 JOIN user_roles ur ON ur.client_id = u.client_id
                 JOIN role_deny_acls rd ON rd.role_name = ur.role_name
                 WHERE u.client_id = ?1
                   AND rd.access = ?2",
            )
            .map_err(|e| format!("sqlite rbac prepare failed: {e}"))?;

        let mut rows = stmt
            .query(params![client_id, access])
            .map_err(|e| format!("sqlite rbac query failed: {e}"))?;

        let mut best_priority: Option<i32> = None;
        let mut tier_has_allow = false;
        let mut tier_has_deny = false;

        while let Some(row) = rows
            .next()
            .map_err(|e| format!("sqlite rbac row failed: {e}"))?
        {
            let effect: String = row
                .get(0)
                .map_err(|e| format!("sqlite rbac effect decode failed: {e}"))?;
            let topic_filter: String = row
                .get(1)
                .map_err(|e| format!("sqlite rbac filter decode failed: {e}"))?;
            if !mqtt_topic_matches(&topic_filter, topic) {
                continue;
            }
            let priority: i32 = row
                .get(2)
                .map_err(|e| format!("sqlite rbac priority decode failed: {e}"))?;

            if best_priority.is_none_or(|best| priority < best) {
                best_priority = Some(priority);
                tier_has_allow = false;
                tier_has_deny = false;
            }
            if best_priority == Some(priority) {
                if effect == "deny" {
                    tier_has_deny = true;
                } else {
                    tier_has_allow = true;
                }
            }
        }

        if best_priority.is_none() {
            return Ok(Some(false));
        }
        if tier_has_deny {
            return Ok(Some(false));
        }
        if tier_has_allow {
            return Ok(Some(true));
        }
        Ok(Some(false))
    }

    fn check_legacy_acl(&self, client_id: &str, topic: &str, access: i32) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT topic FROM acl WHERE client_id = ?1 AND access = ?2")
            .map_err(|e| format!("sqlite legacy prepare failed: {e}"))?;

        let mut rows = stmt
            .query(params![client_id, access])
            .map_err(|e| format!("sqlite legacy query failed: {e}"))?;

        while let Some(row) = rows
            .next()
            .map_err(|e| format!("sqlite legacy row failed: {e}"))?
        {
            let topic_filter: String = row
                .get(0)
                .map_err(|e| format!("sqlite legacy filter decode failed: {e}"))?;
            if mqtt_topic_matches(&topic_filter, topic) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn seed_demo_rules(&self) -> Result<(), String> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE TRANSACTION;")
            .map_err(|e| format!("sqlite seed tx begin failed: {e}"))?;

        if let Err(err) = (|| -> Result<(), String> {
            for role in [
                "data_reader_all",
                "data_reader_public",
                "data_writer",
                "data_private_deny",
                "ops_admin",
                "ops_observer",
            ] {
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO roles(role_name) VALUES(?1)",
                        params![role],
                    )
                    .map_err(|e| format!("sqlite seed roles failed: {e}"))?;
            }

            for user in [
                "client_1",
                "client_2",
                "client_3",
                "ops_admin",
                "ops_observer",
            ] {
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO users(client_id) VALUES(?1)",
                        params![user],
                    )
                    .map_err(|e| format!("sqlite seed users failed: {e}"))?;
            }

            for (client_id, role_name, priority) in [
                ("client_1", "data_writer", 30),
                ("client_1", "data_reader_all", 80),
                ("client_2", "data_reader_all", 100),
                ("client_2", "data_private_deny", 100),
                ("client_3", "data_reader_all", 40),
                ("client_3", "data_private_deny", 120),
                ("client_3", "data_reader_public", 70),
                ("ops_admin", "ops_admin", 10),
                ("ops_observer", "ops_observer", 10),
            ] {
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO user_roles(client_id, role_name, priority) VALUES(?1, ?2, ?3)",
                        params![client_id, role_name, priority],
                    )
                    .map_err(|e| format!("sqlite seed user_roles failed: {e}"))?;
            }

            for (role_name, topic_filter, access) in [
                ("data_reader_all", "sensors/#", ACL_SUBSCRIBE),
                ("data_reader_all", "sensors/#", ACL_READ),
                ("data_reader_public", "sensors/public/#", ACL_SUBSCRIBE),
                ("data_reader_public", "sensors/public/#", ACL_READ),
                ("data_writer", "sensors/#", ACL_WRITE),
                ("ops_admin", "$CONTROL/#", ACL_CONTROL),
                ("ops_admin", "system/notifications/#", ACL_SUBSCRIBE),
                ("ops_admin", "system/notifications/#", ACL_READ),
                ("ops_admin", "system/notifications/#", ACL_WRITE),
                ("ops_observer", "system/notifications/#", ACL_SUBSCRIBE),
                ("ops_observer", "system/notifications/#", ACL_READ),
            ] {
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO role_acls(role_name, topic_filter, access) VALUES(?1, ?2, ?3)",
                        params![role_name, topic_filter, access],
                    )
                    .map_err(|e| format!("sqlite seed role_acls failed: {e}"))?;
            }

            for (role_name, topic_filter, access) in [
                ("data_private_deny", "sensors/private/#", ACL_SUBSCRIBE),
                ("data_private_deny", "sensors/private/#", ACL_READ),
                ("data_private_deny", "sensors/private/#", ACL_WRITE),
                ("ops_observer", "$CONTROL/#", ACL_CONTROL),
                ("ops_observer", "system/notifications/#", ACL_WRITE),
            ] {
                self.conn
                    .execute(
                        "INSERT OR IGNORE INTO role_deny_acls(role_name, topic_filter, access) VALUES(?1, ?2, ?3)",
                        params![role_name, topic_filter, access],
                    )
                    .map_err(|e| format!("sqlite seed role_deny_acls failed: {e}"))?;
            }
            Ok(())
        })() {
            let _ = self.conn.execute_batch("ROLLBACK;");
            return Err(err);
        }

        self.conn
            .execute_batch("COMMIT;")
            .map_err(|e| format!("sqlite seed tx commit failed: {e}"))?;
        Ok(())
    }
}

fn is_valid_filter(filter: &str) -> bool {
    let mut saw_hash = false;
    let parts: Vec<&str> = filter.split('/').collect();
    for (idx, part) in parts.iter().enumerate() {
        if part.contains('#') {
            if *part != "#" || saw_hash || idx != parts.len() - 1 {
                return false;
            }
            saw_hash = true;
            continue;
        }
        if part.contains('+') && *part != "+" {
            return false;
        }
    }
    true
}

fn mqtt_topic_matches(filter: &str, topic: &str) -> bool {
    if !is_valid_filter(filter) {
        return false;
    }
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
    use super::{ACL_CONTROL, ACL_READ, ACL_SUBSCRIBE, ACL_WRITE, SqlitePolicy};
    use rusqlite::params;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SQLITE_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_sqlite_path(test_name: &str) -> String {
        let unique = SQLITE_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("mosq-sqlite-{test_name}-{unique}.db"))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn seed_demo_rules_enables_rbac_checks() {
        let path = temp_sqlite_path("seed-demo");
        let policy = SqlitePolicy::open(&path).expect("sqlite should open");
        policy
            .seed_demo_rules()
            .expect("demo rules should seed successfully");

        assert!(
            policy
                .check("client_1", "sensors/client_1/temp", ACL_WRITE)
                .expect("rbac check should succeed")
        );
        assert!(
            policy
                .check("client_2", "sensors/client_2/temp", ACL_SUBSCRIBE)
                .expect("rbac check should succeed")
        );
        assert!(
            !policy
                .check("client_2", "alerts/global", ACL_READ)
                .expect("rbac check should succeed")
        );
        assert!(
            !policy
                .check("client_2", "sensors/private/device-2", ACL_READ)
                .expect("same-tier deny should override allow")
        );
        assert!(
            policy
                .check("client_3", "sensors/private/device-3", ACL_READ)
                .expect("higher-priority allow should override lower-priority deny")
        );
        assert!(
            policy
                .check("ops_admin", "$CONTROL/dynamic-security/v1", ACL_CONTROL)
                .expect("ops admin should have control access")
        );
        assert!(
            !policy
                .check("ops_observer", "$CONTROL/dynamic-security/v1", ACL_CONTROL)
                .expect("ops observer should be denied control access")
        );
        assert!(
            !policy
                .check("ops_observer", "system/notifications/acl-change", ACL_WRITE)
                .expect("ops observer should be denied notification writes")
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn deny_overrides_allow_with_same_priority() {
        let path = temp_sqlite_path("deny-overrides-allow");
        let policy = SqlitePolicy::open(&path).expect("sqlite should open");

        policy
            .conn
            .execute(
                "INSERT INTO users(client_id) VALUES(?1)",
                params!["client_x"],
            )
            .expect("user insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO roles(role_name) VALUES(?1)",
                params!["allow_role"],
            )
            .expect("role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO roles(role_name) VALUES(?1)",
                params!["deny_role"],
            )
            .expect("role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO user_roles(client_id, role_name, priority) VALUES(?1, ?2, ?3)",
                params!["client_x", "allow_role", 100],
            )
            .expect("user role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO user_roles(client_id, role_name, priority) VALUES(?1, ?2, ?3)",
                params!["client_x", "deny_role", 100],
            )
            .expect("user role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO role_acls(role_name, topic_filter, access) VALUES(?1, ?2, ?3)",
                params!["allow_role", "sensors/private/#", ACL_READ],
            )
            .expect("role allow insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO role_deny_acls(role_name, topic_filter, access) VALUES(?1, ?2, ?3)",
                params!["deny_role", "sensors/private/#", ACL_READ],
            )
            .expect("role deny insert should succeed");

        assert!(
            !policy
                .check("client_x", "sensors/private/a", ACL_READ)
                .expect("rbac check should succeed")
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn higher_priority_allow_beats_lower_priority_deny() {
        let path = temp_sqlite_path("priority-allow-beats-deny");
        let policy = SqlitePolicy::open(&path).expect("sqlite should open");

        policy
            .conn
            .execute(
                "INSERT INTO users(client_id) VALUES(?1)",
                params!["client_y"],
            )
            .expect("user insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO roles(role_name) VALUES(?1)",
                params!["allow_role"],
            )
            .expect("role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO roles(role_name) VALUES(?1)",
                params!["deny_role"],
            )
            .expect("role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO user_roles(client_id, role_name, priority) VALUES(?1, ?2, ?3)",
                params!["client_y", "allow_role", 10],
            )
            .expect("user role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO user_roles(client_id, role_name, priority) VALUES(?1, ?2, ?3)",
                params!["client_y", "deny_role", 100],
            )
            .expect("user role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO role_acls(role_name, topic_filter, access) VALUES(?1, ?2, ?3)",
                params!["allow_role", "sensors/private/#", ACL_READ],
            )
            .expect("role allow insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO role_deny_acls(role_name, topic_filter, access) VALUES(?1, ?2, ?3)",
                params!["deny_role", "sensors/private/#", ACL_READ],
            )
            .expect("role deny insert should succeed");

        assert!(
            policy
                .check("client_y", "sensors/private/a", ACL_READ)
                .expect("rbac check should succeed")
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rbac_decision_does_not_fall_back_to_legacy_acl() {
        let path = temp_sqlite_path("no-fallback");
        let policy = SqlitePolicy::open(&path).expect("sqlite should open");

        policy
            .conn
            .execute(
                "INSERT INTO users(client_id) VALUES(?1)",
                params!["client_1"],
            )
            .expect("user insert should succeed");
        policy
            .conn
            .execute("INSERT INTO roles(role_name) VALUES(?1)", params!["reader"])
            .expect("role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO user_roles(client_id, role_name) VALUES(?1, ?2)",
                params!["client_1", "reader"],
            )
            .expect("user role insert should succeed");
        policy
            .conn
            .execute(
                "INSERT INTO acl(client_id, topic, access) VALUES(?1, ?2, ?3)",
                params!["client_1", "sensors/client_1/temp", ACL_WRITE],
            )
            .expect("legacy acl insert should succeed");

        assert!(
            !policy
                .check("client_1", "sensors/client_1/temp", ACL_WRITE)
                .expect("rbac check should succeed")
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn legacy_acl_is_used_when_no_rbac_identity_exists() {
        let path = temp_sqlite_path("legacy-fallback");
        let policy = SqlitePolicy::open(&path).expect("sqlite should open");

        policy
            .conn
            .execute(
                "INSERT INTO acl(client_id, topic, access) VALUES(?1, ?2, ?3)",
                params!["legacy_client", "sensors/legacy/#", ACL_SUBSCRIBE],
            )
            .expect("legacy acl insert should succeed");

        assert!(
            policy
                .check("legacy_client", "sensors/legacy/temp", ACL_SUBSCRIBE)
                .expect("legacy acl check should succeed")
        );

        let _ = std::fs::remove_file(path);
    }
}
