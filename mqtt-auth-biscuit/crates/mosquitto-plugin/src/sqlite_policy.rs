use rusqlite::{params, Connection};
use std::path::Path;

pub struct SqlitePolicy {
    conn: Connection,
}

impl SqlitePolicy {
    pub fn open(path: &str) -> Result<Self, String> {
        let create_needed = !Path::new(path).exists();
        let conn = Connection::open(path).map_err(|e| format!("sqlite open failed: {e}"))?;
        let policy = Self { conn };
        policy.init_schema(create_needed)?;
        Ok(policy)
    }

    fn init_schema(&self, _create_needed: bool) -> Result<(), String> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS acl(\
                    client_id TEXT NOT NULL,\
                    topic TEXT NOT NULL,\
                    access INTEGER NOT NULL,\
                    PRIMARY KEY(client_id, topic, access)\
                )",
                [],
            )
            .map_err(|e| format!("sqlite schema init failed: {e}"))?;
        Ok(())
    }

    pub fn check(&self, client_id: &str, topic: &str, access: i32) -> Result<bool, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT 1 FROM acl WHERE client_id = ?1 AND topic = ?2 AND access = ?3 LIMIT 1",
            )
            .map_err(|e| format!("sqlite prepare failed: {e}"))?;

        let mut rows = stmt
            .query(params![client_id, topic, access])
            .map_err(|e| format!("sqlite query failed: {e}"))?;

        Ok(rows
            .next()
            .map_err(|e| format!("sqlite row failed: {e}"))?
            .is_some())
    }

    pub fn seed_demo_rules(&self) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO acl(client_id, topic, access) VALUES(?1, ?2, ?3)",
                params!["client_1", "sensors/client_1/temp", 2],
            )
            .map_err(|e| format!("sqlite seed failed: {e}"))?;
        Ok(())
    }
}
