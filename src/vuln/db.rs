use rusqlite::{params, Connection};
use std::path::Path;

use crate::models::vulnerability::VulnRecord;

use super::VulnError;

pub struct VulnDb {
    conn: Connection,
}

impl VulnDb {
    /// Open (or create) the vulnerability database at the given path.
    pub fn open(path: &Path) -> Result<Self, VulnError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, VulnError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<(), VulnError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                aliases TEXT,
                summary TEXT,
                severity TEXT,
                modified TEXT,
                raw_json TEXT
            );
            CREATE TABLE IF NOT EXISTS affected_packages (
                vuln_id TEXT NOT NULL,
                ecosystem TEXT,
                name TEXT NOT NULL,
                purl TEXT,
                versions TEXT,
                ranges TEXT,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
            );
            CREATE INDEX IF NOT EXISTS idx_affected_eco_name
                ON affected_packages(ecosystem, name);
            CREATE INDEX IF NOT EXISTS idx_affected_purl
                ON affected_packages(purl);
            ",
        )?;
        Ok(())
    }

    /// Upsert a batch of vulnerability records into the database.
    pub fn upsert_records(&mut self, records: &[VulnRecord]) -> Result<usize, VulnError> {
        let tx = self.conn.transaction()?;
        let mut count = 0;

        for record in records {
            let aliases_json = serde_json::to_string(&record.aliases).unwrap_or_default();
            let severity_json = serde_json::to_string(&record.severity).unwrap_or_default();
            let raw_json = serde_json::to_string(record).unwrap_or_default();

            tx.execute(
                "INSERT OR REPLACE INTO vulnerabilities (id, aliases, summary, severity, modified, raw_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    record.id,
                    aliases_json,
                    record.summary,
                    severity_json,
                    record.modified,
                    raw_json,
                ],
            )?;

            // Remove old affected_packages for this vuln, then re-insert.
            tx.execute(
                "DELETE FROM affected_packages WHERE vuln_id = ?1",
                params![record.id],
            )?;

            for affected in &record.affected {
                let versions_json = serde_json::to_string(&affected.versions).unwrap_or_default();
                let ranges_json = serde_json::to_string(&affected.ranges).unwrap_or_default();

                tx.execute(
                    "INSERT INTO affected_packages (vuln_id, ecosystem, name, purl, versions, ranges)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        record.id,
                        affected.ecosystem,
                        affected.name,
                        affected.purl,
                        versions_json,
                        ranges_json,
                    ],
                )?;
            }

            count += 1;
        }

        tx.commit()?;
        Ok(count)
    }

    /// Find vulnerability records matching a PURL string.
    pub fn find_by_purl(&self, purl: &str) -> Result<Vec<VulnRecord>, VulnError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT v.raw_json FROM vulnerabilities v
             JOIN affected_packages ap ON v.id = ap.vuln_id
             WHERE ap.purl = ?1",
        )?;

        let records = stmt
            .query_map(params![purl], |row| {
                let raw: String = row.get(0)?;
                Ok(raw)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|raw| serde_json::from_str::<VulnRecord>(&raw).ok())
            .collect();

        Ok(records)
    }

    /// Find vulnerability records matching an ecosystem + package name.
    pub fn find_by_package(
        &self,
        ecosystem: &str,
        name: &str,
    ) -> Result<Vec<VulnRecord>, VulnError> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT v.raw_json FROM vulnerabilities v
             JOIN affected_packages ap ON v.id = ap.vuln_id
             WHERE ap.ecosystem = ?1 AND ap.name = ?2",
        )?;

        let records = stmt
            .query_map(params![ecosystem, name], |row| {
                let raw: String = row.get(0)?;
                Ok(raw)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|raw| serde_json::from_str::<VulnRecord>(&raw).ok())
            .collect();

        Ok(records)
    }

    /// Return the total count of vulnerability records in the database.
    pub fn record_count(&self) -> Result<usize, VulnError> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Return the count of distinct ecosystems stored.
    pub fn ecosystem_count(&self) -> Result<usize, VulnError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT ecosystem) FROM affected_packages WHERE ecosystem IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }
}

/// Return the default database path: ~/.local/share/cra-auditflow/vuln.db
pub fn default_db_path() -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("", "", "cra-auditflow")
        .map(|dirs| dirs.data_dir().join("vuln.db"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::vulnerability::{AffectedPackage, AffectedRange, Reference, Severity};

    fn sample_record() -> VulnRecord {
        VulnRecord {
            id: "GHSA-test-0001".into(),
            aliases: vec!["CVE-2025-0001".into()],
            summary: Some("Test vulnerability".into()),
            severity: vec![Severity {
                score: Some(7.5),
                severity_type: "CVSS_V3".into(),
                vector: None,
            }],
            affected: vec![AffectedPackage {
                ecosystem: Some("npm".into()),
                name: "lodash".into(),
                purl: Some("pkg:npm/lodash".into()),
                versions: vec!["4.17.20".into()],
                ranges: vec![AffectedRange {
                    range_type: "SEMVER".into(),
                    introduced: Some("0".into()),
                    fixed: Some("4.17.21".into()),
                    last_affected: None,
                }],
            }],
            references: vec![Reference {
                ref_type: Some("ADVISORY".into()),
                url: "https://example.com/advisory".into(),
            }],
            modified: "2025-01-01T00:00:00Z".into(),
            withdrawn: None,
        }
    }

    #[test]
    fn open_in_memory() {
        let db = VulnDb::open_in_memory().unwrap();
        assert_eq!(db.record_count().unwrap(), 0);
    }

    #[test]
    fn upsert_and_find_by_purl() {
        let mut db = VulnDb::open_in_memory().unwrap();
        let records = vec![sample_record()];
        let count = db.upsert_records(&records).unwrap();
        assert_eq!(count, 1);
        assert_eq!(db.record_count().unwrap(), 1);

        let found = db.find_by_purl("pkg:npm/lodash").unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "GHSA-test-0001");
    }

    #[test]
    fn find_by_package() {
        let mut db = VulnDb::open_in_memory().unwrap();
        db.upsert_records(&[sample_record()]).unwrap();

        let found = db.find_by_package("npm", "lodash").unwrap();
        assert_eq!(found.len(), 1);

        let not_found = db.find_by_package("pypi", "lodash").unwrap();
        assert!(not_found.is_empty());
    }

    #[test]
    fn upsert_replaces_existing() {
        let mut db = VulnDb::open_in_memory().unwrap();
        let mut record = sample_record();
        db.upsert_records(&[record.clone()]).unwrap();

        record.summary = Some("Updated summary".into());
        db.upsert_records(&[record]).unwrap();

        assert_eq!(db.record_count().unwrap(), 1);
        let found = db.find_by_purl("pkg:npm/lodash").unwrap();
        assert_eq!(found[0].summary.as_deref(), Some("Updated summary"));
    }

    #[test]
    fn default_path_exists() {
        assert!(default_db_path().is_some());
    }
}
