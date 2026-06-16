//! Runtime-side loading for attested-builder database proof sidecars.
//!
//! This module intentionally does not verify proof semantics. It only packages
//! the small proof files into a wire bundle so clients/admin tooling can verify
//! them with `pir-db-attest`.

use crate::protocol::DatabaseProofBundle;
use std::io;
use std::path::Path;

pub fn load_database_proof_bundle(
    db_id: u8,
    proof_dir: impl AsRef<Path>,
) -> io::Result<DatabaseProofBundle> {
    let proof_dir = proof_dir.as_ref();
    Ok(DatabaseProofBundle {
        db_id,
        build_evidence: read(proof_dir, "build-evidence.bin")?,
        root_bundle_payload: read(proof_dir, "root-bundle-payload.bin")?,
        sev_snp_report: read(proof_dir, "build-evidence.sev-snp-report.bin")?,
        database_manifest_sha256: read(proof_dir, "database.manifest.sha256")?,
        all_artifacts_manifest_sha256: read(proof_dir, "all-artifacts.manifest.sha256")?,
        server_db_manifest_toml: read(proof_dir, "server-db/MANIFEST.toml")?,
    })
}

fn read(proof_dir: &Path, rel: &str) -> io::Result<Vec<u8>> {
    let path = proof_dir.join(rel);
    std::fs::read(&path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to read {}: {}", path.display(), err),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_fixture(dir: &Path) {
        std::fs::write(dir.join("build-evidence.bin"), b"evidence").unwrap();
        std::fs::write(dir.join("root-bundle-payload.bin"), b"payload").unwrap();
        std::fs::write(dir.join("build-evidence.sev-snp-report.bin"), b"report").unwrap();
        std::fs::write(dir.join("database.manifest.sha256"), b"database-sha").unwrap();
        std::fs::write(dir.join("all-artifacts.manifest.sha256"), b"all-sha").unwrap();
        std::fs::create_dir(dir.join("server-db")).unwrap();
        std::fs::write(dir.join("server-db").join("MANIFEST.toml"), b"manifest").unwrap();
    }

    #[test]
    fn load_database_proof_bundle_reads_all_sidecars() {
        let temp = TempDir::new().unwrap();
        write_fixture(temp.path());

        let bundle = load_database_proof_bundle(7, temp.path()).unwrap();

        assert_eq!(bundle.db_id, 7);
        assert_eq!(bundle.build_evidence, b"evidence");
        assert_eq!(bundle.root_bundle_payload, b"payload");
        assert_eq!(bundle.sev_snp_report, b"report");
        assert_eq!(bundle.database_manifest_sha256, b"database-sha");
        assert_eq!(bundle.all_artifacts_manifest_sha256, b"all-sha");
        assert_eq!(bundle.server_db_manifest_toml, b"manifest");
    }

    #[test]
    fn load_database_proof_bundle_reports_missing_sidecar_path() {
        let temp = TempDir::new().unwrap();
        write_fixture(temp.path());
        std::fs::remove_file(temp.path().join("root-bundle-payload.bin")).unwrap();

        let err = load_database_proof_bundle(7, temp.path()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("root-bundle-payload.bin"), "{msg}");
        assert!(
            msg.contains(temp.path().to_string_lossy().as_ref()),
            "{msg}"
        );
    }
}
