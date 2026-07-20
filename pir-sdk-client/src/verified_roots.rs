use crate::db_proof::VerifiedDatabaseRoots;
use pir_sdk::{DatabaseCatalog, DatabaseInfo, PirError, PirResult, SyncPlan};
use std::collections::HashMap;

/// Controls whether database-proof roots are advisory or mandatory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RootPolicy {
    /// Preserve the legacy behavior: queries may run without installed roots.
    #[default]
    Advisory,
    /// Refuse every query whose database is not bound to a verified root.
    RequireVerified,
}

/// Session-local roots installed explicitly by the caller after verification.
#[derive(Clone, Debug, Default)]
pub(crate) struct VerifiedRootState {
    policy: RootPolicy,
    roots: HashMap<u8, VerifiedDatabaseRoots>,
    bound_catalog: Option<Vec<CatalogIdentity>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CatalogIdentity {
    db_id: u8,
    kind: String,
    height: u32,
    index_bins: u32,
    chunk_bins: u32,
    index_k: u8,
    chunk_k: u8,
    tag_seed: u64,
    dpf_n_index: u8,
    dpf_n_chunk: u8,
    has_bucket_merkle: bool,
    index_master_seed: u64,
    chunk_master_seed: u64,
    anchor_kind: u8,
    anchor_bytes: Vec<u8>,
}

impl VerifiedRootState {
    pub(crate) fn policy(&self) -> RootPolicy {
        self.policy
    }

    pub(crate) fn set_policy(&mut self, policy: RootPolicy) {
        self.policy = policy;
    }

    pub(crate) fn get(&self, db_id: u8) -> Option<&VerifiedDatabaseRoots> {
        self.roots.get(&db_id)
    }

    pub(crate) fn clear(&mut self) {
        self.roots.clear();
        self.bound_catalog = None;
    }

    pub(crate) fn install(
        &mut self,
        catalog: &DatabaseCatalog,
        roots: VerifiedDatabaseRoots,
    ) -> PirResult<()> {
        let db = catalog
            .get(roots.db_id)
            .ok_or(PirError::DatabaseNotFound(roots.db_id))?;
        ensure_roots_match_catalog(db, &roots)?;
        self.bound_catalog = Some(catalog_identity(catalog));
        self.roots.insert(roots.db_id, roots);
        Ok(())
    }

    /// Drop roots whose catalog identity rotated while keeping unaffected DBs.
    pub(crate) fn reconcile_catalog(&mut self, catalog: &DatabaseCatalog) {
        let identity = catalog_identity(catalog);
        if self
            .bound_catalog
            .as_ref()
            .is_some_and(|old| old != &identity)
        {
            self.clear();
            return;
        }
        self.roots.retain(|db_id, roots| {
            catalog
                .get(*db_id)
                .is_some_and(|db| ensure_roots_match_catalog(db, roots).is_ok())
        });
        if !self.roots.is_empty() {
            self.bound_catalog = Some(identity);
        }
    }

    pub(crate) fn require_db(&self, db_id: u8) -> PirResult<()> {
        if self.policy == RootPolicy::RequireVerified && !self.roots.contains_key(&db_id) {
            return Err(PirError::VerificationFailed(format!(
                "strict root policy: db_id {} has no installed VerifiedDatabaseRoots",
                db_id
            )));
        }
        Ok(())
    }

    pub(crate) fn require_plan(&self, plan: &SyncPlan) -> PirResult<()> {
        for step in &plan.steps {
            self.require_db(step.db_id)?;
        }
        Ok(())
    }
}

fn catalog_identity(catalog: &DatabaseCatalog) -> Vec<CatalogIdentity> {
    catalog
        .databases
        .iter()
        .map(|db| CatalogIdentity {
            db_id: db.db_id,
            kind: format!("{:?}", db.kind),
            height: db.height,
            index_bins: db.index_bins,
            chunk_bins: db.chunk_bins,
            index_k: db.index_k,
            chunk_k: db.chunk_k,
            tag_seed: db.tag_seed,
            dpf_n_index: db.dpf_n_index,
            dpf_n_chunk: db.dpf_n_chunk,
            has_bucket_merkle: db.has_bucket_merkle,
            index_master_seed: db.index_master_seed,
            chunk_master_seed: db.chunk_master_seed,
            anchor_kind: db.anchor_kind,
            anchor_bytes: db.anchor_bytes.clone(),
        })
        .collect()
}

fn ensure_roots_match_catalog(db: &DatabaseInfo, roots: &VerifiedDatabaseRoots) -> PirResult<()> {
    if roots.height != db.height || roots.from_height != db.base_height() {
        return Err(PirError::VerificationFailed(format!(
            "verified roots do not match current catalog for db_id {}: roots {}..{}, catalog {}..{}",
            db.db_id,
            roots.from_height,
            roots.height,
            db.base_height(),
            db.height
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_db_attest::BuildKind;
    use pir_sdk::DatabaseKind;

    fn db(height: u32) -> DatabaseInfo {
        DatabaseInfo {
            db_id: 7,
            kind: DatabaseKind::Full,
            name: "test".into(),
            height,
            index_bins: 1,
            chunk_bins: 1,
            index_k: 1,
            chunk_k: 1,
            tag_seed: 0,
            dpf_n_index: 1,
            dpf_n_chunk: 1,
            has_bucket_merkle: true,
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor_kind: 0,
            anchor_bytes: vec![],
        }
    }

    fn roots(height: u32) -> VerifiedDatabaseRoots {
        VerifiedDatabaseRoots {
            db_id: 7,
            build_kind: BuildKind::Snapshot,
            from_height: 0,
            from_block_hash: [0; 32],
            height,
            block_hash: [0; 32],
            muhash: [0; 32],
            bucket_super_root: [1; 32],
            onion_super_root: [2; 32],
            onion_entry_size: 3328,
            params_hash: [0; 32],
            network_magic: [0; 4],
            builder_binary_sha256: [0; 32],
            builder_git_commit: "test".into(),
        }
    }

    #[test]
    fn install_is_explicit_and_rotation_invalidates() {
        let mut state = VerifiedRootState::default();
        state.set_policy(RootPolicy::RequireVerified);
        assert!(state.require_db(7).is_err());
        state
            .install(
                &DatabaseCatalog {
                    databases: vec![db(10)],
                },
                roots(10),
            )
            .unwrap();
        assert!(state.require_db(7).is_ok());
        state.reconcile_catalog(&DatabaseCatalog {
            databases: vec![db(11)],
        });
        assert!(state.require_db(7).is_err());
    }

    #[test]
    fn query_parameter_rotation_invalidates_roots() {
        let baseline = db(10);
        let variants = [
            DatabaseInfo {
                tag_seed: 1,
                ..baseline.clone()
            },
            DatabaseInfo {
                dpf_n_index: 2,
                ..baseline.clone()
            },
            DatabaseInfo {
                dpf_n_chunk: 2,
                ..baseline.clone()
            },
            DatabaseInfo {
                has_bucket_merkle: false,
                ..baseline.clone()
            },
        ];

        for changed in variants {
            let mut state = VerifiedRootState::default();
            state.set_policy(RootPolicy::RequireVerified);
            state
                .install(
                    &DatabaseCatalog {
                        databases: vec![baseline.clone()],
                    },
                    roots(10),
                )
                .unwrap();
            state.reconcile_catalog(&DatabaseCatalog {
                databases: vec![changed],
            });
            assert!(state.require_db(7).is_err());
        }
    }
}
