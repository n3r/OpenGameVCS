use ogvcs_identity_policy_audit_postgres::{MigrationPhase, MIGRATIONS};
use sha2::{Digest, Sha256};

const V1_EXPAND: &str = include_str!("../../../migrations/identity-policy-audit/000001_expand.sql");
const MANIFEST: &str = include_str!("../../../migrations/identity-policy-audit/manifest.json");

#[test]
fn immutable_predecessors_are_frozen_and_aggregate_v3_is_append_only() {
    let v1_sha = format!("{:x}", Sha256::digest(V1_EXPAND.as_bytes()));
    assert_eq!(
        v1_sha,
        "f31def32f2dc2a5da085187e345fa91ca0defe1035426c17fdeba719bd1df583"
    );
    assert_eq!(MIGRATIONS.len(), 9);
    assert_eq!(MIGRATIONS[0].version, 1);
    assert_eq!(MIGRATIONS[0].phase, MigrationPhase::Expand);
    assert_eq!(MIGRATIONS[0].checksum_sha256, v1_sha);
    for migration in MIGRATIONS {
        assert_eq!(
            format!("{:x}", Sha256::digest(migration.sql.as_bytes())),
            migration.checksum_sha256,
            "migration {} {} digest drifted",
            migration.version,
            migration.phase.as_str()
        );
    }
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
    let entries = manifest["entries"].as_array().unwrap();
    assert_eq!(entries.len(), MIGRATIONS.len());
    for (migration, entry) in MIGRATIONS.iter().zip(entries) {
        assert_eq!(entry["version"].as_u64(), Some(migration.version));
        assert_eq!(entry["phase"].as_str(), Some(migration.phase.as_str()));
        assert_eq!(entry["sha256"].as_str(), Some(migration.checksum_sha256));
        assert_eq!(entry["restartable"].as_bool(), Some(migration.restartable));
        assert_eq!(
            entry["minimumApplicationVersion"].as_str(),
            Some(migration.minimum_application_version)
        );
        assert_eq!(
            entry["maximumApplicationVersion"].as_str(),
            Some(migration.maximum_application_version)
        );
        assert_eq!(
            entry["requiresCompatibilityFence"]
                .as_bool()
                .unwrap_or(false),
            migration.requires_compatibility_fence
        );
    }
    assert!(MIGRATIONS[..3]
        .iter()
        .all(|migration| migration.version == 1));
    assert!(MIGRATIONS[3..6]
        .iter()
        .all(|migration| migration.version == 2));
    assert!(MIGRATIONS[6..]
        .iter()
        .all(|migration| migration.version == 3));
    assert!(MIGRATIONS[3]
        .sql
        .contains("transaction_decision_commitments_commitment_id_opaque_v2"));
    assert!(MIGRATIONS[5]
        .sql
        .contains("DROP CONSTRAINT transaction_decision_commitments_commitment_id_check"));
    assert!(MIGRATIONS[5].requires_compatibility_fence);
    assert!(MIGRATIONS[6]
        .sql
        .contains("CREATE TABLE ogvcs_identity.aggregate_plans"));
    assert!(MIGRATIONS[6]
        .sql
        .contains("CREATE TABLE ogvcs_identity.repository_contract_roots"));
    assert!(MIGRATIONS[6]
        .sql
        .contains("CHECK (item_count BETWEEN 0 AND 100000)"));
    assert!(MIGRATIONS[6]
        .sql
        .contains("GENERATED ALWAYS AS (authority_epoch) STORED"));
    assert!(MIGRATIONS[6]
        .sql
        .contains("resource_digest_projection_digest bytea"));
    assert!(MIGRATIONS[6]
        .sql
        .contains("UNIQUE (plan_id, consumption_id, operation_digest)"));
    assert!(MIGRATIONS[6]
        .sql
        .contains("metadata_tenant_id text NOT NULL"));
    assert!(MIGRATIONS[6]
        .sql
        .contains("settings_generation, settings_descriptor_digest, path_profile, case_mode"));
    assert!(MIGRATIONS[8]
        .sql
        .contains("aggregate_plan_consumptions_append_only"));
    assert!(MIGRATIONS[8]
        .sql
        .contains("guard_compiled_projection_insert"));
    assert!(MIGRATIONS[8]
        .sql
        .contains("guard_aggregate_plan_fact_insert"));
    assert!(MIGRATIONS[8].sql.contains("guard_authority_promotion"));
    assert!(MIGRATIONS[8].requires_compatibility_fence);
}
