use ogvcs_identity_policy_audit_postgres::{MigrationPhase, MIGRATIONS};
use sha2::{Digest, Sha256};

const V1_EXPAND: &str = include_str!("../../../migrations/identity-policy-audit/000001_expand.sql");

#[test]
fn immutable_v1_is_frozen_and_postgres_regex_repair_is_additive_v2() {
    let v1_sha = format!("{:x}", Sha256::digest(V1_EXPAND.as_bytes()));
    assert_eq!(
        v1_sha,
        "f31def32f2dc2a5da085187e345fa91ca0defe1035426c17fdeba719bd1df583"
    );
    assert_eq!(MIGRATIONS.len(), 6);
    assert_eq!(MIGRATIONS[0].version, 1);
    assert_eq!(MIGRATIONS[0].phase, MigrationPhase::Expand);
    assert_eq!(MIGRATIONS[0].checksum_sha256, v1_sha);
    assert!(MIGRATIONS[..3]
        .iter()
        .all(|migration| migration.version == 1));
    assert!(MIGRATIONS[3..]
        .iter()
        .all(|migration| migration.version == 2));
    assert!(MIGRATIONS[3]
        .sql
        .contains("transaction_decision_commitments_commitment_id_opaque_v2"));
    assert!(MIGRATIONS[5]
        .sql
        .contains("DROP CONSTRAINT transaction_decision_commitments_commitment_id_check"));
    assert!(MIGRATIONS[5].requires_compatibility_fence);
}
