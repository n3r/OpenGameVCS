use std::{fs, path::PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn migration_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations/repository-metadata")
}

#[test]
fn migration_manifest_is_ordered_checksummed_and_transactional() {
    let root = migration_root();
    let manifest: Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["schemaVersion"],
        "ogvcs.repository-metadata/migration-manifest/v1"
    );
    assert_eq!(manifest["database"], "postgresql-15-or-newer");
    let entries = manifest["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 36);
    let expected = [
        (1, "expand"),
        (1, "migrate"),
        (1, "contract"),
        (2, "expand"),
        (2, "migrate"),
        (2, "contract"),
        (3, "expand"),
        (3, "migrate"),
        (3, "contract"),
        (4, "expand"),
        (4, "migrate"),
        (4, "contract"),
        (5, "expand"),
        (5, "migrate"),
        (5, "contract"),
        (6, "expand"),
        (6, "migrate"),
        (6, "contract"),
        (7, "expand"),
        (7, "migrate"),
        (7, "contract"),
        (8, "expand"),
        (8, "migrate"),
        (8, "contract"),
        (9, "expand"),
        (9, "migrate"),
        (9, "contract"),
        (10, "expand"),
        (10, "migrate"),
        (10, "contract"),
        (11, "expand"),
        (11, "migrate"),
        (11, "contract"),
        (12, "expand"),
        (12, "migrate"),
        (12, "contract"),
    ];
    for (entry, (version, phase)) in entries.iter().zip(expected) {
        assert_eq!(entry["version"], version);
        assert_eq!(entry["phase"], phase);
        assert_eq!(entry["restartable"], true);
        let path = root.join(entry["path"].as_str().unwrap());
        let bytes = fs::read(path).unwrap();
        let actual = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(entry["sha256"], actual);
        let sql = String::from_utf8(bytes).unwrap();
        assert!(sql.starts_with("BEGIN;"));
        assert!(sql.ends_with("COMMIT;\n"));
    }
    assert_eq!(entries[2]["requiresCompatibilityFence"], true);
    assert_eq!(entries[5]["requiresCompatibilityFence"], true);
    assert_eq!(entries[8]["requiresCompatibilityFence"], true);
    assert_eq!(entries[11]["requiresCompatibilityFence"], true);
    assert_eq!(entries[14]["requiresCompatibilityFence"], true);
    assert_eq!(entries[17]["requiresCompatibilityFence"], true);
    assert_eq!(entries[20]["requiresCompatibilityFence"], true);
    assert_eq!(entries[23]["requiresCompatibilityFence"], true);
    assert_eq!(entries[26]["requiresCompatibilityFence"], true);
    assert_eq!(entries[29]["requiresCompatibilityFence"], true);
    assert_eq!(entries[32]["requiresCompatibilityFence"], true);
    assert_eq!(entries[35]["requiresCompatibilityFence"], true);
}

#[test]
fn version_twelve_adds_only_typed_private_manifest_availability_proof_storage() {
    let root = migration_root();
    let expand = fs::read_to_string(root.join("000012_expand.sql")).unwrap();
    for predecessor in [
        "ba12a576e2a186e75becb51773e9f9c4322c41f37e115546c31eb29776463f3f",
        "2f9e6d1c74b5bd58f42cd004db6e8547c78d9c92aa98e13cc100f17eb84f1c4d",
        "bd54d48f750ca52660d596377c5819eb66f68b8743d3286bd248c14bc03e26e3",
    ] {
        assert!(
            expand.contains(predecessor),
            "missing v11 predecessor pin {predecessor}"
        );
    }
    for evidence in [
        "content_manifest_availability_proofs",
        "content_manifest_availability_authorization_pages",
        "dependency_count BETWEEN 0 AND 4095",
        "identity_subject_digest bytea NOT NULL",
        "production_subject_digest bytea NOT NULL",
        "content_manifest_verification_receipt_digest_v12",
        "SELECT sha256(",
        "verification.receipt_digest =",
        "backend.lifecycle_contract_digest = application.lifecycle_contract_digest",
        "verification.lifecycle_contract_digest = application.lifecycle_contract_digest",
        "application.lifecycle_contract_digest = decode(",
        "db379ccdd81cfe94fec08ddda2ae5031c9ab5b7750007cf1e096cf1e4299a3bc",
        "fact.outbox_event_id = NEW.outbox_event_id",
        "lifecycle.tenant_scope_digest = NEW.tenant_scope_digest",
        "WHEN ordinal.value < NEW.authorization_page_count - 1",
        "THEN 1000",
        "statement_boundary = 'ogvcs.chunking-manifest/production-boundary@1'",
        "statement_profile = 'chunking.opengamevcs/gear-fastcdc-1m@1'",
        "statement_verifier = 'ogvcs.chunking-manifest/verifier@1'",
        "content-manifest-availability",
        "DEFERRABLE INITIALLY DEFERRED",
        "reject_lifecycle_immutable_mutation",
    ] {
        assert!(expand.contains(evidence), "missing v12 evidence {evidence}");
    }
    for forbidden in ["jsonb", "request_root", "CREATE ROUTE", "DELETE FROM"] {
        assert!(!expand
            .to_ascii_lowercase()
            .contains(&forbidden.to_ascii_lowercase()));
    }
    let migrate = fs::read_to_string(root.join("000012_migrate.sql")).unwrap();
    assert!(!migrate.contains("INSERT INTO"));
    assert!(!migrate.contains("UPDATE "));
    let contract = fs::read_to_string(root.join("000012_contract.sql")).unwrap();
    assert!(!contract.contains("DROP "));
    assert!(!contract.contains("DELETE "));
    assert!(!expand.contains("dependency_count BETWEEN 0 AND 4096"));
    assert!(!expand.contains("production_statement_digest = verification_receipt_digest"));
    for (dependencies, accepted) in [(0, true), (4_095, true), (4_096, false)] {
        assert_eq!(
            (0..=4_095).contains(&dependencies),
            accepted,
            "v12 dependency bound must leave room for the manifest in the 4,096-object set"
        );
    }
    assert_eq!(
        expand
            .matches("lifecycle_contract_digest = application.lifecycle_contract_digest")
            .count(),
        2
    );
}

#[test]
fn version_eleven_is_private_nonzero_first_consumption_submit_evidence() {
    let expand = fs::read_to_string(migration_root().join("000011_expand.sql")).unwrap();
    for predecessor in [
        "69cd3b10a60be43f8aeb2214f18df50124f143a242e1a46f72afac10067d976e",
        "1d9691bbf721c888f52981d71bf9727a76c1f2825837bc8ba2f98bb5d00150f5",
        "8526bcffb01289747a7e6de61adcedb0b81788b80738d75850635d2f441b4974",
    ] {
        assert!(
            expand.contains(predecessor),
            "missing v10 predecessor pin {predecessor}"
        );
    }
    for evidence in [
        "CREATE TABLE ogvcs_metadata.submit_intents",
        "operation_count BETWEEN 1 AND 1000",
        "operation_kind IN ('create', 'copy', 'import')",
        "CREATE TABLE ogvcs_metadata.submit_file_id_consumptions",
        "UNIQUE (repository_id, file_id)",
        "candidate_change_set_digest",
        "consumption.prior_owner_kind = operation.prior_owner_kind",
        "consumption.prior_owner_id = operation.prior_owner_id",
        "submit operation set is sealed",
        "submit FileID evidence is sealed",
        "submit_outcome_complete_v11",
        "repository metadata v11 predecessor authority mismatch",
        "DEFERRABLE INITIALLY DEFERRED",
    ] {
        assert!(expand.contains(evidence), "missing {evidence}");
    }
    assert!(!expand.contains("NEW.operation_count = 0 OR"));
    assert!(!std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/atomic-submit")
        .exists());
}

#[test]
fn version_ten_adds_the_same_transaction_aggregate_authorization_bridge() {
    let expand = fs::read_to_string(migration_root().join("000010_expand.sql")).unwrap();
    for evidence in [
        "lifecycle_aggregate_authorization_evidence",
        "identity_plan_id, consumption_id, operation_digest",
        "REFERENCES ogvcs_identity.aggregate_plan_consumptions",
        "authorization_reference",
        "authorization_snapshot",
        "resource_digest_projection_digest",
        "NEW.context_digest = evidence.operation_digest",
        "identity_plan.signer_key_reference = evidence.signer_key_reference",
        "EXTRACT(EPOCH FROM identity_plan.issued_at)",
        "EXTRACT(EPOCH FROM identity_plan.expires_at)",
        "lifecycle_expires_at",
        "aggregate_event) = 1",
        LIFECYCLE_MANIFEST_DIGEST,
        LIFECYCLE_ARTIFACT_SET_DIGEST,
        OBJECT_TRANSFER_MANIFEST_DIGEST,
        OBJECT_TRANSFER_ARTIFACT_SET_DIGEST,
        "lifecycle_aggregate_evidence_complete_v10",
        "DEFERRABLE INITIALLY DEFERRED",
        "fact_ordinal BETWEEN 0 AND 99999",
        "reject_lifecycle_immutable_mutation",
    ] {
        assert!(expand.contains(evidence), "missing {evidence}");
    }
    assert!(
        fs::read_to_string(migration_root().join("000009_expand.sql"))
            .unwrap()
            .contains("fact_ordinal BETWEEN 0 AND 1023")
    );
    assert!(
        !fs::read_to_string(migration_root().join("000010_migrate.sql"))
            .unwrap()
            .contains("UPDATE ogvcs_metadata.lifecycle_publication_plans")
    );
}

const LIFECYCLE_MANIFEST_DIGEST: &str =
    "db379ccdd81cfe94fec08ddda2ae5031c9ab5b7750007cf1e096cf1e4299a3bc";
const LIFECYCLE_ARTIFACT_SET_DIGEST: &str =
    "e2cf52e055a4e85e54ea502a38fee17536a743ff288d4bfb85b246cc43170863";
const OBJECT_TRANSFER_MANIFEST_DIGEST: &str =
    "6748334b4cbc9b155941d8382b6a67c348f0612432a9555cfa215f62681af1d3";
const OBJECT_TRANSFER_ARTIFACT_SET_DIGEST: &str =
    "8e96a6fc57aeabb9c3bd8a363b4bbb70b2bfc4832206b20c1581e92e463bec38";

#[test]
fn version_nine_reserves_repository_backed_lifecycle_evidence() {
    let expand = fs::read_to_string(migration_root().join("000009_expand.sql")).unwrap();
    for evidence in [
        "CREATE TABLE ogvcs_metadata.object_lifecycle",
        "CREATE TABLE ogvcs_metadata.lifecycle_receipts",
        "CREATE TABLE ogvcs_metadata.lifecycle_receipt_consumptions",
        "CREATE TABLE ogvcs_metadata.lifecycle_publication_plans",
        "CREATE TABLE ogvcs_metadata.lifecycle_publication_plan_chunks",
        "CREATE TABLE ogvcs_metadata.lifecycle_publication_plan_items",
        "CREATE TABLE ogvcs_metadata.lifecycle_publication_plan_seals",
        "CREATE TABLE ogvcs_metadata.lifecycle_applications",
        "CREATE TABLE ogvcs_metadata.lifecycle_transaction_facts",
        "CREATE TABLE ogvcs_metadata.lifecycle_publication_reachability",
        "CREATE TABLE ogvcs_metadata.lifecycle_deletion_fences",
        "CREATE TABLE ogvcs_metadata.lifecycle_internal_outbox",
        "health_observation_digest",
        "resource_opaque_digest",
        "structural_commitment_digest",
        "lock_and_validate_lifecycle_publication_plan",
        "FOR UPDATE OF lifecycle",
    ] {
        assert!(expand.contains(evidence), "missing {evidence}");
    }
    assert!(expand.contains("(health = 'not-applicable')"));
    assert!(expand.contains("= (health_generation IS NULL AND health_observation_digest IS NULL)"));
    assert!(!expand.contains("FROM unnest"));
    assert!(
        !fs::read_to_string(migration_root().join("000009_migrate.sql"))
            .unwrap()
            .contains("INSERT INTO ogvcs_metadata.object_lifecycle")
    );
}

#[test]
fn expand_schema_contains_every_authoritative_boundary() {
    let sql = fs::read_to_string(migration_root().join("000001_expand.sql")).unwrap();
    for table in [
        "schema_migrations",
        "repositories",
        "repository_settings",
        "metadata_objects",
        "object_edges",
        "tree_entries",
        "snapshots",
        "snapshot_parents",
        "file_path_history",
        "repository_commit_sequences",
        "references",
        "file_id_registry",
        "file_id_import_mappings",
        "idempotency_records",
        "cursor_states",
        "consistency_tokens",
        "outbox_events",
    ] {
        assert!(
            sql.contains(&format!("CREATE TABLE ogvcs_metadata.{table}")),
            "missing {table}"
        );
    }
    assert!(sql.contains("PRIMARY KEY (repository_id, file_id)"));
    assert!(sql.contains("PRIMARY KEY (repository_id, reference_kind, reference_name)"));
    assert!(sql.contains("UNIQUE (repository_id, tree_digest, basename_utf8)"));
    assert!(sql.contains("UNIQUE (repository_id, tree_digest, file_id)"));
    assert!(sql.contains("object_kind IN (2, 3, 4, 5, 6, 7, 9, 10, 11)"));
    assert!(sql.contains("FOREIGN KEY (repository_id, tree_kind, tree_algorithm, tree_digest)"));
    assert!(
        sql.contains("FOREIGN KEY (repository_id, target_kind, target_algorithm, target_digest)")
    );
    assert!(sql.contains("ADD CONSTRAINT repository_settings_descriptor_fk"));
    assert!(sql.contains("ADD CONSTRAINT file_path_history_file_id_fk"));
    assert!(sql.contains("UNIQUE (repository_id, tenant_id)"));
    assert!(sql.contains("FOREIGN KEY (repository_id, tenant_boundary)"));
    assert!(sql.contains("(entry_kind = 1 AND target_kind = 3)"));
    assert!(sql.contains("(entry_kind IN (2, 3, 4) AND target_kind = 2)"));
    assert!(sql.contains("'path'"));
    assert!(!sql.contains("CREATE TABLE ogvcs_metadata.chunks"));
    assert!(!sql.contains("object_kind IN (1,"));
}

#[test]
fn version_two_adds_enforcement_without_rewriting_version_one() {
    let root = migration_root();
    let version_one = fs::read(root.join("000001_expand.sql")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&version_one)),
        "58b53c7cd61b5f8b0e6fca4184a36379c049947a34751bedb1bd77ded674d53c"
    );
    let expand = fs::read_to_string(root.join("000002_expand.sql")).unwrap();
    let migrate = fs::read_to_string(root.join("000002_migrate.sql")).unwrap();
    let contract = fs::read_to_string(root.join("000002_contract.sql")).unwrap();
    assert!(expand.contains("CREATE TRIGGER repository_settings_immutable"));
    assert!(expand.contains("file_path_history_by_file_id_v2"));
    assert!(expand.contains("operation_ordinal"));
    assert!(contract.contains("DROP INDEX ogvcs_metadata.file_path_history_by_file_id"));
    assert!(contract.contains("RENAME TO file_path_history_by_file_id"));
    assert!(!expand.contains("published_commit_sequence"));
    assert!(!migrate.contains("published_commit_sequence"));
}

#[test]
fn version_three_adds_complete_outbox_delivery_state() {
    let root = migration_root();
    let expand = fs::read_to_string(root.join("000003_expand.sql")).unwrap();
    let contract = fs::read_to_string(root.join("000003_contract.sql")).unwrap();
    for evidence in [
        "lease_id uuid",
        "leased_by text",
        "lease_expires_at timestamptz",
        "delivery_attempts integer NOT NULL DEFAULT 0",
        "acknowledged_at timestamptz",
        "outbox_events_lease_complete",
        "outbox_events_acknowledgement_clears_lease",
        "WHERE acknowledged_at IS NULL",
    ] {
        assert!(expand.contains(evidence), "missing {evidence}");
    }
    assert!(contract.contains("DROP INDEX ogvcs_metadata.outbox_events_available"));
    assert!(contract.contains("RENAME TO outbox_events_available"));
}

#[test]
fn version_six_adds_one_use_scope_bound_file_id_receipts() {
    let expand = fs::read_to_string(migration_root().join("000006_expand.sql")).unwrap();
    assert!(expand.contains("CREATE TABLE ogvcs_metadata.file_id_allocation_receipts"));
    assert!(expand.contains("authenticated_scope_digest bytea NOT NULL"));
    assert!(expand.contains("consumed_at timestamptz NULL"));
    assert!(expand.contains("UNIQUE (repository_id, file_id)"));
}

#[test]
fn version_seven_adds_authority_scope_to_all_metadata_tokens() {
    let expand = fs::read_to_string(migration_root().join("000007_expand.sql")).unwrap();
    for table in [
        "ogvcs_metadata.consistency_tokens",
        "ogvcs_metadata.cursor_states",
        "ogvcs_metadata.repository_list_cursor_states",
    ] {
        assert!(expand.contains(&format!("ALTER TABLE {table}")));
    }
    assert_eq!(
        expand
            .matches("ADD COLUMN authenticated_scope_digest")
            .count(),
        3
    );
}

#[test]
fn version_eight_binds_and_bounds_idempotency_replay_authority() {
    let expand = fs::read_to_string(migration_root().join("000008_expand.sql")).unwrap();
    for evidence in [
        "authorization_reference text",
        "authorization_resources jsonb",
        "authorization_binding_digest bytea",
        "jsonb_array_length(authorization_resources) BETWEEN 1 AND 1000",
        "octet_length(authorization_resources::text) <= 8388608",
        "idempotency_identity_safe_result_bounded",
        "authorization_resources IS NULL\n            OR safe_result IS NULL",
        "octet_length(safe_result::text) <= 1048576",
    ] {
        assert!(expand.contains(evidence), "missing {evidence}");
    }
}

#[test]
fn version_four_adds_deterministic_bounded_ancestry() {
    let expand = fs::read_to_string(migration_root().join("000004_expand.sql")).unwrap();
    for evidence in [
        "bounded_snapshot_ancestry",
        "requested_maximum_depth > 100000",
        "requested_maximum_work > 100001",
        "ORDER BY parent.ordinal",
        "emitted < requested_maximum_work",
    ] {
        assert!(expand.contains(evidence), "missing {evidence}");
    }
}

#[test]
fn version_five_adds_project_scoped_repository_list_cursors() {
    let expand = fs::read_to_string(migration_root().join("000005_expand.sql")).unwrap();
    for evidence in [
        "repository_list_cursor_states",
        "subject_digest bytea",
        "tenant_id uuid",
        "project_id uuid",
        "position_repository_id uuid",
        "authorization_epoch bigint",
    ] {
        assert!(expand.contains(evidence), "missing {evidence}");
    }
}

#[test]
fn migration_runner_declares_lock_checksum_compatibility_and_fence_gates() {
    let source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/migration_runner.rs"),
    )
    .unwrap();
    for evidence in [
        "pg_advisory_lock",
        "MigrationChecksumMismatch",
        "MAXIMUM_SCHEMA_VERSION",
        "compatibility_fence_open",
        "transaction_body",
        "pub fn verify_schema_compatibility",
        "state != \"completed\"",
    ] {
        assert!(
            source.contains(evidence),
            "migration runner missing {evidence}"
        );
    }
    assert!(
        source.find("let existing =").unwrap()
            < source
                .find("migration.requires_compatibility_fence")
                .unwrap(),
        "closed fences must not bypass checksum validation"
    );
}

#[test]
fn rust_domain_errors_match_the_generated_language_neutral_registry() {
    let contract = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/repository-metadata/v1/registries/domain-errors.json");
    let registry: Value = serde_json::from_slice(&fs::read(contract).unwrap()).unwrap();
    let actual: Vec<(u64, &str)> = registry["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["code"].as_u64().unwrap(),
                entry["name"].as_str().unwrap(),
            )
        })
        .collect();
    let expected = [
        (1001, "REPOSITORY_SETTINGS_IMMUTABLE"),
        (1002, "OBJECT_INVALID"),
        (1003, "OBJECT_ID_COLLISION"),
        (1004, "REFERENCE_CONFLICT"),
        (1005, "FILEID_CONFLICT"),
        (1006, "HISTORY_LIMIT_REACHED"),
        (1007, "CONSISTENCY_TOKEN_UNSATISFIED"),
        (1008, "MIGRATION_INCOMPATIBLE"),
        (1009, "MIGRATION_CHECKSUM_MISMATCH"),
        (1010, "METADATA_NOT_FOUND_OR_DENIED"),
        (1011, "TRANSACTION_RETRY_EXHAUSTED"),
    ];
    assert_eq!(actual, expected);
}
