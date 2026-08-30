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
    assert_eq!(entries.len(), 9);
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
