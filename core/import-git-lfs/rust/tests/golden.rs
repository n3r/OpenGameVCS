mod support;

use ogvcs_git_import_preflight::{GitObjectId, ImportLimits, InventoryCounts};
use serde_json::Value;
use support::{hex, policy, ready_fixture, run_fixture};

#[test]
fn committed_known_answer_vector_binds_identifiers_and_transcripts() {
    let vector: Value = serde_json::from_str(include_str!("golden.json")).unwrap();
    let (records, objects) = ready_fixture();
    let report = run_fixture(records, objects, &policy(), ImportLimits::default()).unwrap();
    let actual = [
        (
            "gitSha1",
            GitObjectId::from_sha1([1; 20]).unwrap().to_string(),
        ),
        (
            "gitSha256",
            GitObjectId::from_sha256([2; 32]).unwrap().to_string(),
        ),
        (
            "lfsContentSha256",
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".to_owned(),
        ),
        ("inventoryDigest", hex(&report.inventory_digest)),
        ("policyDigest", hex(&report.policy_digest)),
        ("mappingDigest", hex(&report.mapping_digest)),
        ("reportDigest", hex(&report.report_digest)),
    ];
    for (name, actual) in actual {
        assert_eq!(vector[name].as_str().unwrap(), actual, "{name}");
    }
}

#[test]
fn known_answer_counts_are_stable() {
    let (records, objects) = ready_fixture();
    let report = run_fixture(records, objects, &policy(), ImportLimits::default()).unwrap();
    assert_eq!(
        report.counts,
        InventoryCounts {
            items: 5,
            refs: 1,
            commits: 1,
            trees: 1,
            entries: 1,
            blobs: 1,
            blob_occurrences: 1,
            mappings: 1,
            relationships: 1,
            lfs_pointers: 1,
            lfs_objects: 1,
        }
    );
    assert_eq!(report.git_bytes, 276);
    assert_eq!(report.lfs_bytes_verified, 6);
}
