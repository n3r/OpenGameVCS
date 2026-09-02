mod support;

use std::fs;

use serde_json::Value;
use support::{complete, hex, Graph};

#[test]
fn fixture_derived_content_closure_matches_independent_golden() {
    let mut graph = Graph::golden();
    let report = complete(&mut graph);
    assert!(report.intact);
    assert!(report.findings.is_empty());

    let expected: Value = serde_json::from_slice(
        &fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden.json")).unwrap(),
    )
    .unwrap();
    let ledger = report.coverage;
    assert_eq!(
        serde_json::json!({
            "chunkBytes": ledger.chunk_bytes_verified,
            "chunkObjects": ledger.chunk_objects_verified,
            "fileVersions": ledger.file_versions_traversed,
            "graphEdges": ledger.graph_edges_traversed,
            "logicalFileBytes": ledger.logical_file_bytes,
            "manifestParts": ledger.manifest_parts_traversed,
            "metadataBytes": ledger.metadata_bytes_verified,
            "metadataObjects": ledger.metadata_objects_verified,
            "objectBytes": ledger.object_bytes(),
            "objectCount": ledger.object_count(),
            "sourceBytes": ledger.source_bytes_read,
            "sourceReads": ledger.source_reads,
            "transcriptDigest": hex(&report.transcript_digest),
            "workUnits": ledger.work_units,
        }),
        expected
    );
}
