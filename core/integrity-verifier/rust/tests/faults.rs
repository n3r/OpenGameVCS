mod support;

use ogvcs_integrity_verifier::{
    start_verification, FindingKind, FindingLayer, VerificationControl, VerificationLimits,
    VerificationStatus,
};
use ogvcs_object_model::{Cbor, ObjectKind, ObjectRef};
use support::{
    array_mut, complete, complete_with_limits, field_mut, read_value, remove_field, Behavior,
    Graph, GENERATION,
};

fn assert_finding(
    report: &ogvcs_integrity_verifier::VerificationReport,
    kind: FindingKind,
    layer: FindingLayer,
) {
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.kind == kind && finding.layer == layer),
        "missing {kind:?}/{layer:?}: {:?}",
        report.findings
    );
    assert!(!report.intact);
}

#[test]
fn missing_required_snapshot_tree_reference_is_typed_and_returns_no_payload() {
    let mut graph = Graph::golden();
    let mut snapshot = read_value(&graph, graph.snapshot);
    remove_field(&mut snapshot, 18);
    graph.replace_snapshot(snapshot);
    let report = complete(&mut graph);
    assert_finding(
        &report,
        FindingKind::MetadataReferenceMissing,
        FindingLayer::Snapshot,
    );
    assert_eq!(report.coverage.object_count(), 0);
}

#[test]
fn missing_tree_entry_target_is_a_file_version_reference_finding() {
    let mut graph = Graph::golden();
    let mut tree = read_value(&graph, graph.tree);
    let entries = array_mut(field_mut(&mut tree, 17));
    remove_field(&mut entries[1], 4);
    graph.replace_tree(tree);
    let report = complete(&mut graph);
    assert_finding(
        &report,
        FindingKind::MetadataReferenceMissing,
        FindingLayer::FileVersion,
    );
}

#[test]
fn missing_manifest_chunk_reference_is_typed_before_chunk_reads() {
    let mut graph = Graph::golden();
    let mut manifest = read_value(&graph, graph.manifest);
    let parts = array_mut(field_mut(&mut manifest, 19));
    remove_field(&mut parts[0], 0);
    graph.replace_manifest(manifest);
    let report = complete(&mut graph);
    assert_finding(
        &report,
        FindingKind::MetadataReferenceMissing,
        FindingLayer::Manifest,
    );
    assert_eq!(report.coverage.chunk_objects_verified, 0);
}

#[test]
fn missing_object_is_distinct_from_a_missing_reference() {
    let mut graph = Graph::golden();
    graph.set_behavior(graph.child_tree, Behavior::Missing);
    let report = complete(&mut graph);
    assert_finding(&report, FindingKind::ObjectMissing, FindingLayer::Tree);
}

#[test]
fn declared_storage_size_mismatch_is_detected_before_decode() {
    let mut graph = Graph::golden();
    let bytes = graph.bytes(graph.snapshot);
    graph.set_behavior(
        graph.snapshot,
        Behavior::Found {
            declared_bytes: bytes.len() as u64 + 1,
            bytes,
        },
    );
    let report = complete(&mut graph);
    assert_finding(&report, FindingKind::SizeMismatch, FindingLayer::Snapshot);
    assert_eq!(report.coverage.object_count(), 0);
}

#[test]
fn chunk_declared_storage_size_evidence_names_declared_and_observed_bytes() {
    let mut graph = Graph::golden();
    let chunk = graph.chunks[0];
    let bytes = graph.bytes(chunk);
    let declared_bytes = bytes.len() as u64 + 7;
    graph.set_behavior(
        chunk,
        Behavior::Found {
            declared_bytes,
            bytes: bytes.clone(),
        },
    );
    let report = complete(&mut graph);
    let finding = report
        .findings
        .iter()
        .find(|finding| {
            finding.kind == FindingKind::SizeMismatch && finding.layer == FindingLayer::Chunk
        })
        .expect("typed chunk size finding");
    assert_eq!(finding.expected_bytes(), Some(declared_bytes));
    assert_eq!(finding.observed_bytes(), Some(bytes.len() as u64));
    assert!(!report.intact);
}

#[test]
fn finding_truncation_is_explicitly_inconclusive_and_never_reports_intact() {
    let mut graph = Graph::golden();
    graph.set_behavior(graph.child_tree, Behavior::Missing);
    graph.set_behavior(graph.manifest, Behavior::BackendAmbiguous);
    let report = complete_with_limits(
        &mut graph,
        VerificationLimits {
            max_findings: 1,
            ..VerificationLimits::default()
        },
    );
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].kind, FindingKind::FindingsTruncated);
    assert!(!report.intact);
}

#[test]
fn tree_file_size_mismatch_is_detected_after_manifest_closure_verifies() {
    let mut graph = Graph::golden();
    let mut tree = read_value(&graph, graph.tree);
    let entries = array_mut(field_mut(&mut tree, 17));
    *field_mut(&mut entries[1], 5) = Cbor::UInt(999);
    graph.replace_tree(tree);
    let report = complete(&mut graph);
    assert_finding(
        &report,
        FindingKind::SizeMismatch,
        FindingLayer::FileVersion,
    );
    assert_eq!(report.coverage.chunk_objects_verified, 1);
}

#[test]
fn format_version_change_with_rebound_identity_is_not_accepted() {
    let mut graph = Graph::golden();
    let mut snapshot = read_value(&graph, graph.snapshot);
    *field_mut(&mut snapshot, 0) = Cbor::UInt(2);
    graph.replace_snapshot(snapshot);
    let report = complete(&mut graph);
    assert_finding(&report, FindingKind::FramingVersion, FindingLayer::Snapshot);
}

#[test]
fn manifest_whole_digest_corruption_with_rebound_identity_reaches_ogvcs007_verifier() {
    let mut graph = Graph::golden();
    let mut manifest = read_value(&graph, graph.manifest);
    let Cbor::Bytes(digest) = field_mut(field_mut(&mut manifest, 17), 1) else {
        panic!("typed digest bytes")
    };
    digest[0] ^= 0x80;
    graph.replace_manifest(manifest);
    let report = complete(&mut graph);
    assert_finding(
        &report,
        FindingKind::ManifestCorrupt,
        FindingLayer::Manifest,
    );
    assert_eq!(report.coverage.chunk_objects_verified, 1);
    assert_eq!(report.coverage.metadata_objects_verified, 3);
}

#[test]
fn valid_but_unsupported_manifest_profile_is_source_unavailable_not_corruption() {
    let mut graph = Graph::golden();
    let mut manifest = read_value(&graph, graph.manifest);
    *field_mut(field_mut(&mut manifest, 18), 1) = Cbor::Text("future-gear".into());
    graph.replace_manifest(manifest);
    let page = start_verification(
        graph.root,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(page.status, VerificationStatus::SourceUnavailable);
    assert!(page.report.is_none());
    assert!(page.cursor.findings().any(|finding| {
        finding.kind == FindingKind::SourceFailure && finding.reference == Some(graph.manifest)
    }));
    assert!(!page
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::ManifestCorrupt));
    assert_eq!(page.cursor.coverage().chunk_objects_verified, 0);
}

#[test]
fn one_bit_flip_at_each_serialized_layer_is_detected_before_validity() {
    for layer in [
        FindingLayer::Snapshot,
        FindingLayer::Tree,
        FindingLayer::Manifest,
        FindingLayer::Chunk,
    ] {
        let mut graph = Graph::golden();
        let reference = match layer {
            FindingLayer::Snapshot => graph.snapshot,
            FindingLayer::Tree => graph.tree,
            FindingLayer::Manifest => graph.manifest,
            FindingLayer::Chunk => graph.chunks[0],
            _ => unreachable!(),
        };
        let mut bytes = graph.bytes(reference);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        graph.set_behavior(
            reference,
            Behavior::Found {
                declared_bytes: bytes.len() as u64,
                bytes,
            },
        );
        let report = complete(&mut graph);
        assert_finding(&report, FindingKind::DigestMismatch, layer);
    }
}

#[test]
fn source_and_backend_ambiguity_never_choose_a_copy() {
    for (behavior, expected) in [
        (Behavior::SourceAmbiguous, FindingKind::SourceAmbiguous),
        (Behavior::BackendAmbiguous, FindingKind::BackendAmbiguous),
    ] {
        let mut graph = Graph::golden();
        graph.set_behavior(graph.manifest, behavior);
        let report = complete(&mut graph);
        assert_finding(&report, expected, FindingLayer::Source);
        assert_eq!(report.coverage.chunk_objects_verified, 0);
    }
}

#[test]
fn bounded_source_failure_pauses_with_a_typed_finding_and_no_false_report() {
    let mut graph = Graph::golden();
    graph.set_behavior(graph.tree, Behavior::Failure);
    let page = start_verification(
        graph.root,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(page.status, VerificationStatus::SourceUnavailable);
    assert!(page.report.is_none());
    assert!(page.cursor.findings().any(|finding| {
        finding.kind == FindingKind::SourceFailure && finding.reference == Some(graph.tree)
    }));
}

#[test]
fn wrong_chunk_reference_is_missing_not_plausible_content() {
    let mut graph = Graph::golden();
    let mut manifest = read_value(&graph, graph.manifest);
    let parts = array_mut(field_mut(&mut manifest, 19));
    let wrong = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: [0xa5; 32],
    };
    *field_mut(&mut parts[0], 0) = wrong.to_cbor();
    graph.replace_manifest(manifest);
    let report = complete(&mut graph);
    assert_finding(&report, FindingKind::ObjectMissing, FindingLayer::Chunk);
}

#[test]
fn source_read_generation_drift_is_terminal_for_the_page() {
    let mut graph = Graph::golden();
    let root_bytes = graph.bytes(graph.root).len() as u64;
    graph.source.read_generation = [0x99; 32];
    let page = start_verification(
        graph.root,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(page.status, VerificationStatus::GenerationChanged);
    assert!(page.report.is_none());
    let finding = page.cursor.findings().next().unwrap();
    assert_eq!(finding.kind, FindingKind::GenerationChanged);
    assert_eq!(finding.expected_digest(), Some(GENERATION));
    assert_eq!(finding.observed_digest(), Some([0x99; 32]));
    assert_eq!(page.cursor.coverage().source_reads, 1);
    assert_eq!(page.cursor.coverage().source_bytes_read, root_bytes);
}
