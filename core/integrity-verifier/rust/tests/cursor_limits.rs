mod support;

use ogvcs_integrity_verifier::{
    resume_verification, start_verification, FindingKind, ImmutableObjectSource, ObjectRead,
    ObjectReadOutcome, VerificationControl, VerificationLimits, VerificationStatus,
};
use ogvcs_object_model::ObjectRef;
use support::{Behavior, FixtureSource, Graph, GENERATION, OTHER_GENERATION};

fn multi_chunk_content() -> Vec<u8> {
    (0..5_000_000u64)
        .map(|index| ((index.wrapping_mul(131) + index / 97) & 0xff) as u8)
        .collect()
}

struct CancelOnRead {
    inner: FixtureSource,
    target: ObjectRef,
    control: VerificationControl,
    fired: bool,
}

struct IgnoreReadLimit {
    inner: FixtureSource,
    target: ObjectRef,
}

struct OversizeReturn {
    inner: FixtureSource,
    target: ObjectRef,
}

impl ImmutableObjectSource for OversizeReturn {
    type Error = ();

    fn generation(&mut self) -> Result<[u8; 32], Self::Error> {
        self.inner.generation()
    }

    fn read_object(
        &mut self,
        reference: &ObjectRef,
        maximum_bytes: u64,
    ) -> Result<ObjectRead, Self::Error> {
        let mut read = self.inner.read_object(reference, maximum_bytes)?;
        if reference == &self.target {
            if let ObjectReadOutcome::Found { bytes, .. } = &mut read.outcome {
                bytes.push(0);
            }
        }
        Ok(read)
    }
}

impl ImmutableObjectSource for IgnoreReadLimit {
    type Error = ();

    fn generation(&mut self) -> Result<[u8; 32], Self::Error> {
        self.inner.generation()
    }

    fn read_object(
        &mut self,
        reference: &ObjectRef,
        maximum_bytes: u64,
    ) -> Result<ObjectRead, Self::Error> {
        self.inner.read_object(
            reference,
            if reference == &self.target {
                u64::MAX
            } else {
                maximum_bytes
            },
        )
    }
}

impl ImmutableObjectSource for CancelOnRead {
    type Error = ();

    fn generation(&mut self) -> Result<[u8; 32], Self::Error> {
        self.inner.generation()
    }

    fn read_object(
        &mut self,
        reference: &ObjectRef,
        maximum_bytes: u64,
    ) -> Result<ObjectRead, Self::Error> {
        let read = self.inner.read_object(reference, maximum_bytes)?;
        if !self.fired && reference == &self.target {
            self.fired = true;
            self.control.cancel();
        }
        Ok(read)
    }
}

#[test]
fn one_object_pages_resume_to_the_exact_one_shot_report() {
    let mut one_shot_graph = Graph::golden();
    let one_shot = support::complete(&mut one_shot_graph);

    let mut paged_graph = Graph::golden();
    let limits = VerificationLimits {
        max_page_metadata_objects: 1,
        ..VerificationLimits::default()
    };
    let mut page = support::start(&mut paged_graph, &limits);
    let mut cursor_digests = vec![page.cursor.binding_digest()];
    let mut boundaries = 0;
    while page.status == VerificationStatus::PageBoundary {
        boundaries += 1;
        page = resume_verification(
            page.cursor,
            &mut paged_graph.source,
            &limits,
            &VerificationControl::default(),
        )
        .unwrap();
        cursor_digests.push(page.cursor.binding_digest());
    }
    assert_eq!(boundaries, 3);
    assert_eq!(page.status, VerificationStatus::Complete);
    assert!(cursor_digests.windows(2).all(|pair| pair[0] != pair[1]));
    let paged = page.report.unwrap();
    assert_eq!(paged.coverage, one_shot.coverage);
    assert_eq!(paged.findings, one_shot.findings);
    assert_eq!(paged.transcript_digest, one_shot.transcript_digest);
}

#[test]
fn cursor_is_bound_to_the_captured_generation() {
    let mut graph = Graph::golden();
    let limits = VerificationLimits {
        max_page_metadata_objects: 1,
        ..VerificationLimits::default()
    };
    let page = support::start(&mut graph, &limits);
    assert_eq!(page.status, VerificationStatus::PageBoundary);
    assert_eq!(page.cursor.generation(), GENERATION);

    graph.source.generation = OTHER_GENERATION;
    graph.source.read_generation = OTHER_GENERATION;
    let resumed = resume_verification(
        page.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(resumed.status, VerificationStatus::GenerationChanged);
    assert!(resumed.report.is_none());
    let finding = resumed
        .cursor
        .findings()
        .find(|finding| finding.kind == FindingKind::GenerationChanged)
        .unwrap();
    assert_eq!(finding.expected_digest(), Some(GENERATION));
    assert_eq!(finding.observed_digest(), Some(OTHER_GENERATION));
}

#[test]
fn invalid_resume_envelope_preserves_the_cursor_for_a_valid_retry() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 1,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);
    let binding = boundary.cursor.binding_digest();
    let coverage = boundary.cursor.coverage();

    let invalid = VerificationLimits {
        max_page_source_reads: 0,
        ..VerificationLimits::default()
    };
    let preserved = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &invalid,
        &VerificationControl::default(),
    )
    .expect("invalid resume is a cursor-preserving page stop");
    assert_eq!(preserved.status, VerificationStatus::LimitReached);
    assert!(preserved.report.is_none());
    assert_eq!(preserved.cursor.binding_digest(), binding);
    assert_eq!(preserved.cursor.coverage(), coverage);

    let completed = resume_verification(
        preserved.cursor,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert!(completed.report.unwrap().intact);
}

#[test]
fn cancellation_is_typed_resumable_and_does_not_claim_a_report() {
    let mut graph = Graph::golden();
    let control = VerificationControl::default();
    control.cancel();
    let page = start_verification(
        graph.root,
        &mut graph.source,
        &VerificationLimits::default(),
        &control,
    )
    .unwrap();
    assert_eq!(page.status, VerificationStatus::Cancelled);
    assert!(page.report.is_none());
    assert_eq!(page.cursor.coverage().source_reads, 0);
    assert!(page
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::Cancelled));

    let resumed = resume_verification(
        page.cursor,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(resumed.status, VerificationStatus::Complete);
    assert!(resumed.report.unwrap().intact);
}

#[test]
fn cancellation_raised_during_metadata_read_keeps_that_object_pending() {
    let graph = Graph::golden();
    let control = VerificationControl::default();
    let root_bytes = graph.bytes(graph.root).len() as u64;
    let mut source = CancelOnRead {
        inner: graph.source,
        target: graph.root,
        control: control.clone(),
        fired: false,
    };
    let cancelled = start_verification(
        graph.root,
        &mut source,
        &VerificationLimits::default(),
        &control,
    )
    .unwrap();
    assert_eq!(cancelled.status, VerificationStatus::Cancelled);
    assert_eq!(cancelled.cursor.coverage().metadata_objects_verified, 0);
    assert_eq!(cancelled.cursor.coverage().source_reads, 1);
    assert_eq!(cancelled.cursor.coverage().source_bytes_read, root_bytes);

    let completed = resume_verification(
        cancelled.cursor,
        &mut source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert_eq!(completed.report.unwrap().coverage.source_reads, 6);
}

#[test]
fn initial_root_cursor_is_rejected_before_it_exceeds_the_memory_envelope() {
    let mut graph = Graph::golden();
    let limits = VerificationLimits {
        max_charged_memory_bytes: 1_024,
        ..VerificationLimits::default()
    };
    let failure = start_verification(
        graph.root,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap_err();
    assert_eq!(failure.finding.kind, FindingKind::MemoryLimit);
}

#[test]
fn cursor_count_limit_preserves_the_current_object_for_a_larger_resume() {
    let mut graph = Graph::golden();
    let limits = VerificationLimits {
        max_cursor_objects: 1,
        ..VerificationLimits::default()
    };
    let page = support::start(&mut graph, &limits);
    assert_eq!(page.status, VerificationStatus::LimitReached);
    assert!(page
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::CountLimit));
    assert_eq!(page.cursor.coverage().metadata_objects_verified, 0);

    let resumed = resume_verification(
        page.cursor,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(resumed.status, VerificationStatus::Complete);
    let report = resumed.report.unwrap();
    assert!(report.intact);
    assert_eq!(report.coverage.object_count(), 5);
    assert_eq!(report.coverage.source_reads, 6);
}

#[test]
fn cursor_count_limit_also_bounds_unique_chunk_identities() {
    let mut graph = Graph::golden();
    let limits = VerificationLimits {
        max_cursor_objects: 4,
        ..VerificationLimits::default()
    };
    let page = support::start(&mut graph, &limits);
    assert_eq!(page.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(page.cursor.coverage().chunk_objects_verified, 0);
    assert!(page
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::CountLimit));

    let resumed = resume_verification(
        page.cursor,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(resumed.status, VerificationStatus::Complete);
    assert_eq!(resumed.report.unwrap().coverage.object_count(), 5);
}

#[test]
fn subclosure_manifest_budget_is_terminal_until_the_relevant_envelope_expands() {
    let content = multi_chunk_content();
    let mut graph = Graph::with_content(&content);
    assert!(
        graph.chunks.len() > 1,
        "fixture must exercise multiple chunks"
    );
    let limits = VerificationLimits {
        // Snapshot, root tree, child tree, manifest, then one chunk.
        max_page_source_reads: 5,
        ..VerificationLimits::default()
    };
    let page = support::start(&mut graph, &limits);
    assert_eq!(page.status, VerificationStatus::ManifestRestartRequired);
    assert!(page.report.is_none());
    let first_ledger = page.cursor.coverage();
    let first_binding = page.cursor.binding_digest();

    let same_envelope = resume_verification(
        page.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        same_envelope.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(same_envelope.cursor.coverage(), first_ledger);
    assert_eq!(same_envelope.cursor.binding_digest(), first_binding);

    let expanded = resume_verification(
        same_envelope.cursor,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(expanded.status, VerificationStatus::Complete);
    let report = expanded.report.unwrap();
    assert!(report.intact);
    assert_eq!(
        report.coverage.object_count(),
        4 + graph.chunks.len() as u64
    );
    assert!(report.coverage.source_reads > 4 + graph.chunks.len() as u64);
}

#[test]
fn configured_decode_memory_is_a_retryable_resource_stop_not_corruption() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let low_decode = VerificationLimits {
        max_decode_working_bytes: 1,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &low_decode,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    assert!(limited
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::MemoryLimit));
    assert!(!limited
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::FramingVersion));
    let reads = limited.cursor.coverage().source_reads;

    let unchanged = resume_verification(
        limited.cursor,
        &mut graph.source,
        &low_decode,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        unchanged.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(unchanged.cursor.coverage().source_reads, reads);

    let completed = resume_verification(
        unchanged.cursor,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert!(completed.report.unwrap().intact);
}

#[test]
fn page_byte_growth_alone_releases_a_transfer_restart_marker() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let manifest_bytes = graph.bytes(graph.manifest).len() as u64;
    let chunk_bytes = graph.bytes(graph.chunks[0]).len() as u64;
    assert!(manifest_bytes >= chunk_bytes);
    let limited_envelope = VerificationLimits {
        max_page_source_bytes: manifest_bytes + chunk_bytes - 1,
        max_object_bytes: manifest_bytes,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &limited_envelope,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    let reads = limited.cursor.coverage().source_reads;

    let object_bytes_only = VerificationLimits {
        max_object_bytes: limited_envelope.max_object_bytes + 1,
        ..limited_envelope.clone()
    };
    let still_stopped = resume_verification(
        limited.cursor,
        &mut graph.source,
        &object_bytes_only,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        still_stopped.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(still_stopped.cursor.coverage().source_reads, reads);

    let page_bytes_expanded = VerificationLimits {
        max_page_source_bytes: limited_envelope.max_page_source_bytes + 1,
        ..limited_envelope
    };
    let completed = resume_verification(
        still_stopped.cursor,
        &mut graph.source,
        &page_bytes_expanded,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert!(completed.report.unwrap().intact);
}

#[test]
fn fragment_growth_only_retries_a_stop_reached_while_fragmenting() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let edge_limited = VerificationLimits {
        max_page_work_units: 1,
        max_chunk_fragment_bytes: 10,
        ..VerificationLimits::default()
    };
    let stopped_at_edge = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &edge_limited,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        stopped_at_edge.status,
        VerificationStatus::ManifestRestartRequired
    );
    let edge_reads = stopped_at_edge.cursor.coverage().source_reads;
    let irrelevant_fragment_growth = VerificationLimits {
        max_chunk_fragment_bytes: 64,
        ..edge_limited
    };
    let still_stopped = resume_verification(
        stopped_at_edge.cursor,
        &mut graph.source,
        &irrelevant_fragment_growth,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        still_stopped.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(still_stopped.cursor.coverage().source_reads, edge_reads);

    let fragment_limited = VerificationLimits {
        max_page_work_units: 4,
        max_chunk_fragment_bytes: 10,
        ..VerificationLimits::default()
    };
    let stopped_in_fragments = resume_verification(
        still_stopped.cursor,
        &mut graph.source,
        &fragment_limited,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        stopped_in_fragments.status,
        VerificationStatus::ManifestRestartRequired
    );
    let completed_limits = VerificationLimits {
        max_chunk_fragment_bytes: graph.bytes(graph.chunks[0]).len(),
        ..fragment_limited
    };
    let completed = resume_verification(
        stopped_in_fragments.cursor,
        &mut graph.source,
        &completed_limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert!(completed.report.unwrap().intact);
}

#[test]
fn manifest_index_limit_retries_only_after_index_envelope_expands() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let low_index = VerificationLimits {
        max_manifest_index_bytes: 255,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &low_index,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(limited.cursor.coverage().chunk_objects_verified, 0);
    let ledger = limited.cursor.coverage();
    let binding = limited.cursor.binding_digest();

    let same = resume_verification(
        limited.cursor,
        &mut graph.source,
        &low_index,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(same.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(same.cursor.coverage(), ledger);
    assert_eq!(same.cursor.binding_digest(), binding);

    let irrelevant_memory_growth = VerificationLimits {
        max_charged_memory_bytes: low_index.max_charged_memory_bytes + 1,
        ..low_index.clone()
    };
    let still_stopped = resume_verification(
        same.cursor,
        &mut graph.source,
        &irrelevant_memory_growth,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        still_stopped.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(still_stopped.cursor.coverage(), ledger);

    let corrected = VerificationLimits {
        max_manifest_index_bytes: 256,
        ..low_index
    };
    let completed = resume_verification(
        still_stopped.cursor,
        &mut graph.source,
        &corrected,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert!(completed.report.unwrap().intact);
}

#[test]
fn same_envelope_manifest_stop_still_rechecks_generation() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    let low_index = VerificationLimits {
        max_manifest_index_bytes: 255,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &low_index,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    let reads = limited.cursor.coverage().source_reads;

    graph.source.generation = OTHER_GENERATION;
    graph.source.read_generation = OTHER_GENERATION;
    let changed = resume_verification(
        limited.cursor,
        &mut graph.source,
        &low_index,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(changed.status, VerificationStatus::GenerationChanged);
    assert_eq!(changed.cursor.coverage().source_reads, reads);
}

#[test]
fn same_envelope_manifest_stop_still_honors_cancellation() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    let low_index = VerificationLimits {
        max_manifest_index_bytes: 255,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &low_index,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    let reads = limited.cursor.coverage().source_reads;

    let control = VerificationControl::default();
    control.cancel();
    let cancelled =
        resume_verification(limited.cursor, &mut graph.source, &low_index, &control).unwrap();
    assert_eq!(cancelled.status, VerificationStatus::Cancelled);
    assert!(cancelled.report.is_none());
    assert_eq!(cancelled.cursor.coverage().source_reads, reads);

    let still_stopped = resume_verification(
        cancelled.cursor,
        &mut graph.source,
        &low_index,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        still_stopped.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(still_stopped.cursor.coverage().source_reads, reads);
}

#[test]
fn expanded_manifest_index_reservation_is_readmitted_against_charged_memory() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let low_index = VerificationLimits {
        max_manifest_index_bytes: 255,
        ..VerificationLimits::default()
    };
    let index_limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &low_index,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        index_limited.status,
        VerificationStatus::ManifestRestartRequired
    );

    let manifest_capacity = graph.bytes(graph.manifest).len() as u64;
    let decode = 4_096;
    let corrected_index = 256;
    let ledger = 48;
    let corrected_but_memory_tight = VerificationLimits {
        max_decode_working_bytes: decode,
        max_manifest_index_bytes: corrected_index,
        max_manifest_ledger_bytes: ledger,
        max_charged_memory_bytes: index_limited.cursor.charged_memory_bytes()
            + manifest_capacity * 4
            + decode
            + corrected_index
            + ledger
            - 1,
        ..VerificationLimits::default()
    };
    let reads_before = index_limited.cursor.coverage().source_reads;
    let memory_limited = resume_verification(
        index_limited.cursor,
        &mut graph.source,
        &corrected_but_memory_tight,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        memory_limited.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(
        memory_limited.cursor.coverage().source_reads,
        reads_before + 1,
        "the corrected index envelope retries once, then charged-memory admission stops it"
    );
    let stopped_ledger = memory_limited.cursor.coverage();

    let irrelevant_index_growth = VerificationLimits {
        max_manifest_index_bytes: corrected_index + 1,
        ..corrected_but_memory_tight
    };
    let unchanged = resume_verification(
        memory_limited.cursor,
        &mut graph.source,
        &irrelevant_index_growth,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        unchanged.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(unchanged.cursor.coverage(), stopped_ledger);

    let enough_memory = VerificationLimits {
        max_charged_memory_bytes: VerificationLimits::default().max_charged_memory_bytes,
        ..irrelevant_index_growth
    };
    let completed = resume_verification(
        unchanged.cursor,
        &mut graph.source,
        &enough_memory,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert!(completed.report.unwrap().intact);
}

#[test]
fn manifest_ledger_limit_retries_only_after_ledger_envelope_expands() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let low_ledger = VerificationLimits {
        max_manifest_ledger_bytes: 47,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &low_ledger,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(limited.cursor.coverage().chunk_objects_verified, 0);
    let ledger = limited.cursor.coverage();
    let binding = limited.cursor.binding_digest();

    let same = resume_verification(
        limited.cursor,
        &mut graph.source,
        &low_ledger,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(same.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(same.cursor.coverage(), ledger);
    assert_eq!(same.cursor.binding_digest(), binding);

    let corrected = VerificationLimits {
        max_manifest_ledger_bytes: 48,
        ..low_ledger
    };
    let completed = resume_verification(
        same.cursor,
        &mut graph.source,
        &corrected,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert!(completed.report.unwrap().intact);
}

#[test]
fn expanded_manifest_ledger_reservation_is_readmitted_against_charged_memory() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let low_ledger = VerificationLimits {
        max_manifest_ledger_bytes: 47,
        ..VerificationLimits::default()
    };
    let ledger_limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &low_ledger,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        ledger_limited.status,
        VerificationStatus::ManifestRestartRequired
    );

    let manifest_capacity = graph.bytes(graph.manifest).len() as u64;
    let decode = 4_096;
    let index = 256;
    let corrected_ledger = 48;
    let corrected_but_memory_tight = VerificationLimits {
        max_decode_working_bytes: decode,
        max_manifest_index_bytes: index,
        max_manifest_ledger_bytes: corrected_ledger,
        max_charged_memory_bytes: ledger_limited.cursor.charged_memory_bytes()
            + manifest_capacity * 4
            + decode
            + index
            + corrected_ledger
            - 1,
        ..VerificationLimits::default()
    };
    let reads_before = ledger_limited.cursor.coverage().source_reads;
    let memory_limited = resume_verification(
        ledger_limited.cursor,
        &mut graph.source,
        &corrected_but_memory_tight,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        memory_limited.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(
        memory_limited.cursor.coverage().source_reads,
        reads_before + 1
    );
    let stopped_ledger = memory_limited.cursor.coverage();

    let irrelevant_ledger_growth = VerificationLimits {
        max_manifest_ledger_bytes: corrected_ledger + 1,
        ..corrected_but_memory_tight
    };
    let unchanged = resume_verification(
        memory_limited.cursor,
        &mut graph.source,
        &irrelevant_ledger_growth,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        unchanged.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(unchanged.cursor.coverage(), stopped_ledger);

    let enough_memory = VerificationLimits {
        max_charged_memory_bytes: VerificationLimits::default().max_charged_memory_bytes,
        ..irrelevant_ledger_growth
    };
    let completed = resume_verification(
        unchanged.cursor,
        &mut graph.source,
        &enough_memory,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert!(completed.report.unwrap().intact);
}

#[test]
fn cancellation_mid_manifest_then_subclosure_limit_cannot_same_envelope_livelock() {
    let graph = Graph::with_content(&multi_chunk_content());
    assert!(
        graph.chunks.len() > 1,
        "fixture must exercise multiple chunks"
    );
    let control = VerificationControl::default();
    let mut source = CancelOnRead {
        inner: graph.source.clone(),
        target: graph.chunks[0],
        control: control.clone(),
        fired: false,
    };
    let cancelled = start_verification(
        graph.root,
        &mut source,
        &VerificationLimits::default(),
        &control,
    )
    .unwrap();
    assert_eq!(cancelled.status, VerificationStatus::Cancelled);
    assert!(cancelled.report.is_none());
    assert_eq!(cancelled.cursor.coverage().chunk_objects_verified, 0);
    assert_eq!(cancelled.cursor.coverage().source_reads, 5);

    let subclosure_limits = VerificationLimits {
        // The retry can read the manifest and one chunk, but not its closure.
        max_page_source_reads: 2,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        cancelled.cursor,
        &mut source,
        &subclosure_limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    let ledger = limited.cursor.coverage();
    let binding = limited.cursor.binding_digest();

    let unchanged = resume_verification(
        limited.cursor,
        &mut source,
        &subclosure_limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        unchanged.status,
        VerificationStatus::ManifestRestartRequired
    );
    assert_eq!(unchanged.cursor.coverage(), ledger);
    assert_eq!(unchanged.cursor.binding_digest(), binding);

    let completed = resume_verification(
        unchanged.cursor,
        &mut source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(completed.status, VerificationStatus::Complete);
    let report = completed.report.unwrap();
    assert!(report.intact);
    assert_eq!(
        report.coverage.object_count(),
        4 + graph.chunks.len() as u64
    );
    assert!(report.coverage.source_reads > report.coverage.object_count());
}

#[test]
fn byte_limit_transfers_no_oversized_payload_and_is_resumable() {
    let mut graph = Graph::golden();
    let limits = VerificationLimits {
        max_page_source_bytes: 16,
        max_object_bytes: 16,
        ..VerificationLimits::default()
    };
    let page = support::start(&mut graph, &limits);
    assert_eq!(page.status, VerificationStatus::LimitReached);
    assert_eq!(page.cursor.coverage().source_reads, 1);
    assert_eq!(page.cursor.coverage().source_bytes_read, 0);
    assert!(page
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::ByteLimit));

    let resumed = resume_verification(
        page.cursor,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(resumed.status, VerificationStatus::Complete);
    assert!(resumed.report.unwrap().intact);
}

#[test]
fn exact_work_limit_stops_before_admitting_the_snapshot_edge() {
    let mut graph = Graph::golden();
    let limits = VerificationLimits {
        max_page_work_units: 1,
        ..VerificationLimits::default()
    };
    let page = support::start(&mut graph, &limits);
    assert_eq!(page.status, VerificationStatus::LimitReached);
    let ledger = page.cursor.coverage();
    assert_eq!(ledger.source_reads, 1);
    assert_eq!(ledger.work_units, 1);
    assert_eq!(ledger.graph_edges_traversed, 0);
    assert!(page
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::WorkLimit));
}

#[test]
fn metadata_edge_memory_rejection_does_not_charge_phantom_work() {
    let mut graph = Graph::golden();
    let cancelled_control = VerificationControl::default();
    cancelled_control.cancel();
    let cancelled = start_verification(
        graph.root,
        &mut graph.source,
        &VerificationLimits::default(),
        &cancelled_control,
    )
    .unwrap();
    assert_eq!(cancelled.status, VerificationStatus::Cancelled);

    let decode = 65_536;
    let snapshot_capacity = graph.bytes(graph.snapshot).len() as u64;
    let active_reservation = snapshot_capacity * 4 + decode;
    let limits = VerificationLimits {
        max_decode_working_bytes: decode,
        // The new object/pending entries cost 224 bytes and the edge costs
        // 128. Reject the atomic admission one byte before that combined peak.
        max_charged_memory_bytes: cancelled.cursor.charged_memory_bytes()
            + active_reservation
            + 224
            + 128
            - 1,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        cancelled.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::LimitReached);
    assert_eq!(limited.cursor.coverage().source_reads, 1);
    assert_eq!(
        limited.cursor.coverage().work_units,
        1,
        "only the admitted source read is work; the rejected edge is not"
    );
    assert_eq!(limited.cursor.coverage().graph_edges_traversed, 0);
    assert_eq!(limited.cursor.coverage().metadata_objects_verified, 0);
}

#[test]
fn charged_memory_limit_stops_before_decode_and_records_the_peak_charge() {
    let mut graph = Graph::golden();
    let limits = VerificationLimits {
        max_charged_memory_bytes: 2_000,
        max_decode_working_bytes: 1_024,
        ..VerificationLimits::default()
    };
    let page = support::start(&mut graph, &limits);
    assert_eq!(page.status, VerificationStatus::LimitReached);
    let ledger = page.cursor.coverage();
    assert_eq!(ledger.metadata_objects_verified, 0);
    assert_eq!(ledger.source_reads, 0);
    assert!(ledger.peak_charged_memory_bytes <= limits.max_charged_memory_bytes);
    assert!(page
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::MemoryLimit));
}

#[test]
fn active_manifest_reservation_is_held_while_admitting_a_chunk_buffer() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);
    assert_eq!(boundary.cursor.coverage().metadata_objects_verified, 3);

    let manifest_bytes = graph.bytes(graph.manifest).len() as u64;
    let chunk_bytes = graph.bytes(graph.chunks[0]).len() as u64;
    let decode = 4_096;
    let index = 4_096;
    let ledger = 4_096;
    let manifest_reservation = manifest_bytes * 4 + decode + index + ledger;
    let memory_limits = VerificationLimits {
        max_decode_working_bytes: decode,
        max_manifest_index_bytes: index,
        max_manifest_ledger_bytes: ledger,
        // One manifest->chunk edge costs 128 charged bytes. Leave one byte
        // less than the simultaneous manifest + complete chunk reservation.
        max_charged_memory_bytes: boundary.cursor.charged_memory_bytes()
            + manifest_reservation
            + 128
            + chunk_bytes
            - 1,
        ..VerificationLimits::default()
    };
    let source_reads_before = boundary.cursor.coverage().source_reads;
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &memory_limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(limited.cursor.coverage().chunk_objects_verified, 0);
    assert_eq!(
        limited.cursor.coverage().source_reads,
        source_reads_before + 1,
        "the manifest read is admitted but the chunk read is rejected before allocation"
    );
    assert!(limited
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::MemoryLimit));
    assert!(
        limited.cursor.charged_memory_bytes() + manifest_reservation
            <= memory_limits.max_charged_memory_bytes
    );
}

#[test]
fn manifest_edge_memory_rejection_does_not_charge_phantom_work() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let manifest_bytes = graph.bytes(graph.manifest).len() as u64;
    let decode = 4_096;
    let index = 4_096;
    let ledger = 4_096;
    let manifest_reservation = manifest_bytes * 4 + decode + index + ledger;
    let limits = VerificationLimits {
        max_decode_working_bytes: decode,
        max_manifest_index_bytes: index,
        max_manifest_ledger_bytes: ledger,
        max_charged_memory_bytes: boundary.cursor.charged_memory_bytes()
            + manifest_reservation
            + 128
            - 1,
        ..VerificationLimits::default()
    };
    let before = boundary.cursor.coverage();
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(
        limited.cursor.coverage().source_reads,
        before.source_reads + 1
    );
    assert_eq!(
        limited.cursor.coverage().work_units,
        before.work_units + 1,
        "the rejected manifest edge must not be charged"
    );
    assert_eq!(
        limited.cursor.coverage().graph_edges_traversed,
        before.graph_edges_traversed
    );
    assert_eq!(limited.cursor.coverage().chunk_objects_verified, 0);
}

#[test]
fn spare_manifest_capacity_is_held_with_decoder_index_and_ledger() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let manifest_bytes = graph.bytes(graph.manifest);
    let manifest_capacity = manifest_bytes.len() + 4_096;
    graph.set_behavior(
        graph.manifest,
        Behavior::FoundWithCapacity {
            declared_bytes: manifest_bytes.len() as u64,
            bytes: manifest_bytes,
            capacity: manifest_capacity,
        },
    );
    let decode = 4_096;
    let index = 4_096;
    let ledger = 4_096;
    let manifest_reservation = manifest_capacity as u64 * 4 + decode + index + ledger;
    let limits = VerificationLimits {
        max_decode_working_bytes: decode,
        max_manifest_index_bytes: index,
        max_manifest_ledger_bytes: ledger,
        // The spare-capacity manifest plus decoder/index/ledger state fits,
        // but its first 128-byte chunk edge does not.
        max_charged_memory_bytes: boundary.cursor.charged_memory_bytes()
            + manifest_reservation
            + 128
            - 1,
        ..VerificationLimits::default()
    };
    let before = boundary.cursor.coverage();
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(
        limited.cursor.coverage().source_reads,
        before.source_reads + 1
    );
    assert_eq!(limited.cursor.coverage().work_units, before.work_units + 1);
    assert_eq!(
        limited.cursor.coverage().graph_edges_traversed,
        before.graph_edges_traversed
    );
}

#[test]
fn spare_metadata_capacity_is_held_during_cursor_growth() {
    let mut graph = Graph::golden();
    let snapshot_bytes = graph.bytes(graph.snapshot);
    let snapshot_capacity = snapshot_bytes.len() + 4_096;
    graph.set_behavior(
        graph.snapshot,
        Behavior::FoundWithCapacity {
            declared_bytes: snapshot_bytes.len() as u64,
            bytes: snapshot_bytes,
            capacity: snapshot_capacity,
        },
    );
    let cancelled_control = VerificationControl::default();
    cancelled_control.cancel();
    let cancelled = start_verification(
        graph.root,
        &mut graph.source,
        &VerificationLimits::default(),
        &cancelled_control,
    )
    .unwrap();
    assert_eq!(cancelled.status, VerificationStatus::Cancelled);

    let decode = 65_536;
    let active_reservation = snapshot_capacity as u64 * 4 + decode;
    let limits = VerificationLimits {
        max_decode_working_bytes: decode,
        // The snapshot child costs 224 charged bytes and its edge costs 128.
        // Leave the final 96-byte covered-object key one byte short.
        max_charged_memory_bytes: cancelled.cursor.charged_memory_bytes()
            + active_reservation
            + 224
            + 128
            + 96
            - 1,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        cancelled.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        limited.status,
        VerificationStatus::LimitReached,
        "coverage={:?} charge={} cap={} snapshot={} active={}",
        limited.cursor.coverage(),
        limited.cursor.charged_memory_bytes(),
        limits.max_charged_memory_bytes,
        snapshot_capacity,
        active_reservation,
    );
    assert_eq!(limited.cursor.coverage().source_reads, 1);
    assert_eq!(limited.cursor.coverage().graph_edges_traversed, 1);
    assert_eq!(limited.cursor.coverage().metadata_objects_verified, 0);
    assert!(limited
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::MemoryLimit));
}

#[test]
fn source_vec_capacity_above_metadata_read_cap_is_rejected() {
    let mut graph = Graph::golden();
    let snapshot_bytes = graph.bytes(graph.snapshot);
    let object_limit = snapshot_bytes.len() as u64;
    let returned_capacity = snapshot_bytes.len() + 4_096;
    graph.set_behavior(
        graph.snapshot,
        Behavior::FoundWithCapacity {
            declared_bytes: object_limit,
            bytes: snapshot_bytes,
            capacity: returned_capacity,
        },
    );
    let limits = VerificationLimits {
        max_object_bytes: object_limit,
        ..VerificationLimits::default()
    };
    let page = support::start(&mut graph, &limits);
    assert_eq!(page.status, VerificationStatus::SourceUnavailable);
    assert!(page.report.is_none());
    assert_eq!(page.cursor.coverage().source_reads, 1);
    assert_eq!(page.cursor.coverage().metadata_objects_verified, 0);
    let finding = page
        .cursor
        .findings()
        .find(|finding| finding.kind == FindingKind::SourceFailure)
        .expect("capacity contract failure");
    assert_eq!(finding.expected_bytes(), Some(object_limit));
    assert_eq!(finding.observed_bytes(), Some(returned_capacity as u64));
}

#[test]
fn source_vec_length_above_metadata_read_cap_is_a_source_contract_failure() {
    let graph = Graph::golden();
    let root_bytes = graph.bytes(graph.root).len() as u64;
    let mut source = IgnoreReadLimit {
        inner: graph.source,
        target: graph.root,
    };
    let limits = VerificationLimits {
        max_object_bytes: root_bytes - 1,
        ..VerificationLimits::default()
    };
    let page = start_verification(
        graph.root,
        &mut source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(page.status, VerificationStatus::SourceUnavailable);
    assert!(page.report.is_none());
    assert_eq!(page.cursor.coverage().source_reads, 1);
    assert_eq!(page.cursor.coverage().source_bytes_read, root_bytes);
    let finding = page
        .cursor
        .findings()
        .find(|finding| finding.kind == FindingKind::SourceFailure)
        .expect("length contract failure");
    assert_eq!(finding.expected_bytes(), Some(root_bytes - 1));
    assert!(finding
        .observed_bytes()
        .is_some_and(|bytes| bytes >= root_bytes));
}

#[test]
fn spare_chunk_capacity_is_held_through_coverage_admission() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let chunk = graph.chunks[0];
    let chunk_bytes = graph.bytes(chunk);
    let chunk_capacity = chunk_bytes.len() + 4_096;
    graph.set_behavior(
        chunk,
        Behavior::FoundWithCapacity {
            declared_bytes: chunk_bytes.len() as u64,
            bytes: chunk_bytes,
            capacity: chunk_capacity,
        },
    );
    let manifest_bytes = graph.bytes(graph.manifest).len() as u64;
    let decode = 4_096;
    let index = 4_096;
    let ledger = 4_096;
    let manifest_reservation = manifest_bytes * 4 + decode + index + ledger;
    let limits = VerificationLimits {
        max_decode_working_bytes: decode,
        max_manifest_index_bytes: index,
        max_manifest_ledger_bytes: ledger,
        // The edge and returned chunk capacity fit. The 96-byte chunk
        // coverage identity does not, proving capacity (not just length) is
        // carried through the live reservation.
        max_charged_memory_bytes: boundary.cursor.charged_memory_bytes()
            + manifest_reservation
            + 128
            + chunk_capacity as u64
            + 96
            - 1,
        ..VerificationLimits::default()
    };
    let reads_before = boundary.cursor.coverage().source_reads;
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(limited.cursor.coverage().source_reads, reads_before + 2);
    assert_eq!(limited.cursor.coverage().chunk_objects_verified, 0);
    assert!(
        limited.cursor.charged_memory_bytes() + manifest_reservation + chunk_capacity as u64
            <= limits.max_charged_memory_bytes
    );
}

#[test]
fn source_vec_capacity_above_chunk_read_cap_is_rejected() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let chunk = graph.chunks[0];
    let chunk_bytes = graph.bytes(chunk);
    let manifest_bytes = graph.bytes(graph.manifest);
    let object_limit = manifest_bytes.len().max(chunk_bytes.len()) as u64;
    let returned_capacity = object_limit as usize + 4_096;
    graph.set_behavior(
        chunk,
        Behavior::FoundWithCapacity {
            declared_bytes: chunk_bytes.len() as u64,
            bytes: chunk_bytes,
            capacity: returned_capacity,
        },
    );
    let limits = VerificationLimits {
        max_object_bytes: object_limit,
        ..VerificationLimits::default()
    };
    let page = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(page.status, VerificationStatus::SourceUnavailable);
    assert!(page.report.is_none());
    assert_eq!(page.cursor.coverage().chunk_objects_verified, 0);
    let finding = page
        .cursor
        .findings()
        .find(|finding| finding.kind == FindingKind::SourceFailure)
        .expect("capacity contract failure");
    assert_eq!(finding.reference, Some(chunk));
    assert_eq!(finding.expected_bytes(), Some(object_limit));
    assert_eq!(finding.observed_bytes(), Some(returned_capacity as u64));
}

#[test]
fn source_vec_length_above_chunk_read_cap_is_a_source_contract_failure() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let manifest_bytes = graph.bytes(graph.manifest).len() as u64;
    let chunk = graph.chunks[0];
    let chunk_bytes = graph.bytes(chunk).len() as u64;
    let mut source = OversizeReturn {
        inner: graph.source,
        target: chunk,
    };
    let limits = VerificationLimits {
        max_page_source_bytes: manifest_bytes + chunk_bytes,
        max_object_bytes: manifest_bytes,
        ..VerificationLimits::default()
    };
    let page = resume_verification(
        boundary.cursor,
        &mut source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(page.status, VerificationStatus::SourceUnavailable);
    assert!(page.report.is_none());
    assert_eq!(page.cursor.coverage().chunk_objects_verified, 0);
    let finding = page
        .cursor
        .findings()
        .find(|finding| {
            finding.kind == FindingKind::SourceFailure && finding.reference == Some(chunk)
        })
        .expect("chunk length contract failure");
    assert_eq!(finding.expected_bytes(), Some(chunk_bytes));
    assert!(finding
        .observed_bytes()
        .is_some_and(|bytes| bytes > chunk_bytes));
}

#[test]
fn final_manifest_coverage_key_is_admitted_with_the_manifest_reservation_live() {
    let mut graph = Graph::golden();
    let boundary_limits = VerificationLimits {
        max_page_metadata_objects: 3,
        ..VerificationLimits::default()
    };
    let boundary = support::start(&mut graph, &boundary_limits);
    assert_eq!(boundary.status, VerificationStatus::PageBoundary);

    let manifest_bytes = graph.bytes(graph.manifest).len() as u64;
    let decode = 4_096;
    let index = 4_096;
    let ledger = 4_096;
    let manifest_reservation = manifest_bytes * 4 + decode + index + ledger;
    let limits = VerificationLimits {
        max_decode_working_bytes: decode,
        max_manifest_index_bytes: index,
        max_manifest_ledger_bytes: ledger,
        // Edge + chunk coverage consume 224 cursor bytes. The final manifest
        // coverage key needs another 96; stop one byte before that peak.
        max_charged_memory_bytes: boundary.cursor.charged_memory_bytes()
            + manifest_reservation
            + 224
            + 96
            - 1,
        ..VerificationLimits::default()
    };
    let reads_before = boundary.cursor.coverage().source_reads;
    let limited = resume_verification(
        boundary.cursor,
        &mut graph.source,
        &limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::ManifestRestartRequired);
    assert_eq!(limited.cursor.coverage().chunk_objects_verified, 1);
    assert_eq!(limited.cursor.coverage().metadata_objects_verified, 3);
    assert_eq!(limited.cursor.coverage().source_reads, reads_before + 2);
    assert!(limited
        .cursor
        .findings()
        .any(|finding| finding.kind == FindingKind::MemoryLimit));
}

#[test]
fn findings_and_report_digest_are_independent_of_page_ordering() {
    let mut one_shot_graph = Graph::golden();
    one_shot_graph.set_behavior(one_shot_graph.child_tree, Behavior::Missing);
    one_shot_graph.set_behavior(one_shot_graph.manifest, Behavior::BackendAmbiguous);
    let one_shot = support::complete(&mut one_shot_graph);

    let mut paged_graph = Graph::golden();
    paged_graph.set_behavior(paged_graph.child_tree, Behavior::Missing);
    paged_graph.set_behavior(paged_graph.manifest, Behavior::BackendAmbiguous);
    let limits = VerificationLimits {
        max_page_metadata_objects: 1,
        ..VerificationLimits::default()
    };
    let paged = support::complete_with_limits(&mut paged_graph, limits);

    assert_eq!(paged.findings, one_shot.findings);
    assert_eq!(paged.coverage, one_shot.coverage);
    assert_eq!(paged.transcript_digest, one_shot.transcript_digest);
    assert_eq!(
        paged
            .findings
            .iter()
            .map(|finding| finding.kind)
            .collect::<Vec<_>>(),
        vec![FindingKind::ObjectMissing, FindingKind::BackendAmbiguous]
    );
}

#[test]
fn report_finding_buffer_is_admitted_while_the_cursor_findings_remain_live() {
    let mut graph = Graph::golden();
    graph.set_behavior(graph.child_tree, Behavior::Missing);
    let completed = support::start(&mut graph, &VerificationLimits::default());
    assert_eq!(completed.status, VerificationStatus::Complete);
    assert_eq!(completed.cursor.findings().len(), 1);

    let tight_limits = VerificationLimits {
        max_charged_memory_bytes: completed.cursor.charged_memory_bytes() + 191,
        ..VerificationLimits::default()
    };
    let limited = resume_verification(
        completed.cursor,
        &mut graph.source,
        &tight_limits,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(limited.status, VerificationStatus::LimitReached);
    assert!(limited.report.is_none());
    assert_eq!(limited.cursor.findings().len(), 1);
    assert_eq!(
        limited.cursor.findings().next().map(|finding| finding.kind),
        Some(FindingKind::FindingsTruncated)
    );
    assert!(limited.cursor.charged_memory_bytes() <= tight_limits.max_charged_memory_bytes);

    let expanded = VerificationLimits {
        max_charged_memory_bytes: limited.cursor.charged_memory_bytes() + 192,
        ..VerificationLimits::default()
    };
    let resumed = resume_verification(
        limited.cursor,
        &mut graph.source,
        &expanded,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(resumed.status, VerificationStatus::Complete);
    assert!(!resumed.report.unwrap().intact);
}

#[test]
fn generation_source_failure_is_typed_before_a_cursor_is_created() {
    let mut graph = Graph::golden();
    graph.source.generation_failure = true;
    let failure = start_verification(
        graph.root,
        &mut graph.source,
        &VerificationLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap_err();
    assert_eq!(failure.finding.kind, FindingKind::SourceFailure);
}
