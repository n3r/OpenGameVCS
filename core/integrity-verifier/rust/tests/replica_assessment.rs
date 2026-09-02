mod support;

use ogvcs_integrity_verifier::{
    assess_replica_set, ReplicaAssessmentError, ReplicaAssessmentLimits, ReplicaCandidate,
    ReplicaCandidateObservation, ReplicaCopyOutcome, ReplicaDisposition, VerificationControl,
};
use ogvcs_object_model::{object_id, opaque_object_digest, ObjectKind, ObjectRef};
use support::{Behavior, Graph, GENERATION};

const BACKEND_A: [u8; 32] = [0x11; 32];
const BACKEND_B: [u8; 32] = [0x22; 32];
const BACKEND_C: [u8; 32] = [0x33; 32];

fn chunk_ref(bytes: &[u8]) -> ObjectRef {
    ObjectRef {
        kind: ObjectKind::Chunk,
        digest: object_id(ObjectKind::Chunk, bytes).unwrap(),
    }
}

fn present(backend: [u8; 32], bytes: &[u8], declared_bytes: u64) -> ReplicaCandidate<'_> {
    ReplicaCandidate {
        backend,
        observation: ReplicaCandidateObservation::Present {
            declared_bytes,
            bytes,
        },
    }
}

fn missing(backend: [u8; 32]) -> ReplicaCandidate<'static> {
    ReplicaCandidate {
        backend,
        observation: ReplicaCandidateObservation::Missing,
    }
}

#[test]
fn verified_replicas_are_order_independent_and_select_the_lowest_backend() {
    let bytes = b"independently verified replica bytes";
    let reference = chunk_ref(bytes);
    let candidates = [
        present(BACKEND_B, bytes, bytes.len() as u64),
        present(BACKEND_A, bytes, bytes.len() as u64),
    ];
    let first = assess_replica_set(
        GENERATION,
        reference,
        bytes.len() as u64,
        &candidates,
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    let second = assess_replica_set(
        GENERATION,
        reference,
        bytes.len() as u64,
        &[candidates[1], candidates[0]],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();

    assert_eq!(first, second);
    assert_eq!(first.disposition(), ReplicaDisposition::VerifiedAgreement);
    assert_eq!(first.preferred_source(), Some(BACKEND_A));
    assert_eq!(first.copy_count(), 2);
    assert_eq!(first.copy_outcome_count(ReplicaCopyOutcome::Verified), 2);
    assert!(first.quarantine_previews().is_empty());
    assert!(first.repair_previews().is_empty());
    assert!(!format!("{first:?}").contains(&"11".repeat(32)));
}

#[test]
fn one_verified_and_one_corrupt_copy_yield_exact_non_authoritative_previews() {
    let good = b"verified source bytes";
    let bad = b"corrupted source byte";
    assert_eq!(good.len(), bad.len());
    let reference = chunk_ref(good);
    let assessment = assess_replica_set(
        GENERATION,
        reference,
        good.len() as u64,
        &[
            present(BACKEND_B, bad, bad.len() as u64),
            present(BACKEND_A, good, good.len() as u64),
        ],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();

    assert_eq!(
        assessment.disposition(),
        ReplicaDisposition::RepairCandidate
    );
    assert_eq!(assessment.preferred_source(), Some(BACKEND_A));
    assert_eq!(
        assessment.copy_outcome_count(ReplicaCopyOutcome::DigestMismatch),
        1
    );
    assert_eq!(assessment.quarantine_previews().len(), 1);
    assert_eq!(assessment.quarantine_previews()[0].backend(), BACKEND_B);
    assert_eq!(assessment.repair_previews().len(), 1);
    assert_eq!(assessment.repair_previews()[0].source_backend(), BACKEND_A);
    assert_eq!(
        assessment.repair_previews()[0].destination_backend(),
        BACKEND_B
    );
    assert_eq!(
        assessment.repair_previews()[0].destination_outcome(),
        ReplicaCopyOutcome::DigestMismatch
    );

    let changed_generation = assess_replica_set(
        [0x49; 32],
        reference,
        good.len() as u64,
        &[present(BACKEND_A, good, good.len() as u64)],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_ne!(
        assessment.binding_sha256(),
        changed_generation.binding_sha256()
    );
}

#[test]
fn missing_destination_is_repairable_but_not_a_quarantine_candidate() {
    let bytes = b"repair source";
    let reference = chunk_ref(bytes);
    let assessment = assess_replica_set(
        GENERATION,
        reference,
        bytes.len() as u64,
        &[
            missing(BACKEND_B),
            present(BACKEND_A, bytes, bytes.len() as u64),
        ],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();

    assert_eq!(
        assessment.disposition(),
        ReplicaDisposition::RepairCandidate
    );
    assert!(assessment.quarantine_previews().is_empty());
    assert_eq!(assessment.repair_previews().len(), 1);
    assert_eq!(
        assessment.repair_previews()[0].destination_outcome(),
        ReplicaCopyOutcome::Missing
    );
}

#[test]
fn all_bad_or_missing_copies_are_degraded_and_never_invent_a_source() {
    let good = b"canonical bytes";
    let bad = b"different bytes";
    assert_eq!(good.len(), bad.len());
    let assessment = assess_replica_set(
        GENERATION,
        chunk_ref(good),
        good.len() as u64,
        &[
            missing(BACKEND_A),
            present(BACKEND_B, bad, bad.len() as u64),
        ],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();

    assert_eq!(
        assessment.disposition(),
        ReplicaDisposition::NoVerifiedSource
    );
    assert_eq!(assessment.preferred_source(), None);
    assert!(assessment.repair_previews().is_empty());
    assert_eq!(assessment.quarantine_previews().len(), 1);
}

#[test]
fn differing_corrupt_replicas_are_typed_without_disclosing_content_digests() {
    let expected = [0x41; 16];
    let corrupt_a = [0x42; 16];
    let corrupt_b = [0x43; 16];
    let reference = chunk_ref(&expected);
    let disagreement = assess_replica_set(
        GENERATION,
        reference,
        expected.len() as u64,
        &[
            present(BACKEND_A, &corrupt_a, corrupt_a.len() as u64),
            present(BACKEND_B, &corrupt_b, corrupt_b.len() as u64),
        ],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        disagreement.disposition(),
        ReplicaDisposition::ReplicaDisagreementNoVerifiedSource
    );
    assert_eq!(disagreement.preferred_source(), None);
    assert!(disagreement.repair_previews().is_empty());
    assert_eq!(disagreement.quarantine_previews().len(), 2);

    let same_corruption = assess_replica_set(
        GENERATION,
        reference,
        expected.len() as u64,
        &[
            present(BACKEND_A, &corrupt_a, corrupt_a.len() as u64),
            present(BACKEND_B, &corrupt_a, corrupt_a.len() as u64),
        ],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        same_corruption.disposition(),
        ReplicaDisposition::NoVerifiedSource
    );
    assert_ne!(
        disagreement.binding_sha256(),
        same_corruption.binding_sha256()
    );
    let debug = format!("{disagreement:?}");
    assert!(!debug.contains(&"42".repeat(corrupt_a.len())));
    assert!(!debug.contains(&"43".repeat(corrupt_b.len())));
}

#[test]
fn ambiguity_or_unavailability_suppresses_every_disposition_preview() {
    let bytes = b"verified but obstructed";
    let reference = chunk_ref(bytes);
    for observation in [
        ReplicaCandidateObservation::Ambiguous,
        ReplicaCandidateObservation::Unavailable,
    ] {
        let assessment = assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[
                present(BACKEND_A, bytes, bytes.len() as u64),
                ReplicaCandidate {
                    backend: BACKEND_B,
                    observation,
                },
                present(BACKEND_C, b"not the expected bytes", bytes.len() as u64),
            ],
            &ReplicaAssessmentLimits::default(),
            &VerificationControl::default(),
        )
        .unwrap();
        assert_eq!(assessment.disposition(), ReplicaDisposition::Indeterminate);
        assert_eq!(assessment.preferred_source(), None);
        assert!(assessment.quarantine_previews().is_empty());
        assert!(assessment.repair_previews().is_empty());
    }
}

#[test]
fn metadata_requires_exact_identity_framing_schema_and_kind() {
    let malformed = [0xff];
    let malformed_reference = ObjectRef {
        kind: ObjectKind::Tree,
        digest: opaque_object_digest(ObjectKind::Tree.code(), &malformed).unwrap(),
    };
    let malformed_assessment = assess_replica_set(
        GENERATION,
        malformed_reference,
        malformed.len() as u64,
        &[present(BACKEND_A, &malformed, malformed.len() as u64)],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        malformed_assessment.copy_outcome_count(ReplicaCopyOutcome::FramingVersion),
        1
    );

    let graph = Graph::golden();
    let snapshot_bytes = match graph.source.objects.get(&graph.snapshot).unwrap() {
        Behavior::Found { bytes, .. } => bytes,
        other => panic!("unexpected fixture behavior: {other:?}"),
    };
    let rebound_kind = ObjectRef {
        kind: ObjectKind::Tree,
        digest: opaque_object_digest(ObjectKind::Tree.code(), snapshot_bytes).unwrap(),
    };
    let kind_assessment = assess_replica_set(
        GENERATION,
        rebound_kind,
        snapshot_bytes.len() as u64,
        &[present(
            BACKEND_A,
            snapshot_bytes,
            snapshot_bytes.len() as u64,
        )],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        kind_assessment.copy_outcome_count(ReplicaCopyOutcome::FramingVersion),
        1
    );
}

#[test]
fn metadata_preflight_reserves_the_exact_decode_safety_envelope() {
    let graph = Graph::golden();
    let snapshot_bytes = match graph.source.objects.get(&graph.snapshot).unwrap() {
        Behavior::Found { bytes, .. } => bytes,
        other => panic!("unexpected fixture behavior: {other:?}"),
    };
    let max_single_copy_bytes = snapshot_bytes.len() as u64;
    let max_decode_working_bytes = 64 * 1_024;
    let exact_memory = 1_856 + max_single_copy_bytes * 4 + max_decode_working_bytes;
    let exact = ReplicaAssessmentLimits {
        max_replicas: 1,
        max_single_copy_bytes,
        max_total_bytes: max_single_copy_bytes,
        max_work_units: 6,
        max_charged_memory_bytes: exact_memory,
        max_decode_working_bytes,
    };
    let candidate = present(BACKEND_A, snapshot_bytes, max_single_copy_bytes);

    let assessment = assess_replica_set(
        GENERATION,
        graph.snapshot,
        max_single_copy_bytes,
        &[candidate],
        &exact,
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        assessment.disposition(),
        ReplicaDisposition::SingleVerifiedCopy
    );

    let insufficient = ReplicaAssessmentLimits {
        max_charged_memory_bytes: exact_memory - 1,
        ..exact
    };
    assert_eq!(
        assess_replica_set(
            GENERATION,
            graph.snapshot,
            max_single_copy_bytes,
            &[candidate],
            &insufficient,
            &VerificationControl::default(),
        ),
        Err(ReplicaAssessmentError::MemoryLimit)
    );
}

#[test]
fn declared_or_observed_length_mismatch_precedes_identity_acceptance() {
    let bytes = b"length-bound bytes";
    let reference = chunk_ref(bytes);
    for (declared, expected) in [
        (bytes.len() as u64 + 1, bytes.len() as u64),
        (bytes.len() as u64, bytes.len() as u64 + 1),
    ] {
        let assessment = assess_replica_set(
            GENERATION,
            reference,
            expected,
            &[present(BACKEND_A, bytes, declared)],
            &ReplicaAssessmentLimits::default(),
            &VerificationControl::default(),
        )
        .unwrap();
        assert_eq!(
            assessment.copy_outcome_count(ReplicaCopyOutcome::SizeMismatch),
            1
        );
    }
}

#[test]
fn preflight_enforces_count_byte_work_memory_and_cancellation_bounds() {
    let bytes = b"1234";
    let reference = chunk_ref(bytes);
    let control = VerificationControl::default();

    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[],
            &ReplicaAssessmentLimits::default(),
            &control,
        ),
        Err(ReplicaAssessmentError::EmptyReplicaSet)
    );

    let limits = ReplicaAssessmentLimits {
        max_replicas: 1,
        ..ReplicaAssessmentLimits::default()
    };
    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[
                present(BACKEND_A, bytes, bytes.len() as u64),
                present(BACKEND_B, bytes, bytes.len() as u64),
            ],
            &limits,
            &control,
        ),
        Err(ReplicaAssessmentError::ReplicaLimit)
    );

    let limits = ReplicaAssessmentLimits {
        max_single_copy_bytes: bytes.len() as u64 - 1,
        ..ReplicaAssessmentLimits::default()
    };
    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[present(BACKEND_A, bytes, bytes.len() as u64)],
            &limits,
            &control,
        ),
        Err(ReplicaAssessmentError::ByteLimit)
    );

    let limits = ReplicaAssessmentLimits {
        max_total_bytes: bytes.len() as u64 * 2 - 1,
        ..ReplicaAssessmentLimits::default()
    };
    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[
                present(BACKEND_A, bytes, bytes.len() as u64),
                present(BACKEND_B, bytes, bytes.len() as u64),
            ],
            &limits,
            &control,
        ),
        Err(ReplicaAssessmentError::ByteLimit)
    );

    let limits = ReplicaAssessmentLimits {
        max_work_units: 3,
        ..ReplicaAssessmentLimits::default()
    };
    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[present(BACKEND_A, bytes, bytes.len() as u64)],
            &limits,
            &control,
        ),
        Err(ReplicaAssessmentError::WorkLimit)
    );

    let limits = ReplicaAssessmentLimits {
        max_charged_memory_bytes: 1_855,
        ..ReplicaAssessmentLimits::default()
    };
    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[present(BACKEND_A, bytes, bytes.len() as u64)],
            &limits,
            &control,
        ),
        Err(ReplicaAssessmentError::MemoryLimit)
    );

    let cancelled = VerificationControl::default();
    cancelled.cancel();
    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[present(BACKEND_A, bytes, bytes.len() as u64)],
            &ReplicaAssessmentLimits::default(),
            &cancelled,
        ),
        Err(ReplicaAssessmentError::Cancelled)
    );

    let limits = ReplicaAssessmentLimits {
        max_replicas: 65,
        ..ReplicaAssessmentLimits::default()
    };
    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &[present(BACKEND_A, bytes, bytes.len() as u64)],
            &limits,
            &control,
        ),
        Err(ReplicaAssessmentError::InvalidLimits)
    );
}

#[test]
fn duplicate_backend_and_every_bound_accept_exact_then_reject_plus_one() {
    let bytes = b"exact bound";
    let reference = chunk_ref(bytes);
    let duplicate = [
        present(BACKEND_A, bytes, bytes.len() as u64),
        missing(BACKEND_A),
    ];
    assert_eq!(
        assess_replica_set(
            GENERATION,
            reference,
            bytes.len() as u64,
            &duplicate,
            &ReplicaAssessmentLimits::default(),
            &VerificationControl::default(),
        ),
        Err(ReplicaAssessmentError::DuplicateBackend)
    );

    let exact = ReplicaAssessmentLimits {
        max_replicas: 1,
        max_single_copy_bytes: bytes.len() as u64,
        max_total_bytes: bytes.len() as u64,
        max_work_units: 4,
        max_charged_memory_bytes: 1_856,
        ..ReplicaAssessmentLimits::default()
    };
    assert!(assess_replica_set(
        GENERATION,
        reference,
        bytes.len() as u64,
        &[present(BACKEND_A, bytes, bytes.len() as u64)],
        &exact,
        &VerificationControl::default(),
    )
    .is_ok());
}

#[test]
fn binding_and_local_validation_cover_every_represented_axis() {
    let bytes = b"commitment fixture";
    let reference = chunk_ref(bytes);
    let baseline = assess_replica_set(
        GENERATION,
        reference,
        bytes.len() as u64,
        &[present(BACKEND_A, bytes, bytes.len() as u64)],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    assert_eq!(
        baseline.disposition(),
        ReplicaDisposition::SingleVerifiedCopy
    );
    let changed_backend = assess_replica_set(
        GENERATION,
        reference,
        bytes.len() as u64,
        &[present(BACKEND_B, bytes, bytes.len() as u64)],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    let changed_expected = assess_replica_set(
        GENERATION,
        reference,
        bytes.len() as u64 + 1,
        &[present(BACKEND_A, bytes, bytes.len() as u64)],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();
    let changed_reference = ObjectRef {
        kind: reference.kind,
        digest: [0x99; 32],
    };
    let changed_object = assess_replica_set(
        GENERATION,
        changed_reference,
        bytes.len() as u64,
        &[present(BACKEND_A, bytes, bytes.len() as u64)],
        &ReplicaAssessmentLimits::default(),
        &VerificationControl::default(),
    )
    .unwrap();

    assert_ne!(baseline.binding_sha256(), changed_backend.binding_sha256());
    assert_ne!(baseline.binding_sha256(), changed_expected.binding_sha256());
    assert_ne!(baseline.binding_sha256(), changed_object.binding_sha256());
}
