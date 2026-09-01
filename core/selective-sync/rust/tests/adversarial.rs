use std::{
    io::{self, Write},
    sync::Arc,
};

use ogvcs_path_contract::CaseMode;
use ogvcs_selective_sync_kernel::{
    selection_spec_digest, ContentIdentity, EvaluationBindings, EvaluationControl, HostPlatform,
    IteratorMetadataSource, MatchKind, Materialization, MetadataProjectionBuilder, MetadataRecord,
    MetadataSource, SelectionError, SelectionKernel, SelectionRule, SelectionSpec,
};

fn record(ordinal: u64, path: &str, byte: u8) -> MetadataRecord {
    MetadataRecord {
        ordinal,
        path: path.to_owned(),
        entry_digest: [byte; 32],
        content: Some(ContentIdentity {
            digest: [byte.wrapping_add(1); 32],
            logical_bytes: u64::from(byte) + 1,
        }),
    }
}

fn records() -> Vec<MetadataRecord> {
    vec![
        record(0, "Game", 1),
        record(1, "Game/Derived", 2),
        record(2, "Game/Derived/Preview.bin", 3),
        record(3, "Game/Hero.bin", 4),
    ]
}

fn spec() -> SelectionSpec {
    SelectionSpec::from_rules(
        Materialization::AbsentBySpec,
        [
            SelectionRule::new(0, MatchKind::Exact, "Game", Materialization::MetadataOnly),
            SelectionRule::new(1, MatchKind::Subtree, "Game", Materialization::Full),
            SelectionRule::new(
                2,
                MatchKind::Subtree,
                "Game/Derived",
                Materialization::MetadataOnly,
            ),
            SelectionRule::new(
                3,
                MatchKind::Exact,
                "Game/Derived/Preview.bin",
                Materialization::AbsentBySpec,
            ),
        ],
    )
    .unwrap()
}

fn kernel_for(records: &[MetadataRecord], expected_metadata: Option<[u8; 32]>) -> SelectionKernel {
    let spec = spec();
    let spec_digest = selection_spec_digest(
        &spec,
        "path.opengamevcs/linux@1",
        CaseMode::Sensitive,
        HostPlatform::Linux,
    )
    .unwrap();
    let mut projection = MetadataProjectionBuilder::new(records.len() as u64).unwrap();
    for item in records {
        projection.push(item).unwrap();
    }
    let projection = projection.finish().unwrap();
    let bindings = EvaluationBindings::new(
        [1; 32],
        [2; 32],
        [3; 32],
        "path.opengamevcs/linux@1",
        CaseMode::Sensitive,
        HostPlatform::Linux,
        spec_digest,
        expected_metadata.unwrap_or(projection.digest),
        records.len() as u64,
    )
    .unwrap();
    SelectionKernel::new(bindings, spec).unwrap()
}

#[derive(Default)]
struct FragmentingSink {
    cap: usize,
    bytes: Vec<u8>,
    maximum_request: usize,
}

impl Write for FragmentingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.maximum_request = self.maximum_request.max(bytes.len());
        let count = bytes.len().min(self.cap.max(1));
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FaultSink {
    fail_after: usize,
    written: usize,
    fail_flush: bool,
}

impl Write for FaultSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.written >= self.fail_after {
            return Err(io::Error::other("injected write failure"));
        }
        let count = bytes.len().min(self.fail_after - self.written);
        self.written += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn sink_fragmentation_never_changes_projection_bytes_or_summary() {
    let input = records();
    let kernel = kernel_for(&input, None);
    let mut baseline_source = IteratorMetadataSource::new(input.clone().into_iter());
    let mut baseline = Vec::new();
    let wanted = kernel
        .evaluate(
            &mut baseline_source,
            &mut baseline,
            &EvaluationControl::default(),
        )
        .unwrap();
    for cap in [1, 2, 7, 31, 4_093] {
        let mut source = IteratorMetadataSource::new(input.clone().into_iter());
        let mut sink = FragmentingSink {
            cap,
            ..FragmentingSink::default()
        };
        let actual = kernel
            .evaluate(&mut source, &mut sink, &EvaluationControl::default())
            .unwrap();
        assert_eq!(actual, wanted);
        assert_eq!(sink.bytes, baseline);
        assert!(sink.maximum_request <= 4_154);
    }
}

#[test]
fn first_middle_last_and_flush_sink_faults_return_no_summary() {
    let input = records();
    let kernel = kernel_for(&input, None);
    let mut source = IteratorMetadataSource::new(input.clone().into_iter());
    let mut baseline = Vec::new();
    kernel
        .evaluate(&mut source, &mut baseline, &EvaluationControl::default())
        .unwrap();
    for fail_after in [0, baseline.len() / 2, baseline.len() - 1] {
        let mut source = IteratorMetadataSource::new(input.clone().into_iter());
        let mut sink = FaultSink {
            fail_after,
            written: 0,
            fail_flush: false,
        };
        assert_eq!(
            kernel.evaluate(&mut source, &mut sink, &EvaluationControl::default()),
            Err(SelectionError::SinkFailed)
        );
    }
    let mut source = IteratorMetadataSource::new(input.into_iter());
    let mut sink = FaultSink {
        fail_after: usize::MAX,
        written: 0,
        fail_flush: true,
    };
    assert_eq!(
        kernel.evaluate(&mut source, &mut sink, &EvaluationControl::default()),
        Err(SelectionError::SinkFailed)
    );
}

struct CancellingSource {
    records: std::vec::IntoIter<MetadataRecord>,
    cancellation: Arc<std::sync::atomic::AtomicBool>,
    before_ordinal: u64,
}

impl MetadataSource for CancellingSource {
    type Error = InfallibleSource;

    fn next_record(&mut self) -> std::result::Result<Option<MetadataRecord>, Self::Error> {
        let next = self.records.next();
        if next
            .as_ref()
            .is_some_and(|record| record.ordinal == self.before_ordinal)
        {
            self.cancellation
                .store(true, std::sync::atomic::Ordering::Release);
        }
        Ok(next)
    }
}

#[derive(Debug)]
struct InfallibleSource;

#[test]
fn cancellation_before_header_and_between_records_returns_no_summary() {
    let input = records();
    let kernel = kernel_for(&input, None);
    let control = EvaluationControl::default();
    control.cancel();
    let mut source = IteratorMetadataSource::new(input.clone().into_iter());
    let mut sink = Vec::new();
    assert_eq!(
        kernel.evaluate(&mut source, &mut sink, &control),
        Err(SelectionError::Cancelled)
    );
    assert!(sink.is_empty());

    let control = EvaluationControl::default();
    let flag = control.cancellation_flag();
    let mut source = CancellingSource {
        records: input.into_iter(),
        cancellation: flag,
        before_ordinal: 2,
    };
    let mut sink = Vec::new();
    assert_eq!(
        kernel.evaluate(&mut source, &mut sink, &control),
        Err(SelectionError::Cancelled)
    );
    assert!(!sink.is_empty());
}

struct FailingSource {
    first: Option<MetadataRecord>,
}

impl MetadataSource for FailingSource {
    type Error = ();

    fn next_record(&mut self) -> std::result::Result<Option<MetadataRecord>, Self::Error> {
        self.first.take().map_or(Err(()), |record| Ok(Some(record)))
    }
}

#[test]
fn source_short_long_failure_and_digest_mismatch_leave_only_discardable_bytes() {
    let input = records();
    let kernel = kernel_for(&input, None);
    let mut short = IteratorMetadataSource::new(input[..3].iter().cloned());
    let mut sink = Vec::new();
    assert_eq!(
        kernel.evaluate(&mut short, &mut sink, &EvaluationControl::default()),
        Err(SelectionError::MetadataCountMismatch)
    );
    assert!(!sink.is_empty());

    let mut long_records = input.clone();
    long_records.push(record(4, "Game/Other.bin", 5));
    let mut long = IteratorMetadataSource::new(long_records.into_iter());
    let mut sink = Vec::new();
    assert_eq!(
        kernel.evaluate(&mut long, &mut sink, &EvaluationControl::default()),
        Err(SelectionError::MetadataCountMismatch)
    );

    let mut failed = FailingSource {
        first: Some(input[0].clone()),
    };
    let mut sink = Vec::new();
    assert_eq!(
        kernel.evaluate(&mut failed, &mut sink, &EvaluationControl::default()),
        Err(SelectionError::SourceFailed)
    );

    let mismatch_kernel = kernel_for(&input, Some([0xff; 32]));
    let mut source = IteratorMetadataSource::new(input.into_iter());
    let mut sink = Vec::new();
    assert_eq!(
        mismatch_kernel.evaluate(&mut source, &mut sink, &EvaluationControl::default()),
        Err(SelectionError::MetadataDigestMismatch)
    );
    assert!(!sink.is_empty());
}

#[test]
fn order_duplicates_unicode_and_platform_collisions_fail_closed() {
    for input in [
        vec![record(0, "B", 1), record(1, "A", 2)],
        vec![record(0, "A", 1), record(1, "A", 2)],
    ] {
        let kernel = kernel_for(&input, None);
        let mut source = IteratorMetadataSource::new(input.into_iter());
        let mut sink = Vec::new();
        assert!(matches!(
            kernel.evaluate(&mut source, &mut sink, &EvaluationControl::default()),
            Err(SelectionError::MetadataOrderInvalid | SelectionError::PathCollision)
        ));
    }

    let spec = SelectionSpec::from_rules(Materialization::Full, []).unwrap();
    let spec_digest = selection_spec_digest(
        &spec,
        "path.opengamevcs/windows@1",
        CaseMode::Sensitive,
        HostPlatform::Windows,
    )
    .unwrap();
    let input = vec![record(0, "Game/Hero", 1), record(1, "game/hero", 2)];
    let mut projection = MetadataProjectionBuilder::new(2).unwrap();
    for item in &input {
        projection.push(item).unwrap();
    }
    let projection = projection.finish().unwrap();
    let bindings = EvaluationBindings::new(
        [1; 32],
        [2; 32],
        [3; 32],
        "path.opengamevcs/windows@1",
        CaseMode::Sensitive,
        HostPlatform::Windows,
        spec_digest,
        projection.digest,
        2,
    )
    .unwrap();
    let kernel = SelectionKernel::new(bindings, spec).unwrap();
    let mut source = IteratorMetadataSource::new(input.into_iter());
    let mut sink = Vec::new();
    assert_eq!(
        kernel.evaluate(&mut source, &mut sink, &EvaluationControl::default()),
        Err(SelectionError::PathCollision)
    );

    let decomposed = vec![record(0, "Game/Cafe\u{301}", 1)];
    let kernel = kernel_for(&decomposed, None);
    let mut source = IteratorMetadataSource::new(decomposed.into_iter());
    let mut sink = Vec::new();
    assert_eq!(
        kernel.evaluate(&mut source, &mut sink, &EvaluationControl::default()),
        Err(SelectionError::PathInvalid)
    );
}

#[test]
fn duplicate_and_unicode_fold_colliding_rules_are_rejected() {
    let duplicate = SelectionSpec::from_rules(
        Materialization::Full,
        [
            SelectionRule::new(0, MatchKind::Exact, "Game", Materialization::Full),
            SelectionRule::new(1, MatchKind::Exact, "Game", Materialization::MetadataOnly),
        ],
    )
    .unwrap();
    assert_eq!(
        selection_spec_digest(
            &duplicate,
            "path.opengamevcs/linux@1",
            CaseMode::Sensitive,
            HostPlatform::Linux,
        ),
        Err(SelectionError::RuleDuplicate)
    );

    let folded = SelectionSpec::from_rules(
        Materialization::Full,
        [
            SelectionRule::new(0, MatchKind::Exact, "Game/Straße", Materialization::Full),
            SelectionRule::new(
                1,
                MatchKind::Subtree,
                "Game/STRASSE",
                Materialization::MetadataOnly,
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        selection_spec_digest(
            &folded,
            "path.opengamevcs/linux@1",
            CaseMode::Folded,
            HostPlatform::Linux,
        ),
        Err(SelectionError::PathCollision)
    );
    assert_eq!(
        EvaluationBindings::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "path.opengamevcs/windows@1",
            CaseMode::Sensitive,
            HostPlatform::Linux,
            [4; 32],
            [5; 32],
            0,
        )
        .unwrap_err(),
        SelectionError::PlatformProfileMismatch
    );
}
