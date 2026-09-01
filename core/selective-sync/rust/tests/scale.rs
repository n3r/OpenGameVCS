use std::io::{self, Write};

use ogvcs_path_contract::CaseMode;
use ogvcs_selective_sync_kernel::{
    selection_spec_digest, ContentIdentity, EvaluationBindings, EvaluationControl, HostPlatform,
    IteratorMetadataSource, MatchKind, Materialization, MetadataProjectionBuilder, MetadataRecord,
    SelectionError, SelectionKernel, SelectionRule, SelectionSpec, METADATA_RECORDS_MAXIMUM,
    SINK_FRAGMENT_BYTES_MAXIMUM,
};

fn record(ordinal: u64) -> MetadataRecord {
    let mut entry_digest = [0xabu8; 32];
    entry_digest[..8].copy_from_slice(&ordinal.to_be_bytes());
    MetadataRecord {
        ordinal,
        path: format!("Scale/{ordinal:06}"),
        entry_digest,
        content: Some(ContentIdentity {
            digest: [0xcdu8; 32],
            logical_bytes: 1,
        }),
    }
}

fn spec() -> SelectionSpec {
    SelectionSpec::from_rules(
        Materialization::AbsentBySpec,
        [SelectionRule::new(
            0,
            MatchKind::Subtree,
            "Scale",
            Materialization::Full,
        )],
    )
    .unwrap()
}

fn kernel(count: u64) -> SelectionKernel {
    let spec = spec();
    let spec_digest = selection_spec_digest(
        &spec,
        "path.opengamevcs/linux@1",
        CaseMode::Sensitive,
        HostPlatform::Linux,
    )
    .unwrap();
    let mut projection = MetadataProjectionBuilder::new(count).unwrap();
    for ordinal in 0..count {
        projection.push(&record(ordinal)).unwrap();
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
        projection.digest,
        count,
    )
    .unwrap();
    SelectionKernel::new(bindings, spec).unwrap()
}

#[derive(Default)]
struct CountingSink {
    bytes: u64,
    calls: u64,
    maximum_fragment: usize,
}

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes += bytes.len() as u64;
        self.calls += 1;
        self.maximum_fragment = self.maximum_fragment.max(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn exact_100000_is_streamed_with_one_bounded_record_and_fragment_at_a_time() {
    let kernel = kernel(METADATA_RECORDS_MAXIMUM);
    let mut source = IteratorMetadataSource::new((0..METADATA_RECORDS_MAXIMUM).map(record));
    let mut sink = CountingSink::default();
    let summary = kernel
        .evaluate(&mut source, &mut sink, &EvaluationControl::default())
        .unwrap();
    assert_eq!(summary.record_count, METADATA_RECORDS_MAXIMUM);
    assert_eq!(summary.full_count, METADATA_RECORDS_MAXIMUM);
    assert_eq!(summary.full_content_count, METADATA_RECORDS_MAXIMUM);
    assert_eq!(summary.full_logical_bytes, METADATA_RECORDS_MAXIMUM);
    assert_eq!(summary.output_bytes, sink.bytes);
    assert!(sink.calls >= METADATA_RECORDS_MAXIMUM);
    assert!(sink.maximum_fragment <= SINK_FRAGMENT_BYTES_MAXIMUM);
}

#[test]
fn count_plus_one_is_rejected_before_retaining_or_emitting_the_extra_record() {
    assert_eq!(
        EvaluationBindings::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "path.opengamevcs/linux@1",
            CaseMode::Sensitive,
            HostPlatform::Linux,
            [4; 32],
            [5; 32],
            METADATA_RECORDS_MAXIMUM + 1,
        )
        .unwrap_err(),
        SelectionError::MetadataCountLimit
    );

    let kernel = kernel(METADATA_RECORDS_MAXIMUM);
    let mut source = IteratorMetadataSource::new((0..=METADATA_RECORDS_MAXIMUM).map(record));
    let mut sink = CountingSink::default();
    assert_eq!(
        kernel.evaluate(&mut source, &mut sink, &EvaluationControl::default()),
        Err(SelectionError::MetadataCountMismatch)
    );
}
