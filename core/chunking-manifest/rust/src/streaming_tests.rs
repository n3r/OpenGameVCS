use std::{
    cell::Cell,
    fs::{create_dir, read_dir, remove_dir},
    io::{self, Write},
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use super::*;

#[derive(Default)]
struct CountingSink {
    bytes: u64,
    maximum_write_bytes: usize,
    writes: u64,
}

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .expect("test byte count");
        self.maximum_write_bytes = self.maximum_write_bytes.max(bytes.len());
        self.writes += 1;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FailAfter {
    accepted: u64,
    maximum: u64,
}

impl Write for FailAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.accepted >= self.maximum {
            return Err(io::Error::new(io::ErrorKind::Other, "injected failure"));
        }
        let remaining = usize::try_from(self.maximum - self.accepted).unwrap_or(usize::MAX);
        let accepted = remaining.min(bytes.len());
        self.accepted += accepted as u64;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CancelOnFirstWrite {
    control: OperationControl,
    writes: u64,
}

struct FailOnFlush;

impl Write for FailOnFlush {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Other, "injected failure"))
    }
}

impl Write for CancelOnFirstWrite {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.writes == 0 {
            self.control.cancel();
        }
        self.writes += 1;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct SyntheticRecords {
    count: u64,
    visited: Rc<Cell<u64>>,
}

impl SyntheticRecords {
    fn new(count: u64) -> (Self, Rc<Cell<u64>>) {
        let visited = Rc::new(Cell::new(0));
        (
            Self {
                count,
                visited: Rc::clone(&visited),
            },
            visited,
        )
    }
}

impl ManifestRecords for SyntheticRecords {
    fn record_count(&self) -> u64 {
        self.count
    }

    fn visit_records(
        &mut self,
        consume: &mut dyn FnMut(LedgerRecord) -> Result<(), ChunkError>,
    ) -> Result<(), ChunkError> {
        for index in 0..self.count {
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&index.to_be_bytes());
            consume(LedgerRecord {
                digest,
                length: 1,
                boundary: index + 1,
            })?;
            self.visited.set(index + 1);
        }
        Ok(())
    }
}

fn encode_synthetic<W: Write>(
    count: u64,
    writer: W,
) -> Result<(ManifestEncodingSummary, Rc<Cell<u64>>), ChunkError> {
    let (mut records, visited) = SyntheticRecords::new(count);
    let summary = encode_manifest_to(
        writer,
        count,
        [0x5a; 32],
        &mut records,
        &OperationControl::default(),
        Instant::now(),
    )?;
    Ok((summary, visited))
}

fn scratch_directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "ogvcs-chunk-streaming-unit-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    create_dir(&path).unwrap();
    path
}

#[test]
fn synthetic_streaming_counts_one_4096_and_100000_parts_with_bounded_output_state() {
    assert!(std::mem::size_of::<ManifestStreamSummary>() <= 256);
    for count in [1, 4_096, 100_000] {
        let mut sink = CountingSink::default();
        let (summary, visited) = encode_synthetic(count, &mut sink).unwrap();
        assert_eq!(visited.get(), count);
        assert_eq!(sink.bytes, summary.bytes);
        assert!(sink.bytes > count);
        assert!(sink.bytes <= MANIFEST_BYTES_MAXIMUM);
        assert!(sink.writes > count);
        assert!(sink.maximum_write_bytes <= MANIFEST_EMIT_BYTES_MAXIMUM);
        assert!(summary
            .object_id
            .starts_with("ogvcs:v1:content-manifest:sha256:"));
    }
}

#[test]
fn count_maximum_plus_one_is_rejected_before_visiting_or_writing() {
    let count = CHUNK_COUNT_MAXIMUM as u64 + 1;
    let (mut records, visited) = SyntheticRecords::new(count);
    let mut sink = CountingSink::default();
    let error = encode_manifest_to(
        &mut sink,
        count,
        [0x5a; 32],
        &mut records,
        &OperationControl::default(),
        Instant::now(),
    )
    .unwrap_err();
    assert_eq!(error, ChunkError::CountExceeded);
    assert_eq!(visited.get(), 0);
    assert_eq!(sink.bytes, 0);
    assert_eq!(sink.writes, 0);
}

#[test]
fn first_middle_and_last_byte_sink_failures_return_no_summary() {
    let mut counting = CountingSink::default();
    let (complete, _) = encode_synthetic(4_096, &mut counting).unwrap();
    assert_eq!(complete.bytes, counting.bytes);

    for maximum in [0, complete.bytes / 2, complete.bytes - 1] {
        let mut writer = FailAfter {
            accepted: 0,
            maximum,
        };
        assert_eq!(
            encode_synthetic(4_096, &mut writer).unwrap_err(),
            ChunkError::SinkFailed
        );
        assert_eq!(writer.accepted, maximum);
    }
}

#[test]
fn final_sink_flush_failure_returns_no_summary() {
    assert_eq!(
        encode_synthetic(4_096, FailOnFlush).unwrap_err(),
        ChunkError::SinkFailed
    );
}

#[test]
fn cancellation_during_manifest_output_returns_no_summary() {
    let control = OperationControl::default();
    let (mut records, visited) = SyntheticRecords::new(4_096);
    let writer = CancelOnFirstWrite {
        control: control.clone(),
        writes: 0,
    };
    let error = encode_manifest_to(
        writer,
        4_096,
        [0x5a; 32],
        &mut records,
        &control,
        Instant::now(),
    )
    .unwrap_err();
    assert_eq!(error, ChunkError::ResourceExhausted);
    assert_eq!(visited.get(), 0);
}

#[test]
fn cancellation_of_a_spilled_manifest_replay_leaves_no_ledger_artifact() {
    let directory = scratch_directory();
    let mut ledger = Ledger::new(LedgerOptions {
        max_memory_bytes: 0,
        max_scratch_bytes: 1024 * 1024,
        scratch_directory: directory.clone(),
    })
    .unwrap();
    for index in 0..4_096u64 {
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&index.to_be_bytes());
        ledger
            .append(LedgerRecord {
                digest,
                length: 1,
                boundary: index + 1,
            })
            .unwrap();
    }
    assert!(ledger.metrics().spilled);
    assert_eq!(read_dir(&directory).unwrap().count(), 1);

    let control = OperationControl::default();
    let writer = CancelOnFirstWrite {
        control: control.clone(),
        writes: 0,
    };
    let error = encode_manifest_to(
        writer,
        4_096,
        [0x5a; 32],
        &mut ledger,
        &control,
        Instant::now(),
    )
    .unwrap_err();
    assert_eq!(error, ChunkError::ResourceExhausted);
    drop(ledger);
    assert_eq!(read_dir(&directory).unwrap().count(), 0);
    remove_dir(directory).unwrap();
}
