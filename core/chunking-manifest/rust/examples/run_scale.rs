use std::{
    cell::RefCell,
    env, fs,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    rc::Rc,
    time::Instant,
};

use ogvcs_chunking_manifest::{
    ChunkError, Chunker, LedgerOptions, MANIFEST_BYTES_MAXIMUM, MANIFEST_EMIT_BYTES_MAXIMUM,
    PROFILE, SCALAR_WORKING_MINIMUM,
};
use ogvcs_object_model::{sha256, Sha256Writer};
use serde_json::json;

const LOGICAL_BYTES: u64 = 100 * 1024 * 1024 * 1024;
const PATTERN_BYTES: usize = 8 * 1024 * 1024;
const REPETITIONS: u64 = LOGICAL_BYTES / PATTERN_BYTES as u64;
const LCG_SEED: u32 = 0x4f47_5643;
const LCG_MULTIPLIER: u32 = 1_664_525;
const LCG_INCREMENT: u32 = 1_013_904_223;
const PATTERN_SHA256: &str = "b4798e6f4c78cbeb0b69d6a83b60dfb1bb68196f8c7913dec1bf1bc6fa3921a4";
const WALL_TIME_MILLISECONDS_MAXIMUM: u64 = 18_000_000;
const PEAK_RSS_BYTES_MAXIMUM: u64 = 512 * 1024 * 1024;
const LEDGER_MEMORY_BYTES_MAXIMUM: u64 = 1024 * 1024;
const LEDGER_SCRATCH_BYTES_MAXIMUM: u64 = 64 * 1024 * 1024;
const TRANSCRIPT_DOMAIN: &[u8] = b"OGVCS-CHUNK-SCALE-BOUNDARY-TRANSCRIPT-V1\0";

struct ScaleStats {
    transcript: Sha256Writer,
    chunk_count: u64,
    total_chunk_bytes: u64,
    minimum_chunk_bytes: u64,
    maximum_chunk_bytes: u64,
}

struct ScratchCleanup(PathBuf);

impl Drop for ScratchCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ManifestFileSink {
    file: Option<File>,
    path: PathBuf,
    bytes: u64,
    maximum_write_bytes: usize,
}

impl ManifestFileSink {
    fn new(root: &Path) -> io::Result<Self> {
        let path = root.join("manifest.cbor.partial");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        Ok(Self {
            file: Some(options.open(&path)?),
            path,
            bytes: 0,
            maximum_write_bytes: 0,
        })
    }

    fn sync_and_remove(&mut self) -> io::Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "manifest sink already removed"))?;
        file.flush()?;
        file.sync_all()?;
        if file.metadata()?.len() != self.bytes {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "manifest sink length mismatch",
            ));
        }
        self.file.take();
        fs::remove_file(&self.path)?;
        File::open(
            self.path
                .parent()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "manifest parent missing"))?,
        )?
        .sync_all()
    }
}

impl Write for ManifestFileSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > MANIFEST_BYTES_MAXIMUM.saturating_sub(self.bytes) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "manifest sink bound exceeded",
            ));
        }
        self.maximum_write_bytes = self.maximum_write_bytes.max(bytes.len());
        let written = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "manifest sink removed"))?
            .write(bytes)?;
        self.bytes = self
            .bytes
            .checked_add(written as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "manifest byte overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "manifest sink removed"))?
            .flush()
    }
}

impl Drop for ManifestFileSink {
    fn drop(&mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.path);
    }
}

fn fail(message: &str) -> ! {
    panic!("chunking exact-scale failure: {message}");
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            use std::fmt::Write;
            write!(&mut text, "{byte:02x}").expect("string write");
            text
        })
}

fn source_pattern() -> Vec<u8> {
    let mut bytes = vec![0_u8; PATTERN_BYTES];
    let mut state = LCG_SEED;
    for byte in &mut bytes {
        state = state
            .wrapping_mul(LCG_MULTIPLIER)
            .wrapping_add(LCG_INCREMENT);
        *byte = (state >> 24) as u8;
    }
    bytes
}

fn source_revision() -> String {
    let value = env::var("OGVCS_SOURCE_REVISION")
        .unwrap_or_else(|_| fail("OGVCS_SOURCE_REVISION is required"));
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        fail("OGVCS_SOURCE_REVISION must be one exact lowercase Git object ID");
    }
    value
}

fn report_path() -> PathBuf {
    let value = env::var_os("OGVCS_SCALE_REPORT_PATH")
        .unwrap_or_else(|| fail("OGVCS_SCALE_REPORT_PATH is required"));
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        fail("OGVCS_SCALE_REPORT_PATH must be absolute");
    }
    path
}

fn scratch_root() -> PathBuf {
    let parent = env::var_os("RUNNER_TEMP")
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).unwrap_or_else(|_| fail("scratch randomness unavailable"));
    let root = parent.join(format!("ogvcs-chunk-scale-rust-{}", hex(&random)));
    fs::create_dir(&root).unwrap_or_else(|_| fail("scratch directory unavailable"));
    root
}

fn peak_rss_bytes() -> u64 {
    let status = fs::read_to_string("/proc/self/status")
        .unwrap_or_else(|_| fail("Linux VmHWM is unavailable"));
    let kib = status
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("VmHWM:")?;
            value.split_whitespace().next()?.parse::<u64>().ok()
        })
        .unwrap_or_else(|| fail("Linux VmHWM is invalid"));
    kib.checked_mul(1024)
        .unwrap_or_else(|| fail("Linux VmHWM overflowed"))
}

fn runtime_version() -> String {
    env::var("OGVCS_RUST_VERSION").unwrap_or_else(|_| "1.82.0".to_owned())
}

fn runtime_architecture() -> &'static str {
    match env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => fail("the exact campaign requires x64 or arm64"),
    }
}

fn main() {
    if env::consts::OS != "linux" {
        fail("the exact campaign is Linux-only");
    }
    let runtime_architecture = runtime_architecture();
    let source_revision = source_revision();
    let report_path = report_path();
    let scratch_root = ScratchCleanup(scratch_root());
    let started = Instant::now();
    let pattern = source_pattern();
    if hex(&sha256(&pattern)) != PATTERN_SHA256 {
        fail("the deterministic source pattern does not match its frozen digest");
    }
    let stats = Rc::new(RefCell::new(ScaleStats {
        transcript: {
            let mut writer = Sha256Writer::new();
            writer.update(TRANSCRIPT_DOMAIN);
            writer
        },
        chunk_count: 0,
        total_chunk_bytes: 0,
        minimum_chunk_bytes: u64::MAX,
        maximum_chunk_bytes: 0,
    }));
    let sink_stats = Rc::clone(&stats);
    let ledger_options = LedgerOptions {
        max_memory_bytes: LEDGER_MEMORY_BYTES_MAXIMUM,
        max_scratch_bytes: LEDGER_SCRATCH_BYTES_MAXIMUM,
        scratch_directory: scratch_root.0.clone(),
    };
    let mut chunker = Chunker::new_with_ledger_resources(
        LOGICAL_BYTES,
        PROFILE,
        1,
        0,
        SCALAR_WORKING_MINIMUM,
        ledger_options,
        false,
        move |_bytes, part, index| {
            let mut stats = sink_stats.borrow_mut();
            stats.total_chunk_bytes = stats
                .total_chunk_bytes
                .checked_add(part.length)
                .ok_or(ChunkError::ResourceExhausted)?;
            stats.minimum_chunk_bytes = stats.minimum_chunk_bytes.min(part.length);
            stats.maximum_chunk_bytes = stats.maximum_chunk_bytes.max(part.length);
            let boundary = stats.total_chunk_bytes;
            stats.transcript.update(&(index as u64).to_be_bytes());
            stats.transcript.update(&part.digest);
            stats.transcript.update(&part.length.to_be_bytes());
            stats.transcript.update(&boundary.to_be_bytes());
            stats.chunk_count += 1;
            Ok(())
        },
    )
    .unwrap_or_else(|error| fail(error.code()));

    for repetition in 0..REPETITIONS {
        chunker
            .update(&pattern)
            .unwrap_or_else(|error| fail(error.code()));
        if (repetition + 1) % 640 == 0 {
            eprintln!("[rust-scale] {} GiB / 100 GiB", (repetition + 1) / 128);
        }
    }
    let mut manifest_sink = ManifestFileSink::new(&scratch_root.0)
        .unwrap_or_else(|_| fail("manifest sink unavailable"));
    let result = chunker
        .finish_to_manifest(&mut manifest_sink)
        .unwrap_or_else(|error| fail(error.code()));
    if manifest_sink.bytes != result.manifest_bytes
        || manifest_sink.maximum_write_bytes > MANIFEST_EMIT_BYTES_MAXIMUM
    {
        fail("manifest sink bounds failed");
    }
    manifest_sink
        .sync_and_remove()
        .unwrap_or_else(|_| fail("manifest sink cleanup failed"));
    let scratch_artifacts_after = fs::read_dir(&scratch_root.0)
        .unwrap_or_else(|_| fail("scratch directory disappeared"))
        .count() as u64;
    let wall_time_milliseconds = u64::try_from(started.elapsed().as_millis())
        .unwrap_or_else(|_| fail("wall time overflowed"));
    let peak_rss_bytes = peak_rss_bytes();
    let throughput_bytes_per_second = LOGICAL_BYTES
        .saturating_mul(1000)
        .checked_div(wall_time_milliseconds.max(1))
        .unwrap_or(0);
    let manifest_sha256 = result.manifest_sha256;
    let manifest_bytes = result.manifest_bytes;
    let whole_file_sha256 = hex(&result.whole_file_digest);
    let manifest_object_id = result.manifest_object_id.clone();
    let ledger = result.ledger;
    let mut stats = stats.borrow_mut();
    let transcript = std::mem::take(&mut stats.transcript).finish();
    let chunk_count = stats.chunk_count;
    let total_chunk_bytes = stats.total_chunk_bytes;
    let minimum_chunk_bytes = stats.minimum_chunk_bytes;
    let maximum_chunk_bytes = stats.maximum_chunk_bytes;
    drop(stats);

    let mut violations = Vec::new();
    if result.logical_length != LOGICAL_BYTES || total_chunk_bytes != LOGICAL_BYTES {
        violations.push("logical byte accounting");
    }
    if result.class != "cdc-1m"
        || chunk_count == 0
        || result.part_count != chunk_count
        || ledger.records != chunk_count
    {
        violations.push("chunk accounting");
    }
    if minimum_chunk_bytes < 1 || maximum_chunk_bytes > 2_097_152 {
        violations.push("chunk size bounds");
    }
    if !ledger.spilled
        || ledger.peak_memory_bytes > LEDGER_MEMORY_BYTES_MAXIMUM
        || ledger.peak_scratch_bytes > LEDGER_SCRATCH_BYTES_MAXIMUM
    {
        violations.push("ledger bounds");
    }
    if scratch_artifacts_after != 0 {
        violations.push("scratch cleanup");
    }
    if peak_rss_bytes > PEAK_RSS_BYTES_MAXIMUM {
        violations.push("peak RSS");
    }
    if wall_time_milliseconds > WALL_TIME_MILLISECONDS_MAXIMUM {
        violations.push("wall time");
    }
    if !violations.is_empty() {
        fail(&format!(
            "declared bounds failed: {}",
            violations.join(", ")
        ));
    }
    fs::remove_dir_all(&scratch_root.0).unwrap_or_else(|_| fail("scratch cleanup failed"));

    let report = json!({
        "schemaVersion": "ogvcs.chunking-manifest/scale-report/v1",
        "implementation": "rust",
        "profile": PROFILE,
        "sourceRevision": source_revision,
        "exactScaleExecuted": true,
        "runtime": {
            "os": env::consts::OS,
            "architecture": runtime_architecture,
            "version": runtime_version(),
        },
        "source": {
            "schemaVersion": "ogvcs.chunking-manifest/scale-source-repeated-lcg-v1",
            "logicalBytes": LOGICAL_BYTES.to_string(),
            "patternBytes": PATTERN_BYTES,
            "repetitions": REPETITIONS,
            "patternSha256": PATTERN_SHA256,
            "seed": LCG_SEED,
            "multiplier": LCG_MULTIPLIER,
            "increment": LCG_INCREMENT,
            "outputByte": "state-bits-31-through-24-after-step",
        },
        "result": {
            "class": result.class,
            "logicalBytes": result.logical_length.to_string(),
            "chunkCount": chunk_count,
            "totalChunkBytes": total_chunk_bytes.to_string(),
            "minimumChunkBytes": minimum_chunk_bytes,
            "maximumChunkBytes": maximum_chunk_bytes,
            "wholeFileSha256": whole_file_sha256,
            "manifestObjectId": manifest_object_id,
            "manifestSha256": hex(&manifest_sha256),
            "manifestBytes": manifest_bytes,
            "boundaryTranscriptSha256": hex(&transcript),
        },
        "resources": {
            "wallTimeMilliseconds": wall_time_milliseconds,
            "throughputBytesPerSecond": throughput_bytes_per_second,
            "peakRssBytes": peak_rss_bytes,
            "maxRssSource": "linux:/proc/self/status:VmHWM-kib",
            "patternBufferBytes": pattern.len(),
            "scalarWorkingMemoryBytes": SCALAR_WORKING_MINIMUM,
            "ledgerRecords": ledger.records,
            "ledgerPeakMemoryBytes": ledger.peak_memory_bytes,
            "ledgerPeakScratchBytes": ledger.peak_scratch_bytes,
            "ledgerSpilled": ledger.spilled,
            "scratchArtifactsAfter": scratch_artifacts_after,
        },
        "bounds": {
            "wallTimeMillisecondsMaximum": WALL_TIME_MILLISECONDS_MAXIMUM,
            "peakRssBytesMaximum": PEAK_RSS_BYTES_MAXIMUM,
            "ledgerMemoryBytesMaximum": LEDGER_MEMORY_BYTES_MAXIMUM,
            "ledgerScratchBytesMaximum": LEDGER_SCRATCH_BYTES_MAXIMUM,
            "temporaryWholeFileAllowed": false,
        },
        "overallStatus": "passed",
    });

    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|_| fail("report directory unavailable"));
    }
    let report_bytes = format!(
        "{}\n",
        serde_json::to_string_pretty(&report)
            .unwrap_or_else(|_| fail("report serialization failed"))
    );
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&report_path)
        .unwrap_or_else(|_| fail("report create-new failed"));
    output
        .write_all(report_bytes.as_bytes())
        .and_then(|()| output.sync_all())
        .unwrap_or_else(|_| fail("report write failed"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_file_sink_is_create_new_bounded_synced_and_drop_cleaned() {
        let root = ScratchCleanup(scratch_root());
        let mut sink = ManifestFileSink::new(&root.0).unwrap();
        sink.write_all(&[0x5a; 63]).unwrap();
        assert_eq!(sink.bytes, 63);
        assert_eq!(sink.maximum_write_bytes, 63);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&sink.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        sink.sync_and_remove().unwrap();
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);

        let collision = root.0.join("manifest.cbor.partial");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&collision)
            .unwrap();
        assert!(ManifestFileSink::new(&root.0).is_err());
        fs::remove_file(collision).unwrap();

        {
            let mut partial = ManifestFileSink::new(&root.0).unwrap();
            partial.write_all(&[0xa7]).unwrap();
        }
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);

        {
            let mut bounded = ManifestFileSink::new(&root.0).unwrap();
            bounded.bytes = MANIFEST_BYTES_MAXIMUM;
            assert!(bounded.write(&[0]).is_err());
        }
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }
}
