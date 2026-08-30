use std::{
    fs::{remove_dir, remove_file, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use crate::ChunkError;

pub const LEDGER_RECORD_BYTES: u64 = 48;
pub const DEFAULT_LEDGER_MEMORY_BYTES: u64 = 1_048_576;
pub const DEFAULT_SCRATCH_BYTES: u64 = 64 * 1024 * 1024;
pub const LEDGER_MAXIMUM_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LedgerOptions {
    pub max_memory_bytes: u64,
    pub max_scratch_bytes: u64,
    pub scratch_directory: PathBuf,
}

impl Default for LedgerOptions {
    fn default() -> Self {
        Self {
            max_memory_bytes: DEFAULT_LEDGER_MEMORY_BYTES,
            max_scratch_bytes: DEFAULT_SCRATCH_BYTES,
            scratch_directory: std::env::temp_dir(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerMetrics {
    pub records: u64,
    pub memory_bytes: u64,
    pub peak_memory_bytes: u64,
    pub scratch_bytes: u64,
    pub peak_scratch_bytes: u64,
    pub spilled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LedgerRecord {
    pub digest: [u8; 32],
    pub length: u64,
    pub boundary: u64,
}

impl LedgerRecord {
    fn encode(self) -> [u8; LEDGER_RECORD_BYTES as usize] {
        let mut bytes = [0u8; LEDGER_RECORD_BYTES as usize];
        bytes[..32].copy_from_slice(&self.digest);
        bytes[32..40].copy_from_slice(&self.length.to_be_bytes());
        bytes[40..48].copy_from_slice(&self.boundary.to_be_bytes());
        bytes
    }

    fn decode(bytes: [u8; LEDGER_RECORD_BYTES as usize]) -> Self {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[..32]);
        Self {
            digest,
            length: u64::from_be_bytes(bytes[32..40].try_into().expect("eight bytes")),
            boundary: u64::from_be_bytes(bytes[40..48].try_into().expect("eight bytes")),
        }
    }
}

pub(crate) struct Ledger {
    options: LedgerOptions,
    resident: Vec<[u8; LEDGER_RECORD_BYTES as usize]>,
    file: Option<File>,
    directory: Option<PathBuf>,
    path: Option<PathBuf>,
    count: u64,
    scratch_bytes: u64,
    peak_memory_bytes: u64,
    peak_scratch_bytes: u64,
}

impl Ledger {
    pub(crate) fn new(mut options: LedgerOptions) -> Result<Self, ChunkError> {
        let supplied = std::fs::symlink_metadata(&options.scratch_directory)
            .map_err(|_| ChunkError::ResourceInvalid)?;
        if options.max_memory_bytes > LEDGER_MAXIMUM_BYTES
            || options.max_scratch_bytes > LEDGER_MAXIMUM_BYTES
            || !supplied.is_dir()
            || supplied.file_type().is_symlink()
        {
            return Err(ChunkError::ResourceInvalid);
        }
        options.scratch_directory = std::fs::canonicalize(&options.scratch_directory)
            .map_err(|_| ChunkError::ResourceInvalid)?;
        let capacity =
            usize::try_from((options.max_memory_bytes / LEDGER_RECORD_BYTES).min(1_048_576))
                .map_err(|_| ChunkError::ResourceInvalid)?;
        let peak_memory_bytes = capacity as u64 * LEDGER_RECORD_BYTES;
        Ok(Self {
            options,
            resident: Vec::with_capacity(capacity),
            file: None,
            directory: None,
            path: None,
            count: 0,
            scratch_bytes: 0,
            peak_memory_bytes,
            peak_scratch_bytes: 0,
        })
    }

    pub(crate) const fn len(&self) -> u64 {
        self.count
    }

    fn private_directory(root: &Path) -> Result<PathBuf, ChunkError> {
        for _ in 0..32 {
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).map_err(|_| ChunkError::ScratchExhausted)?;
            let token =
                nonce
                    .iter()
                    .fold(String::with_capacity(nonce.len() * 2), |mut token, byte| {
                        use std::fmt::Write;
                        write!(&mut token, "{byte:02x}").expect("string write");
                        token
                    });
            let path = root.join(format!(".ogvcs-chunk-ledger-{token}"));
            match create_private_directory(&path) {
                Ok(()) => return Ok(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ChunkError::ScratchExhausted),
            }
        }
        Err(ChunkError::ScratchExhausted)
    }

    fn write_record(
        &mut self,
        bytes: &[u8; LEDGER_RECORD_BYTES as usize],
    ) -> Result<(), ChunkError> {
        let next = self
            .scratch_bytes
            .checked_add(LEDGER_RECORD_BYTES)
            .ok_or(ChunkError::ScratchExhausted)?;
        if next > self.options.max_scratch_bytes {
            return Err(ChunkError::ScratchExhausted);
        }
        self.file
            .as_mut()
            .ok_or(ChunkError::SessionFailed)?
            .write_all(bytes)
            .map_err(|_| ChunkError::ScratchExhausted)?;
        self.scratch_bytes = next;
        self.peak_scratch_bytes = self.peak_scratch_bytes.max(next);
        Ok(())
    }

    fn spill(&mut self) -> Result<(), ChunkError> {
        if self.file.is_some() {
            return Ok(());
        }
        let required = (self.resident.len() as u64 + 1)
            .checked_mul(LEDGER_RECORD_BYTES)
            .ok_or(ChunkError::ScratchExhausted)?;
        if required > self.options.max_scratch_bytes {
            return Err(ChunkError::ScratchExhausted);
        }
        let directory = Self::private_directory(&self.options.scratch_directory)?;
        let path = directory.join("records.bin");
        let file = match create_private_file(&path) {
            Ok(file) => file,
            Err(_) => {
                let _ = remove_dir(&directory);
                return Err(ChunkError::ScratchExhausted);
            }
        };
        self.directory = Some(directory);
        self.path = Some(path);
        self.file = Some(file);
        let resident = std::mem::take(&mut self.resident);
        for record in resident {
            if let Err(error) = self.write_record(&record) {
                self.cleanup();
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn append(&mut self, record: LedgerRecord) -> Result<(), ChunkError> {
        let resident_maximum = self.options.max_memory_bytes / LEDGER_RECORD_BYTES;
        let bytes = record.encode();
        if self.file.is_none() && (self.resident.len() as u64) < resident_maximum {
            self.resident.push(bytes);
        } else {
            self.spill()?;
            self.write_record(&bytes)?;
        }
        self.count = self.count.checked_add(1).ok_or(ChunkError::CountExceeded)?;
        Ok(())
    }

    pub(crate) fn for_each(
        &mut self,
        mut consume: impl FnMut(LedgerRecord) -> Result<(), ChunkError>,
    ) -> Result<(), ChunkError> {
        if let Some(file) = self.file.as_mut() {
            file.seek(SeekFrom::Start(0))
                .map_err(|_| ChunkError::SessionFailed)?;
            for _ in 0..self.count {
                let mut bytes = [0u8; LEDGER_RECORD_BYTES as usize];
                file.read_exact(&mut bytes)
                    .map_err(|_| ChunkError::SessionFailed)?;
                consume(LedgerRecord::decode(bytes))?;
            }
        } else {
            for bytes in &self.resident {
                consume(LedgerRecord::decode(*bytes))?;
            }
        }
        Ok(())
    }

    pub(crate) fn metrics(&self) -> LedgerMetrics {
        LedgerMetrics {
            records: self.count,
            memory_bytes: if self.file.is_none() {
                self.resident.len() as u64 * LEDGER_RECORD_BYTES
            } else {
                0
            },
            peak_memory_bytes: self.peak_memory_bytes,
            scratch_bytes: self.scratch_bytes,
            peak_scratch_bytes: self.peak_scratch_bytes,
            spilled: self.file.is_some(),
        }
    }

    pub(crate) fn cleanup(&mut self) {
        self.file.take();
        if let Some(path) = self.path.take() {
            let _ = remove_file(path);
        }
        if let Some(directory) = self.directory.take() {
            let _ = remove_dir(directory);
        }
        self.resident = Vec::new();
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

impl Drop for Ledger {
    fn drop(&mut self) {
        self.cleanup();
    }
}
