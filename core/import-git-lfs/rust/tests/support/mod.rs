#![allow(dead_code)]

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ogvcs_git_import_preflight::*;
use sha2::{Digest, Sha256};

pub const SOURCE_GENERATION: [u8; 32] = [0x91; 32];
pub const LFS_GENERATION: [u8; 32] = [0x92; 32];
pub const MAPPING_GENERATION: [u8; 32] = [0x93; 32];

pub fn sha1(byte: u8) -> GitObjectId {
    GitObjectId::from_sha1([byte; 20]).unwrap()
}

pub fn sha256_oid(byte: u8) -> GitObjectId {
    GitObjectId::from_sha256([byte; 32]).unwrap()
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn canonical_pointer(content: &[u8]) -> Vec<u8> {
    format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {}\n",
        hex(&digest(content)),
        content.len()
    )
    .into_bytes()
}

pub fn extension_pointer(content: &[u8]) -> Vec<u8> {
    let before = digest(b"before-extension");
    format!(
        "version https://git-lfs.github.com/spec/v1\next-0-crypt sha256:{}\noid sha256:{}\nsize {}\n",
        hex(&before),
        hex(&digest(content)),
        content.len()
    )
    .into_bytes()
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    )
}

pub fn policy() -> ImportPolicy {
    ImportPolicy {
        descriptor: ObjectRef {
            kind: ObjectKind::RepositoryDescriptor,
            digest: [0x31; 32],
        },
        importer_profile: ProfileRef::new("importer.test", "fixture-adapter", 1).unwrap(),
        source_namespace_digest: [0x41; 32],
        path_profile: PathProfile::parse("path.opengamevcs/portable@1").unwrap(),
        case_mode: CaseMode::Folded,
        permit_executable: false,
        permit_symlink_inventory: false,
        permit_submodule_inventory: false,
    }
}

pub fn mapping_request(identity: u8, file_id: u8) -> ImportRequest {
    let policy = policy();
    ImportRequest {
        importer_profile: policy.importer_profile,
        source_namespace_digest: policy.source_namespace_digest,
        source_identity_digest: [identity; 32],
        requested_file_id: FileId::new([file_id; 16]).unwrap(),
    }
}

pub fn path_digest(path: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"opengamevcs/git-import/path-diagnostic/v1\0");
    hash.update((path.len() as u64).to_be_bytes());
    hash.update(path.as_bytes());
    hash.finalize().into()
}

pub fn occurrence(id: GitObjectId, path: &str) -> SourceOccurrence {
    SourceOccurrence::new(id, path_digest(path))
}

pub fn ready_fixture() -> (Vec<ImportRecord>, BTreeMap<LfsObjectId, Vec<u8>>) {
    let content = b"hello\n".to_vec();
    let pointer = canonical_pointer(&content);
    let lfs_oid = match classify_lfs_pointer(&pointer).unwrap() {
        PointerClassification::Canonical(pointer) => pointer.oid,
        PointerClassification::NotPointer => unreachable!(),
    };
    let records = vec![
        ImportRecord::Ref {
            name: "refs/heads/main".to_owned(),
            target: sha1(1),
        },
        ImportRecord::Commit {
            id: sha1(1),
            encoded_bytes: 100,
            parent_count: 0,
        },
        ImportRecord::Tree {
            id: sha1(2),
            encoded_bytes: 50,
            entry_count: 1,
        },
        ImportRecord::Entry {
            id: sha1(3),
            path: "Assets/hello.txt".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer,
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(3), "Assets/hello.txt"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    (records, BTreeMap::from([(lfs_oid, content)]))
}

pub struct VecInventory {
    records: VecDeque<ImportRecord>,
    generation: [u8; 32],
    calls: Cell<u64>,
    drift_after_call: Option<u64>,
    fail_at_call: Option<u64>,
}

impl VecInventory {
    pub fn new(records: Vec<ImportRecord>) -> Self {
        Self {
            records: records.into(),
            generation: SOURCE_GENERATION,
            calls: Cell::new(0),
            drift_after_call: None,
            fail_at_call: None,
        }
    }

    pub fn drift_after(mut self, call: u64) -> Self {
        self.drift_after_call = Some(call);
        self
    }

    pub fn with_generation(mut self, generation: [u8; 32]) -> Self {
        self.generation = generation;
        self
    }

    pub fn fail_at(mut self, call: u64) -> Self {
        self.fail_at_call = Some(call);
        self
    }

    pub fn calls(&self) -> u64 {
        self.calls.get()
    }
}

impl InventorySource for VecInventory {
    type Error = ();

    fn generation(&self) -> [u8; 32] {
        if self
            .drift_after_call
            .is_some_and(|threshold| self.calls.get() >= threshold)
        {
            [0xff; 32]
        } else {
            self.generation
        }
    }

    fn next_record(&mut self) -> Result<Option<ImportRecord>, Self::Error> {
        let call = self.calls.get() + 1;
        self.calls.set(call);
        if self.fail_at_call == Some(call) {
            return Err(());
        }
        Ok(self.records.pop_front())
    }
}

pub struct MapLfs {
    pub objects: BTreeMap<LfsObjectId, Vec<u8>>,
    pub ambiguous: bool,
    pub overreport: bool,
    pub generation: [u8; 32],
    pub reads: Cell<u64>,
    pub maximum_read_bytes: Option<usize>,
    pub drift_after_read: Option<u64>,
    pub fail_at_read: Option<u64>,
}

impl MapLfs {
    pub fn new(objects: BTreeMap<LfsObjectId, Vec<u8>>) -> Self {
        Self {
            objects,
            ambiguous: false,
            overreport: false,
            generation: LFS_GENERATION,
            reads: Cell::new(0),
            maximum_read_bytes: None,
            drift_after_read: None,
            fail_at_read: None,
        }
    }
}

impl LfsContentSource for MapLfs {
    type Error = ();

    fn generation(&self) -> [u8; 32] {
        if self
            .drift_after_read
            .is_some_and(|threshold| self.reads.get() >= threshold)
        {
            [0xee; 32]
        } else {
            self.generation
        }
    }

    fn read(
        &mut self,
        oid: LfsObjectId,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<ImportReadStatus, Self::Error> {
        let call = self.reads.get() + 1;
        self.reads.set(call);
        if self.fail_at_read == Some(call) {
            return Err(());
        }
        if self.ambiguous {
            return Ok(ImportReadStatus::Ambiguous);
        }
        let Some(bytes) = self.objects.get(&oid) else {
            return Ok(ImportReadStatus::Missing);
        };
        if self.overreport {
            return Ok(ImportReadStatus::Data(buffer.len() + 1));
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= bytes.len() {
            return Ok(ImportReadStatus::Data(0));
        }
        let accepted = self
            .maximum_read_bytes
            .unwrap_or(buffer.len())
            .min(buffer.len());
        let end = (start + accepted).min(bytes.len());
        buffer[..end - start].copy_from_slice(&bytes[start..end]);
        Ok(ImportReadStatus::Data(end - start))
    }
}

pub struct Authority {
    pub descriptor: ObjectRef,
    pub generation: [u8; 32],
    pub calls: Cell<u64>,
    pub generation_calls: Cell<u64>,
    pub drift_after_decision: bool,
    pub drift_at_generation_call: Option<u64>,
    pub cancel_at_generation_call: Option<(u64, Arc<AtomicBool>)>,
    pub fail: bool,
    pub corrupt_key: bool,
    pub replacement_file_id: Option<FileId>,
    pub retry: bool,
    pub state: ImportState,
}

impl Authority {
    pub fn new(policy: &ImportPolicy) -> Self {
        Self {
            descriptor: policy.descriptor,
            generation: MAPPING_GENERATION,
            calls: Cell::new(0),
            generation_calls: Cell::new(0),
            drift_after_decision: false,
            drift_at_generation_call: None,
            cancel_at_generation_call: None,
            fail: false,
            corrupt_key: false,
            replacement_file_id: None,
            retry: false,
            state: ImportState::Reserved,
        }
    }
}

impl MappingAuthority for Authority {
    type Error = ();

    fn generation(&self) -> [u8; 32] {
        let generation_call = self.generation_calls.get() + 1;
        self.generation_calls.set(generation_call);
        if let Some((target, cancellation)) = &self.cancel_at_generation_call {
            if generation_call == *target {
                cancellation.store(true, Ordering::Release);
            }
        }
        if (self.drift_after_decision && self.calls.get() > 0)
            || self.drift_at_generation_call == Some(generation_call)
        {
            [0xdd; 32]
        } else {
            self.generation
        }
    }

    fn decide(&self, request: &ImportRequest) -> Result<ImportDecision, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(());
        }
        let file_id = self
            .replacement_file_id
            .unwrap_or(request.requested_file_id);
        let provisional = ImportMapping {
            descriptor: self.descriptor,
            importer_profile: request.importer_profile.clone(),
            source_namespace_digest: request.source_namespace_digest,
            source_identity_digest: request.source_identity_digest,
            file_id,
            state: self.state,
            declared_mapping_key: [0; 32],
        };
        let mut key = import_mapping_key(self.descriptor, &provisional).unwrap();
        if self.corrupt_key {
            key[0] ^= 0xff;
        }
        Ok(ImportDecision {
            file_id,
            state: self.state,
            retry: self.retry,
            mapping_key: key,
        })
    }
}

pub fn expectation(records: &[ImportRecord]) -> ExpectedInventory {
    let mut hash = Sha256::new();
    hash.update(b"opengamevcs/git-import/source-inventory/v1\0");
    let mut counts = InventoryCounts::default();
    let mut git_bytes = 0u64;
    let mut input_bytes = 0u64;
    let mut lfs_objects = BTreeSet::new();
    let mut lfs_pointer_blobs = BTreeSet::new();
    let mut blob_objects = BTreeSet::new();
    for record in records {
        counts.items += 1;
        input_bytes += record_input_bytes(record);
        match record {
            ImportRecord::Ref { name, target } => {
                counts.refs += 1;
                hash.update([1]);
                hash_bytes(&mut hash, name.as_bytes());
                hash_oid(&mut hash, *target);
            }
            ImportRecord::Commit {
                id,
                encoded_bytes,
                parent_count,
            } => {
                counts.commits += 1;
                counts.relationships += u64::from(*parent_count);
                git_bytes += encoded_bytes;
                hash.update([2]);
                hash_oid(&mut hash, *id);
                hash.update(encoded_bytes.to_be_bytes());
                hash.update(parent_count.to_be_bytes());
            }
            ImportRecord::Tree {
                id,
                encoded_bytes,
                entry_count,
            } => {
                counts.trees += 1;
                counts.relationships += entry_count;
                git_bytes += encoded_bytes;
                hash.update([3]);
                hash_oid(&mut hash, *id);
                hash.update(encoded_bytes.to_be_bytes());
                hash.update(entry_count.to_be_bytes());
            }
            ImportRecord::Entry {
                id,
                path,
                mode,
                encoded_bytes,
                pointer_probe,
                lfs,
            } => {
                counts.entries += 1;
                if *mode != GitEntryMode::Submodule {
                    counts.blob_occurrences += 1;
                    if blob_objects.insert(*id) {
                        counts.blobs += 1;
                        git_bytes += encoded_bytes;
                    }
                    if *lfs == LfsDisposition::Required
                        && *mode != GitEntryMode::Symlink
                        && lfs_pointer_blobs.insert(*id)
                    {
                        if let Ok(PointerClassification::Canonical(pointer)) =
                            classify_lfs_pointer(pointer_probe)
                        {
                            counts.lfs_pointers += 1;
                            lfs_objects.insert(pointer.oid);
                        }
                    }
                }
                hash.update([4]);
                hash_oid(&mut hash, *id);
                hash_bytes(&mut hash, path.as_bytes());
                hash.update(mode_code(*mode).to_be_bytes());
                hash.update(encoded_bytes.to_be_bytes());
                hash_bytes(&mut hash, pointer_probe);
                hash.update([match lfs {
                    LfsDisposition::Ordinary => 0,
                    LfsDisposition::Required => 1,
                }]);
            }
            ImportRecord::Mapping {
                occurrence,
                request,
            } => {
                counts.mappings += 1;
                hash.update([5]);
                hash_oid(&mut hash, occurrence.source_object());
                hash.update(occurrence.path_digest());
                hash_profile(&mut hash, &request.importer_profile);
                hash.update(request.source_namespace_digest);
                hash.update(request.source_identity_digest);
                hash.update(request.requested_file_id.as_bytes());
            }
        }
    }
    counts.lfs_objects = lfs_objects.len() as u64;
    ExpectedInventory {
        source_generation: SOURCE_GENERATION,
        lfs_generation: LFS_GENERATION,
        mapping_generation: MAPPING_GENERATION,
        counts,
        git_bytes,
        input_bytes,
        inventory_digest: hash.finalize().into(),
    }
}

pub fn run_fixture(
    records: Vec<ImportRecord>,
    objects: BTreeMap<LfsObjectId, Vec<u8>>,
    policy_value: &ImportPolicy,
    limits: ImportLimits,
) -> Result<ImportPreflightReport, ImportPreflightError> {
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(policy_value);
    preflight_git_import(
        &mut inventory,
        &mut lfs,
        &mut authority,
        policy_value,
        limits,
        expected,
        &OperationControl::default(),
    )
}

fn hash_oid(hash: &mut Sha256, oid: GitObjectId) {
    if let Some(bytes) = oid.sha1_bytes() {
        hash.update([1]);
        hash.update(bytes);
    } else if let Some(bytes) = oid.sha256_bytes() {
        hash.update([2]);
        hash.update(bytes);
    } else {
        unreachable!();
    }
}

fn hash_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn hash_profile(hash: &mut Sha256, profile: &ProfileRef) {
    hash_bytes(hash, profile.namespace().as_bytes());
    hash_bytes(hash, profile.id().as_bytes());
    hash.update(profile.major().to_be_bytes());
}

fn mode_code(mode: GitEntryMode) -> u32 {
    match mode {
        GitEntryMode::Regular => 0o100644,
        GitEntryMode::Executable => 0o100755,
        GitEntryMode::Symlink => 0o120000,
        GitEntryMode::Submodule => 0o160000,
    }
}

fn record_input_bytes(record: &ImportRecord) -> u64 {
    let base = 16u64;
    match record {
        ImportRecord::Ref { name, target } => base + name.len() as u64 + target.byte_len() as u64,
        ImportRecord::Commit { id, .. } | ImportRecord::Tree { id, .. } => {
            base + 16 + id.byte_len() as u64
        }
        ImportRecord::Entry {
            id,
            path,
            pointer_probe,
            ..
        } => base + 24 + id.byte_len() as u64 + path.len() as u64 + pointer_probe.len() as u64,
        ImportRecord::Mapping {
            occurrence,
            request,
        } => {
            base + 144
                + occurrence.source_object().byte_len() as u64
                + request.importer_profile.namespace().len() as u64
                + request.importer_profile.id().len() as u64
        }
    }
}
