//! Bounded private OGVCS-018 backup-completeness manifest candidate.
#![forbid(unsafe_code)]

use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicBool, Ordering},
};

use ogvcs_object_model::{hard_limit_maximum, ObjectKind, ObjectRef, Sha256Writer};

// Digest framing stores lengths as u64. Reject any future unsupported target
// whose pointer-sized slice length could not be represented without loss.
const _: () = assert!(usize::BITS <= u64::BITS);

const ROOTS_MAXIMUM: u64 = 1_024;
const OBJECTS_MAXIMUM: u64 = 1_000_000;
const INVENTORY_BYTES_MAXIMUM: u64 = 1 << 50;
const WORK_UNITS_MAXIMUM: u64 = 2_001_024;
const RETAINED_BASE_CHARGE: u64 = 4_096;
const RETAINED_ROOT_CHARGE: u64 = 192;
const RETAINED_BYTES_MAXIMUM: u64 = RETAINED_BASE_CHARGE + (ROOTS_MAXIMUM * RETAINED_ROOT_CHARGE);

const ROOTS_DOMAIN: &[u8] = b"OpenGameVCS private backup roots rc1\0";
const INVENTORY_DOMAIN: &[u8] = b"OpenGameVCS private backup inventory rc1\0";
const COPIES_DOMAIN: &[u8] = b"OpenGameVCS private backup copy evidence rc1\0";
const MANIFEST_DOMAIN: &[u8] = b"OpenGameVCS private backup manifest rc1\0";

pub type Commitment = [u8; 32];
pub type Generation = [u8; 32];
pub const BACKUP_MANIFEST_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RootKind {
    Branch,
    Tag,
}

impl RootKind {
    const fn code(self) -> u8 {
        match self {
            Self::Branch => 1,
            Self::Tag => 2,
        }
    }
}

/// An opaque root row. `name_commitment` is not a ref name, but this crate
/// cannot prove that the caller's commitment construction is hiding or
/// unlinkable.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RootBinding {
    pub kind: RootKind,
    pub name_commitment: Commitment,
    pub snapshot: ObjectRef,
}

/// Opaque binding for the designated backup target and its declared policy.
/// None of these commitments is authority by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupTargetBinding {
    pub target: Commitment,
    pub credential_scope: Commitment,
    pub retention_policy: Commitment,
    pub encryption_policy: Commitment,
}

/// Immutable metadata boundary supplied by a future authenticated capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCapture {
    pub tenant: Commitment,
    pub repository: Commitment,
    pub metadata_generation: Generation,
    pub inventory_generation: Generation,
    pub schema: Commitment,
    pub protocol: Commitment,
    pub configuration: Commitment,
    pub lock_treatment: Commitment,
    pub audit_treatment: Commitment,
    pub capture_authority: Commitment,
    pub reachability_proof: Commitment,
    pub integrity_verification: Commitment,
    pub source_storage: Commitment,
    pub source_credential_scope: Commitment,
    pub target: BackupTargetBinding,
    pub captured_at_unix_seconds: u64,
    pub minimum_retention_until_unix_seconds: u64,
    pub declared_object_count: u64,
    pub declared_inventory_bytes: u64,
    pub roots: Vec<RootBinding>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjectInventoryEntry {
    pub object: ObjectRef,
    pub object_bytes: u64,
}

/// Supplied evidence for one copy in the declared target. This is data to bind,
/// not a trusted production receipt or credential.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BackupCopyEvidence {
    pub object: ObjectRef,
    pub object_bytes: u64,
    pub target: Commitment,
    pub storage_generation: Generation,
    pub verification_receipt: Commitment,
    pub retention_proof: Commitment,
    pub retention_until_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupLimits {
    pub max_roots: u64,
    pub max_objects: u64,
    pub max_inventory_bytes: u64,
    pub max_work_units: u64,
    pub max_retained_bytes: u64,
}

impl Default for BackupLimits {
    fn default() -> Self {
        Self {
            max_roots: ROOTS_MAXIMUM,
            max_objects: OBJECTS_MAXIMUM,
            max_inventory_bytes: INVENTORY_BYTES_MAXIMUM,
            max_work_units: WORK_UNITS_MAXIMUM,
            max_retained_bytes: RETAINED_BYTES_MAXIMUM,
        }
    }
}

impl BackupLimits {
    fn valid(self) -> bool {
        self.max_roots > 0
            && self.max_roots <= ROOTS_MAXIMUM
            && self.max_objects > 0
            && self.max_objects <= OBJECTS_MAXIMUM
            && self.max_inventory_bytes > 0
            && self.max_inventory_bytes <= INVENTORY_BYTES_MAXIMUM
            && self.max_work_units > 0
            && self.max_work_units <= WORK_UNITS_MAXIMUM
            && self.max_retained_bytes >= RETAINED_BASE_CHARGE
            && self.max_retained_bytes <= RETAINED_BYTES_MAXIMUM
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupError {
    InvalidLimits,
    InvalidCapture,
    RootLimit,
    RootOrder,
    ObjectLimit,
    ByteLimit,
    WorkLimit,
    MemoryLimit,
    InventoryOrder,
    CopyOrder,
    ObjectMismatch,
    MissingRoot,
    InvalidCopyEvidence,
    Cancelled,
    AccountingOverflow,
}

impl BackupError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "BACKUP_LIMITS_INVALID",
            Self::InvalidCapture => "BACKUP_CAPTURE_INVALID",
            Self::RootLimit => "BACKUP_ROOT_LIMIT",
            Self::RootOrder => "BACKUP_ROOT_ORDER",
            Self::ObjectLimit => "BACKUP_OBJECT_LIMIT",
            Self::ByteLimit => "BACKUP_BYTE_LIMIT",
            Self::WorkLimit => "BACKUP_WORK_LIMIT",
            Self::MemoryLimit => "BACKUP_MEMORY_LIMIT",
            Self::InventoryOrder => "BACKUP_INVENTORY_ORDER",
            Self::CopyOrder => "BACKUP_COPY_ORDER",
            Self::ObjectMismatch => "BACKUP_OBJECT_MISMATCH",
            Self::MissingRoot => "BACKUP_ROOT_MISSING",
            Self::InvalidCopyEvidence => "BACKUP_COPY_EVIDENCE_INVALID",
            Self::Cancelled => "BACKUP_CANCELLED",
            Self::AccountingOverflow => "BACKUP_ACCOUNTING_OVERFLOW",
        }
    }
}

pub struct BackupControl<'a> {
    cancellation: Option<&'a AtomicBool>,
}

impl<'a> BackupControl<'a> {
    pub const fn none() -> Self {
        Self { cancellation: None }
    }

    pub const fn with_cancellation(cancellation: &'a AtomicBool) -> Self {
        Self {
            cancellation: Some(cancellation),
        }
    }

    fn check(&self) -> Result<(), BackupError> {
        if self
            .cancellation
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            Err(BackupError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupManifest {
    pub version: u16,
    pub capture: BackupCapture,
    pub roots_digest: Commitment,
    pub inventory_digest: Commitment,
    pub copy_evidence_digest: Commitment,
    pub object_count: u64,
    pub inventory_bytes: u64,
    pub work_units: u64,
    pub retained_bytes: u64,
    pub manifest_digest: Commitment,
}

impl BackupManifest {
    /// Reconstructs this private manifest's structural checksum and logical
    /// ledgers. This is not signature, producer-authentication, or storage-
    /// verification authority, and it cannot reconstruct the consumed streams.
    pub fn has_valid_binding(&self) -> bool {
        let Ok(root_count) = u64::try_from(self.capture.roots.len()) else {
            return false;
        };
        self.version == BACKUP_MANIFEST_VERSION
            && validate_capture(&self.capture, BackupLimits::default()).is_ok()
            && self.object_count == self.capture.declared_object_count
            && self.inventory_bytes == self.capture.declared_inventory_bytes
            && work_charge(root_count, self.object_count)
                .is_ok_and(|charge| charge == self.work_units)
            && retained_charge(root_count).is_ok_and(|charge| charge == self.retained_bytes)
            && self.roots_digest == digest_roots(&self.capture.roots, root_count)
            && self.manifest_digest
                == digest_manifest_fields(
                    &self.capture,
                    self.roots_digest,
                    self.inventory_digest,
                    self.copy_evidence_digest,
                    self.object_count,
                    self.inventory_bytes,
                    self.work_units,
                    self.retained_bytes,
                )
    }
}

/// Builds a private manifest complete only with respect to the supplied streams,
/// or returns no report. Iterator lengths
/// are preflighted before either iterator is polled; each declared row is then
/// consumed in sorted lockstep and never retained. Each stream receives one
/// final end-of-stream probe so a dishonest exact length cannot hide an extra
/// row.
pub fn build_backup_manifest<E, C>(
    mut capture: BackupCapture,
    expected_inventory: E,
    backup_copies: C,
    limits: BackupLimits,
    control: BackupControl<'_>,
) -> Result<BackupManifest, BackupError>
where
    E: IntoIterator<Item = ObjectInventoryEntry>,
    E::IntoIter: ExactSizeIterator,
    C: IntoIterator<Item = BackupCopyEvidence>,
    C::IntoIter: ExactSizeIterator,
{
    if !limits.valid() {
        return Err(BackupError::InvalidLimits);
    }
    control.check()?;
    validate_capture(&capture, limits)?;

    // Discard caller-owned spare capacity before the root vector becomes
    // retained manifest state. The caller's pre-existing allocation remains
    // outside this crate's deterministic retained-memory ledger.
    capture.roots = capture.roots.into_boxed_slice().into_vec();
    control.check()?;
    let root_count =
        u64::try_from(capture.roots.len()).map_err(|_| BackupError::AccountingOverflow)?;

    let mut expected = expected_inventory.into_iter();
    control.check()?;
    let mut copies = backup_copies.into_iter();
    control.check()?;
    let expected_length =
        u64::try_from(expected.len()).map_err(|_| BackupError::AccountingOverflow)?;
    control.check()?;
    let copy_length = u64::try_from(copies.len()).map_err(|_| BackupError::AccountingOverflow)?;
    control.check()?;
    if expected_length != capture.declared_object_count
        || copy_length != capture.declared_object_count
    {
        return Err(BackupError::ObjectMismatch);
    }
    control.check()?;

    let roots_digest = digest_roots(&capture.roots, root_count);
    let retained_bytes = retained_charge(root_count)?;
    let mut required_roots: BTreeSet<ObjectRef> =
        capture.roots.iter().map(|root| root.snapshot).collect();
    control.check()?;
    let required_root_count =
        u64::try_from(required_roots.len()).map_err(|_| BackupError::AccountingOverflow)?;
    if required_root_count > capture.declared_object_count {
        return Err(BackupError::MissingRoot);
    }
    let mut inventory_hash = domain_writer(INVENTORY_DOMAIN);
    let mut copies_hash = domain_writer(COPIES_DOMAIN);
    let mut previous_inventory = None;
    let mut previous_copy = None;
    let mut inventory_bytes = 0u64;
    let mut object_count = 0u64;
    let mut work_units = root_count;
    let chunk_bytes_maximum =
        hard_limit_maximum("chunk-payload-bytes").map_err(|_| BackupError::InvalidCapture)?;
    let metadata_bytes_maximum =
        hard_limit_maximum("metadata-payload-bytes").map_err(|_| BackupError::InvalidCapture)?;

    for _ in 0..capture.declared_object_count {
        control.check()?;
        let inventory = expected.next();
        control.check()?;
        let inventory = inventory.ok_or(BackupError::ObjectMismatch)?;
        let copy = copies.next();
        control.check()?;
        let copy = copy.ok_or(BackupError::ObjectMismatch)?;
        object_count = object_count
            .checked_add(1)
            .ok_or(BackupError::AccountingOverflow)?;
        if previous_inventory.is_some_and(|previous| previous >= inventory.object) {
            return Err(BackupError::InventoryOrder);
        }
        if previous_copy.is_some_and(|previous| previous >= copy.object) {
            return Err(BackupError::CopyOrder);
        }
        if inventory.object != copy.object || inventory.object_bytes != copy.object_bytes {
            return Err(BackupError::ObjectMismatch);
        }
        let object_bytes_maximum = if inventory.object.kind == ObjectKind::Chunk {
            chunk_bytes_maximum
        } else {
            metadata_bytes_maximum
        };
        if inventory.object_bytes > object_bytes_maximum
            || (inventory.object.kind != ObjectKind::Chunk && inventory.object_bytes == 0)
        {
            return Err(BackupError::ByteLimit);
        }
        validate_copy(&capture, copy)?;

        inventory_bytes = inventory_bytes
            .checked_add(inventory.object_bytes)
            .ok_or(BackupError::AccountingOverflow)?;
        if inventory_bytes > capture.declared_inventory_bytes
            || inventory_bytes > limits.max_inventory_bytes
        {
            return Err(BackupError::ByteLimit);
        }
        work_units = work_units
            .checked_add(2)
            .ok_or(BackupError::AccountingOverflow)?;
        if work_units > limits.max_work_units {
            return Err(BackupError::WorkLimit);
        }

        hash_inventory_entry(&mut inventory_hash, inventory);
        hash_copy_evidence(&mut copies_hash, copy);
        required_roots.remove(&inventory.object);
        previous_inventory = Some(inventory.object);
        previous_copy = Some(copy.object);
        control.check()?;
    }

    // ExactSizeIterator is a safe preflight optimization, not an authority.
    // Probe both streams once at the declared boundary so a lying iterator
    // cannot hide a one-sided additional row behind zip's shortest-stream
    // behavior.
    control.check()?;
    let expected_tail = expected.next();
    control.check()?;
    let copy_tail = copies.next();
    control.check()?;
    if expected_tail.is_some() || copy_tail.is_some() {
        return Err(BackupError::ObjectMismatch);
    }

    if object_count != capture.declared_object_count
        || inventory_bytes != capture.declared_inventory_bytes
    {
        return Err(BackupError::ObjectMismatch);
    }
    if !required_roots.is_empty() {
        return Err(BackupError::MissingRoot);
    }
    control.check()?;

    let inventory_digest = inventory_hash.finish();
    let copy_evidence_digest = copies_hash.finish();
    let manifest_digest = digest_manifest_fields(
        &capture,
        roots_digest,
        inventory_digest,
        copy_evidence_digest,
        object_count,
        inventory_bytes,
        work_units,
        retained_bytes,
    );
    Ok(BackupManifest {
        version: BACKUP_MANIFEST_VERSION,
        object_count,
        capture,
        roots_digest,
        inventory_digest,
        copy_evidence_digest,
        inventory_bytes,
        work_units,
        retained_bytes,
        manifest_digest,
    })
}

fn validate_capture(capture: &BackupCapture, limits: BackupLimits) -> Result<(), BackupError> {
    let root_count =
        u64::try_from(capture.roots.len()).map_err(|_| BackupError::AccountingOverflow)?;
    if capture.roots.is_empty() {
        return Err(BackupError::InvalidCapture);
    }
    if root_count > limits.max_roots {
        return Err(BackupError::RootLimit);
    }
    if capture.declared_object_count == 0
        || capture.declared_object_count > limits.max_objects
        || capture.declared_object_count > OBJECTS_MAXIMUM
    {
        return Err(BackupError::ObjectLimit);
    }
    if capture.declared_inventory_bytes > limits.max_inventory_bytes
        || capture.declared_inventory_bytes > INVENTORY_BYTES_MAXIMUM
    {
        return Err(BackupError::ByteLimit);
    }
    let metadata_bytes_maximum =
        hard_limit_maximum("metadata-payload-bytes").map_err(|_| BackupError::InvalidCapture)?;
    let maximum_possible_inventory_bytes = capture
        .declared_object_count
        .checked_mul(metadata_bytes_maximum)
        .ok_or(BackupError::AccountingOverflow)?;
    if capture.declared_inventory_bytes > maximum_possible_inventory_bytes {
        return Err(BackupError::ByteLimit);
    }
    let minimum_work = work_charge(root_count, capture.declared_object_count)?;
    if minimum_work > limits.max_work_units {
        return Err(BackupError::WorkLimit);
    }
    if retained_charge(root_count)? > limits.max_retained_bytes {
        return Err(BackupError::MemoryLimit);
    }
    if capture.captured_at_unix_seconds == 0
        || capture.minimum_retention_until_unix_seconds <= capture.captured_at_unix_seconds
        || capture.metadata_generation != capture.inventory_generation
        || commitments(&[
            capture.tenant,
            capture.repository,
            capture.metadata_generation,
            capture.schema,
            capture.protocol,
            capture.configuration,
            capture.lock_treatment,
            capture.audit_treatment,
            capture.capture_authority,
            capture.reachability_proof,
            capture.integrity_verification,
            capture.source_storage,
            capture.source_credential_scope,
            capture.target.target,
            capture.target.credential_scope,
            capture.target.retention_policy,
            capture.target.encryption_policy,
        ])
        .is_err()
        || capture.source_storage == capture.target.target
        || capture.source_credential_scope == capture.target.credential_scope
        || capture.capture_authority == capture.target.credential_scope
    {
        return Err(BackupError::InvalidCapture);
    }
    let mut previous = None;
    for root in &capture.roots {
        if root.snapshot.kind != ObjectKind::Snapshot || root.name_commitment == [0; 32] {
            return Err(BackupError::InvalidCapture);
        }
        let key = (root.kind, root.name_commitment);
        if previous.is_some_and(|previous| previous >= key) {
            return Err(BackupError::RootOrder);
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_copy(capture: &BackupCapture, copy: BackupCopyEvidence) -> Result<(), BackupError> {
    if copy.target != capture.target.target
        || copy.storage_generation == [0; 32]
        || copy.verification_receipt == [0; 32]
        || copy.retention_proof == [0; 32]
        || copy.retention_until_unix_seconds < capture.minimum_retention_until_unix_seconds
    {
        Err(BackupError::InvalidCopyEvidence)
    } else {
        Ok(())
    }
}

fn commitments(values: &[Commitment]) -> Result<(), BackupError> {
    if values.iter().any(|value| *value == [0; 32]) {
        Err(BackupError::InvalidCapture)
    } else {
        Ok(())
    }
}

fn retained_charge(roots: u64) -> Result<u64, BackupError> {
    roots
        .checked_mul(RETAINED_ROOT_CHARGE)
        .and_then(|charge| charge.checked_add(RETAINED_BASE_CHARGE))
        .ok_or(BackupError::AccountingOverflow)
}

fn work_charge(roots: u64, objects: u64) -> Result<u64, BackupError> {
    objects
        .checked_mul(2)
        .and_then(|objects| roots.checked_add(objects))
        .ok_or(BackupError::AccountingOverflow)
}

fn domain_writer(domain: &[u8]) -> Sha256Writer {
    let mut writer = Sha256Writer::new();
    field(&mut writer, domain);
    writer
}

fn digest_roots(roots: &[RootBinding], root_count: u64) -> Commitment {
    let mut writer = domain_writer(ROOTS_DOMAIN);
    writer.update(&root_count.to_be_bytes());
    for root in roots {
        writer.update(&[root.kind.code()]);
        field(&mut writer, &root.name_commitment);
        object_field(&mut writer, root.snapshot);
    }
    writer.finish()
}

fn hash_inventory_entry(writer: &mut Sha256Writer, entry: ObjectInventoryEntry) {
    object_field(writer, entry.object);
    writer.update(&entry.object_bytes.to_be_bytes());
}

fn hash_copy_evidence(writer: &mut Sha256Writer, copy: BackupCopyEvidence) {
    object_field(writer, copy.object);
    writer.update(&copy.object_bytes.to_be_bytes());
    field(writer, &copy.target);
    field(writer, &copy.storage_generation);
    field(writer, &copy.verification_receipt);
    field(writer, &copy.retention_proof);
    writer.update(&copy.retention_until_unix_seconds.to_be_bytes());
}

#[allow(clippy::too_many_arguments)]
fn digest_manifest_fields(
    capture: &BackupCapture,
    roots_digest: Commitment,
    inventory_digest: Commitment,
    copy_evidence_digest: Commitment,
    object_count: u64,
    inventory_bytes: u64,
    work_units: u64,
    retained_bytes: u64,
) -> Commitment {
    let mut writer = domain_writer(MANIFEST_DOMAIN);
    writer.update(&BACKUP_MANIFEST_VERSION.to_be_bytes());
    field(&mut writer, &capture.tenant);
    field(&mut writer, &capture.repository);
    field(&mut writer, &capture.metadata_generation);
    field(&mut writer, &capture.inventory_generation);
    field(&mut writer, &capture.schema);
    field(&mut writer, &capture.protocol);
    field(&mut writer, &capture.configuration);
    field(&mut writer, &capture.lock_treatment);
    field(&mut writer, &capture.audit_treatment);
    field(&mut writer, &capture.capture_authority);
    field(&mut writer, &capture.reachability_proof);
    field(&mut writer, &capture.integrity_verification);
    field(&mut writer, &capture.source_storage);
    field(&mut writer, &capture.source_credential_scope);
    field(&mut writer, &capture.target.target);
    field(&mut writer, &capture.target.credential_scope);
    field(&mut writer, &capture.target.retention_policy);
    field(&mut writer, &capture.target.encryption_policy);
    writer.update(&capture.captured_at_unix_seconds.to_be_bytes());
    writer.update(&capture.minimum_retention_until_unix_seconds.to_be_bytes());
    writer.update(&capture.declared_object_count.to_be_bytes());
    writer.update(&capture.declared_inventory_bytes.to_be_bytes());
    field(&mut writer, &roots_digest);
    field(&mut writer, &inventory_digest);
    field(&mut writer, &copy_evidence_digest);
    writer.update(&object_count.to_be_bytes());
    writer.update(&inventory_bytes.to_be_bytes());
    writer.update(&work_units.to_be_bytes());
    writer.update(&retained_bytes.to_be_bytes());
    writer.finish()
}

fn object_field(writer: &mut Sha256Writer, object: ObjectRef) {
    writer.update(&object.kind.code().to_be_bytes());
    field(writer, &object.digest);
}

fn field(writer: &mut Sha256Writer, value: &[u8]) {
    // The compile-time pointer-width assertion above makes this conversion
    // exact on every supported target; current callers are also fixed domains
    // and 32-byte commitments.
    writer.update(&(value.len() as u64).to_be_bytes());
    writer.update(value);
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, sync::atomic::AtomicBool};

    use super::*;

    fn object(kind: ObjectKind, byte: u8) -> ObjectRef {
        ObjectRef {
            kind,
            digest: [byte; 32],
        }
    }

    fn capture(count: u64, bytes: u64) -> BackupCapture {
        BackupCapture {
            tenant: [1; 32],
            repository: [2; 32],
            metadata_generation: [3; 32],
            inventory_generation: [3; 32],
            schema: [4; 32],
            protocol: [5; 32],
            configuration: [6; 32],
            lock_treatment: [7; 32],
            audit_treatment: [8; 32],
            capture_authority: [9; 32],
            reachability_proof: [17; 32],
            integrity_verification: [18; 32],
            source_storage: [10; 32],
            source_credential_scope: [11; 32],
            target: BackupTargetBinding {
                target: [12; 32],
                credential_scope: [13; 32],
                retention_policy: [14; 32],
                encryption_policy: [15; 32],
            },
            captured_at_unix_seconds: 100,
            minimum_retention_until_unix_seconds: 200,
            declared_object_count: count,
            declared_inventory_bytes: bytes,
            roots: vec![RootBinding {
                kind: RootKind::Branch,
                name_commitment: [16; 32],
                snapshot: object(ObjectKind::Snapshot, 20),
            }],
        }
    }

    fn inventory() -> Vec<ObjectInventoryEntry> {
        vec![
            ObjectInventoryEntry {
                object: object(ObjectKind::Chunk, 10),
                object_bytes: 11,
            },
            ObjectInventoryEntry {
                object: object(ObjectKind::Tree, 15),
                object_bytes: 22,
            },
            ObjectInventoryEntry {
                object: object(ObjectKind::Snapshot, 20),
                object_bytes: 33,
            },
        ]
    }

    fn copies(inventory: &[ObjectInventoryEntry]) -> Vec<BackupCopyEvidence> {
        inventory
            .iter()
            .map(|entry| BackupCopyEvidence {
                object: entry.object,
                object_bytes: entry.object_bytes,
                target: [12; 32],
                storage_generation: [21; 32],
                verification_receipt: [22; 32],
                retention_proof: [23; 32],
                retention_until_unix_seconds: 300,
            })
            .collect()
    }

    fn build(
        capture: BackupCapture,
        inventory: Vec<ObjectInventoryEntry>,
        copies: Vec<BackupCopyEvidence>,
        limits: BackupLimits,
    ) -> Result<BackupManifest, BackupError> {
        build_backup_manifest(capture, inventory, copies, limits, BackupControl::none())
    }

    #[test]
    fn exact_inventory_builds_one_deterministic_bound_manifest() {
        let inventory = inventory();
        let copies = copies(&inventory);
        let first = build(
            capture(3, 66),
            inventory.clone(),
            copies.clone(),
            BackupLimits::default(),
        )
        .unwrap();
        let second = build(capture(3, 66), inventory, copies, BackupLimits::default()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.object_count, 3);
        assert_eq!(first.inventory_bytes, 66);
        assert_eq!(first.work_units, 7);
        assert_eq!(
            first.manifest_digest,
            [
                166, 218, 35, 191, 19, 249, 211, 70, 234, 58, 134, 81, 132, 226, 144, 122, 52, 157,
                82, 17, 20, 50, 218, 64, 56, 184, 173, 69, 13, 156, 254, 10,
            ]
        );
        assert!(first.has_valid_binding());
    }

    #[test]
    fn missing_additional_or_mismatched_copy_returns_no_manifest() {
        let inventory = inventory();
        let mut copy_rows = copies(&inventory);
        copy_rows.pop();
        assert_eq!(
            build(
                capture(3, 66),
                inventory.clone(),
                copy_rows,
                BackupLimits::default()
            ),
            Err(BackupError::ObjectMismatch)
        );
        let mut copy_rows = copies(&inventory);
        copy_rows[1].object_bytes += 1;
        assert_eq!(
            build(
                capture(3, 66),
                inventory,
                copy_rows,
                BackupLimits::default()
            ),
            Err(BackupError::ObjectMismatch)
        );
    }

    #[test]
    fn both_streams_must_be_strictly_sorted_and_duplicate_free() {
        let mut inventory_rows = inventory();
        inventory_rows.swap(0, 1);
        let copy_rows = copies(&inventory_rows);
        assert_eq!(
            build(
                capture(3, 66),
                inventory_rows,
                copy_rows,
                BackupLimits::default()
            ),
            Err(BackupError::InventoryOrder)
        );

        let inventory_rows = inventory();
        let mut copy_rows = copies(&inventory_rows);
        copy_rows[1] = copy_rows[0];
        assert_eq!(
            build(
                capture(3, 66),
                inventory_rows,
                copy_rows,
                BackupLimits::default()
            ),
            Err(BackupError::CopyOrder)
        );
    }

    #[test]
    fn every_declared_snapshot_root_must_be_in_the_inventory() {
        let inventory = inventory();
        let copies = copies(&inventory);
        let mut capture = capture(3, 66);
        capture.roots[0].snapshot = object(ObjectKind::Snapshot, 99);
        assert_eq!(
            build(capture, inventory, copies, BackupLimits::default()),
            Err(BackupError::MissingRoot)
        );
    }

    #[test]
    fn root_shapes_order_and_configured_bound_are_fail_closed() {
        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let mut invalid_capture = capture(3, 66);
        invalid_capture.roots[0].snapshot = object(ObjectKind::Tree, 20);
        assert_eq!(
            build(
                invalid_capture,
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits::default()
            ),
            Err(BackupError::InvalidCapture)
        );

        let mut over_root_capture = capture(3, 66);
        over_root_capture.roots.push(RootBinding {
            kind: RootKind::Tag,
            name_commitment: [17; 32],
            snapshot: object(ObjectKind::Snapshot, 20),
        });
        assert_eq!(
            build(
                over_root_capture,
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits {
                    max_roots: 1,
                    ..BackupLimits::default()
                }
            ),
            Err(BackupError::RootLimit)
        );

        let mut duplicate_capture = capture(3, 66);
        duplicate_capture.roots.push(duplicate_capture.roots[0]);
        assert_eq!(
            build(
                duplicate_capture,
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits::default()
            ),
            Err(BackupError::RootOrder)
        );

        let mut duplicate_name_capture = capture(3, 66);
        duplicate_name_capture.roots.push(RootBinding {
            kind: RootKind::Branch,
            name_commitment: duplicate_name_capture.roots[0].name_commitment,
            snapshot: object(ObjectKind::Snapshot, 21),
        });
        assert_eq!(
            build(
                duplicate_name_capture,
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits::default()
            ),
            Err(BackupError::RootOrder)
        );

        let mut hard_over_capture = capture(3, 66);
        hard_over_capture.roots = vec![hard_over_capture.roots[0]; 1_025];
        assert_eq!(
            build(
                hard_over_capture,
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits::default()
            ),
            Err(BackupError::RootLimit)
        );
        assert_eq!(
            build(
                capture(3, 66),
                inventory_rows,
                copy_rows,
                BackupLimits {
                    max_roots: 0,
                    ..BackupLimits::default()
                }
            ),
            Err(BackupError::InvalidLimits)
        );
    }

    #[test]
    fn object_byte_and_work_limits_accept_exact_and_reject_plus_one() {
        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let exact = BackupLimits {
            max_roots: 1,
            max_objects: 3,
            max_inventory_bytes: 66,
            max_work_units: 7,
            max_retained_bytes: RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE,
        };
        assert!(build(
            capture(3, 66),
            inventory_rows.clone(),
            copy_rows.clone(),
            exact
        )
        .is_ok());
        assert_eq!(
            build(
                capture(3, 66),
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits {
                    max_objects: 2,
                    ..exact
                }
            ),
            Err(BackupError::ObjectLimit)
        );
        assert_eq!(
            build(
                capture(3, 66),
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits {
                    max_inventory_bytes: 65,
                    ..exact
                }
            ),
            Err(BackupError::ByteLimit)
        );
        assert_eq!(
            build(
                capture(3, 66),
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits {
                    max_work_units: 6,
                    ..exact
                }
            ),
            Err(BackupError::WorkLimit)
        );

        assert_eq!(
            build(
                capture(3, 66),
                inventory_rows,
                copy_rows,
                BackupLimits {
                    max_retained_bytes: exact.max_retained_bytes - 1,
                    ..exact
                }
            ),
            Err(BackupError::MemoryLimit)
        );
    }

    #[test]
    fn retained_manifest_roots_discard_unbounded_caller_spare_capacity() {
        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let mut oversized_capacity = Vec::with_capacity(16_384);
        oversized_capacity.push(capture(3, 66).roots[0]);
        assert!(oversized_capacity.capacity() > oversized_capacity.len());
        let mut capture = capture(3, 66);
        capture.roots = oversized_capacity;

        let manifest = build(capture, inventory_rows, copy_rows, BackupLimits::default()).unwrap();
        assert_eq!(
            manifest.capture.roots.capacity(),
            manifest.capture.roots.len()
        );
        assert_eq!(
            manifest.retained_bytes,
            RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE
        );
    }

    #[test]
    fn object_rows_cannot_exceed_the_frozen_ogvcs002_kind_limits() {
        let mut inventory_rows = inventory();
        inventory_rows[0].object_bytes = hard_limit_maximum("chunk-payload-bytes").unwrap() + 1;
        let copy_rows = copies(&inventory_rows);
        let bytes = inventory_rows.iter().map(|row| row.object_bytes).sum();
        assert_eq!(
            build(
                capture(3, bytes),
                inventory_rows,
                copy_rows,
                BackupLimits::default()
            ),
            Err(BackupError::ByteLimit)
        );

        let mut inventory_rows = inventory();
        inventory_rows[1].object_bytes = hard_limit_maximum("metadata-payload-bytes").unwrap() + 1;
        let copy_rows = copies(&inventory_rows);
        let bytes = inventory_rows.iter().map(|row| row.object_bytes).sum();
        assert_eq!(
            build(
                capture(3, bytes),
                inventory_rows,
                copy_rows,
                BackupLimits::default()
            ),
            Err(BackupError::ByteLimit)
        );
    }

    #[test]
    fn empty_chunk_is_valid_but_metadata_payload_length_cannot_be_zero() {
        let mut empty_chunk_inventory = inventory();
        empty_chunk_inventory[0].object_bytes = 0;
        let empty_chunk_copies = copies(&empty_chunk_inventory);
        assert!(build(
            capture(3, 55),
            empty_chunk_inventory,
            empty_chunk_copies,
            BackupLimits::default()
        )
        .is_ok());

        let mut empty_metadata_inventory = inventory();
        empty_metadata_inventory[1].object_bytes = 0;
        let empty_metadata_copies = copies(&empty_metadata_inventory);
        assert_eq!(
            build(
                capture(3, 44),
                empty_metadata_inventory,
                empty_metadata_copies,
                BackupLimits::default()
            ),
            Err(BackupError::ByteLimit)
        );
    }

    #[test]
    fn default_envelopes_can_represent_their_joint_exact_maximum() {
        assert_eq!(WORK_UNITS_MAXIMUM, ROOTS_MAXIMUM + (OBJECTS_MAXIMUM * 2));
        assert_eq!(BackupLimits::default().max_work_units, WORK_UNITS_MAXIMUM);
        assert_eq!(
            BackupLimits::default().max_retained_bytes,
            RETAINED_BYTES_MAXIMUM
        );
    }

    #[test]
    fn every_configured_limit_rejects_zero_or_a_hard_maximum_overrun() {
        let default = BackupLimits::default();
        let invalid = [
            BackupLimits {
                max_roots: 0,
                ..default
            },
            BackupLimits {
                max_roots: ROOTS_MAXIMUM + 1,
                ..default
            },
            BackupLimits {
                max_objects: 0,
                ..default
            },
            BackupLimits {
                max_objects: OBJECTS_MAXIMUM + 1,
                ..default
            },
            BackupLimits {
                max_inventory_bytes: 0,
                ..default
            },
            BackupLimits {
                max_inventory_bytes: INVENTORY_BYTES_MAXIMUM + 1,
                ..default
            },
            BackupLimits {
                max_work_units: 0,
                ..default
            },
            BackupLimits {
                max_work_units: WORK_UNITS_MAXIMUM + 1,
                ..default
            },
            BackupLimits {
                max_retained_bytes: RETAINED_BASE_CHARGE - 1,
                ..default
            },
            BackupLimits {
                max_retained_bytes: RETAINED_BYTES_MAXIMUM + 1,
                ..default
            },
        ];
        let inventory = inventory();
        let copies = copies(&inventory);
        for limits in invalid {
            assert_eq!(
                build(capture(3, 66), inventory.clone(), copies.clone(), limits),
                Err(BackupError::InvalidLimits)
            );
        }
    }

    struct ObservedExact<'a, T> {
        inner: std::vec::IntoIter<T>,
        polls: &'a Cell<usize>,
        reported_len: usize,
    }

    impl<T> Iterator for ObservedExact<'_, T> {
        type Item = T;

        fn next(&mut self) -> Option<Self::Item> {
            self.polls.set(self.polls.get() + 1);
            self.inner.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.reported_len, Some(self.reported_len))
        }
    }

    impl<T> ExactSizeIterator for ObservedExact<'_, T> {
        fn len(&self) -> usize {
            self.reported_len
        }
    }

    #[test]
    fn impossible_aggregate_bytes_and_unique_root_count_fail_before_stream_polling() {
        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let expected_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        let impossible_bytes = hard_limit_maximum("metadata-payload-bytes").unwrap() * 3 + 1;
        assert_eq!(
            build_backup_manifest(
                capture(3, impossible_bytes),
                ObservedExact {
                    inner: inventory_rows.clone().into_iter(),
                    polls: &expected_polls,
                    reported_len: 3,
                },
                ObservedExact {
                    inner: copy_rows.clone().into_iter(),
                    polls: &copy_polls,
                    reported_len: 3,
                },
                BackupLimits::default(),
                BackupControl::none()
            ),
            Err(BackupError::ByteLimit)
        );
        assert_eq!(expected_polls.get(), 0);
        assert_eq!(copy_polls.get(), 0);

        let mut too_many_unique_roots = capture(1, 33);
        too_many_unique_roots.roots.push(RootBinding {
            kind: RootKind::Tag,
            name_commitment: [17; 32],
            snapshot: object(ObjectKind::Snapshot, 21),
        });
        let expected_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        assert_eq!(
            build_backup_manifest(
                too_many_unique_roots,
                ObservedExact {
                    inner: inventory_rows.into_iter(),
                    polls: &expected_polls,
                    reported_len: 1,
                },
                ObservedExact {
                    inner: copy_rows.into_iter(),
                    polls: &copy_polls,
                    reported_len: 1,
                },
                BackupLimits::default(),
                BackupControl::none()
            ),
            Err(BackupError::MissingRoot)
        );
        assert_eq!(expected_polls.get(), 0);
        assert_eq!(copy_polls.get(), 0);
    }

    #[test]
    fn declared_count_preflight_does_not_poll_and_actual_length_violations_fail() {
        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let expected_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        assert_eq!(
            build_backup_manifest(
                capture(2, 66),
                ObservedExact {
                    inner: inventory_rows.clone().into_iter(),
                    polls: &expected_polls,
                    reported_len: 3,
                },
                ObservedExact {
                    inner: copy_rows.clone().into_iter(),
                    polls: &copy_polls,
                    reported_len: 3,
                },
                BackupLimits::default(),
                BackupControl::none()
            ),
            Err(BackupError::ObjectMismatch)
        );
        assert_eq!(expected_polls.get(), 0);
        assert_eq!(copy_polls.get(), 0);

        let mut over_inventory = inventory_rows;
        over_inventory.push(ObjectInventoryEntry {
            object: object(ObjectKind::Attestation, 25),
            object_bytes: 0,
        });
        let over_copies = copies(&over_inventory);
        let expected_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        assert_eq!(
            build_backup_manifest(
                capture(3, 66),
                ObservedExact {
                    inner: over_inventory.into_iter(),
                    polls: &expected_polls,
                    reported_len: 3,
                },
                ObservedExact {
                    inner: over_copies.into_iter(),
                    polls: &copy_polls,
                    reported_len: 3,
                },
                BackupLimits::default(),
                BackupControl::none()
            ),
            Err(BackupError::ObjectMismatch)
        );
        assert_eq!(expected_polls.get(), 4);
        assert_eq!(copy_polls.get(), 4);

        let mut short_inventory = inventory();
        short_inventory.pop();
        let full_inventory = inventory();
        let full_copies = copies(&full_inventory);
        let expected_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        assert_eq!(
            build_backup_manifest(
                capture(3, 66),
                ObservedExact {
                    inner: short_inventory.into_iter(),
                    polls: &expected_polls,
                    reported_len: 3,
                },
                ObservedExact {
                    inner: full_copies.into_iter(),
                    polls: &copy_polls,
                    reported_len: 3,
                },
                BackupLimits::default(),
                BackupControl::none()
            ),
            Err(BackupError::ObjectMismatch)
        );
        assert_eq!(expected_polls.get(), 3);
        assert_eq!(copy_polls.get(), 2);

        let full_inventory = inventory();
        let mut short_copies = copies(&full_inventory);
        short_copies.pop();
        let expected_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        assert_eq!(
            build_backup_manifest(
                capture(3, 66),
                ObservedExact {
                    inner: full_inventory.into_iter(),
                    polls: &expected_polls,
                    reported_len: 3,
                },
                ObservedExact {
                    inner: short_copies.into_iter(),
                    polls: &copy_polls,
                    reported_len: 3,
                },
                BackupLimits::default(),
                BackupControl::none()
            ),
            Err(BackupError::ObjectMismatch)
        );
        assert_eq!(expected_polls.get(), 3);
        assert_eq!(copy_polls.get(), 3);
    }

    #[test]
    fn one_sided_exact_size_iterator_overrun_cannot_hide_at_the_zip_boundary() {
        let base_inventory = inventory();
        let base_copies = copies(&base_inventory);

        let mut extra_inventory = base_inventory.clone();
        extra_inventory.push(ObjectInventoryEntry {
            object: object(ObjectKind::Attestation, 25),
            object_bytes: 1,
        });
        let expected_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        assert_eq!(
            build_backup_manifest(
                capture(3, 66),
                ObservedExact {
                    inner: extra_inventory.into_iter(),
                    polls: &expected_polls,
                    reported_len: 3,
                },
                ObservedExact {
                    inner: base_copies.clone().into_iter(),
                    polls: &copy_polls,
                    reported_len: 3,
                },
                BackupLimits::default(),
                BackupControl::none()
            ),
            Err(BackupError::ObjectMismatch)
        );
        assert_eq!(expected_polls.get(), 4);
        assert_eq!(copy_polls.get(), 4);

        let mut extra_copies = base_copies;
        extra_copies.push(BackupCopyEvidence {
            object: object(ObjectKind::Attestation, 25),
            object_bytes: 1,
            target: [12; 32],
            storage_generation: [21; 32],
            verification_receipt: [22; 32],
            retention_proof: [23; 32],
            retention_until_unix_seconds: 300,
        });
        let expected_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        assert_eq!(
            build_backup_manifest(
                capture(3, 66),
                ObservedExact {
                    inner: base_inventory.into_iter(),
                    polls: &expected_polls,
                    reported_len: 3,
                },
                ObservedExact {
                    inner: extra_copies.into_iter(),
                    polls: &copy_polls,
                    reported_len: 3,
                },
                BackupLimits::default(),
                BackupControl::none()
            ),
            Err(BackupError::ObjectMismatch)
        );
        assert_eq!(expected_polls.get(), 4);
        assert_eq!(copy_polls.get(), 4);
    }

    #[test]
    fn source_and_target_bindings_cannot_alias() {
        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let mut target_alias_capture = capture(3, 66);
        target_alias_capture.target.target = target_alias_capture.source_storage;
        assert_eq!(
            build(
                target_alias_capture,
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits::default()
            ),
            Err(BackupError::InvalidCapture)
        );

        let mut credential_alias_capture = capture(3, 66);
        credential_alias_capture.target.credential_scope =
            credential_alias_capture.capture_authority;
        assert_eq!(
            build(
                credential_alias_capture,
                inventory_rows.clone(),
                copy_rows.clone(),
                BackupLimits::default()
            ),
            Err(BackupError::InvalidCapture)
        );

        let mut source_credential_alias_capture = capture(3, 66);
        source_credential_alias_capture.target.credential_scope =
            source_credential_alias_capture.source_credential_scope;
        assert_eq!(
            build(
                source_credential_alias_capture,
                inventory_rows,
                copy_rows,
                BackupLimits::default()
            ),
            Err(BackupError::InvalidCapture)
        );
    }

    #[test]
    fn ogvcs002_object_identity_is_not_reinterpreted_by_zero_sentinel_rules() {
        let mut inventory_rows = inventory();
        inventory_rows[0].object.digest = [0; 32];
        let copy_rows = copies(&inventory_rows);
        let manifest = build(
            capture(3, 66),
            inventory_rows,
            copy_rows,
            BackupLimits::default(),
        )
        .unwrap();
        assert!(manifest.has_valid_binding());

        let mut zero_root_capture = capture(3, 66);
        zero_root_capture.roots[0].snapshot.digest = [0; 32];
        let mut inventory_rows = inventory();
        inventory_rows[2].object.digest = [0; 32];
        let copy_rows = copies(&inventory_rows);
        let manifest = build(
            zero_root_capture,
            inventory_rows,
            copy_rows,
            BackupLimits::default(),
        )
        .unwrap();
        assert!(manifest.has_valid_binding());
    }

    #[test]
    fn objectref_order_matches_frozen_ogvcs002_canonical_reference_bytes() {
        let mut objects = Vec::new();
        for code in (1..=11).rev() {
            let kind = ObjectKind::from_code(code).unwrap();
            objects.push(object(kind, 255));
            objects.push(object(kind, 0));
        }
        let mut native_order = objects.clone();
        native_order.sort();
        let mut canonical_order: Vec<_> = objects
            .into_iter()
            .map(|object| {
                (
                    ogvcs_object_model::encode_canonical(&object.to_cbor()).unwrap(),
                    object,
                )
            })
            .collect();
        canonical_order.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            native_order,
            canonical_order
                .into_iter()
                .map(|(_, object)| object)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn copy_evidence_binds_target_receipts_generation_and_retention() {
        let inventory = inventory();
        for mutate in 0..5 {
            let mut copy_rows = copies(&inventory);
            match mutate {
                0 => copy_rows[1].target = [99; 32],
                1 => copy_rows[1].storage_generation = [0; 32],
                2 => copy_rows[1].verification_receipt = [0; 32],
                3 => copy_rows[1].retention_proof = [0; 32],
                _ => copy_rows[1].retention_until_unix_seconds = 199,
            }
            assert_eq!(
                build(
                    capture(3, 66),
                    inventory.clone(),
                    copy_rows,
                    BackupLimits::default()
                ),
                Err(BackupError::InvalidCopyEvidence)
            );
        }
    }

    #[test]
    fn retention_time_ordering_is_overflow_free_across_the_full_u64_domain() {
        let inventory = inventory();
        let mut copy_rows = copies(&inventory);
        for copy in &mut copy_rows {
            copy.retention_until_unix_seconds = u64::MAX;
        }
        let mut maximum_capture = capture(3, 66);
        maximum_capture.captured_at_unix_seconds = u64::MAX - 1;
        maximum_capture.minimum_retention_until_unix_seconds = u64::MAX;
        assert!(build(
            maximum_capture,
            inventory.clone(),
            copy_rows,
            BackupLimits::default()
        )
        .is_ok());

        let copy_rows = copies(&inventory);
        let mut non_increasing_capture = capture(3, 66);
        non_increasing_capture.minimum_retention_until_unix_seconds =
            non_increasing_capture.captured_at_unix_seconds;
        assert_eq!(
            build(
                non_increasing_capture,
                inventory,
                copy_rows,
                BackupLimits::default()
            ),
            Err(BackupError::InvalidCapture)
        );
    }

    #[test]
    fn changed_capture_or_copy_evidence_changes_the_manifest_digest() {
        let inventory = inventory();
        let copies = copies(&inventory);
        let baseline = build(
            capture(3, 66),
            inventory.clone(),
            copies.clone(),
            BackupLimits::default(),
        )
        .unwrap();
        let mut changed_capture = capture(3, 66);
        changed_capture.configuration = [88; 32];
        let changed = build(
            changed_capture,
            inventory.clone(),
            copies.clone(),
            BackupLimits::default(),
        )
        .unwrap();
        assert_ne!(baseline.manifest_digest, changed.manifest_digest);

        let mut changed_copies = copies;
        changed_copies[1].retention_proof = [89; 32];
        let changed = build(
            capture(3, 66),
            inventory,
            changed_copies,
            BackupLimits::default(),
        )
        .unwrap();
        assert_ne!(baseline.manifest_digest, changed.manifest_digest);
    }

    #[test]
    fn inventory_root_and_copy_digests_bind_every_row_field() {
        let inventory_digest = |rows: &[ObjectInventoryEntry]| {
            let mut writer = domain_writer(INVENTORY_DOMAIN);
            for row in rows {
                hash_inventory_entry(&mut writer, *row);
            }
            writer.finish()
        };
        let copy_digest = |rows: &[BackupCopyEvidence]| {
            let mut writer = domain_writer(COPIES_DOMAIN);
            for row in rows {
                hash_copy_evidence(&mut writer, *row);
            }
            writer.finish()
        };

        let inventory = inventory();
        let baseline_inventory = inventory_digest(&inventory);
        let mut changed = inventory.clone();
        changed[0].object.kind = ObjectKind::ContentManifest;
        assert_ne!(baseline_inventory, inventory_digest(&changed));
        let mut changed = inventory.clone();
        changed[0].object.digest = [77; 32];
        assert_ne!(baseline_inventory, inventory_digest(&changed));
        let mut changed = inventory.clone();
        changed[0].object_bytes += 1;
        assert_ne!(baseline_inventory, inventory_digest(&changed));

        let copies = copies(&inventory);
        let baseline_copies = copy_digest(&copies);
        for mutation in 0..8 {
            let mut changed = copies.clone();
            match mutation {
                0 => changed[0].object.kind = ObjectKind::ContentManifest,
                1 => changed[0].object.digest = [78; 32],
                2 => changed[0].object_bytes += 1,
                3 => changed[0].target = [79; 32],
                4 => changed[0].storage_generation = [80; 32],
                5 => changed[0].verification_receipt = [81; 32],
                6 => changed[0].retention_proof = [82; 32],
                _ => changed[0].retention_until_unix_seconds += 1,
            }
            assert_ne!(baseline_copies, copy_digest(&changed));
        }

        let baseline_capture = capture(3, 66);
        let baseline_roots = digest_roots(&baseline_capture.roots, 1);
        let mut changed = baseline_capture.roots.clone();
        changed[0].kind = RootKind::Tag;
        assert_ne!(baseline_roots, digest_roots(&changed, 1));
        let mut changed = baseline_capture.roots.clone();
        changed[0].name_commitment = [83; 32];
        assert_ne!(baseline_roots, digest_roots(&changed, 1));
        let mut changed = baseline_capture.roots.clone();
        changed[0].snapshot.kind = ObjectKind::Attestation;
        assert_ne!(baseline_roots, digest_roots(&changed, 1));
        let mut changed = baseline_capture.roots.clone();
        changed[0].snapshot.digest = [84; 32];
        assert_ne!(baseline_roots, digest_roots(&changed, 1));
        assert_ne!(baseline_roots, digest_roots(&baseline_capture.roots, 2));
    }

    #[test]
    fn manifest_digest_binds_every_capture_projection_and_terminal_ledger_field() {
        let baseline_capture = capture(3, 66);
        let roots_digest = digest_roots(&baseline_capture.roots, 1);
        let inventory_digest = [31; 32];
        let copy_digest = [32; 32];
        let digest = |capture: &BackupCapture,
                      roots: Commitment,
                      inventory: Commitment,
                      copies: Commitment,
                      count: u64,
                      bytes: u64,
                      work: u64,
                      retained: u64| {
            digest_manifest_fields(
                capture, roots, inventory, copies, count, bytes, work, retained,
            )
        };
        let baseline = digest(
            &baseline_capture,
            roots_digest,
            inventory_digest,
            copy_digest,
            3,
            66,
            7,
            RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE,
        );

        macro_rules! assert_capture_field {
            ($field:ident, $value:expr) => {{
                let mut changed = baseline_capture.clone();
                changed.$field = $value;
                assert_ne!(
                    baseline,
                    digest(
                        &changed,
                        roots_digest,
                        inventory_digest,
                        copy_digest,
                        3,
                        66,
                        7,
                        RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE,
                    ),
                    "capture field {} was not bound",
                    stringify!($field)
                );
            }};
        }
        macro_rules! assert_target_field {
            ($field:ident, $value:expr) => {{
                let mut changed = baseline_capture.clone();
                changed.target.$field = $value;
                assert_ne!(
                    baseline,
                    digest(
                        &changed,
                        roots_digest,
                        inventory_digest,
                        copy_digest,
                        3,
                        66,
                        7,
                        RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE,
                    ),
                    "target field {} was not bound",
                    stringify!($field)
                );
            }};
        }

        assert_capture_field!(tenant, [41; 32]);
        assert_capture_field!(repository, [42; 32]);
        assert_capture_field!(metadata_generation, [43; 32]);
        assert_capture_field!(inventory_generation, [44; 32]);
        assert_capture_field!(schema, [45; 32]);
        assert_capture_field!(protocol, [46; 32]);
        assert_capture_field!(configuration, [47; 32]);
        assert_capture_field!(lock_treatment, [48; 32]);
        assert_capture_field!(audit_treatment, [49; 32]);
        assert_capture_field!(capture_authority, [50; 32]);
        assert_capture_field!(reachability_proof, [51; 32]);
        assert_capture_field!(integrity_verification, [52; 32]);
        assert_capture_field!(source_storage, [53; 32]);
        assert_capture_field!(source_credential_scope, [54; 32]);
        assert_target_field!(target, [55; 32]);
        assert_target_field!(credential_scope, [56; 32]);
        assert_target_field!(retention_policy, [57; 32]);
        assert_target_field!(encryption_policy, [58; 32]);
        assert_capture_field!(captured_at_unix_seconds, 101);
        assert_capture_field!(minimum_retention_until_unix_seconds, 201);
        assert_capture_field!(declared_object_count, 4);
        assert_capture_field!(declared_inventory_bytes, 67);

        let mut changed_roots = baseline_capture.clone();
        changed_roots.roots[0].name_commitment = [59; 32];
        let changed_roots_digest = digest_roots(&changed_roots.roots, 1);
        assert_ne!(
            baseline,
            digest(
                &changed_roots,
                changed_roots_digest,
                inventory_digest,
                copy_digest,
                3,
                66,
                7,
                RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE,
            )
        );
        assert_ne!(
            baseline,
            digest(
                &baseline_capture,
                [60; 32],
                inventory_digest,
                copy_digest,
                3,
                66,
                7,
                RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE,
            )
        );
        assert_ne!(
            baseline,
            digest(
                &baseline_capture,
                roots_digest,
                [61; 32],
                copy_digest,
                3,
                66,
                7,
                RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE,
            )
        );
        assert_ne!(
            baseline,
            digest(
                &baseline_capture,
                roots_digest,
                inventory_digest,
                [62; 32],
                3,
                66,
                7,
                RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE,
            )
        );
        for (count, bytes, work, retained) in [
            (4, 66, 7, RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE),
            (3, 67, 7, RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE),
            (3, 66, 8, RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE),
            (3, 66, 7, RETAINED_BASE_CHARGE + RETAINED_ROOT_CHARGE + 1),
        ] {
            assert_ne!(
                baseline,
                digest(
                    &baseline_capture,
                    roots_digest,
                    inventory_digest,
                    copy_digest,
                    count,
                    bytes,
                    work,
                    retained,
                )
            );
        }
    }

    #[test]
    fn cancellation_before_or_during_iteration_returns_no_manifest() {
        let cancelled = AtomicBool::new(true);
        let inventory = inventory();
        let copies = copies(&inventory);
        assert_eq!(
            build_backup_manifest(
                capture(3, 66),
                inventory.clone(),
                copies.clone(),
                BackupLimits::default(),
                BackupControl::with_cancellation(&cancelled)
            ),
            Err(BackupError::Cancelled)
        );

        cancelled.store(false, Ordering::Release);
        struct CancellingLength<'a, T> {
            inner: std::vec::IntoIter<T>,
            flag: &'a AtomicBool,
            len_calls: &'a Cell<usize>,
            cancel: bool,
        }

        impl<T> Iterator for CancellingLength<'_, T> {
            type Item = T;

            fn next(&mut self) -> Option<Self::Item> {
                self.inner.next()
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                self.inner.size_hint()
            }
        }

        impl<T> ExactSizeIterator for CancellingLength<'_, T> {
            fn len(&self) -> usize {
                self.len_calls.set(self.len_calls.get() + 1);
                if self.cancel {
                    self.flag.store(true, Ordering::Release);
                }
                self.inner.len()
            }
        }

        let expected_len_calls = Cell::new(0);
        let copy_len_calls = Cell::new(0);
        assert_eq!(
            build_backup_manifest(
                capture(3, 66),
                CancellingLength {
                    inner: inventory.clone().into_iter(),
                    flag: &cancelled,
                    len_calls: &expected_len_calls,
                    cancel: true,
                },
                CancellingLength {
                    inner: copies.clone().into_iter(),
                    flag: &cancelled,
                    len_calls: &copy_len_calls,
                    cancel: false,
                },
                BackupLimits::default(),
                BackupControl::with_cancellation(&cancelled)
            ),
            Err(BackupError::Cancelled)
        );
        assert_eq!(expected_len_calls.get(), 1);
        assert_eq!(copy_len_calls.get(), 0);

        cancelled.store(false, Ordering::Release);
        struct Cancelling<'a, I> {
            inner: I,
            flag: &'a AtomicBool,
            polls: &'a Cell<usize>,
        }

        impl<I: Iterator> Iterator for Cancelling<'_, I> {
            type Item = I::Item;

            fn next(&mut self) -> Option<Self::Item> {
                let item = self.inner.next();
                self.polls.set(self.polls.get() + 1);
                if self.polls.get() == 2 {
                    self.flag.store(true, Ordering::Release);
                }
                item
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                self.inner.size_hint()
            }
        }

        impl<I: ExactSizeIterator> ExactSizeIterator for Cancelling<'_, I> {
            fn len(&self) -> usize {
                self.inner.len()
            }
        }

        let inventory_polls = Cell::new(0);
        let copy_polls = Cell::new(0);
        let cancelling_inventory = Cancelling {
            inner: inventory.into_iter(),
            flag: &cancelled,
            polls: &inventory_polls,
        };
        assert_eq!(
            build_backup_manifest(
                capture(3, 66),
                cancelling_inventory,
                ObservedExact {
                    inner: copies.into_iter(),
                    polls: &copy_polls,
                    reported_len: 3,
                },
                BackupLimits::default(),
                BackupControl::with_cancellation(&cancelled)
            ),
            Err(BackupError::Cancelled)
        );
        assert_eq!(inventory_polls.get(), 2);
        assert_eq!(copy_polls.get(), 1);
    }

    #[test]
    fn malformed_capture_commitments_and_generation_fail_before_iteration() {
        let inventory = inventory();
        let copies = copies(&inventory);
        let mut zero_schema_capture = capture(3, 66);
        zero_schema_capture.schema = [0; 32];
        assert_eq!(
            build(
                zero_schema_capture,
                inventory.clone(),
                copies.clone(),
                BackupLimits::default()
            ),
            Err(BackupError::InvalidCapture)
        );
        let mut drifted_capture = capture(3, 66);
        drifted_capture.inventory_generation = [99; 32];
        assert_eq!(
            build(drifted_capture, inventory, copies, BackupLimits::default()),
            Err(BackupError::InvalidCapture)
        );
    }

    #[test]
    fn manifest_binding_detects_projection_tampering() {
        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let mut manifest = build(
            capture(3, 66),
            inventory_rows,
            copy_rows,
            BackupLimits::default(),
        )
        .unwrap();
        assert!(manifest.has_valid_binding());
        manifest.inventory_bytes += 1;
        assert!(!manifest.has_valid_binding());

        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let mut manifest = build(
            capture(3, 66),
            inventory_rows,
            copy_rows,
            BackupLimits::default(),
        )
        .unwrap();
        manifest.work_units += 1;
        manifest.manifest_digest = digest_manifest_fields(
            &manifest.capture,
            manifest.roots_digest,
            manifest.inventory_digest,
            manifest.copy_evidence_digest,
            manifest.object_count,
            manifest.inventory_bytes,
            manifest.work_units,
            manifest.retained_bytes,
        );
        assert!(!manifest.has_valid_binding());

        manifest.work_units -= 1;
        manifest.retained_bytes += 1;
        manifest.manifest_digest = digest_manifest_fields(
            &manifest.capture,
            manifest.roots_digest,
            manifest.inventory_digest,
            manifest.copy_evidence_digest,
            manifest.object_count,
            manifest.inventory_bytes,
            manifest.work_units,
            manifest.retained_bytes,
        );
        assert!(!manifest.has_valid_binding());
    }

    #[test]
    fn structural_self_check_reconstructs_roots_but_not_consumed_streams() {
        let inventory_rows = inventory();
        let copy_rows = copies(&inventory_rows);
        let mut manifest = build(
            capture(3, 66),
            inventory_rows,
            copy_rows,
            BackupLimits::default(),
        )
        .unwrap();

        manifest.roots_digest = [91; 32];
        manifest.manifest_digest = digest_manifest_fields(
            &manifest.capture,
            manifest.roots_digest,
            manifest.inventory_digest,
            manifest.copy_evidence_digest,
            manifest.object_count,
            manifest.inventory_bytes,
            manifest.work_units,
            manifest.retained_bytes,
        );
        assert!(!manifest.has_valid_binding());

        manifest.roots_digest = digest_roots(&manifest.capture.roots, 1);
        manifest.inventory_digest = [92; 32];
        manifest.copy_evidence_digest = [93; 32];
        manifest.manifest_digest = digest_manifest_fields(
            &manifest.capture,
            manifest.roots_digest,
            manifest.inventory_digest,
            manifest.copy_evidence_digest,
            manifest.object_count,
            manifest.inventory_bytes,
            manifest.work_units,
            manifest.retained_bytes,
        );
        assert!(manifest.has_valid_binding());
    }
}
