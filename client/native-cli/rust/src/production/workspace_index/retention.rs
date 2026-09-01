//! Reader-safe retention for immutable workspace-index generations.
//!
//! This module is private local-state authority. It deliberately uses a
//! durable logical epoch rather than wall time, and pairs it with an OS lock
//! whose lifetime is owned by the reader process. Epoch expiry makes abandoned
//! lease records reclaimable; a still-locked reader always pins its generation.

use super::{
    artifact_names, constant_time_digest_eq, existing_index_directory, index_error, index_invalid,
    index_limit, index_recovery_required, index_write_unavailable, open_private_file,
    payload_wrapper, read_cursor_key, read_json_private, validate_seal_quick,
    validate_watcher_state, validate_wrapped, ActiveManifest, GenerationSeal, MutationLock,
    VerifiedWorkspaceMetadata, WatcherState, MAX_CONTROL_BYTES,
};
use crate::{random_hex, sync_directory, valid_digest, validated_root, CliError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const WORKSPACE_INDEX_COMPACTION_REPORT_SCHEMA: &str =
    "ogvcs.workspace-index/compaction-report/v1";
pub const BASE_RETAINED_GENERATIONS: usize = 2;
pub const MAX_COMPACTION_GENERATIONS_PER_RUN: usize = 8;
pub const MAX_READER_LEASES: usize = 128;

pub const MAX_AUTHENTICATED_GENERATIONS: usize = 128;
const MAX_RETENTION_NAMESPACE_ENTRIES: usize =
    MAX_AUTHENTICATED_GENERATIONS * 7 + MAX_READER_LEASES + 8;
const LEASE_EXPIRY_EPOCHS: u64 = 2;
const RETENTION_STATE_NAME: &str = "retention-v1.json";
const COMPACTION_INTENT_NAME: &str = "compaction-v1.json";
const LEASE_DIRECTORY_NAME: &str = "reader-leases-v1";
const RETENTION_STATE_DOMAIN: &[u8] = b"ogvcs.workspace-index/retention-state-hmac/v1\0";
const READER_LEASE_DOMAIN: &[u8] = b"ogvcs.workspace-index/reader-lease-hmac/v1\0";
const COMPACTION_INTENT_DOMAIN: &[u8] = b"ogvcs.workspace-index/compaction-intent-hmac/v1\0";
const MIGRATED_GENERATION_DOMAIN: &[u8] =
    b"ogvcs.workspace-index/migrated-generation-authority/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceIndexCompactionReport {
    pub schema: &'static str,
    pub epoch: u64,
    pub removed_generations: u64,
    pub removed_artifacts: u64,
    pub retained_generations: u64,
    pub pinned_generations: u64,
    pub reclaimed_leases: u64,
    pub more_pending: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationRecord {
    generation_id: String,
    generation: u64,
    generation_authority_sha256: String,
    generation_seal_sha256: String,
}

impl GenerationRecord {
    fn from_active(active: &ActiveManifest) -> Self {
        Self {
            generation_id: active.payload.generation_id.clone(),
            generation: active.payload.generation,
            generation_authority_sha256: active.payload_sha256.clone(),
            generation_seal_sha256: active.payload.generation_seal_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetentionStatePayload {
    schema: String,
    epoch: u64,
    workspace_id_digest: String,
    repository_id_hex: String,
    generations: Vec<GenerationRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RetentionState {
    payload: RetentionStatePayload,
    payload_sha256: String,
    mac_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReaderLeasePayload {
    schema: String,
    lease_id: String,
    generation: GenerationRecord,
    workspace_id_digest: String,
    repository_id_hex: String,
    issued_epoch: u64,
    expires_after_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReaderLease {
    payload: ReaderLeasePayload,
    payload_sha256: String,
    mac_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompactionIntentPayload {
    schema: String,
    epoch: u64,
    active: GenerationRecord,
    predecessor: Option<GenerationRecord>,
    candidates: Vec<GenerationRecord>,
    stale_lease_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompactionIntent {
    payload: CompactionIntentPayload,
    payload_sha256: String,
    mac_sha256: String,
}

pub(super) struct GenerationReadLease {
    path: PathBuf,
    lease_directory: PathBuf,
    file: Option<ValidatedFile>,
}

impl Drop for GenerationReadLease {
    fn drop(&mut self) {
        if let Some(validated) = self.file.take() {
            let remove = revalidate_path_identity(&self.path, &validated).is_ok();
            unlock_file(&validated.file);
            // The create-new Windows handle deliberately denies delete sharing;
            // close it before path removal. The identity check above narrows the
            // interval but does not claim same-authority unlink-by-handle safety.
            drop(validated);
            if remove && fs::remove_file(&self.path).is_ok() {
                let _ = sync_directory(&self.lease_directory);
            }
        }
    }
}

#[cfg(test)]
impl GenerationReadLease {
    pub(super) fn path_for_test(&self) -> &Path {
        &self.path
    }

    pub(super) fn abandon_for_test(mut self) {
        if let Some(validated) = self.file.take() {
            unlock_file(&validated.file);
        }
        // Drop now sees no live file and deliberately leaves the durable lease
        // record, exactly modelling process death after namespace publication.
    }
}

#[cfg(test)]
pub(super) fn rewrite_lease_binding_for_test(
    index: &Path,
    path: &Path,
    workspace_digest: &str,
    repository_id_hex: &str,
) {
    let key = read_cursor_key(index).unwrap();
    let mut lease: ReaderLease = read_json_private(path, MAX_CONTROL_BYTES).unwrap();
    lease.payload.workspace_id_digest = workspace_digest.to_owned();
    lease.payload.repository_id_hex = repository_id_hex.to_owned();
    lease.payload_sha256 = super::json_digest(&lease.payload).unwrap();
    lease.mac_sha256 = envelope_mac(&key, READER_LEASE_DOMAIN, &lease.payload).unwrap();
    let mut bytes = serde_json::to_vec(&lease).unwrap();
    bytes.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    sync_directory(path.parent().unwrap()).unwrap();
}

struct ExclusivelyLockedLease {
    name: String,
    path: PathBuf,
    file: File,
    lease: ReaderLease,
}

struct ValidatedFile {
    file: File,
    #[cfg(not(windows))]
    device: u64,
    #[cfg(not(windows))]
    inode: u64,
}

impl Drop for ExclusivelyLockedLease {
    fn drop(&mut self) {
        unlock_file(&self.file);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RetentionCrashPoint {
    EpochPublished = 1,
    LeasePublished = 2,
    IntentPublished = 3,
    LeaseDirectorySynced = 4,
    GenerationRemoved = 5,
    GenerationDirectorySynced = 6,
    StatePublished = 7,
    IntentRemoved = 8,
}

#[cfg(test)]
thread_local! {
    static RETENTION_CRASH_POINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn set_retention_crash_point(point: RetentionCrashPoint) {
    RETENTION_CRASH_POINT.with(|value| value.set(point as u8));
}

fn crash_now(point: RetentionCrashPoint) -> bool {
    #[cfg(test)]
    {
        RETENTION_CRASH_POINT.with(|value| {
            if value.get() == point as u8 {
                value.set(0);
                true
            } else {
                false
            }
        })
    }
    #[cfg(not(test))]
    {
        let _ = point;
        false
    }
}

fn injected_crash() -> CliError {
    index_error(
        "WORKSPACE_INDEX_COMPACTION_INJECTED_CRASH",
        "The test interrupted reader retention at a durable compaction boundary.",
        "Run workspace index recovery before retrying compaction or status.",
    )
}

fn owner_hmac(key: &[u8; 32], domain: &[u8], bytes: &[u8]) -> String {
    let mut inner_key = [0x36u8; 64];
    let mut outer_key = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(domain);
    inner.update(bytes);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    super::finalize_hasher(outer)
}

fn envelope_mac<T: Serialize>(
    key: &[u8; 32],
    domain: &[u8],
    payload: &T,
) -> Result<String, CliError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| super::internal_error())?;
    Ok(owner_hmac(key, domain, &bytes))
}

fn wrap_state(payload: RetentionStatePayload, key: &[u8; 32]) -> Result<RetentionState, CliError> {
    let (payload, payload_sha256) = payload_wrapper(payload)?;
    let mac_sha256 = envelope_mac(key, RETENTION_STATE_DOMAIN, &payload)?;
    Ok(RetentionState {
        payload,
        payload_sha256,
        mac_sha256,
    })
}

fn wrap_lease(payload: ReaderLeasePayload, key: &[u8; 32]) -> Result<ReaderLease, CliError> {
    let (payload, payload_sha256) = payload_wrapper(payload)?;
    let mac_sha256 = envelope_mac(key, READER_LEASE_DOMAIN, &payload)?;
    Ok(ReaderLease {
        payload,
        payload_sha256,
        mac_sha256,
    })
}

fn wrap_intent(
    payload: CompactionIntentPayload,
    key: &[u8; 32],
) -> Result<CompactionIntent, CliError> {
    let (payload, payload_sha256) = payload_wrapper(payload)?;
    let mac_sha256 = envelope_mac(key, COMPACTION_INTENT_DOMAIN, &payload)?;
    Ok(CompactionIntent {
        payload,
        payload_sha256,
        mac_sha256,
    })
}

fn validate_envelope<T: Serialize>(
    payload: &T,
    payload_sha256: &str,
    mac_sha256: &str,
    key: &[u8; 32],
    domain: &[u8],
) -> Result<(), CliError> {
    validate_wrapped(payload, payload_sha256)?;
    if !valid_digest(mac_sha256)
        || !constant_time_digest_eq(mac_sha256, &envelope_mac(key, domain, payload)?)
    {
        return Err(index_invalid());
    }
    Ok(())
}

fn workspace_id_digest(metadata: &VerifiedWorkspaceMetadata) -> String {
    super::digest_text(&metadata.workspace_id)
}

fn valid_lease_id(value: &str) -> bool {
    value.len() == 35
        && value.starts_with("l1.")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn lease_file_name(lease_id: &str) -> String {
    format!("lease-{lease_id}.json")
}

fn lease_id_from_name(name: &str) -> Option<&str> {
    name.strip_prefix("lease-")
        .and_then(|value| value.strip_suffix(".json"))
        .filter(|value| valid_lease_id(value))
}

fn validate_record(record: &GenerationRecord) -> Result<(), CliError> {
    if !super::valid_generation_id(&record.generation_id)
        || record.generation == 0
        || !valid_digest(&record.generation_authority_sha256)
        || !valid_digest(&record.generation_seal_sha256)
    {
        return Err(index_invalid());
    }
    Ok(())
}

fn migrated_generation_authority(seal_sha256: &str) -> Result<String, CliError> {
    if !valid_digest(seal_sha256) {
        return Err(index_invalid());
    }
    let mut hasher = Sha256::new();
    hasher.update(MIGRATED_GENERATION_DOMAIN);
    hasher.update(seal_sha256.as_bytes());
    Ok(super::finalize_hasher(hasher))
}

fn generation_artifact_identity(name: &str) -> Option<(&'static str, &str)> {
    for kind in [
        "entries", "lookup", "findings", "ignores", "events", "watcher", "seal",
    ] {
        let prefix = format!("{kind}-");
        if let Some(generation_id) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".v1"))
            .filter(|value| super::valid_generation_id(value))
        {
            return Some((kind, generation_id));
        }
    }
    None
}

fn validate_regular_control(index: &Path, name: &str) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(index.join(name)).map_err(|_| index_invalid())?;
    if super::is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(index_invalid());
    }
    Ok(())
}

fn enumerate_generation_namespace(
    index: &Path,
    allow_transition: bool,
) -> Result<BTreeMap<String, BTreeSet<String>>, CliError> {
    let mut generations: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut count = 0usize;
    for result in fs::read_dir(index).map_err(|_| index_invalid())? {
        count = count.checked_add(1).ok_or_else(index_invalid)?;
        if count > MAX_RETENTION_NAMESPACE_ENTRIES {
            return Err(index_limit("WORKSPACE_INDEX_RETENTION_NAMESPACE_LIMIT"));
        }
        let entry = result.map_err(|_| index_invalid())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| index_invalid())?;
        match name.as_str() {
            "active.json" | super::CURSOR_KEY_NAME | RETENTION_STATE_NAME => {
                validate_regular_control(index, &name)?;
            }
            "transition.json" if allow_transition => {
                validate_regular_control(index, &name)?;
                let transition: super::Transition =
                    read_json_private(&index.join(&name), MAX_CONTROL_BYTES)?;
                validate_wrapped(&transition.payload, &transition.payload_sha256)?;
                if transition.payload.schema != "ogvcs.workspace-index/transition/v1"
                    || !super::valid_generation_id(&transition.payload.generation_id)
                    || transition.payload.artifact_names
                        != artifact_names(&transition.payload.generation_id)
                    || transition
                        .payload
                        .prior_active_sha256
                        .as_deref()
                        .is_some_and(|digest| !valid_digest(digest))
                {
                    return Err(index_invalid());
                }
            }
            LEASE_DIRECTORY_NAME => {
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| index_invalid())?;
                if super::is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    return Err(index_invalid());
                }
                crate::ensure_private_directory(&entry.path())?;
            }
            COMPACTION_INTENT_NAME => return Err(index_recovery_required()),
            _ => {
                let (kind, generation_id) =
                    generation_artifact_identity(&name).ok_or_else(index_invalid)?;
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| index_invalid())?;
                if super::is_link_or_reparse(&metadata) || !metadata.is_file() {
                    return Err(index_invalid());
                }
                if !generations
                    .entry(generation_id.to_owned())
                    .or_default()
                    .insert(kind.to_owned())
                {
                    return Err(index_invalid());
                }
            }
        }
    }
    if generations.len() > MAX_AUTHENTICATED_GENERATIONS {
        return Err(index_limit("WORKSPACE_INDEX_GENERATION_HISTORY_LIMIT"));
    }
    let expected: BTreeSet<String> = [
        "entries", "lookup", "findings", "ignores", "events", "watcher", "seal",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if generations.values().any(|names| names != &expected) {
        return Err(index_invalid());
    }
    Ok(generations)
}

fn validate_state_shape(
    state: &RetentionState,
    metadata: &VerifiedWorkspaceMetadata,
    key: &[u8; 32],
) -> Result<(), CliError> {
    validate_envelope(
        &state.payload,
        &state.payload_sha256,
        &state.mac_sha256,
        key,
        RETENTION_STATE_DOMAIN,
    )?;
    let payload = &state.payload;
    if payload.schema != "ogvcs.workspace-index/retention-state/v1"
        || payload.epoch == 0
        || payload.workspace_id_digest != workspace_id_digest(metadata)
        || payload.repository_id_hex != metadata.binding.repository_id_hex
        || payload.generations.is_empty()
        || payload.generations.len() > MAX_AUTHENTICATED_GENERATIONS
    {
        return Err(index_invalid());
    }
    let mut prior = None;
    let mut ids = BTreeSet::new();
    for record in &payload.generations {
        validate_record(record)?;
        if prior.is_some_and(|value| value >= record.generation)
            || !ids.insert(record.generation_id.as_str())
        {
            return Err(index_invalid());
        }
        prior = Some(record.generation);
    }
    if payload.generations.len() >= BASE_RETAINED_GENERATIONS {
        let current = &payload.generations[payload.generations.len() - 1];
        let predecessor = &payload.generations[payload.generations.len() - 2];
        if predecessor.generation.checked_add(1) != Some(current.generation) {
            return Err(index_invalid());
        }
    }
    Ok(())
}

fn validate_state_current(state: &RetentionState, active: &ActiveManifest) -> Result<(), CliError> {
    if state.payload.generations.last() != Some(&GenerationRecord::from_active(active)) {
        return Err(index_invalid());
    }
    Ok(())
}

fn read_state(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    key: &[u8; 32],
) -> Result<Option<RetentionState>, CliError> {
    let path = index.join(RETENTION_STATE_NAME);
    let state = match fs::symlink_metadata(&path) {
        Ok(metadata) if !super::is_link_or_reparse(&metadata) && metadata.is_file() => {
            Some(read_json_private(&path, MAX_CONTROL_BYTES)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        _ => return Err(index_invalid()),
    };
    if let Some(state) = &state {
        validate_state_shape(state, metadata, key)?;
    }
    Ok(state)
}

fn write_state(index: &Path, state: &RetentionState) -> Result<(), CliError> {
    super::write_json_atomic(&index.join(RETENTION_STATE_NAME), state)?;
    sync_directory(index)
}

fn authenticate_existing_generation(
    index: &Path,
    generation_id: &str,
    active: &ActiveManifest,
) -> Result<GenerationRecord, CliError> {
    let seal: GenerationSeal = read_json_private(
        &index.join(format!("seal-{generation_id}.v1")),
        MAX_CONTROL_BYTES,
    )?;
    validate_wrapped(&seal.payload, &seal.payload_sha256)?;
    if seal.payload.generation_id != generation_id
        || seal.payload.generation > active.payload.generation
    {
        return Err(index_invalid());
    }
    validate_generation_artifacts(
        index,
        &GenerationRecord {
            generation_id: generation_id.to_owned(),
            generation: seal.payload.generation,
            generation_authority_sha256: if generation_id == active.payload.generation_id {
                active.payload_sha256.clone()
            } else {
                migrated_generation_authority(&seal.payload_sha256)?
            },
            generation_seal_sha256: seal.payload_sha256.clone(),
        },
    )?;
    for artifact in [
        &seal.payload.entries,
        &seal.payload.lookup,
        &seal.payload.findings,
        &seal.payload.ignores,
    ] {
        if super::hash_file(&index.join(&artifact.name))? != artifact.sha256 {
            return Err(index_invalid());
        }
    }
    super::validate_lookup_order(index, &seal.payload)?;
    let watcher: WatcherState = read_json_private(
        &index.join(format!("watcher-{generation_id}.v1")),
        MAX_CONTROL_BYTES,
    )?;
    super::validate_watch_records(index, &seal.payload, &watcher.payload)?;
    let record = GenerationRecord {
        generation_id: generation_id.to_owned(),
        generation: seal.payload.generation,
        generation_authority_sha256: if generation_id == active.payload.generation_id {
            active.payload_sha256.clone()
        } else {
            migrated_generation_authority(&seal.payload_sha256)?
        },
        generation_seal_sha256: seal.payload_sha256,
    };
    validate_record(&record)?;
    Ok(record)
}

fn authenticate_existing_generations(
    index: &Path,
    active: &ActiveManifest,
) -> Result<Vec<GenerationRecord>, CliError> {
    let namespace = enumerate_generation_namespace(index, index.join("transition.json").exists())?;
    if let Some(directory) = checked_lease_directory(index, false)? {
        if !lease_entries(&directory)?.is_empty() {
            return Err(index_invalid());
        }
    }
    let mut records = Vec::with_capacity(namespace.len());
    for generation_id in namespace.keys() {
        records.push(authenticate_existing_generation(
            index,
            generation_id,
            active,
        )?);
    }
    records.sort_by_key(|record| record.generation);
    if records.is_empty()
        || records.last() != Some(&GenerationRecord::from_active(active))
        || records
            .windows(2)
            .any(|pair| pair[0].generation.checked_add(1) != Some(pair[1].generation))
    {
        return Err(index_invalid());
    }
    Ok(records)
}

fn validate_authenticated_namespace(index: &Path, state: &RetentionState) -> Result<(), CliError> {
    let namespace = enumerate_generation_namespace(index, false)?;
    let expected: BTreeSet<&str> = state
        .payload
        .generations
        .iter()
        .map(|record| record.generation_id.as_str())
        .collect();
    let observed: BTreeSet<&str> = namespace.keys().map(String::as_str).collect();
    if observed != expected {
        return Err(index_invalid());
    }
    if let Some(directory) = checked_lease_directory(index, false)? {
        let _ = lease_entries(&directory)?;
    }
    Ok(())
}

fn validate_recovery_namespace(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    state: &RetentionState,
    intent: &CompactionIntent,
) -> Result<(), CliError> {
    let candidate_ids: BTreeSet<&str> = intent
        .payload
        .candidates
        .iter()
        .map(|record| record.generation_id.as_str())
        .collect();
    let mut allowed_ids: BTreeSet<&str> = state
        .payload
        .generations
        .iter()
        .map(|record| record.generation_id.as_str())
        .collect();
    allowed_ids.extend(candidate_ids.iter().copied());
    let mut observed: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut count = 0usize;
    for result in fs::read_dir(index).map_err(|_| index_invalid())? {
        count = count.checked_add(1).ok_or_else(index_invalid)?;
        if count > MAX_RETENTION_NAMESPACE_ENTRIES {
            return Err(index_limit("WORKSPACE_INDEX_RETENTION_NAMESPACE_LIMIT"));
        }
        let entry = result.map_err(|_| index_invalid())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| index_invalid())?;
        match name.as_str() {
            "active.json"
            | super::CURSOR_KEY_NAME
            | RETENTION_STATE_NAME
            | COMPACTION_INTENT_NAME => validate_regular_control(index, &name)?,
            LEASE_DIRECTORY_NAME => {
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| index_invalid())?;
                if super::is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    return Err(index_invalid());
                }
                crate::ensure_private_directory(&entry.path())?;
            }
            _ => {
                let (kind, generation_id) =
                    generation_artifact_identity(&name).ok_or_else(index_invalid)?;
                if !allowed_ids.contains(generation_id) {
                    return Err(index_invalid());
                }
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| index_invalid())?;
                if super::is_link_or_reparse(&metadata) || !metadata.is_file() {
                    return Err(index_invalid());
                }
                if !observed
                    .entry(generation_id.to_owned())
                    .or_default()
                    .insert(kind.to_owned())
                {
                    return Err(index_invalid());
                }
            }
        }
    }
    let expected: BTreeSet<String> = [
        "entries", "lookup", "findings", "ignores", "events", "watcher", "seal",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for record in &state.payload.generations {
        if !candidate_ids.contains(record.generation_id.as_str())
            && observed.get(&record.generation_id) != Some(&expected)
        {
            return Err(index_invalid());
        }
    }
    for record in &intent.payload.candidates {
        let in_state = state.payload.generations.contains(record);
        match observed.get(&record.generation_id) {
            Some(names) if in_state && names.is_subset(&expected) => {}
            None => {}
            _ => return Err(index_invalid()),
        }
    }
    let (pinned, stale) = inspect_leases(index, metadata, state)?;
    if intent
        .payload
        .candidates
        .iter()
        .any(|record| pinned.contains(&record.generation_id))
    {
        return Err(index_recovery_required());
    }
    let intended_stale: BTreeSet<&str> = intent
        .payload
        .stale_lease_names
        .iter()
        .map(String::as_str)
        .collect();
    if stale
        .iter()
        .any(|lease| !intended_stale.contains(lease.name.as_str()))
    {
        return Err(index_invalid());
    }
    Ok(())
}

fn observe_active_state(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
) -> Result<RetentionState, CliError> {
    let key = read_cursor_key(index)?;
    let active_record = GenerationRecord::from_active(active);
    let state = match read_state(index, metadata, &key)? {
        None => {
            let generations = authenticate_existing_generations(index, active)?;
            wrap_state(
                RetentionStatePayload {
                    schema: "ogvcs.workspace-index/retention-state/v1".to_owned(),
                    epoch: 1,
                    workspace_id_digest: workspace_id_digest(metadata),
                    repository_id_hex: metadata.binding.repository_id_hex.clone(),
                    generations,
                },
                &key,
            )?
        }
        Some(state) if state.payload.generations.last() == Some(&active_record) => {
            return Ok(state)
        }
        Some(mut state) => {
            let prior = state.payload.generations.last().ok_or_else(index_invalid)?;
            if prior.generation.checked_add(1) != Some(active.payload.generation)
                || state.payload.generations.len() >= MAX_AUTHENTICATED_GENERATIONS
            {
                return Err(index_invalid());
            }
            state.payload.epoch = state
                .payload
                .epoch
                .checked_add(1)
                .ok_or_else(index_invalid)?;
            state.payload.generations.push(active_record);
            wrap_state(state.payload, &key)?
        }
    };
    write_state(index, &state)?;
    Ok(state)
}

pub(super) fn observe_active_generation(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
) -> Result<(), CliError> {
    observe_active_state(index, metadata, active).map(|_| ())
}

pub(super) fn ensure_generation_capacity(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
) -> Result<(), CliError> {
    let state = observe_active_state(index, metadata, active)?;
    validate_authenticated_namespace(index, &state)?;
    for record in &state.payload.generations {
        validate_generation_seal_authority(index, record)?;
    }
    if state.payload.generations.len() >= MAX_AUTHENTICATED_GENERATIONS {
        return Err(index_limit("WORKSPACE_INDEX_GENERATION_HISTORY_LIMIT"));
    }
    Ok(())
}

fn advance_epoch(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
) -> Result<RetentionState, CliError> {
    let key = read_cursor_key(index)?;
    let mut state = observe_active_state(index, metadata, active)?;
    validate_state_shape(&state, metadata, &key)?;
    validate_state_current(&state, active)?;
    state.payload.epoch = state
        .payload
        .epoch
        .checked_add(1)
        .ok_or_else(index_invalid)?;
    state = wrap_state(state.payload, &key)?;
    write_state(index, &state)?;
    Ok(state)
}

fn checked_lease_directory(index: &Path, create: bool) -> Result<Option<PathBuf>, CliError> {
    let directory = index.join(LEASE_DIRECTORY_NAME);
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if !super::is_link_or_reparse(&metadata) && metadata.is_dir() => {
            crate::ensure_private_directory(&directory)?;
            Ok(Some(directory))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            crate::create_private_directory(&directory)?;
            sync_directory(index)?;
            Ok(Some(directory))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        _ => Err(index_invalid()),
    }
}

fn lease_entries(directory: &Path) -> Result<Vec<(String, PathBuf)>, CliError> {
    let mut entries = Vec::new();
    for result in fs::read_dir(directory).map_err(|_| index_invalid())? {
        if entries.len() >= MAX_READER_LEASES {
            return Err(index_limit("WORKSPACE_INDEX_READER_LEASE_LIMIT"));
        }
        let entry = result.map_err(|_| index_invalid())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| index_invalid())?;
        if lease_id_from_name(&name).is_none() {
            return Err(index_invalid());
        }
        entries.push((name, entry.path()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn validate_open_file(path: &Path, file: File) -> Result<ValidatedFile, CliError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| index_invalid())?;
    if super::is_link_or_reparse(&path_metadata) || !path_metadata.is_file() {
        return Err(index_invalid());
    }
    let opened = file.metadata().map_err(|_| index_invalid())?;
    if !opened.is_file() || opened.len() != path_metadata.len() {
        return Err(index_invalid());
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.nlink() != 1
            || path_metadata.nlink() != 1
            || opened.dev() != path_metadata.dev()
            || opened.ino() != path_metadata.ino()
        {
            return Err(index_invalid());
        }
        Ok(ValidatedFile {
            file,
            device: opened.dev(),
            inode: opened.ino(),
        })
    }
    #[cfg(windows)]
    {
        Ok(ValidatedFile { file })
    }
}

fn open_validated_file(path: &Path) -> Result<ValidatedFile, CliError> {
    validate_open_file(path, open_private_file(path)?)
}

fn revalidate_path_identity(path: &Path, validated: &ValidatedFile) -> Result<(), CliError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|_| index_invalid())?;
    if super::is_link_or_reparse(&path_metadata) || !path_metadata.is_file() {
        return Err(index_invalid());
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = validated.file.metadata().map_err(|_| index_invalid())?;
        if opened.nlink() != 1
            || path_metadata.nlink() != 1
            || opened.dev() != validated.device
            || opened.ino() != validated.inode
            || path_metadata.dev() != validated.device
            || path_metadata.ino() != validated.inode
        {
            return Err(index_invalid());
        }
    }
    #[cfg(windows)]
    {
        let opened = validated.file.metadata().map_err(|_| index_invalid())?;
        if !opened.is_file() || opened.len() != path_metadata.len() {
            return Err(index_invalid());
        }
    }
    Ok(())
}

fn validate_lease(
    lease: &ReaderLease,
    expected_id: &str,
    metadata: &VerifiedWorkspaceMetadata,
    state: &RetentionState,
    key: &[u8; 32],
) -> Result<(), CliError> {
    validate_envelope(
        &lease.payload,
        &lease.payload_sha256,
        &lease.mac_sha256,
        key,
        READER_LEASE_DOMAIN,
    )?;
    let payload = &lease.payload;
    if payload.schema != "ogvcs.workspace-index/reader-lease/v1"
        || payload.lease_id != expected_id
        || payload.workspace_id_digest != workspace_id_digest(metadata)
        || payload.repository_id_hex != metadata.binding.repository_id_hex
        || payload.issued_epoch == 0
        || payload.expires_after_epoch
            != payload
                .issued_epoch
                .checked_add(LEASE_EXPIRY_EPOCHS)
                .ok_or_else(index_invalid)?
        || payload.issued_epoch > state.payload.epoch
        || !state.payload.generations.contains(&payload.generation)
    {
        return Err(index_invalid());
    }
    validate_record(&payload.generation)
}

pub(super) fn acquire_generation_read_lease(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
) -> Result<GenerationReadLease, CliError> {
    let key = read_cursor_key(index)?;
    let state = observe_active_state(index, metadata, active)?;
    validate_state_current(&state, active)?;
    let directory = checked_lease_directory(index, true)?.ok_or_else(index_invalid)?;
    let existing_leases = lease_entries(&directory)?;
    if existing_leases.len() >= MAX_READER_LEASES {
        return Err(index_limit("WORKSPACE_INDEX_READER_LEASE_LIMIT"));
    }
    for (name, path) in existing_leases {
        let id = lease_id_from_name(&name).ok_or_else(index_invalid)?;
        let lease: ReaderLease = read_json_private(&path, MAX_CONTROL_BYTES)?;
        validate_lease(&lease, id, metadata, &state, &key)?;
    }
    let lease_id = format!("l1.{}", random_hex(16)?);
    let expires_after_epoch = state
        .payload
        .epoch
        .checked_add(LEASE_EXPIRY_EPOCHS)
        .ok_or_else(index_invalid)?;
    let lease = wrap_lease(
        ReaderLeasePayload {
            schema: "ogvcs.workspace-index/reader-lease/v1".to_owned(),
            lease_id: lease_id.clone(),
            generation: GenerationRecord::from_active(active),
            workspace_id_digest: workspace_id_digest(metadata),
            repository_id_hex: metadata.binding.repository_id_hex.clone(),
            issued_epoch: state.payload.epoch,
            expires_after_epoch,
        },
        &key,
    )?;
    let path = directory.join(lease_file_name(&lease_id));
    let mut bytes = serde_json::to_vec(&lease).map_err(|_| super::internal_error())?;
    bytes.push(b'\n');
    let mut file =
        crate::create_private_file(&path, true).map_err(|_| index_write_unavailable())?;
    file.write_all(&bytes)
        .map_err(|_| index_write_unavailable())?;
    file.sync_all().map_err(|_| index_write_unavailable())?;
    let validated = validate_open_file(&path, file)?;
    lock_shared(&validated.file)?;
    sync_directory(&directory)?;
    if crash_now(RetentionCrashPoint::LeasePublished) {
        return Err(injected_crash());
    }
    Ok(GenerationReadLease {
        path,
        lease_directory: directory,
        file: Some(validated),
    })
}

fn validate_generation_seal_authority(
    index: &Path,
    record: &GenerationRecord,
) -> Result<(), CliError> {
    let seal: GenerationSeal = read_json_private(
        &index.join(format!("seal-{}.v1", record.generation_id)),
        MAX_CONTROL_BYTES,
    )?;
    validate_wrapped(&seal.payload, &seal.payload_sha256)?;
    if seal.payload.generation_id != record.generation_id
        || seal.payload.generation != record.generation
        || seal.payload_sha256 != record.generation_seal_sha256
    {
        return Err(index_invalid());
    }
    validate_seal_quick(index, &seal)?;
    let watcher_path = index.join(format!("watcher-{}.v1", record.generation_id));
    let watcher_metadata = fs::symlink_metadata(watcher_path).map_err(|_| index_invalid())?;
    if super::is_link_or_reparse(&watcher_metadata) || !watcher_metadata.is_file() {
        return Err(index_invalid());
    }
    Ok(())
}

fn validate_generation_artifacts(index: &Path, record: &GenerationRecord) -> Result<(), CliError> {
    validate_generation_seal_authority(index, record)?;
    let seal: GenerationSeal = read_json_private(
        &index.join(format!("seal-{}.v1", record.generation_id)),
        MAX_CONTROL_BYTES,
    )?;
    let watcher: WatcherState = read_json_private(
        &index.join(format!("watcher-{}.v1", record.generation_id)),
        MAX_CONTROL_BYTES,
    )?;
    validate_wrapped(&watcher.payload, &watcher.payload_sha256)?;
    validate_watcher_state(index, &seal, &watcher)
}

fn inspect_leases(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    state: &RetentionState,
) -> Result<(BTreeSet<String>, Vec<ExclusivelyLockedLease>), CliError> {
    let Some(directory) = checked_lease_directory(index, false)? else {
        return Ok((BTreeSet::new(), Vec::new()));
    };
    let key = read_cursor_key(index)?;
    let mut pinned = BTreeSet::new();
    let mut stale = Vec::new();
    for (name, path) in lease_entries(&directory)? {
        let id = lease_id_from_name(&name).ok_or_else(index_invalid)?;
        let lease: ReaderLease = read_json_private(&path, MAX_CONTROL_BYTES)?;
        validate_lease(&lease, id, metadata, state, &key)?;
        let validated = open_validated_file(&path)?;
        if try_lock_exclusive(&validated.file)? {
            revalidate_path_identity(&path, &validated)?;
            if lease.payload.expires_after_epoch <= state.payload.epoch {
                stale.push(ExclusivelyLockedLease {
                    name,
                    path,
                    file: validated.file,
                    lease,
                });
            } else {
                pinned.insert(lease.payload.generation.generation_id.clone());
                unlock_file(&validated.file);
            }
        } else {
            pinned.insert(lease.payload.generation.generation_id.clone());
        }
    }
    Ok((pinned, stale))
}

fn intent_path(index: &Path) -> PathBuf {
    index.join(COMPACTION_INTENT_NAME)
}

pub(super) fn compaction_pending(index: &Path) -> Result<bool, CliError> {
    match fs::symlink_metadata(intent_path(index)) {
        Ok(metadata) if !super::is_link_or_reparse(&metadata) && metadata.is_file() => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        _ => Err(index_invalid()),
    }
}

fn validate_intent(
    intent: &CompactionIntent,
    state: &RetentionState,
    active: &ActiveManifest,
    key: &[u8; 32],
) -> Result<(), CliError> {
    validate_envelope(
        &intent.payload,
        &intent.payload_sha256,
        &intent.mac_sha256,
        key,
        COMPACTION_INTENT_DOMAIN,
    )?;
    let payload = &intent.payload;
    let active_record = GenerationRecord::from_active(active);
    let predecessor = state.payload.generations.iter().rev().nth(1).cloned();
    if payload.schema != "ogvcs.workspace-index/compaction-intent/v1"
        || payload.epoch == 0
        || payload.epoch != state.payload.epoch
        || payload.active != active_record
        || payload.predecessor != predecessor
        || payload.candidates.len() > MAX_COMPACTION_GENERATIONS_PER_RUN
        || payload.stale_lease_names.len() > MAX_READER_LEASES
    {
        return Err(index_invalid());
    }
    let mut ids = BTreeSet::new();
    let mut candidates_are_in_state = None;
    let mut prior_generation = None;
    for record in &payload.candidates {
        validate_record(record)?;
        if record == &active_record
            || payload.predecessor.as_ref() == Some(record)
            || record.generation >= active_record.generation
            || !ids.insert(record.generation_id.as_str())
            || prior_generation.is_some_and(|prior| prior >= record.generation)
        {
            return Err(index_invalid());
        }
        prior_generation = Some(record.generation);
        let in_state = match state
            .payload
            .generations
            .iter()
            .find(|candidate| candidate.generation_id == record.generation_id)
        {
            Some(candidate) if candidate == record => true,
            Some(_) => return Err(index_invalid()),
            None if state
                .payload
                .generations
                .iter()
                .all(|candidate| candidate.generation != record.generation) =>
            {
                false
            }
            None => return Err(index_invalid()),
        };
        if candidates_are_in_state.is_some_and(|expected| expected != in_state) {
            return Err(index_invalid());
        }
        candidates_are_in_state = Some(in_state);
    }
    let mut names = BTreeSet::new();
    for name in &payload.stale_lease_names {
        if lease_id_from_name(name).is_none() || !names.insert(name.as_str()) {
            return Err(index_invalid());
        }
    }
    Ok(())
}

fn write_intent(index: &Path, intent: &CompactionIntent) -> Result<(), CliError> {
    super::write_json_new(&intent_path(index), intent)?;
    sync_directory(index)
}

fn remove_known_file(path: &Path, missing_ok: bool) -> Result<bool, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !super::is_link_or_reparse(&metadata) && metadata.is_file() => {
            let validated = open_validated_file(path)?;
            revalidate_path_identity(path, &validated)?;
            fs::remove_file(path).map_err(|_| index_write_unavailable())?;
            Ok(true)
        }
        Err(error) if missing_ok && error.kind() == io::ErrorKind::NotFound => Ok(false),
        _ => Err(index_invalid()),
    }
}

fn remove_generation(
    index: &Path,
    record: &GenerationRecord,
    missing_ok: bool,
) -> Result<u64, CliError> {
    let mut removed = 0u64;
    for name in artifact_names(&record.generation_id) {
        if remove_known_file(&index.join(name), missing_ok)? {
            removed = removed.checked_add(1).ok_or_else(index_invalid)?;
        }
    }
    Ok(removed)
}

fn apply_intent(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
    mut state: RetentionState,
    intent: &CompactionIntent,
    missing_ok: bool,
) -> Result<(RetentionState, u64, u64), CliError> {
    let key = read_cursor_key(index)?;
    validate_state_shape(&state, metadata, &key)?;
    validate_state_current(&state, active)?;
    validate_intent(intent, &state, active, &key)?;
    let lease_directory = checked_lease_directory(index, false)?;
    let mut reclaimed = 0u64;
    if let Some(directory) = &lease_directory {
        for name in &intent.payload.stale_lease_names {
            let path = directory.join(name);
            match fs::symlink_metadata(&path) {
                Ok(file_metadata)
                    if !super::is_link_or_reparse(&file_metadata) && file_metadata.is_file() =>
                {
                    let id = lease_id_from_name(name).ok_or_else(index_invalid)?;
                    let lease: ReaderLease = read_json_private(&path, MAX_CONTROL_BYTES)?;
                    validate_lease(&lease, id, metadata, &state, &key)?;
                    if lease.payload.expires_after_epoch > intent.payload.epoch {
                        return Err(index_invalid());
                    }
                    let validated = open_validated_file(&path)?;
                    if !try_lock_exclusive(&validated.file)? {
                        return Err(index_recovery_required());
                    }
                    revalidate_path_identity(&path, &validated)?;
                    fs::remove_file(&path).map_err(|_| index_write_unavailable())?;
                    unlock_file(&validated.file);
                    reclaimed = reclaimed.checked_add(1).ok_or_else(index_invalid)?;
                }
                Err(error) if missing_ok && error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(index_invalid()),
            }
        }
        sync_directory(directory)?;
        if crash_now(RetentionCrashPoint::LeaseDirectorySynced) {
            return Err(injected_crash());
        }
    } else if !intent.payload.stale_lease_names.is_empty() {
        return Err(index_invalid());
    }
    let mut removed_artifacts = 0u64;
    for (ordinal, record) in intent.payload.candidates.iter().enumerate() {
        removed_artifacts = removed_artifacts
            .checked_add(remove_generation(index, record, missing_ok)?)
            .ok_or_else(index_invalid)?;
        if ordinal == 0 && crash_now(RetentionCrashPoint::GenerationRemoved) {
            return Err(injected_crash());
        }
    }
    sync_directory(index)?;
    if crash_now(RetentionCrashPoint::GenerationDirectorySynced) {
        return Err(injected_crash());
    }
    let candidate_ids: BTreeSet<&str> = intent
        .payload
        .candidates
        .iter()
        .map(|record| record.generation_id.as_str())
        .collect();
    state
        .payload
        .generations
        .retain(|record| !candidate_ids.contains(record.generation_id.as_str()));
    state = wrap_state(state.payload, &key)?;
    write_state(index, &state)?;
    if crash_now(RetentionCrashPoint::StatePublished) {
        return Err(injected_crash());
    }
    remove_known_file(&intent_path(index), false)?;
    sync_directory(index)?;
    if crash_now(RetentionCrashPoint::IntentRemoved) {
        return Err(injected_crash());
    }
    Ok((state, removed_artifacts, reclaimed))
}

pub(super) fn recover_compaction_at(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
) -> Result<bool, CliError> {
    if !compaction_pending(index)? {
        return Ok(false);
    }
    let key = read_cursor_key(index)?;
    let state = read_state(index, metadata, &key)?.ok_or_else(index_invalid)?;
    let intent: CompactionIntent = read_json_private(&intent_path(index), MAX_CONTROL_BYTES)?;
    validate_intent(&intent, &state, active, &key)?;
    validate_recovery_namespace(index, metadata, &state, &intent)?;
    apply_intent(index, metadata, active, state, &intent, true)?;
    Ok(true)
}

pub fn compact_workspace_index(root: &Path) -> Result<WorkspaceIndexCompactionReport, CliError> {
    let root = validated_root(root)?;
    let _lock = MutationLock::acquire(&root)?;
    let index = existing_index_directory(&root)?;
    if index.join("transition.json").exists() || compaction_pending(&index)? {
        return Err(index_recovery_required());
    }
    let (loaded_index, metadata, active, _, _, _) = super::load_active(&root, false)?;
    if loaded_index != index {
        return Err(index_invalid());
    }
    let state = advance_epoch(&index, &metadata, &active)?;
    if crash_now(RetentionCrashPoint::EpochPublished) {
        return Err(injected_crash());
    }
    let key = read_cursor_key(&index)?;
    validate_state_shape(&state, &metadata, &key)?;
    validate_state_current(&state, &active)?;
    validate_authenticated_namespace(&index, &state)?;
    for record in &state.payload.generations {
        validate_generation_seal_authority(&index, record)?;
    }
    let (mut pinned, stale) = inspect_leases(&index, &metadata, &state)?;
    let active_record = state
        .payload
        .generations
        .last()
        .cloned()
        .ok_or_else(index_invalid)?;
    let predecessor = state.payload.generations.iter().rev().nth(1).cloned();
    pinned.insert(active_record.generation_id.clone());
    if let Some(record) = &predecessor {
        pinned.insert(record.generation_id.clone());
    }
    let eligible: Vec<GenerationRecord> = state
        .payload
        .generations
        .iter()
        .filter(|record| !pinned.contains(&record.generation_id))
        .cloned()
        .collect();
    let more_pending = eligible.len() > MAX_COMPACTION_GENERATIONS_PER_RUN;
    let candidates: Vec<GenerationRecord> = eligible
        .into_iter()
        .take(MAX_COMPACTION_GENERATIONS_PER_RUN)
        .collect();
    let stale_lease_names: Vec<String> = stale.iter().map(|lease| lease.name.clone()).collect();
    if candidates.is_empty() && stale_lease_names.is_empty() {
        return Ok(WorkspaceIndexCompactionReport {
            schema: WORKSPACE_INDEX_COMPACTION_REPORT_SCHEMA,
            epoch: state.payload.epoch,
            removed_generations: 0,
            removed_artifacts: 0,
            retained_generations: state.payload.generations.len() as u64,
            pinned_generations: pinned.len() as u64,
            reclaimed_leases: 0,
            more_pending,
        });
    }
    let intent = wrap_intent(
        CompactionIntentPayload {
            schema: "ogvcs.workspace-index/compaction-intent/v1".to_owned(),
            epoch: state.payload.epoch,
            active: active_record,
            predecessor,
            candidates: candidates.clone(),
            stale_lease_names,
        },
        &key,
    )?;
    write_intent(&index, &intent)?;
    if crash_now(RetentionCrashPoint::IntentPublished) {
        return Err(injected_crash());
    }
    // The exclusive handles keep every abandoned lease stable between planning
    // and its authenticated intent publication. Legitimate readers never reuse
    // a lease identifier.
    for lease in &stale {
        if lease.path.file_name().and_then(|name| name.to_str()) != Some(lease.name.as_str())
            || lease.lease.payload.expires_after_epoch > state.payload.epoch
        {
            return Err(index_invalid());
        }
    }
    drop(stale);
    let removed_count = intent.payload.candidates.len() as u64;
    let (state, removed_artifacts, reclaimed_leases) =
        apply_intent(&index, &metadata, &active, state, &intent, false)?;
    Ok(WorkspaceIndexCompactionReport {
        schema: WORKSPACE_INDEX_COMPACTION_REPORT_SCHEMA,
        epoch: state.payload.epoch,
        removed_generations: removed_count,
        removed_artifacts,
        retained_generations: state.payload.generations.len() as u64,
        pinned_generations: pinned.len() as u64,
        reclaimed_leases,
        more_pending,
    })
}

#[cfg(not(windows))]
fn lock_shared(file: &File) -> Result<(), CliError> {
    // SAFETY: file owns a live descriptor and flock has no additional pointer
    // preconditions.
    if unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(file),
            libc::LOCK_SH | libc::LOCK_NB,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(index_write_unavailable())
    }
}

#[cfg(windows)]
fn lock_shared(file: &File) -> Result<(), CliError> {
    use std::mem::zeroed;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_FAIL_IMMEDIATELY};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: the file handle and zeroed synchronous OVERLAPPED are valid.
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    if unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    } == 0
    {
        Err(index_write_unavailable())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn try_lock_exclusive(file: &File) -> Result<bool, CliError> {
    // SAFETY: file owns a live descriptor and flock has no pointer arguments.
    if unsafe {
        libc::flock(
            std::os::fd::AsRawFd::as_raw_fd(file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    } == 0
    {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(index_invalid())
    }
}

#[cfg(windows)]
fn try_lock_exclusive(file: &File) -> Result<bool, CliError> {
    use std::mem::zeroed;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: the file handle and zeroed synchronous OVERLAPPED are valid.
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    if unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    } != 0
    {
        return Ok(true);
    }
    if io::Error::last_os_error().raw_os_error() == Some(33) {
        Ok(false)
    } else {
        Err(index_invalid())
    }
}

#[cfg(not(windows))]
fn unlock_file(file: &File) {
    // SAFETY: the descriptor remains live for this call.
    unsafe {
        libc::flock(std::os::fd::AsRawFd::as_raw_fd(file), libc::LOCK_UN);
    }
}

#[cfg(windows)]
fn unlock_file(file: &File) {
    use std::mem::zeroed;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: the live handle owns the matching byte-range lock.
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    unsafe {
        UnlockFileEx(file.as_raw_handle() as _, 0, 1, 0, &mut overlapped);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_hmac_matches_independent_known_answer_and_rejects_hostile_variants() {
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        assert_eq!(
            owner_hmac(&key, READER_LEASE_DOMAIN, b"known-answer"),
            "78717d62d38c4c9794e4120459b955a2df0d034dc5d296b70ef2ea3b946f70eb"
        );
        let payload = serde_json::json!({"answer": 42, "scope": "workspace-a"});
        let payload_sha256 = super::super::json_digest(&payload).unwrap();
        let mac = envelope_mac(&key, READER_LEASE_DOMAIN, &payload).unwrap();
        validate_envelope(&payload, &payload_sha256, &mac, &key, READER_LEASE_DOMAIN).unwrap();

        let mut wrong_key = key;
        wrong_key[0] ^= 0x80;
        assert!(validate_envelope(
            &payload,
            &payload_sha256,
            &mac,
            &wrong_key,
            READER_LEASE_DOMAIN,
        )
        .is_err());
        let tampered = serde_json::json!({"answer": 43, "scope": "workspace-a"});
        assert!(validate_envelope(
            &tampered,
            &super::super::json_digest(&tampered).unwrap(),
            &mac,
            &key,
            READER_LEASE_DOMAIN,
        )
        .is_err());
        assert!(validate_envelope(
            &payload,
            &payload_sha256,
            &mac,
            &key,
            RETENTION_STATE_DOMAIN,
        )
        .is_err());
    }
}
