//! Pure, bounded OGVCS-013 selective-sync selection kernel candidate.
//!
//! The output is an untrusted projection, not a sync plan, grant, receipt, or
//! production-operation brand. Every emitted byte must be discarded on error.
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use ogvcs_path_contract::{case_fold, path_collision_keys_with_options, CaseMode, PathProfile};
use sha2::{Digest as _, Sha256};

mod generated_contract;
pub use generated_contract::{
    CONTRACT_ARTIFACT_SET_SHA256, CONTRACT_MANIFEST_SHA256, CONTRACT_VERSION,
    ERROR_REGISTRY_SHA256, GOLDEN_VECTORS_SHA256, PATH_CONTRACT_MANIFEST_SHA256,
};

pub const SPEC_SCHEMA_VERSION: &str = "ogvcs.selective-sync/workspace-selection-spec/v1";
pub const METADATA_RECORDS_MAXIMUM: u64 = 100_000;
pub const RULES_MAXIMUM: usize = 4_096;
pub const RULE_BYTES_MAXIMUM: usize = 4_114;
pub const COMPILED_RULE_BYTES_MAXIMUM: u64 = 16_777_216;
pub const FULL_LOGICAL_BYTES_MAXIMUM: u64 = 9_007_199_254_740_991;
pub const INPUT_RECORD_BYTES_MAXIMUM: usize = 4_185;
pub const OUTPUT_RECORD_BYTES_MAXIMUM: usize = 4_154;
pub const COLLISION_KEY_BYTES_MAXIMUM: usize = 32_768;
pub const COLLISION_KEY_BYTES_TOTAL_MAXIMUM: u64 = 67_108_864;
pub const METADATA_BYTES_MAXIMUM: u64 = 67_108_864;
pub const OUTPUT_BYTES_MAXIMUM: u64 = 75_497_472;
pub const SINK_FRAGMENT_BYTES_MAXIMUM: usize = 4_154;
pub const LOGICAL_BYTES_MAXIMUM: u64 = 1_099_511_627_776;

const SPEC_DOMAIN: &[u8] = b"OpenGameVCS selective sync spec v1\0";
const METADATA_DOMAIN: &[u8] = b"OpenGameVCS selective sync metadata projection v1\0";
const BINDINGS_DOMAIN: &[u8] = b"OpenGameVCS selective sync evaluation bindings v1\0";
const OUTPUT_DOMAIN: &[u8] = b"OpenGameVCS selective sync output projection v1\0";
const OUTPUT_MAGIC: &[u8] = b"OGVCS-SELECT-V1\0";

pub type ProjectionDigest = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionError {
    AdapterInvalid,
    BindingInvalid,
    Cancelled,
    CollisionKeyLimit,
    CollisionKeyTotalLimit,
    CompiledRuleLimit,
    ContractInvalid,
    InputInvalid,
    InputRecordLimit,
    LedgerLimit,
    LogicalBytesLimit,
    MetadataBytesLimit,
    MetadataCountLimit,
    MetadataCountMismatch,
    MetadataDigestMismatch,
    MetadataOrdinalInvalid,
    MetadataOrderInvalid,
    OutputBytesLimit,
    OutputRecordLimit,
    PathCollision,
    PathInvalid,
    PlatformProfileMismatch,
    ProjectionInvalid,
    RuleDuplicate,
    RuleLimit,
    SinkFailed,
    SinkFragmentLimit,
    SinkInvalid,
    SourceFailed,
    SourceInvalid,
    SpecDigestMismatch,
    SpecInvalid,
}

impl SelectionError {
    pub const ALL: [Self; 32] = [
        Self::AdapterInvalid,
        Self::BindingInvalid,
        Self::Cancelled,
        Self::CollisionKeyLimit,
        Self::CollisionKeyTotalLimit,
        Self::CompiledRuleLimit,
        Self::ContractInvalid,
        Self::InputInvalid,
        Self::InputRecordLimit,
        Self::LedgerLimit,
        Self::LogicalBytesLimit,
        Self::MetadataBytesLimit,
        Self::MetadataCountLimit,
        Self::MetadataCountMismatch,
        Self::MetadataDigestMismatch,
        Self::MetadataOrdinalInvalid,
        Self::MetadataOrderInvalid,
        Self::OutputBytesLimit,
        Self::OutputRecordLimit,
        Self::PathCollision,
        Self::PathInvalid,
        Self::PlatformProfileMismatch,
        Self::ProjectionInvalid,
        Self::RuleDuplicate,
        Self::RuleLimit,
        Self::SinkFailed,
        Self::SinkFragmentLimit,
        Self::SinkInvalid,
        Self::SourceFailed,
        Self::SourceInvalid,
        Self::SpecDigestMismatch,
        Self::SpecInvalid,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::AdapterInvalid => "SELECT_ADAPTER_INVALID",
            Self::BindingInvalid => "SELECT_BINDING_INVALID",
            Self::Cancelled => "SELECT_CANCELLED",
            Self::CollisionKeyLimit => "SELECT_COLLISION_KEY_LIMIT",
            Self::CollisionKeyTotalLimit => "SELECT_COLLISION_KEY_TOTAL_LIMIT",
            Self::CompiledRuleLimit => "SELECT_COMPILED_RULE_LIMIT",
            Self::ContractInvalid => "SELECT_CONTRACT_INVALID",
            Self::InputInvalid => "SELECT_INPUT_INVALID",
            Self::InputRecordLimit => "SELECT_INPUT_RECORD_LIMIT",
            Self::LedgerLimit => "SELECT_LEDGER_LIMIT",
            Self::LogicalBytesLimit => "SELECT_LOGICAL_BYTES_LIMIT",
            Self::MetadataBytesLimit => "SELECT_METADATA_BYTES_LIMIT",
            Self::MetadataCountLimit => "SELECT_METADATA_COUNT_LIMIT",
            Self::MetadataCountMismatch => "SELECT_METADATA_COUNT_MISMATCH",
            Self::MetadataDigestMismatch => "SELECT_METADATA_DIGEST_MISMATCH",
            Self::MetadataOrdinalInvalid => "SELECT_METADATA_ORDINAL_INVALID",
            Self::MetadataOrderInvalid => "SELECT_METADATA_ORDER_INVALID",
            Self::OutputBytesLimit => "SELECT_OUTPUT_BYTES_LIMIT",
            Self::OutputRecordLimit => "SELECT_OUTPUT_RECORD_LIMIT",
            Self::PathCollision => "SELECT_PATH_COLLISION",
            Self::PathInvalid => "SELECT_PATH_INVALID",
            Self::PlatformProfileMismatch => "SELECT_PLATFORM_PROFILE_MISMATCH",
            Self::ProjectionInvalid => "SELECT_PROJECTION_INVALID",
            Self::RuleDuplicate => "SELECT_RULE_DUPLICATE",
            Self::RuleLimit => "SELECT_RULE_LIMIT",
            Self::SinkFailed => "SELECT_SINK_FAILED",
            Self::SinkFragmentLimit => "SELECT_SINK_FRAGMENT_LIMIT",
            Self::SinkInvalid => "SELECT_SINK_INVALID",
            Self::SourceFailed => "SELECT_SOURCE_FAILED",
            Self::SourceInvalid => "SELECT_SOURCE_INVALID",
            Self::SpecDigestMismatch => "SELECT_SPEC_DIGEST_MISMATCH",
            Self::SpecInvalid => "SELECT_SPEC_INVALID",
        }
    }
}

impl std::fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SelectionError {}

pub type Result<T> = std::result::Result<T, SelectionError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Materialization {
    Full = 1,
    MetadataOnly = 2,
    AbsentBySpec = 3,
}

impl Materialization {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::MetadataOnly => "metadata-only",
            Self::AbsentBySpec => "absent-by-spec",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MatchKind {
    Exact = 1,
    Subtree = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HostPlatform {
    Linux = 1,
    Macos = 2,
    Windows = 3,
}

impl HostPlatform {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionRule {
    ordinal: u64,
    match_kind: MatchKind,
    path: String,
    materialization: Materialization,
}

impl SelectionRule {
    pub fn new(
        ordinal: u64,
        match_kind: MatchKind,
        path: impl Into<String>,
        materialization: Materialization,
    ) -> Self {
        Self {
            ordinal,
            match_kind,
            path: path.into(),
            materialization,
        }
    }

    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    pub const fn match_kind(&self) -> MatchKind {
        self.match_kind
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn materialization(&self) -> Materialization {
        self.materialization
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionSpec {
    default_materialization: Materialization,
    rules: Vec<SelectionRule>,
}

impl SelectionSpec {
    pub fn from_rules<I>(default_materialization: Materialization, rules: I) -> Result<Self>
    where
        I: IntoIterator<Item = SelectionRule>,
    {
        let mut retained = Vec::new();
        for rule in rules {
            if retained.len() >= RULES_MAXIMUM {
                return Err(SelectionError::RuleLimit);
            }
            if rule.ordinal != retained.len() as u64 {
                return Err(SelectionError::SpecInvalid);
            }
            retained.push(rule);
        }
        Ok(Self {
            default_materialization,
            rules: retained,
        })
    }

    pub const fn default_materialization(&self) -> Materialization {
        self.default_materialization
    }

    pub fn rules(&self) -> &[SelectionRule] {
        &self.rules
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentIdentity {
    pub digest: ProjectionDigest,
    pub logical_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataRecord {
    pub ordinal: u64,
    pub path: String,
    /// Opaque metadata-record commitment used only in the input projection.
    /// It is never emitted as a content or entry identity.
    pub entry_digest: ProjectionDigest,
    pub content: Option<ContentIdentity>,
}

#[derive(Clone, Debug)]
pub struct EvaluationBindings {
    snapshot_digest: ProjectionDigest,
    settings_digest: ProjectionDigest,
    consistency_token_digest: ProjectionDigest,
    path_profile: PathProfile,
    case_mode: CaseMode,
    platform: HostPlatform,
    spec_digest: ProjectionDigest,
    metadata_projection_digest: ProjectionDigest,
    metadata_record_count: u64,
}

impl EvaluationBindings {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_digest: ProjectionDigest,
        settings_digest: ProjectionDigest,
        consistency_token_digest: ProjectionDigest,
        path_profile: &str,
        case_mode: CaseMode,
        platform: HostPlatform,
        spec_digest: ProjectionDigest,
        metadata_projection_digest: ProjectionDigest,
        metadata_record_count: u64,
    ) -> Result<Self> {
        let path_profile =
            PathProfile::parse(path_profile).map_err(|_| SelectionError::BindingInvalid)?;
        if metadata_record_count > METADATA_RECORDS_MAXIMUM {
            return Err(SelectionError::MetadataCountLimit);
        }
        if !platform_matches(path_profile, platform) {
            return Err(SelectionError::PlatformProfileMismatch);
        }
        Ok(Self {
            snapshot_digest,
            settings_digest,
            consistency_token_digest,
            path_profile,
            case_mode,
            platform,
            spec_digest,
            metadata_projection_digest,
            metadata_record_count,
        })
    }

    pub const fn metadata_record_count(&self) -> u64 {
        self.metadata_record_count
    }

    pub const fn spec_digest(&self) -> ProjectionDigest {
        self.spec_digest
    }

    pub const fn metadata_projection_digest(&self) -> ProjectionDigest {
        self.metadata_projection_digest
    }

    pub const fn path_profile(&self) -> PathProfile {
        self.path_profile
    }

    pub const fn case_mode(&self) -> CaseMode {
        self.case_mode
    }

    pub const fn platform(&self) -> HostPlatform {
        self.platform
    }
}

#[derive(Clone, Debug, Default)]
pub struct EvaluationControl {
    cancellation: Arc<AtomicBool>,
}

impl EvaluationControl {
    pub fn with_cancellation(cancellation: Arc<AtomicBool>) -> Self {
        Self { cancellation }
    }

    pub fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancellation)
    }

    pub fn cancel(&self) {
        self.cancellation.store(true, Ordering::Release);
    }

    fn check(&self) -> Result<()> {
        if self.cancellation.load(Ordering::Acquire) {
            Err(SelectionError::Cancelled)
        } else {
            Ok(())
        }
    }
}

pub trait MetadataSource {
    type Error;
    fn next_record(&mut self) -> std::result::Result<Option<MetadataRecord>, Self::Error>;
}

pub struct IteratorMetadataSource<I> {
    iterator: I,
}

impl<I> IteratorMetadataSource<I> {
    pub const fn new(iterator: I) -> Self {
        Self { iterator }
    }
}

impl<I> MetadataSource for IteratorMetadataSource<I>
where
    I: Iterator<Item = MetadataRecord>,
{
    type Error = Infallible;

    fn next_record(&mut self) -> std::result::Result<Option<MetadataRecord>, Self::Error> {
        Ok(self.iterator.next())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataProjectionSummary {
    pub digest: ProjectionDigest,
    pub record_count: u64,
    pub metadata_bytes: u64,
}

pub struct MetadataProjectionBuilder {
    hasher: Sha256,
    declared_count: u64,
    record_count: u64,
    metadata_bytes: u64,
}

impl MetadataProjectionBuilder {
    pub fn new(declared_count: u64) -> Result<Self> {
        if declared_count > METADATA_RECORDS_MAXIMUM {
            return Err(SelectionError::MetadataCountLimit);
        }
        let mut hasher = Sha256::new();
        hasher.update(METADATA_DOMAIN);
        hasher.update(declared_count.to_be_bytes());
        Ok(Self {
            hasher,
            declared_count,
            record_count: 0,
            metadata_bytes: 0,
        })
    }

    pub fn push(&mut self, record: &MetadataRecord) -> Result<()> {
        if self.record_count >= self.declared_count {
            return Err(SelectionError::MetadataCountMismatch);
        }
        if record.ordinal != self.record_count {
            return Err(SelectionError::MetadataOrdinalInvalid);
        }
        let frame = encode_input_record(record)?;
        self.metadata_bytes = checked_add_limit(
            self.metadata_bytes,
            frame.len() as u64,
            METADATA_BYTES_MAXIMUM,
            SelectionError::MetadataBytesLimit,
        )?;
        self.hasher.update(&frame);
        self.record_count += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<MetadataProjectionSummary> {
        if self.record_count != self.declared_count {
            return Err(SelectionError::MetadataCountMismatch);
        }
        Ok(MetadataProjectionSummary {
            digest: finalize(self.hasher),
            record_count: self.record_count,
            metadata_bytes: self.metadata_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationSummary {
    pub bindings_digest: ProjectionDigest,
    pub metadata_projection_digest: ProjectionDigest,
    pub output_projection_digest: ProjectionDigest,
    pub record_count: u64,
    pub full_count: u64,
    pub metadata_only_count: u64,
    pub absent_by_spec_count: u64,
    pub full_content_count: u64,
    pub full_logical_bytes: u64,
    pub metadata_bytes: u64,
    pub output_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct RuleChoice {
    ordinal: u64,
    materialization: Materialization,
}

#[derive(Debug, Default)]
struct TrieNode {
    children: BTreeMap<String, usize>,
    exact: Option<RuleChoice>,
    subtree: Option<RuleChoice>,
}

#[derive(Debug)]
struct CompiledSpec {
    default_materialization: Materialization,
    nodes: Vec<TrieNode>,
    digest: ProjectionDigest,
    collision_key_bytes: u64,
}

impl CompiledSpec {
    fn classify(&self, segments: &[String], case_mode: CaseMode) -> Materialization {
        let mut node_index = 0usize;
        let mut choice: Option<RuleChoice> = None;
        for (position, segment) in segments.iter().enumerate() {
            let key = match case_mode {
                CaseMode::Sensitive => segment.clone(),
                CaseMode::Folded => case_fold(segment),
            };
            let Some(next) = self.nodes[node_index].children.get(&key).copied() else {
                break;
            };
            node_index = next;
            if let Some(candidate) = self.nodes[node_index].subtree {
                if choice.is_none_or(|current| candidate.ordinal > current.ordinal) {
                    choice = Some(candidate);
                }
            }
            if position + 1 == segments.len() {
                if let Some(candidate) = self.nodes[node_index].exact {
                    if choice.is_none_or(|current| candidate.ordinal > current.ordinal) {
                        choice = Some(candidate);
                    }
                }
            }
        }
        choice
            .map(|value| value.materialization)
            .unwrap_or(self.default_materialization)
    }
}

pub struct SelectionKernel {
    bindings: EvaluationBindings,
    bindings_digest: ProjectionDigest,
    compiled: CompiledSpec,
}

impl SelectionKernel {
    pub fn new(bindings: EvaluationBindings, spec: SelectionSpec) -> Result<Self> {
        let compiled = compile_spec(
            &spec,
            bindings.path_profile,
            bindings.case_mode,
            bindings.platform,
        )?;
        if compiled.digest != bindings.spec_digest {
            return Err(SelectionError::SpecDigestMismatch);
        }
        let bindings_digest = evaluation_bindings_digest(&bindings);
        Ok(Self {
            bindings,
            bindings_digest,
            compiled,
        })
    }

    /// Streams a discard-on-error projection into `sink`.
    ///
    /// The header is written from caller-declared bindings before source EOF
    /// and digest verification. No emitted byte is trustworthy unless this
    /// method reaches its final flush and returns a summary.
    pub fn evaluate<S, W>(
        &self,
        source: &mut S,
        sink: &mut W,
        control: &EvaluationControl,
    ) -> Result<EvaluationSummary>
    where
        S: MetadataSource,
        W: Write,
    {
        control.check()?;
        let mut output_hasher = Sha256::new();
        output_hasher.update(OUTPUT_DOMAIN);
        let mut output_bytes = 0u64;
        emit(sink, &mut output_hasher, &mut output_bytes, OUTPUT_MAGIC)?;
        emit(
            sink,
            &mut output_hasher,
            &mut output_bytes,
            &self.bindings.metadata_record_count.to_be_bytes(),
        )?;
        emit(
            sink,
            &mut output_hasher,
            &mut output_bytes,
            &self.bindings_digest,
        )?;

        let mut metadata_hasher = Sha256::new();
        metadata_hasher.update(METADATA_DOMAIN);
        metadata_hasher.update(self.bindings.metadata_record_count.to_be_bytes());
        let mut platform_spellings = BTreeMap::<String, String>::new();
        let mut previous_repository_key: Option<String> = None;
        let mut collision_key_bytes = self.compiled.collision_key_bytes;
        let mut summary = EvaluationSummary {
            bindings_digest: self.bindings_digest,
            metadata_projection_digest: [0; 32],
            output_projection_digest: [0; 32],
            record_count: 0,
            full_count: 0,
            metadata_only_count: 0,
            absent_by_spec_count: 0,
            full_content_count: 0,
            full_logical_bytes: 0,
            metadata_bytes: 0,
            output_bytes: 0,
        };

        loop {
            control.check()?;
            let next = source
                .next_record()
                .map_err(|_| SelectionError::SourceFailed)?;
            control.check()?;
            let Some(record) = next else { break };
            if summary.record_count >= self.bindings.metadata_record_count {
                return Err(SelectionError::MetadataCountMismatch);
            }
            if summary.record_count >= METADATA_RECORDS_MAXIMUM {
                return Err(SelectionError::MetadataCountLimit);
            }
            if record.ordinal != summary.record_count {
                return Err(SelectionError::MetadataOrdinalInvalid);
            }
            let keys = path_collision_keys_with_options(
                &record.path,
                self.bindings.path_profile,
                self.bindings.case_mode,
            )
            .map_err(|_| SelectionError::PathInvalid)?;
            check_collision_key(keys.repository_key().as_str())?;
            check_collision_key(keys.platform_key())?;
            collision_key_bytes = checked_add_limit(
                collision_key_bytes,
                (keys.repository_key().as_str().len() + keys.platform_key().len()) as u64,
                COLLISION_KEY_BYTES_TOTAL_MAXIMUM,
                SelectionError::CollisionKeyTotalLimit,
            )?;
            if let Some(previous) = previous_repository_key.as_deref() {
                match previous.cmp(keys.repository_key().as_str()) {
                    std::cmp::Ordering::Equal => return Err(SelectionError::PathCollision),
                    std::cmp::Ordering::Greater => {
                        return Err(SelectionError::MetadataOrderInvalid)
                    }
                    std::cmp::Ordering::Less => {}
                }
            }
            previous_repository_key = Some(keys.repository_key().as_str().to_owned());
            if platform_spellings
                .insert(keys.platform_key().to_owned(), record.path.clone())
                .is_some()
            {
                return Err(SelectionError::PathCollision);
            }
            let input_frame = encode_input_record(&record)?;
            summary.metadata_bytes = checked_add_limit(
                summary.metadata_bytes,
                input_frame.len() as u64,
                METADATA_BYTES_MAXIMUM,
                SelectionError::MetadataBytesLimit,
            )?;
            metadata_hasher.update(&input_frame);

            let materialization = self
                .compiled
                .classify(keys.path().segments(), self.bindings.case_mode);
            match materialization {
                Materialization::Full => {
                    summary.full_count += 1;
                    if let Some(content) = record.content {
                        summary.full_content_count += 1;
                        summary.full_logical_bytes = summary
                            .full_logical_bytes
                            .checked_add(content.logical_bytes)
                            .ok_or(SelectionError::LedgerLimit)?;
                        if summary.full_logical_bytes > FULL_LOGICAL_BYTES_MAXIMUM {
                            return Err(SelectionError::LedgerLimit);
                        }
                    }
                }
                Materialization::MetadataOnly => summary.metadata_only_count += 1,
                Materialization::AbsentBySpec => summary.absent_by_spec_count += 1,
            }
            let output_frame = encode_output_record(&record, materialization)?;
            emit(sink, &mut output_hasher, &mut output_bytes, &output_frame)?;
            summary.record_count += 1;
        }

        if summary.record_count != self.bindings.metadata_record_count {
            return Err(SelectionError::MetadataCountMismatch);
        }
        let metadata_digest = finalize(metadata_hasher);
        if metadata_digest != self.bindings.metadata_projection_digest {
            return Err(SelectionError::MetadataDigestMismatch);
        }
        control.check()?;
        sink.flush().map_err(|_| SelectionError::SinkFailed)?;
        summary.metadata_projection_digest = metadata_digest;
        summary.output_projection_digest = finalize(output_hasher);
        summary.output_bytes = output_bytes;
        Ok(summary)
    }
}

pub fn selection_spec_digest(
    spec: &SelectionSpec,
    path_profile: &str,
    case_mode: CaseMode,
    platform: HostPlatform,
) -> Result<ProjectionDigest> {
    let profile = PathProfile::parse(path_profile).map_err(|_| SelectionError::BindingInvalid)?;
    Ok(compile_spec(spec, profile, case_mode, platform)?.digest)
}

fn compile_spec(
    spec: &SelectionSpec,
    profile: PathProfile,
    case_mode: CaseMode,
    platform: HostPlatform,
) -> Result<CompiledSpec> {
    if !platform_matches(profile, platform) {
        return Err(SelectionError::PlatformProfileMismatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(SPEC_DOMAIN);
    update_text(&mut hasher, SPEC_SCHEMA_VERSION);
    hasher.update(1u64.to_be_bytes());
    hasher.update([spec.default_materialization as u8]);
    hasher.update((spec.rules.len() as u64).to_be_bytes());
    let mut compiled_bytes = 0u64;
    let mut collision_key_bytes = 0u64;
    let mut repository_spellings = BTreeMap::<String, String>::new();
    let mut platform_spellings = BTreeMap::<String, String>::new();
    let mut scoped = BTreeSet::<(MatchKind, String)>::new();
    let mut nodes = vec![TrieNode::default()];

    for (index, rule) in spec.rules.iter().enumerate() {
        if rule.ordinal != index as u64 {
            return Err(SelectionError::SpecInvalid);
        }
        let keys = path_collision_keys_with_options(&rule.path, profile, case_mode)
            .map_err(|_| SelectionError::PathInvalid)?;
        check_collision_key(keys.repository_key().as_str())?;
        check_collision_key(keys.platform_key())?;
        collision_key_bytes = checked_add_limit(
            collision_key_bytes,
            (keys.repository_key().as_str().len() + keys.platform_key().len()) as u64,
            COLLISION_KEY_BYTES_TOTAL_MAXIMUM,
            SelectionError::CollisionKeyTotalLimit,
        )?;
        let scoped_key = (rule.match_kind, keys.repository_key().as_str().to_owned());
        if !scoped.insert(scoped_key) {
            return Err(SelectionError::RuleDuplicate);
        }
        if repository_spellings
            .get(keys.repository_key().as_str())
            .is_some_and(|prior| prior != keys.path().canonical())
            || platform_spellings
                .get(keys.platform_key())
                .is_some_and(|prior| prior != keys.path().canonical())
        {
            return Err(SelectionError::PathCollision);
        }
        repository_spellings.insert(
            keys.repository_key().as_str().to_owned(),
            keys.path().canonical().to_owned(),
        );
        platform_spellings.insert(
            keys.platform_key().to_owned(),
            keys.path().canonical().to_owned(),
        );

        let frame = encode_rule(
            rule.ordinal,
            rule.match_kind,
            keys.path().canonical(),
            rule.materialization,
        )?;
        compiled_bytes = checked_add_limit(
            compiled_bytes,
            frame.len() as u64,
            COMPILED_RULE_BYTES_MAXIMUM,
            SelectionError::CompiledRuleLimit,
        )?;
        hasher.update(&frame);

        let mut node_index = 0usize;
        for segment in keys.path().segments() {
            let segment_key = match case_mode {
                CaseMode::Sensitive => segment.clone(),
                CaseMode::Folded => case_fold(segment),
            };
            let next = if let Some(next) = nodes[node_index].children.get(&segment_key) {
                *next
            } else {
                let next = nodes.len();
                nodes.push(TrieNode::default());
                nodes[node_index].children.insert(segment_key, next);
                next
            };
            node_index = next;
        }
        let choice = RuleChoice {
            ordinal: rule.ordinal,
            materialization: rule.materialization,
        };
        match rule.match_kind {
            MatchKind::Exact => nodes[node_index].exact = Some(choice),
            MatchKind::Subtree => nodes[node_index].subtree = Some(choice),
        }
    }

    Ok(CompiledSpec {
        default_materialization: spec.default_materialization,
        nodes,
        digest: finalize(hasher),
        collision_key_bytes,
    })
}

fn platform_matches(profile: PathProfile, platform: HostPlatform) -> bool {
    match profile.as_str() {
        "path.opengamevcs/portable@1" => true,
        "path.opengamevcs/linux@1" => platform == HostPlatform::Linux,
        "path.opengamevcs/macos@1" => platform == HostPlatform::Macos,
        "path.opengamevcs/windows@1" => platform == HostPlatform::Windows,
        _ => false,
    }
}

fn evaluation_bindings_digest(bindings: &EvaluationBindings) -> ProjectionDigest {
    let mut hasher = Sha256::new();
    hasher.update(BINDINGS_DOMAIN);
    hasher.update(bindings.snapshot_digest);
    hasher.update(bindings.settings_digest);
    hasher.update(bindings.consistency_token_digest);
    update_text(&mut hasher, bindings.path_profile.as_str());
    hasher.update([match bindings.case_mode {
        CaseMode::Sensitive => 1,
        CaseMode::Folded => 2,
    }]);
    hasher.update([bindings.platform as u8]);
    hasher.update(bindings.spec_digest);
    hasher.update(bindings.metadata_projection_digest);
    hasher.update(bindings.metadata_record_count.to_be_bytes());
    finalize(hasher)
}

fn encode_rule(
    ordinal: u64,
    match_kind: MatchKind,
    path: &str,
    materialization: Materialization,
) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(18 + path.len());
    frame.extend_from_slice(&ordinal.to_be_bytes());
    frame.push(match_kind as u8);
    append_text(&mut frame, path);
    frame.push(materialization as u8);
    if frame.len() > RULE_BYTES_MAXIMUM {
        return Err(SelectionError::RuleLimit);
    }
    Ok(frame)
}

fn encode_input_record(record: &MetadataRecord) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(89 + record.path.len());
    frame.extend_from_slice(&record.ordinal.to_be_bytes());
    append_text(&mut frame, &record.path);
    frame.extend_from_slice(&record.entry_digest);
    append_content(&mut frame, record.content)?;
    if frame.len() > INPUT_RECORD_BYTES_MAXIMUM {
        return Err(SelectionError::InputRecordLimit);
    }
    Ok(frame)
}

fn encode_output_record(
    record: &MetadataRecord,
    materialization: Materialization,
) -> Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(58 + record.path.len());
    frame.extend_from_slice(&record.ordinal.to_be_bytes());
    append_text(&mut frame, &record.path);
    frame.push(materialization as u8);
    append_content(
        &mut frame,
        if materialization == Materialization::Full {
            record.content
        } else {
            None
        },
    )?;
    if frame.len() > OUTPUT_RECORD_BYTES_MAXIMUM {
        return Err(SelectionError::OutputRecordLimit);
    }
    Ok(frame)
}

fn append_content(frame: &mut Vec<u8>, content: Option<ContentIdentity>) -> Result<()> {
    match content {
        None => frame.push(0),
        Some(content) => {
            if content.logical_bytes > LOGICAL_BYTES_MAXIMUM {
                return Err(SelectionError::LogicalBytesLimit);
            }
            frame.push(1);
            frame.extend_from_slice(&content.digest);
            frame.extend_from_slice(&content.logical_bytes.to_be_bytes());
        }
    }
    Ok(())
}

fn emit<W: Write>(
    sink: &mut W,
    hasher: &mut Sha256,
    output_bytes: &mut u64,
    fragment: &[u8],
) -> Result<()> {
    if fragment.len() > SINK_FRAGMENT_BYTES_MAXIMUM {
        return Err(SelectionError::SinkFragmentLimit);
    }
    let next = checked_add_limit(
        *output_bytes,
        fragment.len() as u64,
        OUTPUT_BYTES_MAXIMUM,
        SelectionError::OutputBytesLimit,
    )?;
    hasher.update(fragment);
    sink.write_all(fragment)
        .map_err(|_| SelectionError::SinkFailed)?;
    *output_bytes = next;
    Ok(())
}

fn check_collision_key(key: &str) -> Result<()> {
    if key.len() > COLLISION_KEY_BYTES_MAXIMUM {
        Err(SelectionError::CollisionKeyLimit)
    } else {
        Ok(())
    }
}

fn checked_add_limit(current: u64, added: u64, maximum: u64, error: SelectionError) -> Result<u64> {
    let next = current.checked_add(added).ok_or(error)?;
    if next > maximum {
        Err(error)
    } else {
        Ok(next)
    }
}

fn update_text(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn append_text(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn finalize(hasher: Sha256) -> ProjectionDigest {
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_numeric_ceiling_accepts_exact_and_rejects_plus_one() {
        for maximum in [
            COMPILED_RULE_BYTES_MAXIMUM,
            COLLISION_KEY_BYTES_TOTAL_MAXIMUM,
            FULL_LOGICAL_BYTES_MAXIMUM,
            METADATA_BYTES_MAXIMUM,
            OUTPUT_BYTES_MAXIMUM,
        ] {
            assert_eq!(
                checked_add_limit(0, maximum, maximum, SelectionError::LedgerLimit),
                Ok(maximum)
            );
            assert_eq!(
                checked_add_limit(maximum, 1, maximum, SelectionError::LedgerLimit),
                Err(SelectionError::LedgerLimit)
            );
        }
        assert_eq!(RULE_BYTES_MAXIMUM, 4_114);
        assert_eq!(INPUT_RECORD_BYTES_MAXIMUM, 4_185);
        assert_eq!(OUTPUT_RECORD_BYTES_MAXIMUM, 4_154);
        assert_eq!(SINK_FRAGMENT_BYTES_MAXIMUM, OUTPUT_RECORD_BYTES_MAXIMUM);
        assert_eq!(COLLISION_KEY_BYTES_MAXIMUM, 32_768);
    }

    #[test]
    fn every_per_item_and_count_ceiling_accepts_exact_and_rejects_plus_one() {
        let maximum_path = "a".repeat(4_096);
        let rule = encode_rule(0, MatchKind::Exact, &maximum_path, Materialization::Full).unwrap();
        assert_eq!(rule.len(), RULE_BYTES_MAXIMUM);
        assert_eq!(
            encode_rule(
                0,
                MatchKind::Exact,
                &"a".repeat(4_097),
                Materialization::Full,
            ),
            Err(SelectionError::RuleLimit)
        );

        let record = MetadataRecord {
            ordinal: 0,
            path: maximum_path,
            entry_digest: [1; 32],
            content: Some(ContentIdentity {
                digest: [2; 32],
                logical_bytes: LOGICAL_BYTES_MAXIMUM,
            }),
        };
        assert_eq!(
            encode_input_record(&record).unwrap().len(),
            INPUT_RECORD_BYTES_MAXIMUM
        );
        assert_eq!(
            encode_output_record(&record, Materialization::Full)
                .unwrap()
                .len(),
            OUTPUT_RECORD_BYTES_MAXIMUM
        );
        let mut plus_one = record.clone();
        plus_one.path.push('a');
        assert_eq!(
            encode_input_record(&plus_one),
            Err(SelectionError::InputRecordLimit)
        );
        assert_eq!(
            encode_output_record(&plus_one, Materialization::Full),
            Err(SelectionError::OutputRecordLimit)
        );
        let mut logical_plus_one = record;
        logical_plus_one.content.as_mut().unwrap().logical_bytes = LOGICAL_BYTES_MAXIMUM + 1;
        assert_eq!(
            encode_input_record(&logical_plus_one),
            Err(SelectionError::LogicalBytesLimit)
        );

        assert_eq!(
            check_collision_key(&"k".repeat(COLLISION_KEY_BYTES_MAXIMUM)),
            Ok(())
        );
        assert_eq!(
            check_collision_key(&"k".repeat(COLLISION_KEY_BYTES_MAXIMUM + 1)),
            Err(SelectionError::CollisionKeyLimit)
        );
        let rules = (0..RULES_MAXIMUM).map(|ordinal| {
            SelectionRule::new(ordinal as u64, MatchKind::Exact, "A", Materialization::Full)
        });
        assert_eq!(
            SelectionSpec::from_rules(Materialization::AbsentBySpec, rules)
                .unwrap()
                .rules()
                .len(),
            RULES_MAXIMUM
        );
        let plus_one_rules = (0..=RULES_MAXIMUM).map(|ordinal| {
            SelectionRule::new(ordinal as u64, MatchKind::Exact, "A", Materialization::Full)
        });
        assert_eq!(
            SelectionSpec::from_rules(Materialization::AbsentBySpec, plus_one_rules),
            Err(SelectionError::RuleLimit)
        );
        assert!(MetadataProjectionBuilder::new(METADATA_RECORDS_MAXIMUM).is_ok());
        assert!(matches!(
            MetadataProjectionBuilder::new(METADATA_RECORDS_MAXIMUM + 1),
            Err(SelectionError::MetadataCountLimit)
        ));
    }
}
