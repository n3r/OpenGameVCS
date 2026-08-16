use crate::{Error, ErrorCode, Registry, Result, ValidationStage};

pub(crate) const MAX_ASSET_GROUP_MEMBERS: u64 = 64;
pub(crate) const MAX_ASSET_GROUPS: u64 = 10_000;
pub(crate) const MAX_BUNDLE_INDEX_ENTRIES: u64 = 20_000_000;
pub(crate) const MAX_BUNDLE_ITEM_BYTES: u64 = 536_871_424;
pub(crate) const MAX_BUNDLE_LOGICAL_RECORDS: u64 = 10_000_000;
pub(crate) const MAX_BUNDLE_OBJECTS: u64 = 10_000_000;
pub(crate) const MAX_BUNDLE_ROOTS: u64 = 20_000_000;
pub(crate) const MAX_BUNDLE_SEQUENCE_BYTES: u64 = 2_199_023_255_552;
pub(crate) const MAX_BUNDLE_TOTAL_ITEMS: u64 = 40_000_002;
pub(crate) const MAX_BUNDLE_TRAVERSAL_EDGES: u64 = 100_000_000;
pub(crate) const MAX_CBOR_NESTING: u64 = 32;
pub(crate) const MAX_CHANGE_SET_OPERATIONS: u64 = 1_000_000;
pub(crate) const MAX_CHUNK_BYTES: u64 = 67_108_864;
pub(crate) const MAX_EXTENSION_AGGREGATE_BYTES: u64 = 16_777_216;
pub(crate) const MAX_EXTENSIONS_PER_OBJECT: u64 = 128;
pub(crate) const MAX_GENERIC_VALUE_BYTES: u64 = 16_777_216;
pub(crate) const MAX_LOGICAL_FILE_BYTES: u64 = 1_099_511_627_776;
pub(crate) const MAX_MANIFEST_CHUNKS: u64 = 1_048_576;
pub(crate) const MAX_METADATA_BYTES: u64 = 536_870_912;
pub(crate) const MAX_PATH_BYTES: u64 = 4_096;
pub(crate) const MAX_PATH_SEGMENT_BYTES: u64 = 255;
pub(crate) const MAX_PATH_SEGMENTS: u64 = 256;
pub(crate) const MAX_SNAPSHOT_MESSAGE_BYTES: u64 = 1_048_576;
pub(crate) const MAX_SNAPSHOT_PARENTS: u64 = 8;
pub(crate) const MAX_TREE_ENTRIES: u64 = 1_000_000;

pub const HARD_LIMIT_NAMES: [&str; 25] = [
    "asset-group-members",
    "asset-groups",
    "bundle-index-entries",
    "bundle-largest-item-bytes",
    "bundle-logical-records",
    "bundle-objects",
    "bundle-roots",
    "bundle-sequence-bytes",
    "bundle-total-items",
    "bundle-traversal-edges",
    "cbor-nesting-depth",
    "change-set-operations",
    "chunk-payload-bytes",
    "extension-aggregate-bytes-per-object",
    "extensions-per-object",
    "generic-text-or-byte-value-bytes",
    "logical-file-bytes",
    "manifest-chunks",
    "metadata-payload-bytes",
    "path-bytes",
    "path-segment-bytes",
    "path-segments",
    "snapshot-message-bytes",
    "snapshot-parents",
    "tree-entries",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardLimitDecision {
    pub accepted: bool,
    pub code: Option<ErrorCode>,
    /// Caller ceiling after it has been capped by [`maximum`](Self::maximum).
    pub effective_maximum: u64,
    pub layer: u8,
    /// Frozen, non-overridable format-v1 maximum.
    pub maximum: u64,
    pub name: &'static str,
    /// Frozen diagnostic stage used when this decision rejects.
    pub stage: ValidationStage,
    pub value: u64,
}

fn definition(name: &str) -> Option<(u64, ErrorCode, u8, u8, ValidationStage)> {
    use ValidationStage::{CanonicalFraming, ConfiguredResourcePreflight, KnownSchema};
    Some(match name {
        "asset-group-members" => (
            MAX_ASSET_GROUP_MEMBERS,
            ErrorCode::LimitCount,
            2,
            2,
            KnownSchema,
        ),
        "asset-groups" => (MAX_ASSET_GROUPS, ErrorCode::LimitCount, 2, 2, KnownSchema),
        "bundle-index-entries" => (
            MAX_BUNDLE_INDEX_ENTRIES,
            ErrorCode::BundleBudgetExceeded,
            1,
            1,
            ConfiguredResourcePreflight,
        ),
        "bundle-largest-item-bytes" => (
            MAX_BUNDLE_ITEM_BYTES,
            ErrorCode::BundleBudgetExceeded,
            1,
            1,
            ConfiguredResourcePreflight,
        ),
        "bundle-logical-records" => (
            MAX_BUNDLE_LOGICAL_RECORDS,
            ErrorCode::BundleBudgetExceeded,
            1,
            1,
            ConfiguredResourcePreflight,
        ),
        "bundle-objects" => (
            MAX_BUNDLE_OBJECTS,
            ErrorCode::BundleBudgetExceeded,
            1,
            1,
            ConfiguredResourcePreflight,
        ),
        "bundle-roots" => (
            MAX_BUNDLE_ROOTS,
            ErrorCode::BundleBudgetExceeded,
            1,
            1,
            ConfiguredResourcePreflight,
        ),
        "bundle-sequence-bytes" => (
            MAX_BUNDLE_SEQUENCE_BYTES,
            ErrorCode::BundleBudgetExceeded,
            1,
            1,
            ConfiguredResourcePreflight,
        ),
        "bundle-total-items" => (
            MAX_BUNDLE_TOTAL_ITEMS,
            ErrorCode::BundleBudgetExceeded,
            1,
            1,
            ConfiguredResourcePreflight,
        ),
        "bundle-traversal-edges" => (
            MAX_BUNDLE_TRAVERSAL_EDGES,
            ErrorCode::BundleBudgetExceeded,
            1,
            1,
            ConfiguredResourcePreflight,
        ),
        "cbor-nesting-depth" => (
            MAX_CBOR_NESTING,
            ErrorCode::LimitNesting,
            2,
            1,
            CanonicalFraming,
        ),
        "change-set-operations" => (
            MAX_CHANGE_SET_OPERATIONS,
            ErrorCode::LimitCount,
            2,
            2,
            KnownSchema,
        ),
        "chunk-payload-bytes" => (
            MAX_CHUNK_BYTES,
            ErrorCode::LimitChunkBytes,
            2,
            1,
            ConfiguredResourcePreflight,
        ),
        "extension-aggregate-bytes-per-object" => (
            MAX_EXTENSION_AGGREGATE_BYTES,
            ErrorCode::LimitExtensionBytes,
            2,
            1,
            CanonicalFraming,
        ),
        "extensions-per-object" => (
            MAX_EXTENSIONS_PER_OBJECT,
            ErrorCode::LimitCount,
            2,
            1,
            CanonicalFraming,
        ),
        "generic-text-or-byte-value-bytes" => (
            MAX_GENERIC_VALUE_BYTES,
            ErrorCode::LimitValueBytes,
            2,
            1,
            CanonicalFraming,
        ),
        "logical-file-bytes" => (
            MAX_LOGICAL_FILE_BYTES,
            ErrorCode::LimitLogicalBytes,
            2,
            2,
            KnownSchema,
        ),
        "manifest-chunks" => (
            MAX_MANIFEST_CHUNKS,
            ErrorCode::LimitCount,
            2,
            2,
            KnownSchema,
        ),
        "metadata-payload-bytes" => (
            MAX_METADATA_BYTES,
            ErrorCode::LimitMetadataBytes,
            2,
            1,
            ConfiguredResourcePreflight,
        ),
        "path-bytes" => (
            MAX_PATH_BYTES,
            ErrorCode::PathCoreInvalid,
            2,
            2,
            KnownSchema,
        ),
        "path-segment-bytes" => (
            MAX_PATH_SEGMENT_BYTES,
            ErrorCode::PathCoreInvalid,
            2,
            2,
            KnownSchema,
        ),
        "path-segments" => (
            MAX_PATH_SEGMENTS,
            ErrorCode::PathCoreInvalid,
            2,
            2,
            KnownSchema,
        ),
        "snapshot-message-bytes" => (
            MAX_SNAPSHOT_MESSAGE_BYTES,
            ErrorCode::LimitValueBytes,
            2,
            2,
            KnownSchema,
        ),
        "snapshot-parents" => (
            MAX_SNAPSHOT_PARENTS,
            ErrorCode::SnapshotParentCountInvalid,
            2,
            2,
            KnownSchema,
        ),
        "tree-entries" => (MAX_TREE_ENTRIES, ErrorCode::LimitCount, 2, 2, KnownSchema),
        _ => return None,
    })
}

/// Returns the frozen format-v1 maximum for `name`.
pub fn hard_limit_maximum(name: &'static str) -> Result<u64> {
    definition(name)
        .map(|entry| entry.0)
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid).with_layer(2))
}

/// Caps a deployment ceiling at the frozen format-v1 maximum.
pub fn configured_hard_limit(name: &'static str, configured: u64) -> Result<u64> {
    Ok(configured.min(hard_limit_maximum(name)?))
}

/// A compact, copyable set of caller ceilings for all frozen limit families.
///
/// Values can only be reduced: [`with_limit`](Self::with_limit) caps every
/// requested value at the corresponding format-v1 maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HardLimitCeilings {
    values: [u64; HARD_LIMIT_NAMES.len()],
}

impl HardLimitCeilings {
    pub const HARD: Self = Self {
        values: [
            MAX_ASSET_GROUP_MEMBERS,
            MAX_ASSET_GROUPS,
            MAX_BUNDLE_INDEX_ENTRIES,
            MAX_BUNDLE_ITEM_BYTES,
            MAX_BUNDLE_LOGICAL_RECORDS,
            MAX_BUNDLE_OBJECTS,
            MAX_BUNDLE_ROOTS,
            MAX_BUNDLE_SEQUENCE_BYTES,
            MAX_BUNDLE_TOTAL_ITEMS,
            MAX_BUNDLE_TRAVERSAL_EDGES,
            MAX_CBOR_NESTING,
            MAX_CHANGE_SET_OPERATIONS,
            MAX_CHUNK_BYTES,
            MAX_EXTENSION_AGGREGATE_BYTES,
            MAX_EXTENSIONS_PER_OBJECT,
            MAX_GENERIC_VALUE_BYTES,
            MAX_LOGICAL_FILE_BYTES,
            MAX_MANIFEST_CHUNKS,
            MAX_METADATA_BYTES,
            MAX_PATH_BYTES,
            MAX_PATH_SEGMENT_BYTES,
            MAX_PATH_SEGMENTS,
            MAX_SNAPSHOT_MESSAGE_BYTES,
            MAX_SNAPSHOT_PARENTS,
            MAX_TREE_ENTRIES,
        ],
    };

    pub fn with_limit(mut self, name: &'static str, maximum: u64) -> Result<Self> {
        let index = limit_index(name)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid).with_layer(2))?;
        self.values[index] = configured_hard_limit(name, maximum)?;
        Ok(self)
    }

    pub fn maximum(self, name: &'static str) -> Result<u64> {
        let index = limit_index(name)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid).with_layer(2))?;
        Ok(self.values[index])
    }

    /// Intersects two ceiling sets without permitting either to exceed the
    /// frozen authority.
    pub fn constrained_by(mut self, configured: Self) -> Self {
        for (current, requested) in self.values.iter_mut().zip(configured.values) {
            *current = (*current).min(requested);
        }
        self
    }

    pub fn enforce(self, name: &'static str, value: u64) -> Result<HardLimitDecision> {
        enforce_hard_limit_with_ceiling(name, value, self.maximum(name)?)
    }
}

impl Default for HardLimitCeilings {
    fn default() -> Self {
        Self::HARD
    }
}

fn limit_index(name: &str) -> Option<usize> {
    HARD_LIMIT_NAMES
        .iter()
        .position(|candidate| *candidate == name)
}

/// Executes one isolated hard-limit preflight without allocating from `value`.
///
/// This is the implementation boundary used by the normative virtual
/// max/max+1 constructors. It proves exact unsigned comparison, error code,
/// and layer; it does not claim that a maximum-sized object was materialized.
pub fn evaluate_hard_limit(
    registry: &Registry,
    name: &'static str,
    value: u64,
) -> Result<HardLimitDecision> {
    let (maximum, code, accept_layer, reject_layer, stage) =
        definition(name).ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
    let entry = registry
        .limit(name)
        .ok_or_else(|| Error::new(ErrorCode::RegistryInvalid))?;
    if entry.value != maximum || entry.error_code != code.as_str() {
        return Err(Error::new(ErrorCode::RegistryInvalid));
    }
    let accepted = value <= maximum;
    Ok(HardLimitDecision {
        accepted,
        code: (!accepted).then_some(code),
        effective_maximum: maximum,
        layer: if accepted { accept_layer } else { reject_layer },
        maximum,
        name,
        stage,
        value,
    })
}

pub fn enforce_hard_limit(name: &'static str, value: u64) -> Result<HardLimitDecision> {
    let maximum = hard_limit_maximum(name)?;
    enforce_hard_limit_with_ceiling(name, value, maximum)
}

/// Enforces a caller ceiling after capping it at the frozen maximum.
pub fn enforce_hard_limit_with_ceiling(
    name: &'static str,
    value: u64,
    configured: u64,
) -> Result<HardLimitDecision> {
    let (maximum, code, accept_layer, reject_layer, stage) =
        definition(name).ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid).with_layer(2))?;
    let effective_maximum = configured.min(maximum);
    let accepted = value <= effective_maximum;
    let decision = HardLimitDecision {
        accepted,
        code: (!accepted).then_some(code),
        effective_maximum,
        layer: if accepted { accept_layer } else { reject_layer },
        maximum,
        name,
        stage,
        value,
    };
    if accepted {
        Ok(decision)
    } else {
        Err(Error::new(code).with_layer(reject_layer).with_stage(stage))
    }
}

/// Internal contextual form for schema rules whose stable error differs from
/// the isolated hard-limit registry error (for example manifest part length).
pub(crate) fn enforce_hard_limit_context(
    name: &'static str,
    value: u64,
    configured: u64,
    code: ErrorCode,
    layer: u8,
) -> Result<HardLimitDecision> {
    match enforce_hard_limit_with_ceiling(name, value, configured) {
        Ok(decision) => Ok(decision),
        Err(error) => {
            let contextual = Error::new(code).with_layer(layer);
            if code == error.code && code.supports_site(layer, error.stage) {
                Err(contextual.with_stage(error.stage))
            } else {
                Err(contextual)
            }
        }
    }
}
