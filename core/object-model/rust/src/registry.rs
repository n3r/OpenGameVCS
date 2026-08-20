use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
    sync::OnceLock,
};

use serde_json::{Map, Value};

use crate::{hash::Sha256Writer, Error, ErrorCode, ProfileRef, Result, ValidationStage};

pub const REGISTRY_FILES: [&str; 12] = [
    "object-kinds.json",
    "hash-algorithms.json",
    "common-fields.json",
    "kind-fields.json",
    "entry-kinds.json",
    "entry-modes.json",
    "required-features.json",
    "extensions.json",
    "profiles.json",
    "logical-record-types.json",
    "semantic-enums.json",
    "limits.json",
];

pub const BUNDLED_REGISTRY_SET_DIGEST: [u8; 32] = [
    0x6c, 0xa5, 0x5f, 0x10, 0xd2, 0xcd, 0x20, 0x13, 0x9e, 0x77, 0xa1, 0x9a, 0xe0, 0xd2, 0x97, 0x75,
    0x7a, 0x0f, 0x05, 0xb0, 0xac, 0xd3, 0xa3, 0xb3, 0x8a, 0x6e, 0xe4, 0x73, 0xe2, 0xbf, 0x84, 0xc6,
];

const MAX_REGISTRY_FILE_BYTES: usize = 16_777_216;
const MAX_REGISTRY_SET_BYTES: usize = 33_554_432;

const BUNDLED_FILES: [(&str, &[u8]); 12] = [
    (
        "object-kinds.json",
        include_bytes!("../registries/object-kinds.json"),
    ),
    (
        "hash-algorithms.json",
        include_bytes!("../registries/hash-algorithms.json"),
    ),
    (
        "common-fields.json",
        include_bytes!("../registries/common-fields.json"),
    ),
    (
        "kind-fields.json",
        include_bytes!("../registries/kind-fields.json"),
    ),
    (
        "entry-kinds.json",
        include_bytes!("../registries/entry-kinds.json"),
    ),
    (
        "entry-modes.json",
        include_bytes!("../registries/entry-modes.json"),
    ),
    (
        "required-features.json",
        include_bytes!("../registries/required-features.json"),
    ),
    (
        "extensions.json",
        include_bytes!("../registries/extensions.json"),
    ),
    (
        "profiles.json",
        include_bytes!("../registries/profiles.json"),
    ),
    (
        "logical-record-types.json",
        include_bytes!("../registries/logical-record-types.json"),
    ),
    (
        "semantic-enums.json",
        include_bytes!("../registries/semantic-enums.json"),
    ),
    ("limits.json", include_bytes!("../registries/limits.json")),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryState {
    Reserved,
    ConformanceOnly,
    Ratified,
    Deprecated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Read,
    ConformanceWrite,
    ProductionWrite,
}

pub(crate) fn require_write_operation(operation: Operation) -> Result<()> {
    if matches!(
        operation,
        Operation::ConformanceWrite | Operation::ProductionWrite
    ) {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::ConfiguredResourcePreflight))
    }
}

/// One registry assignment selected by a read or write operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryAssignment<'a> {
    ObjectKind(u16),
    HashAlgorithm(u16),
    CommonField(u16),
    KindField { cddl_rule: &'a str, code: u16 },
    EntryKind(u16),
    EntryMode(u16),
    RequiredFeature(u32),
    Extension(&'a ProfileRef),
    Profile(&'a ProfileRef),
    LogicalRecordType(u16),
    SemanticEnum { domain: &'a str, code: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryEntry {
    pub profile: ProfileRef,
    pub family: String,
    pub state: RegistryState,
    pub production_write_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectKindRegistryEntry {
    pub code: u16,
    pub name: String,
    pub text_token: String,
    pub state: RegistryState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogicalRecordRegistryEntry {
    pub code: u16,
    pub name: String,
    pub state: RegistryState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureRegistryEntry {
    pub code: u32,
    pub name: String,
    pub state: RegistryState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionRegistryEntry {
    pub profile: ProfileRef,
    pub state: RegistryState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticEnumRegistryEntry {
    pub code: u32,
    pub name: String,
    pub state: RegistryState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LimitRegistryEntry {
    pub name: String,
    pub value: u64,
    pub unit: String,
    pub error_code: String,
}

#[derive(Clone, Debug)]
pub struct Registry {
    profiles: BTreeMap<ProfileRef, RegistryEntry>,
    features: BTreeMap<u32, FeatureRegistryEntry>,
    object_kinds: BTreeMap<u16, ObjectKindRegistryEntry>,
    logical_record_types: BTreeMap<u16, LogicalRecordRegistryEntry>,
    extensions: BTreeMap<ProfileRef, ExtensionRegistryEntry>,
    semantic_enums: BTreeMap<String, BTreeMap<u32, SemanticEnumRegistryEntry>>,
    limits: BTreeMap<String, LimitRegistryEntry>,
    documents: BTreeMap<String, Value>,
    registry_set_digest: Option<[u8; 32]>,
}

impl Registry {
    pub(crate) fn require_complete_authority(&self) -> Result<()> {
        if self.registry_set_digest.is_some()
            && REGISTRY_FILES
                .iter()
                .all(|name| self.documents.contains_key(*name))
            && self.documents.len() == REGISTRY_FILES.len()
        {
            Ok(())
        } else {
            Err(Error::new(ErrorCode::SchemaFieldInvalid)
                .with_layer(1)
                .with_stage(ValidationStage::ConfiguredResourcePreflight))
        }
    }
    /// Atomically validates and loads normalized profile and feature entries.
    /// This compatibility constructor does not represent a complete registry
    /// set and therefore has no registry-set digest.
    pub fn load(
        entries: impl IntoIterator<Item = RegistryEntry>,
        features: impl IntoIterator<Item = u32>,
    ) -> Result<Self> {
        let mut profiles = BTreeMap::new();
        let mut previous: Option<ProfileRef> = None;
        for entry in entries {
            if entry.family.is_empty()
                || !entry.family.is_ascii()
                || entry.production_write_allowed != (entry.state == RegistryState::Ratified)
                || previous
                    .as_ref()
                    .is_some_and(|profile| profile >= &entry.profile)
                || profiles
                    .insert(entry.profile.clone(), entry.clone())
                    .is_some()
            {
                return invalid();
            }
            previous = Some(entry.profile);
        }
        let mut feature_map = BTreeMap::new();
        let mut previous_feature = None;
        for feature in features {
            if feature == 0
                || previous_feature.is_some_and(|previous| previous >= feature)
                || feature_map
                    .insert(
                        feature,
                        FeatureRegistryEntry {
                            code: feature,
                            name: format!("feature-{feature}"),
                            state: RegistryState::Ratified,
                        },
                    )
                    .is_some()
            {
                return invalid();
            }
            previous_feature = Some(feature);
        }
        Ok(Self {
            profiles,
            features: feature_map,
            object_kinds: BTreeMap::new(),
            logical_record_types: BTreeMap::new(),
            extensions: BTreeMap::new(),
            semantic_enums: BTreeMap::new(),
            limits: BTreeMap::new(),
            documents: BTreeMap::new(),
            registry_set_digest: None,
        })
    }

    /// Parses and validates all twelve canonical registry JSON files as one
    /// atomic snapshot. Names must be the exact basenames in `REGISTRY_FILES`.
    pub fn from_json_files(files: &[(&str, &[u8])]) -> Result<Self> {
        if files.len() != REGISTRY_FILES.len() {
            return invalid();
        }
        let mut sources = BTreeMap::new();
        let mut total_bytes = 0usize;
        for (name, bytes) in files {
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or_else(registry_invalid)?;
            if !REGISTRY_FILES.contains(name)
                || bytes.len() > MAX_REGISTRY_FILE_BYTES
                || total_bytes > MAX_REGISTRY_SET_BYTES
                || sources.insert(*name, *bytes).is_some()
            {
                return invalid();
            }
        }

        let mut documents = BTreeMap::new();
        for (name, expected_registry) in REGISTRY_FILES.iter().zip([
            "ogvcs.repository-format.object-kinds",
            "ogvcs.repository-format.hash-algorithms",
            "ogvcs.repository-format.common-fields",
            "ogvcs.repository-format.kind-fields",
            "ogvcs.repository-format.entry-kinds",
            "ogvcs.repository-format.entry-modes",
            "ogvcs.repository-format.required-features",
            "ogvcs.repository-format.extensions",
            "ogvcs.repository-format.profiles",
            "ogvcs.repository-format.logical-record-types",
            "ogvcs.repository-format.semantic-enums",
            "ogvcs.repository-format.hard-limits",
        ]) {
            let bytes = sources.get(name).ok_or_else(registry_invalid)?;
            let document = parse_canonical_json(bytes)?;
            let object = json_object(&document)?;
            if json_u64(object, "formatVersion")? != 1
                || json_u64(object, "registryVersion")? != 1
                || json_str(object, "registry")? != expected_registry
            {
                return invalid();
            }
            validate_document(name, object)?;
            documents.insert((*name).to_owned(), document);
        }
        validate_cross_document(&documents)?;
        validate_frozen_assignments(&documents)?;

        let object_kinds = index_object_kinds(document_entries(&documents, "object-kinds.json")?)?;
        let logical_record_types =
            index_logical_records(document_entries(&documents, "logical-record-types.json")?)?;
        let profiles = index_profiles(document_entries(&documents, "profiles.json")?)?;
        let features = index_features(document_entries(&documents, "required-features.json")?)?;
        let extensions = index_extensions(document_entries(&documents, "extensions.json")?)?;
        let semantic_enums = index_semantic_enums(&documents)?;
        let limits = index_limits(document_entries(&documents, "limits.json")?)?;
        let digest = registry_set_digest(&sources)?;

        Ok(Self {
            profiles,
            features,
            object_kinds,
            logical_record_types,
            extensions,
            semantic_enums,
            limits,
            documents,
            registry_set_digest: Some(digest),
        })
    }

    /// Reads the complete set before parsing it, so I/O or validation failure
    /// cannot expose a partially populated registry.
    pub fn load_directory(directory: impl AsRef<Path>) -> Result<Self> {
        let mut owned = Vec::with_capacity(REGISTRY_FILES.len());
        let mut total_bytes = 0usize;
        for name in REGISTRY_FILES {
            let path = directory.as_ref().join(name);
            let file = File::open(path).map_err(|_| Error::new(ErrorCode::RegistryInvalid))?;
            let metadata = file
                .metadata()
                .map_err(|_| Error::new(ErrorCode::RegistryInvalid))?;
            let remaining = MAX_REGISTRY_SET_BYTES
                .checked_sub(total_bytes)
                .ok_or_else(registry_invalid)?
                .min(MAX_REGISTRY_FILE_BYTES);
            if !metadata.is_file() || metadata.len() > remaining as u64 {
                return invalid();
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take((remaining as u64).saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|_| Error::new(ErrorCode::RegistryInvalid))?;
            if bytes.len() > remaining {
                return invalid();
            }
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or_else(registry_invalid)?;
            owned.push((name, bytes));
        }
        let borrowed: Vec<_> = owned
            .iter()
            .map(|(name, bytes)| (*name, bytes.as_slice()))
            .collect();
        Self::from_json_files(&borrowed)
    }

    /// Package-contained, exact format-v1 snapshot; no repository checkout or
    /// network access is needed at runtime.
    pub fn bundled() -> Self {
        static BUNDLED: OnceLock<Registry> = OnceLock::new();
        BUNDLED
            .get_or_init(|| {
                let registry = Registry::from_json_files(&BUNDLED_FILES)
                    .expect("packaged registry files are canonical and consistent");
                assert_eq!(
                    registry.registry_set_digest,
                    Some(BUNDLED_REGISTRY_SET_DIGEST),
                    "packaged registry set digest"
                );
                registry
            })
            .clone()
    }

    pub fn registry_set_digest(&self) -> Option<&[u8; 32]> {
        self.registry_set_digest.as_ref()
    }

    pub fn object_kind(&self, code: u16) -> Option<&ObjectKindRegistryEntry> {
        self.object_kinds.get(&code)
    }

    pub fn logical_record_type(&self, code: u16) -> Option<&LogicalRecordRegistryEntry> {
        self.logical_record_types.get(&code)
    }

    pub fn profile(&self, profile: &ProfileRef) -> Option<&RegistryEntry> {
        self.profiles.get(profile)
    }

    pub fn required_feature(&self, code: u32) -> Option<&FeatureRegistryEntry> {
        self.features.get(&code)
    }

    pub fn extension(&self, profile: &ProfileRef) -> Option<&ExtensionRegistryEntry> {
        self.extensions.get(profile)
    }

    pub fn semantic_enum(&self, domain: &str, code: u32) -> Option<&SemanticEnumRegistryEntry> {
        self.semantic_enums.get(domain)?.get(&code)
    }

    pub fn limit(&self, name: &str) -> Option<&LimitRegistryEntry> {
        self.limits.get(name)
    }

    /// Returns one immutable, fully validated canonical registry document by
    /// its exact basename. All twelve authorities remain discoverable even
    /// when the crate has no specialized typed view for that registry.
    pub fn registry_document(&self, name: &str) -> Option<&Value> {
        self.documents.get(name)
    }

    pub fn registry_entry_count(&self, name: &str) -> Option<usize> {
        let document = self.documents.get(name)?.as_object()?;
        if name == "semantic-enums.json" {
            return document.get("domains")?.as_array().map(Vec::len);
        }
        document.get("entries")?.as_array().map(Vec::len)
    }

    pub fn supports_feature(&self, feature: u32) -> bool {
        self.features
            .get(&feature)
            .is_some_and(|entry| entry.state == RegistryState::Ratified)
    }

    /// Applies the exhaustive format-v1 lifecycle table to a selected
    /// assignment. Missing assignments retain their family-specific error.
    pub fn check_assignment(
        &self,
        assignment: RegistryAssignment<'_>,
        operation: Operation,
    ) -> Result<RegistryState> {
        let state = self
            .assignment_state(assignment)?
            .ok_or_else(|| assignment_unknown(assignment))?;
        check_registry_state(state, operation)?;
        if let RegistryAssignment::Profile(profile) = assignment {
            let entry = self
                .profiles
                .get(profile)
                .ok_or_else(|| Error::new(ErrorCode::ProfileUnknown))?;
            if operation == Operation::ProductionWrite && !entry.production_write_allowed {
                return Err(Error::new(if state == RegistryState::ConformanceOnly {
                    ErrorCode::ProfileConformanceOnly
                } else {
                    ErrorCode::ProfileStateForbidden
                }));
            }
        }
        Ok(state)
    }

    /// Like [`Registry::check_assignment`], but an omitted compatibility
    /// authority makes no lifecycle claim. A present authority still rejects
    /// an unknown selected assignment.
    pub fn check_assignment_if_present(
        &self,
        assignment: RegistryAssignment<'_>,
        operation: Operation,
    ) -> Result<Option<RegistryState>> {
        if !self.assignment_authority_present(assignment) {
            return Ok(None);
        }
        self.check_assignment(assignment, operation).map(Some)
    }

    fn assignment_authority_present(&self, assignment: RegistryAssignment<'_>) -> bool {
        match assignment {
            RegistryAssignment::ObjectKind(_) => !self.object_kinds.is_empty(),
            RegistryAssignment::RequiredFeature(_) => !self.features.is_empty(),
            RegistryAssignment::Extension(_) => !self.extensions.is_empty(),
            RegistryAssignment::Profile(_) => !self.profiles.is_empty(),
            RegistryAssignment::LogicalRecordType(_) => !self.logical_record_types.is_empty(),
            RegistryAssignment::SemanticEnum { domain, .. } => self
                .semantic_enums
                .get(domain)
                .is_some_and(|entries| !entries.is_empty()),
            RegistryAssignment::HashAlgorithm(_) => {
                self.documents.contains_key("hash-algorithms.json")
            }
            RegistryAssignment::CommonField(_) => self.documents.contains_key("common-fields.json"),
            RegistryAssignment::KindField { .. } => self.documents.contains_key("kind-fields.json"),
            RegistryAssignment::EntryKind(_) => self.documents.contains_key("entry-kinds.json"),
            RegistryAssignment::EntryMode(_) => self.documents.contains_key("entry-modes.json"),
        }
    }

    fn assignment_state(
        &self,
        assignment: RegistryAssignment<'_>,
    ) -> Result<Option<RegistryState>> {
        match assignment {
            RegistryAssignment::ObjectKind(code) => {
                Ok(self.object_kinds.get(&code).map(|entry| entry.state))
            }
            RegistryAssignment::RequiredFeature(code) => {
                Ok(self.features.get(&code).map(|entry| entry.state))
            }
            RegistryAssignment::Extension(profile) => {
                Ok(self.extensions.get(profile).map(|entry| entry.state))
            }
            RegistryAssignment::Profile(profile) => {
                Ok(self.profiles.get(profile).map(|entry| entry.state))
            }
            RegistryAssignment::LogicalRecordType(code) => Ok(self
                .logical_record_types
                .get(&code)
                .map(|entry| entry.state)),
            RegistryAssignment::SemanticEnum { domain, code } => Ok(self
                .semantic_enums
                .get(domain)
                .and_then(|entries| entries.get(&code))
                .map(|entry| entry.state)),
            RegistryAssignment::HashAlgorithm(code) => {
                self.document_code_state("hash-algorithms.json", u64::from(code), None)
            }
            RegistryAssignment::CommonField(code) => {
                self.document_code_state("common-fields.json", u64::from(code), None)
            }
            RegistryAssignment::KindField { cddl_rule, code } => {
                self.document_code_state("kind-fields.json", u64::from(code), Some(cddl_rule))
            }
            RegistryAssignment::EntryKind(code) => {
                self.document_code_state("entry-kinds.json", u64::from(code), None)
            }
            RegistryAssignment::EntryMode(code) => {
                self.document_code_state("entry-modes.json", u64::from(code), None)
            }
        }
    }

    fn document_code_state(
        &self,
        name: &str,
        code: u64,
        cddl_rule: Option<&str>,
    ) -> Result<Option<RegistryState>> {
        let Some(document) = self.documents.get(name) else {
            return Ok(None);
        };
        for value in json_array(json_object(document)?, "entries")? {
            let entry = json_object(value)?;
            if json_u64(entry, "code")? == code
                && cddl_rule.is_none_or(|rule| json_str(entry, "cddlRule").ok() == Some(rule))
            {
                return parse_state(json_str(entry, "state")?).map(Some);
            }
        }
        Ok(None)
    }

    pub fn check_profile(
        &self,
        profile: &ProfileRef,
        family: &str,
        operation: Operation,
    ) -> Result<()> {
        let entry = self
            .profiles
            .get(profile)
            .ok_or_else(|| Error::new(ErrorCode::ProfileUnknown))?;
        if entry.family != family {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        self.check_assignment(RegistryAssignment::Profile(profile), operation)
            .map(|_| ())
    }
}

fn check_registry_state(state: RegistryState, operation: Operation) -> Result<()> {
    match (state, operation) {
        (RegistryState::Reserved, _) => Err(Error::new(ErrorCode::ProfileStateForbidden)),
        (RegistryState::ConformanceOnly, Operation::Read | Operation::ProductionWrite) => {
            Err(Error::new(ErrorCode::ProfileConformanceOnly))
        }
        (RegistryState::ConformanceOnly, Operation::ConformanceWrite)
        | (RegistryState::Ratified, _)
        | (RegistryState::Deprecated, Operation::Read | Operation::ConformanceWrite) => Ok(()),
        (RegistryState::Deprecated, Operation::ProductionWrite) => {
            Err(Error::new(ErrorCode::ProfileStateForbidden))
        }
    }
}

fn assignment_unknown(assignment: RegistryAssignment<'_>) -> Error {
    let code = match assignment {
        RegistryAssignment::ObjectKind(_) => ErrorCode::ObjectKindUnsupported,
        RegistryAssignment::LogicalRecordType(_) => ErrorCode::LogicalRecordTypeUnsupported,
        RegistryAssignment::RequiredFeature(_) => ErrorCode::RequiredFeatureUnsupported,
        RegistryAssignment::Extension(_) | RegistryAssignment::Profile(_) => {
            ErrorCode::ProfileUnknown
        }
        RegistryAssignment::HashAlgorithm(_)
        | RegistryAssignment::CommonField(_)
        | RegistryAssignment::KindField { .. }
        | RegistryAssignment::EntryKind(_)
        | RegistryAssignment::EntryMode(_)
        | RegistryAssignment::SemanticEnum { .. } => ErrorCode::SchemaFieldInvalid,
    };
    Error::new(code)
}

fn parse_canonical_json(bytes: &[u8]) -> Result<Value> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) || bytes.contains(&b'\r') || !bytes.ends_with(b"\n") {
        return invalid();
    }
    let text = core::str::from_utf8(bytes).map_err(|_| registry_invalid())?;
    if text.starts_with('\u{feff}') {
        return invalid();
    }
    let value: Value = serde_json::from_str(text).map_err(|_| registry_invalid())?;
    let mut canonical = serde_json::to_string_pretty(&value).map_err(|_| registry_invalid())?;
    canonical.push('\n');
    if canonical.as_bytes() != bytes {
        return invalid();
    }
    Ok(value)
}

fn validate_document(name: &str, document: &Map<String, Value>) -> Result<()> {
    if name == "semantic-enums.json" {
        let domains = json_array(document, "domains")?;
        let mut domain_names = BTreeSet::new();
        for domain in domains {
            let domain = json_object(domain)?;
            let name = json_str(domain, "name")?;
            if name.is_empty() || !domain_names.insert(name) {
                return invalid();
            }
            exact_keys(domain, &["entries", "name"], &[])?;
            let entries = json_array(domain, "entries")?;
            for entry in entries {
                exact_keys(json_object(entry)?, &["code", "name", "state"], &[])?;
            }
            validate_code_entries(entries, true)?;
        }
        return Ok(());
    }

    let entries = json_array(document, "entries")?;
    for entry in entries {
        validate_entry_shape(name, json_object(entry)?)?;
    }
    if name == "profiles.json" || name == "extensions.json" {
        validate_profile_entries(entries, name == "profiles.json")?;
    } else if name == "kind-fields.json" {
        validate_kind_fields(entries)?;
    } else if name == "limits.json" {
        validate_limit_entries(entries)?;
    } else {
        validate_code_entries(entries, name == "common-fields.json")?;
        validate_ranges(name, document, entries)?;
    }
    Ok(())
}

fn exact_keys(object: &Map<String, Value>, required: &[&str], optional: &[&str]) -> Result<()> {
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return invalid();
    }
    Ok(())
}

fn nonempty_string(object: &Map<String, Value>, key: &str) -> Result<()> {
    if json_str(object, key)?.is_empty() {
        return invalid();
    }
    Ok(())
}

fn sorted_nonempty_u64_array(object: &Map<String, Value>, key: &str) -> Result<()> {
    let values = json_u64_array(object, key)?;
    if values.is_empty() || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid();
    }
    Ok(())
}

fn valid_text_token(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !value.ends_with('-')
        && !value.contains("--")
}

fn validate_wire_shape(value: &Value) -> Result<()> {
    let shape = json_object(value)?;
    if shape.is_empty() {
        return invalid();
    }
    for (key, value) in shape {
        if key.parse::<u64>().is_err()
            || (key.len() > 1 && key.starts_with('0'))
            || value.as_str().is_none_or(str::is_empty)
        {
            return invalid();
        }
    }
    Ok(())
}

fn validate_entry_shape(file: &str, entry: &Map<String, Value>) -> Result<()> {
    match file {
        "object-kinds.json" => {
            exact_keys(
                entry,
                &["code", "name", "payload", "state", "textToken"],
                &[],
            )?;
            if !matches!(
                json_str(entry, "payload")?,
                "raw-bytes" | "deterministic-cbor"
            ) || !valid_text_token(json_str(entry, "textToken")?)
            {
                return invalid();
            }
        }
        "hash-algorithms.json" => {
            exact_keys(entry, &["code", "digestBytes", "name", "state"], &[])?;
            if !(1..=65_535).contains(&json_u64(entry, "digestBytes")?) {
                return invalid();
            }
        }
        "common-fields.json" => {
            exact_keys(entry, &["code", "name", "required", "state", "type"], &[])?;
            json_bool(entry, "required")?;
            nonempty_string(entry, "type")?;
        }
        "kind-fields.json" => {
            exact_keys(
                entry,
                &[
                    "cddlRule",
                    "code",
                    "name",
                    "requirement",
                    "scope",
                    "state",
                    "type",
                ],
                &["itemType", "logicalRecordType", "objectKind"],
            )?;
            for key in ["cddlRule", "name", "scope", "type"] {
                nonempty_string(entry, key)?;
            }
            if json_str(entry, "scope")?
                != format!("repository-format.cddl#{}", json_str(entry, "cddlRule")?)
                || !matches!(
                    json_str(entry, "requirement")?,
                    "required" | "optional" | "conditional"
                )
                || json_u64(entry, "code")? > 4095
            {
                return invalid();
            }
            let discriminators = ["itemType", "logicalRecordType", "objectKind"]
                .into_iter()
                .filter(|key| entry.contains_key(*key))
                .collect::<Vec<_>>();
            if discriminators.len() > 1
                || discriminators.iter().any(|key| {
                    json_u64(entry, key).is_err() || json_u64(entry, key).ok() == Some(0)
                })
            {
                return invalid();
            }
        }
        "entry-kinds.json" => {
            exact_keys(
                entry,
                &["allowedModeCodes", "code", "name", "state", "targetKind"],
                &[],
            )?;
            sorted_nonempty_u64_array(entry, "allowedModeCodes")?;
            nonempty_string(entry, "targetKind")?;
        }
        "entry-modes.json" => {
            exact_keys(
                entry,
                &[
                    "allowedEntryKindCodes",
                    "code",
                    "name",
                    "portableMode",
                    "state",
                ],
                &[],
            )?;
            sorted_nonempty_u64_array(entry, "allowedEntryKindCodes")?;
            let mode = json_str(entry, "portableMode")?;
            if mode.len() != 6 || !mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
                return invalid();
            }
        }
        "required-features.json" => {
            exact_keys(entry, &["code", "name", "state"], &["behavior"])?;
            if entry.contains_key("behavior") {
                nonempty_string(entry, "behavior")?;
            }
        }
        "extensions.json" => {
            exact_keys(entry, &["id", "major", "namespace", "state"], &[])?;
        }
        "profiles.json" => {
            exact_keys(
                entry,
                &[
                    "family",
                    "id",
                    "major",
                    "namespace",
                    "owner",
                    "productionWriteAllowed",
                    "state",
                ],
                &[],
            )?;
            nonempty_string(entry, "owner")?;
        }
        "logical-record-types.json" => {
            exact_keys(entry, &["code", "name", "state"], &["wireShape"])?;
            if let Some(shape) = entry.get("wireShape") {
                validate_wire_shape(shape)?;
            } else if json_u64(entry, "code")? >= 10 {
                return invalid();
            }
        }
        "limits.json" => {
            exact_keys(entry, &["errorCode", "name", "unit", "value"], &[])?;
            let code = json_str(entry, "errorCode")?;
            if code.is_empty()
                || !code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return invalid();
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_code_entries(entries: &[Value], allow_zero: bool) -> Result<()> {
    let mut previous = None;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = json_object(entry)?;
        let code = json_u64(entry, "code")?;
        let name = json_str(entry, "name")?;
        if (!allow_zero && code == 0)
            || previous.is_some_and(|previous| previous >= code)
            || !names.insert(name)
            || name.is_empty()
        {
            return invalid();
        }
        if let Some(value) = entry.get("state") {
            parse_state(value.as_str().ok_or_else(registry_invalid)?)?;
        }
        previous = Some(code);
    }
    Ok(())
}

fn validate_ranges(file: &str, document: &Map<String, Value>, entries: &[Value]) -> Result<()> {
    let maximum = match file {
        "common-fields.json" => 15,
        "entry-kinds.json"
        | "entry-modes.json"
        | "hash-algorithms.json"
        | "logical-record-types.json"
        | "object-kinds.json" => u64::from(u16::MAX),
        "kind-fields.json" => 4095,
        "required-features.json" => u64::from(u32::MAX),
        _ => u64::MAX,
    };
    let mut ranges = Vec::new();
    for key in ["reserved", "unassigned"] {
        if let Some(value) = document.get(key) {
            for range in value.as_array().ok_or_else(registry_invalid)? {
                let range = json_object(range)?;
                let from = json_u64(range, "from")?;
                let to = json_u64(range, "to")?;
                if from > to || to > maximum {
                    return invalid();
                }
                ranges.push((from, to));
            }
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 >= pair[1].0) {
        return invalid();
    }
    for entry in entries {
        let code = json_u64(json_object(entry)?, "code")?;
        if code > maximum
            || ranges
                .iter()
                .any(|(from, to)| (*from..=*to).contains(&code))
            || ranges.last().is_some_and(|(_, maximum)| code > *maximum)
        {
            return invalid();
        }
    }
    Ok(())
}

fn validate_profile_entries(entries: &[Value], production_flag: bool) -> Result<()> {
    let mut previous: Option<(String, String, u32)> = None;
    for entry in entries {
        let entry = json_object(entry)?;
        let namespace = json_str(entry, "namespace")?;
        let id = json_str(entry, "id")?;
        let major = u32::try_from(json_u64(entry, "major")?).map_err(|_| registry_invalid())?;
        ProfileRef::new(namespace, id, major).map_err(|_| registry_invalid())?;
        let tuple = (namespace.to_owned(), id.to_owned(), major);
        if previous.as_ref().is_some_and(|previous| previous >= &tuple) {
            return invalid();
        }
        let state = parse_state(json_str(entry, "state")?)?;
        if production_flag {
            let family = json_str(entry, "family")?;
            if family.is_empty()
                || !family.is_ascii()
                || json_bool(entry, "productionWriteAllowed")? != (state == RegistryState::Ratified)
            {
                return invalid();
            }
        }
        previous = Some(tuple);
    }
    Ok(())
}

fn validate_kind_fields(entries: &[Value]) -> Result<()> {
    let mut previous: Option<(String, u64)> = None;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = json_object(entry)?;
        let rule = json_str(entry, "cddlRule")?;
        let scope = json_str(entry, "scope")?;
        let code = json_u64(entry, "code")?;
        let name = json_str(entry, "name")?;
        let tuple = (rule.to_owned(), code);
        if scope != format!("repository-format.cddl#{rule}")
            || code > 4095
            || previous.as_ref().is_some_and(|previous| previous >= &tuple)
            || !names.insert((rule, name))
        {
            return invalid();
        }
        parse_state(json_str(entry, "state")?)?;
        previous = Some(tuple);
    }
    Ok(())
}

fn validate_limit_entries(entries: &[Value]) -> Result<()> {
    const UNITS: &[&str] = &[
        "bytes",
        "chunks",
        "edges",
        "encoded-bytes",
        "entries",
        "entries-per-group",
        "groups",
        "items",
        "levels",
        "members-per-group",
        "objects",
        "operations",
        "parents",
        "records",
        "roots",
        "segments",
        "utf8-bytes",
    ];
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = json_object(entry)?;
        if json_u64(entry, "value")? == 0
            || !names.insert(json_str(entry, "name")?)
            || !UNITS.contains(&json_str(entry, "unit")?)
            || json_str(entry, "errorCode")?.is_empty()
        {
            return invalid();
        }
    }
    Ok(())
}

fn validate_cross_document(documents: &BTreeMap<String, Value>) -> Result<()> {
    let object_entries = document_entries(documents, "object-kinds.json")?;
    let mut object_names = BTreeSet::new();
    let mut object_tokens = BTreeSet::new();
    for entry in object_entries {
        let entry = json_object(entry)?;
        if !object_names.insert(json_str(entry, "name")?)
            || !object_tokens.insert(json_str(entry, "textToken")?)
        {
            return invalid();
        }
    }

    let kinds = document_entries(documents, "entry-kinds.json")?;
    let modes = document_entries(documents, "entry-modes.json")?;
    for kind in kinds {
        let kind = json_object(kind)?;
        if !object_names.contains(json_str(kind, "targetKind")?) {
            return invalid();
        }
        let kind_code = json_u64(kind, "code")?;
        for mode_code in json_u64_array(kind, "allowedModeCodes")? {
            let mode = find_code(modes, mode_code)?;
            if !json_u64_array(mode, "allowedEntryKindCodes")?.contains(&kind_code) {
                return invalid();
            }
        }
    }
    for mode in modes {
        let mode = json_object(mode)?;
        let mode_code = json_u64(mode, "code")?;
        for kind_code in json_u64_array(mode, "allowedEntryKindCodes")? {
            let kind = find_code(kinds, kind_code)?;
            if !json_u64_array(kind, "allowedModeCodes")?.contains(&mode_code) {
                return invalid();
            }
        }
    }

    let common = json_object(
        documents
            .get("common-fields.json")
            .ok_or_else(registry_invalid)?,
    )?;
    let range = json_object(common.get("kindFieldRange").ok_or_else(registry_invalid)?)?;
    if json_u64(range, "from")? != 16 || json_u64(range, "to")? != 4095 {
        return invalid();
    }
    let algorithm = find_code(document_entries(documents, "hash-algorithms.json")?, 1)?;
    if json_str(algorithm, "name")? != "sha256" || json_u64(algorithm, "digestBytes")? != 32 {
        return invalid();
    }
    Ok(())
}

fn assignment_key(file: &str, entry: &Map<String, Value>) -> Result<String> {
    match file {
        "profiles.json" | "extensions.json" => Ok(format!(
            "{}/{}@{}",
            json_str(entry, "namespace")?,
            json_str(entry, "id")?,
            json_u64(entry, "major")?
        )),
        "kind-fields.json" => Ok(format!(
            "{}\0{}",
            json_str(entry, "cddlRule")?,
            json_u64(entry, "code")?
        )),
        "limits.json" => Ok(json_str(entry, "name")?.to_owned()),
        _ => Ok(json_u64(entry, "code")?.to_string()),
    }
}

fn without_keys(value: &Map<String, Value>, keys: &[&str]) -> Value {
    let mut result = value.clone();
    for key in keys {
        result.remove(*key);
    }
    Value::Object(result)
}

fn allowed_lifecycle(previous: Option<&str>, current: Option<&str>) -> bool {
    previous == current
        || current == Some("deprecated")
            && matches!(previous, Some("ratified" | "conformance-only"))
}

fn validate_frozen_entries(file: &str, previous: &[Value], current: &[Value]) -> Result<()> {
    let mut current_by_key = BTreeMap::new();
    for entry in current {
        let entry = json_object(entry)?;
        current_by_key.insert(assignment_key(file, entry)?, entry);
    }
    for entry in previous {
        let previous_entry = json_object(entry)?;
        let current_entry = current_by_key
            .get(&assignment_key(file, previous_entry)?)
            .ok_or_else(registry_invalid)?;
        if !allowed_lifecycle(
            previous_entry.get("state").and_then(Value::as_str),
            current_entry.get("state").and_then(Value::as_str),
        ) || without_keys(previous_entry, &["state", "productionWriteAllowed"])
            != without_keys(current_entry, &["state", "productionWriteAllowed"])
        {
            return invalid();
        }
    }
    Ok(())
}

fn validate_frozen_assignments(documents: &BTreeMap<String, Value>) -> Result<()> {
    let mut baseline = BTreeMap::new();
    for (name, bytes) in BUNDLED_FILES {
        baseline.insert(name.to_owned(), parse_canonical_json(bytes)?);
    }
    for file in REGISTRY_FILES {
        let previous = json_object(baseline.get(file).ok_or_else(registry_invalid)?)?;
        let current = json_object(documents.get(file).ok_or_else(registry_invalid)?)?;
        if without_keys(previous, &["entries", "domains", "unassigned"])
            != without_keys(current, &["entries", "domains", "unassigned"])
        {
            return invalid();
        }
        if file == "semantic-enums.json" {
            let mut current_domains = BTreeMap::new();
            for domain in json_array(current, "domains")? {
                let domain = json_object(domain)?;
                current_domains.insert(json_str(domain, "name")?, domain);
            }
            for domain in json_array(previous, "domains")? {
                let previous_domain = json_object(domain)?;
                let current_domain = current_domains
                    .get(json_str(previous_domain, "name")?)
                    .ok_or_else(registry_invalid)?;
                if without_keys(previous_domain, &["entries", "unassigned"])
                    != without_keys(current_domain, &["entries", "unassigned"])
                {
                    return invalid();
                }
                validate_frozen_entries(
                    file,
                    json_array(previous_domain, "entries")?,
                    json_array(current_domain, "entries")?,
                )?;
            }
        } else {
            validate_frozen_entries(
                file,
                json_array(previous, "entries")?,
                json_array(current, "entries")?,
            )?;
        }
    }
    Ok(())
}

fn index_object_kinds(entries: &[Value]) -> Result<BTreeMap<u16, ObjectKindRegistryEntry>> {
    entries
        .iter()
        .map(|entry| {
            let entry = json_object(entry)?;
            let code = u16::try_from(json_u64(entry, "code")?).map_err(|_| registry_invalid())?;
            Ok((
                code,
                ObjectKindRegistryEntry {
                    code,
                    name: json_str(entry, "name")?.to_owned(),
                    text_token: json_str(entry, "textToken")?.to_owned(),
                    state: parse_state(json_str(entry, "state")?)?,
                },
            ))
        })
        .collect()
}

fn index_logical_records(entries: &[Value]) -> Result<BTreeMap<u16, LogicalRecordRegistryEntry>> {
    entries
        .iter()
        .map(|entry| {
            let entry = json_object(entry)?;
            let code = u16::try_from(json_u64(entry, "code")?).map_err(|_| registry_invalid())?;
            Ok((
                code,
                LogicalRecordRegistryEntry {
                    code,
                    name: json_str(entry, "name")?.to_owned(),
                    state: parse_state(json_str(entry, "state")?)?,
                },
            ))
        })
        .collect()
}

fn index_profiles(entries: &[Value]) -> Result<BTreeMap<ProfileRef, RegistryEntry>> {
    entries
        .iter()
        .map(|entry| {
            let entry = json_object(entry)?;
            let profile = profile_ref(entry)?;
            let state = parse_state(json_str(entry, "state")?)?;
            Ok((
                profile.clone(),
                RegistryEntry {
                    profile,
                    family: json_str(entry, "family")?.to_owned(),
                    state,
                    production_write_allowed: json_bool(entry, "productionWriteAllowed")?,
                },
            ))
        })
        .collect()
}

fn index_features(entries: &[Value]) -> Result<BTreeMap<u32, FeatureRegistryEntry>> {
    entries
        .iter()
        .map(|entry| {
            let entry = json_object(entry)?;
            let code = u32::try_from(json_u64(entry, "code")?).map_err(|_| registry_invalid())?;
            Ok((
                code,
                FeatureRegistryEntry {
                    code,
                    name: json_str(entry, "name")?.to_owned(),
                    state: parse_state(json_str(entry, "state")?)?,
                },
            ))
        })
        .collect()
}

fn index_extensions(entries: &[Value]) -> Result<BTreeMap<ProfileRef, ExtensionRegistryEntry>> {
    entries
        .iter()
        .map(|entry| {
            let entry = json_object(entry)?;
            let profile = profile_ref(entry)?;
            Ok((
                profile.clone(),
                ExtensionRegistryEntry {
                    profile,
                    state: parse_state(json_str(entry, "state")?)?,
                },
            ))
        })
        .collect()
}

fn index_semantic_enums(
    documents: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, BTreeMap<u32, SemanticEnumRegistryEntry>>> {
    let document = json_object(
        documents
            .get("semantic-enums.json")
            .ok_or_else(registry_invalid)?,
    )?;
    let mut result = BTreeMap::new();
    for domain in json_array(document, "domains")? {
        let domain = json_object(domain)?;
        let name = json_str(domain, "name")?.to_owned();
        let entries = json_array(domain, "entries")?
            .iter()
            .map(|entry| {
                let entry = json_object(entry)?;
                let code =
                    u32::try_from(json_u64(entry, "code")?).map_err(|_| registry_invalid())?;
                Ok((
                    code,
                    SemanticEnumRegistryEntry {
                        code,
                        name: json_str(entry, "name")?.to_owned(),
                        state: parse_state(json_str(entry, "state")?)?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        if result.insert(name, entries).is_some() {
            return invalid();
        }
    }
    Ok(result)
}

fn index_limits(entries: &[Value]) -> Result<BTreeMap<String, LimitRegistryEntry>> {
    entries
        .iter()
        .map(|entry| {
            let entry = json_object(entry)?;
            let name = json_str(entry, "name")?.to_owned();
            Ok((
                name.clone(),
                LimitRegistryEntry {
                    name,
                    value: json_u64(entry, "value")?,
                    unit: json_str(entry, "unit")?.to_owned(),
                    error_code: json_str(entry, "errorCode")?.to_owned(),
                },
            ))
        })
        .collect()
}

fn registry_set_digest(sources: &BTreeMap<&str, &[u8]>) -> Result<[u8; 32]> {
    let mut hash = Sha256Writer::new();
    hash.update(b"OpenGameVCS registry set\0");
    hash.update(&1u16.to_be_bytes());
    for name in REGISTRY_FILES {
        let path = format!("registries/{name}");
        let path_length = u32::try_from(path.len()).map_err(|_| registry_invalid())?;
        let bytes = sources.get(name).ok_or_else(registry_invalid)?;
        let file_length = u64::try_from(bytes.len()).map_err(|_| registry_invalid())?;
        hash.update(&path_length.to_be_bytes());
        hash.update(path.as_bytes());
        hash.update(&file_length.to_be_bytes());
        hash.update(bytes);
    }
    Ok(hash.finish())
}

fn parse_state(value: &str) -> Result<RegistryState> {
    match value {
        "reserved" => Ok(RegistryState::Reserved),
        "conformance-only" => Ok(RegistryState::ConformanceOnly),
        "ratified" => Ok(RegistryState::Ratified),
        "deprecated" => Ok(RegistryState::Deprecated),
        _ => invalid(),
    }
}

fn profile_ref(entry: &Map<String, Value>) -> Result<ProfileRef> {
    let major = u32::try_from(json_u64(entry, "major")?).map_err(|_| registry_invalid())?;
    ProfileRef::new(json_str(entry, "namespace")?, json_str(entry, "id")?, major)
        .map_err(|_| registry_invalid())
}

fn document_entries<'a>(documents: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a [Value]> {
    json_array(
        json_object(documents.get(name).ok_or_else(registry_invalid)?)?,
        "entries",
    )
}

fn find_code(entries: &[Value], wanted: u64) -> Result<&Map<String, Value>> {
    entries
        .iter()
        .map(json_object)
        .find_map(|entry| match entry {
            Ok(entry) if json_u64(entry, "code").ok() == Some(wanted) => Some(Ok(entry)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .unwrap_or_else(invalid)
}

fn json_object(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().ok_or_else(registry_invalid)
}

fn json_array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a [Value]> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(registry_invalid)
}

fn json_str<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(registry_invalid)
}

fn json_u64(object: &Map<String, Value>, key: &str) -> Result<u64> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(registry_invalid)
}

fn json_bool(object: &Map<String, Value>, key: &str) -> Result<bool> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(registry_invalid)
}

fn json_u64_array(object: &Map<String, Value>, key: &str) -> Result<Vec<u64>> {
    json_array(object, key)?
        .iter()
        .map(|value| value.as_u64().ok_or_else(registry_invalid))
        .collect()
}

fn invalid<T>() -> Result<T> {
    Err(registry_invalid())
}

const fn registry_invalid() -> Error {
    Error::new(ErrorCode::RegistryInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_documents_are_individually_canonical_and_valid() {
        let expected = [
            "ogvcs.repository-format.object-kinds",
            "ogvcs.repository-format.hash-algorithms",
            "ogvcs.repository-format.common-fields",
            "ogvcs.repository-format.kind-fields",
            "ogvcs.repository-format.entry-kinds",
            "ogvcs.repository-format.entry-modes",
            "ogvcs.repository-format.required-features",
            "ogvcs.repository-format.extensions",
            "ogvcs.repository-format.profiles",
            "ogvcs.repository-format.logical-record-types",
            "ogvcs.repository-format.semantic-enums",
            "ogvcs.repository-format.hard-limits",
        ];
        for ((name, bytes), expected_registry) in BUNDLED_FILES.iter().zip(expected) {
            let document = parse_canonical_json(bytes)
                .unwrap_or_else(|error| panic!("{name} canonical parse: {error}"));
            let object = json_object(&document).unwrap();
            assert_eq!(json_str(object, "registry").unwrap(), expected_registry);
            validate_document(name, object)
                .unwrap_or_else(|error| panic!("{name} validation: {error}"));
        }
    }

    #[test]
    fn packaged_registry_set_is_consistent() {
        let registry = Registry::from_json_files(&BUNDLED_FILES).unwrap();
        assert_eq!(
            registry.registry_set_digest(),
            Some(&BUNDLED_REGISTRY_SET_DIGEST)
        );
        assert_eq!(registry.object_kind(3).unwrap().text_token, "tree");
        assert_eq!(
            registry.logical_record_type(9).unwrap().name,
            "fixture-event"
        );
        assert_eq!(
            registry
                .profile(&ProfileRef::new("path.test", "opaque", 1).unwrap())
                .unwrap()
                .family,
            "path"
        );
        assert!(registry.required_feature(1).is_none());
        assert!(registry
            .extension(&ProfileRef::new("extension.test", "none", 1).unwrap())
            .is_none());
        assert_eq!(
            registry.semantic_enum("operation", 7).unwrap().name,
            "restore"
        );
        assert_eq!(
            registry.limit("metadata-payload-bytes").unwrap().value,
            536_870_912
        );
        assert_eq!(
            REGISTRY_FILES
                .iter()
                .filter(|name| registry.registry_document(name).is_some())
                .count(),
            REGISTRY_FILES.len()
        );
        assert_eq!(
            registry.registry_entry_count("hash-algorithms.json"),
            Some(1)
        );
        assert_eq!(registry.registry_entry_count("common-fields.json"), Some(4));
        assert!(registry.registry_entry_count("kind-fields.json").unwrap() > 300);
        assert_eq!(registry.registry_entry_count("entry-kinds.json"), Some(4));
        assert_eq!(registry.registry_entry_count("entry-modes.json"), Some(4));
    }

    #[test]
    fn object_tokens_and_every_frozen_code_domain_are_bounded() {
        let mut object_kinds = parse_canonical_json(BUNDLED_FILES[0].1).unwrap();
        object_kinds["entries"][0]["textToken"] = Value::String("a".repeat(64));
        assert_eq!(
            validate_document("object-kinds.json", json_object(&object_kinds).unwrap())
                .unwrap_err()
                .code,
            ErrorCode::RegistryInvalid
        );

        for (file, maximum) in [
            ("object-kinds.json", u64::from(u16::MAX)),
            ("hash-algorithms.json", u64::from(u16::MAX)),
            ("common-fields.json", 15),
            ("kind-fields.json", 4095),
            ("entry-kinds.json", u64::from(u16::MAX)),
            ("entry-modes.json", u64::from(u16::MAX)),
            ("required-features.json", u64::from(u32::MAX)),
            ("logical-record-types.json", u64::from(u16::MAX)),
        ] {
            let bytes = BUNDLED_FILES
                .iter()
                .find_map(|(name, bytes)| (*name == file).then_some(*bytes))
                .unwrap();
            let mut document = parse_canonical_json(bytes).unwrap();
            if let Some(entry) = document["entries"]
                .as_array_mut()
                .and_then(|entries| entries.first_mut())
            {
                entry["code"] = Value::from(maximum + 1);
            } else {
                document["entries"] = serde_json::json!([{
                    "code": maximum + 1,
                    "name": "past-endpoint",
                    "state": "ratified"
                }]);
            }
            assert_eq!(
                validate_document(file, json_object(&document).unwrap())
                    .unwrap_err()
                    .code,
                ErrorCode::RegistryInvalid,
                "entry endpoint for {file}"
            );

            for range_family in ["reserved", "unassigned"] {
                let mut document = parse_canonical_json(bytes).unwrap();
                let Some(range) = document
                    .get_mut(range_family)
                    .and_then(Value::as_array_mut)
                    .and_then(|ranges| ranges.first_mut())
                else {
                    continue;
                };
                range["to"] = Value::from(maximum + 1);
                assert_eq!(
                    validate_document(file, json_object(&document).unwrap())
                        .unwrap_err()
                        .code,
                    ErrorCode::RegistryInvalid,
                    "{range_family} endpoint for {file}"
                );
            }
        }
    }

    fn owned_bundled() -> Vec<(String, Vec<u8>)> {
        BUNDLED_FILES
            .iter()
            .map(|(name, bytes)| ((*name).to_owned(), bytes.to_vec()))
            .collect()
    }

    fn load_owned(files: &[(String, Vec<u8>)]) -> Result<Registry> {
        let borrowed: Vec<_> = files
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect();
        Registry::from_json_files(&borrowed)
    }

    #[test]
    fn malformed_or_noncanonical_json_rejects_the_entire_set() {
        for mutation in ["bom", "crlf", "whitespace", "duplicate-key"] {
            let mut files = owned_bundled();
            let object_kinds = &mut files[0].1;
            match mutation {
                "bom" => {
                    object_kinds.splice(0..0, [0xef, 0xbb, 0xbf]);
                }
                "crlf" => {
                    let newline = object_kinds.iter().position(|byte| *byte == b'\n').unwrap();
                    object_kinds.insert(newline, b'\r');
                }
                "whitespace" => {
                    object_kinds.insert(object_kinds.len() - 1, b' ');
                }
                "duplicate-key" => {
                    let source = core::str::from_utf8(object_kinds).unwrap();
                    *object_kinds = source
                        .replacen(
                            "{\n  \"entries\":",
                            "{\n  \"entries\": [],\n  \"entries\":",
                            1,
                        )
                        .into_bytes();
                }
                _ => unreachable!(),
            };
            assert_eq!(
                load_owned(&files).unwrap_err().code,
                ErrorCode::RegistryInvalid
            );
        }
    }

    #[test]
    fn cross_registry_inconsistency_and_incomplete_sets_are_atomic_failures() {
        let mut files = owned_bundled();
        let entry_kinds = files
            .iter_mut()
            .find(|(name, _)| name == "entry-kinds.json")
            .unwrap();
        let mut value = parse_canonical_json(&entry_kinds.1).unwrap();
        value["entries"][0]["targetKind"] = Value::String("missing-kind".to_owned());
        let mut canonical = serde_json::to_string_pretty(&value).unwrap();
        canonical.push('\n');
        entry_kinds.1 = canonical.into_bytes();
        assert_eq!(
            load_owned(&files).unwrap_err().code,
            ErrorCode::RegistryInvalid
        );

        let mut missing = owned_bundled();
        missing.pop();
        assert_eq!(
            load_owned(&missing).unwrap_err().code,
            ErrorCode::RegistryInvalid
        );
        let mut duplicate = owned_bundled();
        duplicate[11].0 = duplicate[0].0.clone();
        assert_eq!(
            load_owned(&duplicate).unwrap_err().code,
            ErrorCode::RegistryInvalid
        );
    }

    #[test]
    fn frozen_assignments_cannot_be_reassigned_or_removed() {
        let canonical = |value: &Value| {
            let mut text = serde_json::to_string_pretty(value).unwrap();
            text.push('\n');
            text.into_bytes()
        };

        let mut reassigned = owned_bundled();
        let object_kinds = &mut reassigned[0].1;
        let mut document = parse_canonical_json(object_kinds).unwrap();
        document["entries"][0]["payload"] = Value::String("deterministic-cbor".to_owned());
        *object_kinds = canonical(&document);
        assert_eq!(
            load_owned(&reassigned).unwrap_err().code,
            ErrorCode::RegistryInvalid
        );

        let mut removed = owned_bundled();
        let logical_records = removed
            .iter_mut()
            .find(|(name, _)| name == "logical-record-types.json")
            .unwrap();
        let mut document = parse_canonical_json(&logical_records.1).unwrap();
        document["entries"].as_array_mut().unwrap().remove(0);
        logical_records.1 = canonical(&document);
        assert_eq!(
            load_owned(&removed).unwrap_err().code,
            ErrorCode::RegistryInvalid
        );

        let mut deprecated = owned_bundled();
        let object_kinds = &mut deprecated[0].1;
        let mut document = parse_canonical_json(object_kinds).unwrap();
        document["entries"][0]["state"] = Value::String("deprecated".to_owned());
        *object_kinds = canonical(&document);
        assert_eq!(
            load_owned(&deprecated)
                .unwrap()
                .object_kind(1)
                .unwrap()
                .state,
            RegistryState::Deprecated
        );
    }

    #[test]
    fn additive_entries_require_their_registry_specific_wire_shape() {
        let canonical = |value: &Value| {
            let mut text = serde_json::to_string_pretty(value).unwrap();
            text.push('\n');
            text.into_bytes()
        };

        let mut missing_limit_code = owned_bundled();
        let file = missing_limit_code
            .iter_mut()
            .find(|(name, _)| name == "limits.json")
            .unwrap();
        let mut document = parse_canonical_json(&file.1).unwrap();
        document["entries"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"name":"zzz","unit":"bytes","value":1}));
        file.1 = canonical(&document);
        assert_eq!(
            load_owned(&missing_limit_code).unwrap_err().code,
            ErrorCode::RegistryInvalid
        );

        for (name, entry) in [
            (
                "object-kinds.json",
                serde_json::json!({"code":12,"name":"new-kind","state":"ratified","textToken":"new-kind"}),
            ),
            (
                "hash-algorithms.json",
                serde_json::json!({"code":2,"name":"sha-next","state":"ratified"}),
            ),
            (
                "logical-record-types.json",
                serde_json::json!({"code":10,"name":"new-record","state":"ratified"}),
            ),
        ] {
            let mut files = owned_bundled();
            let file = files.iter_mut().find(|(file, _)| file == name).unwrap();
            let mut document = parse_canonical_json(&file.1).unwrap();
            let code = entry["code"].as_u64().unwrap();
            document["entries"].as_array_mut().unwrap().push(entry);
            document["unassigned"][0]["from"] = Value::from(code + 1);
            file.1 = canonical(&document);
            assert_eq!(
                load_owned(&files).unwrap_err().code,
                ErrorCode::RegistryInvalid,
                "{name}"
            );
        }

        let mut additive = owned_bundled();
        let file = additive
            .iter_mut()
            .find(|(name, _)| name == "required-features.json")
            .unwrap();
        let mut document = parse_canonical_json(&file.1).unwrap();
        document["entries"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "behavior":"validate the unchanged registered base kind semantics",
                "code":1,
                "name":"additive-feature",
                "state":"ratified"
            }));
        document["unassigned"][0]["from"] = Value::from(2);
        file.1 = canonical(&document);
        assert_eq!(
            load_owned(&additive)
                .unwrap()
                .required_feature(1)
                .unwrap()
                .name,
            "additive-feature"
        );
    }

    #[test]
    fn profile_states_follow_the_frozen_context_table() {
        let profile = |id, state| RegistryEntry {
            profile: ProfileRef::new("profile-state.test", id, 1).unwrap(),
            family: "path".to_owned(),
            state,
            production_write_allowed: state == RegistryState::Ratified,
        };
        let registry = Registry::load(
            [
                profile("conformance", RegistryState::ConformanceOnly),
                profile("deprecated", RegistryState::Deprecated),
                profile("ratified", RegistryState::Ratified),
                profile("reserved", RegistryState::Reserved),
            ],
            [],
        )
        .unwrap();
        let get = |id| ProfileRef::new("profile-state.test", id, 1).unwrap();

        assert_eq!(
            registry
                .check_profile(&get("conformance"), "path", Operation::Read)
                .unwrap_err()
                .code,
            ErrorCode::ProfileConformanceOnly
        );
        registry
            .check_profile(&get("conformance"), "path", Operation::ConformanceWrite)
            .unwrap();
        assert_eq!(
            registry
                .check_profile(&get("conformance"), "path", Operation::ProductionWrite)
                .unwrap_err()
                .code,
            ErrorCode::ProfileConformanceOnly
        );
        for operation in [Operation::Read, Operation::ConformanceWrite] {
            registry
                .check_profile(&get("deprecated"), "path", operation)
                .unwrap();
        }
        assert_eq!(
            registry
                .check_profile(&get("deprecated"), "path", Operation::ProductionWrite)
                .unwrap_err()
                .code,
            ErrorCode::ProfileStateForbidden
        );
        for operation in [
            Operation::Read,
            Operation::ConformanceWrite,
            Operation::ProductionWrite,
        ] {
            registry
                .check_profile(&get("ratified"), "path", operation)
                .unwrap();
            assert_eq!(
                registry
                    .check_profile(&get("reserved"), "path", operation)
                    .unwrap_err()
                    .code,
                ErrorCode::ProfileStateForbidden
            );
        }
    }

    #[test]
    fn assignment_lifecycle_table_has_all_twelve_operation_cases() {
        let cases = [
            (RegistryState::Ratified, Operation::Read, None),
            (RegistryState::Ratified, Operation::ConformanceWrite, None),
            (RegistryState::Ratified, Operation::ProductionWrite, None),
            (RegistryState::Deprecated, Operation::Read, None),
            (RegistryState::Deprecated, Operation::ConformanceWrite, None),
            (
                RegistryState::Deprecated,
                Operation::ProductionWrite,
                Some(ErrorCode::ProfileStateForbidden),
            ),
            (
                RegistryState::ConformanceOnly,
                Operation::Read,
                Some(ErrorCode::ProfileConformanceOnly),
            ),
            (
                RegistryState::ConformanceOnly,
                Operation::ConformanceWrite,
                None,
            ),
            (
                RegistryState::ConformanceOnly,
                Operation::ProductionWrite,
                Some(ErrorCode::ProfileConformanceOnly),
            ),
            (
                RegistryState::Reserved,
                Operation::Read,
                Some(ErrorCode::ProfileStateForbidden),
            ),
            (
                RegistryState::Reserved,
                Operation::ConformanceWrite,
                Some(ErrorCode::ProfileStateForbidden),
            ),
            (
                RegistryState::Reserved,
                Operation::ProductionWrite,
                Some(ErrorCode::ProfileStateForbidden),
            ),
        ];
        for (state, operation, expected) in cases {
            let mut registry = Registry::bundled().clone();
            registry.object_kinds.get_mut(&3).unwrap().state = state;
            let result = registry.check_assignment(RegistryAssignment::ObjectKind(3), operation);
            assert_eq!(result.err().map(|error| error.code), expected);
        }
    }

    #[test]
    fn every_selected_assignment_family_uses_the_shared_lifecycle_primitive() {
        let mut registry = Registry::bundled().clone();
        registry.features.insert(
            1,
            FeatureRegistryEntry {
                code: 1,
                name: "test-feature".to_owned(),
                state: RegistryState::Ratified,
            },
        );
        let extension = ProfileRef::new("extension.test", "known", 1).unwrap();
        registry.extensions.insert(
            extension.clone(),
            ExtensionRegistryEntry {
                profile: extension.clone(),
                state: RegistryState::Ratified,
            },
        );
        let profile = ProfileRef::new("path.test", "opaque", 1).unwrap();
        let assignments = [
            RegistryAssignment::ObjectKind(3),
            RegistryAssignment::HashAlgorithm(1),
            RegistryAssignment::CommonField(0),
            RegistryAssignment::KindField {
                cddl_rule: "tree",
                code: 16,
            },
            RegistryAssignment::EntryKind(1),
            RegistryAssignment::EntryMode(1),
            RegistryAssignment::RequiredFeature(1),
            RegistryAssignment::Extension(&extension),
            RegistryAssignment::Profile(&profile),
            RegistryAssignment::LogicalRecordType(1),
            RegistryAssignment::SemanticEnum {
                domain: "operation",
                code: 1,
            },
        ];
        for assignment in assignments {
            registry
                .check_assignment(assignment, Operation::ConformanceWrite)
                .unwrap();
        }
    }
}
