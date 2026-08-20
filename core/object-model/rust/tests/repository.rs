use std::{collections::BTreeMap, path::PathBuf, str::FromStr, thread, time::Duration};

use ogvcs_object_model::*;
use serde_json::Value;

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";
const REGISTRY_ROOT: &str = "../../../spec/repository-format/v1/registries";

fn scenario(id: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(format!("{VECTOR_ROOT}/scenarios/cases/{id}.json")).unwrap(),
    )
    .unwrap()
}

fn reference(value: &Value) -> ObjectRef {
    ObjectRef::from_str(value.as_str().unwrap()).unwrap()
}

fn cbor_field(value: &Cbor, wanted: u64) -> &Cbor {
    let Cbor::Map(fields) = value else {
        panic!("CBOR map")
    };
    &fields
        .iter()
        .find(|(key, _)| *key == Cbor::UInt(wanted))
        .unwrap()
        .1
}

fn uint_for_test(value: &Cbor) -> u64 {
    let Cbor::UInt(value) = value else {
        panic!("CBOR uint")
    };
    *value
}

fn replace_cbor_field(value: &mut Cbor, wanted: u64, replacement: Cbor) {
    let Cbor::Map(fields) = value else {
        panic!("CBOR map")
    };
    let field = fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(wanted))
        .unwrap();
    field.1 = replacement;
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut result = [0; N];
    for (slot, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("lowercase hex"),
        };
        *slot = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    result
}

fn file_id(value: &Value) -> FileId {
    FileId::from_str(&format!("fid:{}", value.as_str().unwrap())).unwrap()
}

fn load_lookup(document: &Value, limits: RepositoryLimits) -> RepositoryObjectLookup {
    try_load_lookup(document, limits).unwrap()
}

fn lookup_entries(document: &Value) -> BTreeMap<ObjectRef, Vec<u8>> {
    document["context"]["objectLookup"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let path = PathBuf::from(VECTOR_ROOT).join(entry["artifact"]["path"].as_str().unwrap());
            (reference(&entry["ref"]), std::fs::read(path).unwrap())
        })
        .collect()
}

fn decoded_entry(entries: &BTreeMap<ObjectRef, Vec<u8>>, reference: ObjectRef) -> Cbor {
    decode_canonical(entries.get(&reference).unwrap(), Limits::METADATA).unwrap()
}

fn encoded_entry(kind: ObjectKind, value: &Cbor) -> (ObjectRef, Vec<u8>) {
    let payload = encode_canonical(value).unwrap();
    (
        ObjectRef {
            kind,
            digest: object_id(kind, &payload).unwrap(),
        },
        payload,
    )
}

struct TestPathProfileValidator {
    profile: ProfileRef,
    case_mode: PathCaseMode,
    accepted: bool,
    constant_keys: bool,
    calls: std::cell::Cell<usize>,
}

impl TestPathProfileValidator {
    fn new(profile: ProfileRef, accepted: bool, constant_keys: bool) -> Self {
        Self {
            profile,
            case_mode: PathCaseMode::CaseSensitive,
            accepted,
            constant_keys,
            calls: std::cell::Cell::new(0),
        }
    }

    fn with_case_mode(mut self, case_mode: PathCaseMode) -> Self {
        self.case_mode = case_mode;
        self
    }
}

impl PathProfileValidator for TestPathProfileValidator {
    fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    fn case_mode(&self) -> PathCaseMode {
        self.case_mode
    }

    fn validate(&self, segments: &[String]) -> PathProfileDecision {
        self.calls.set(self.calls.get() + 1);
        if !self.accepted {
            return PathProfileDecision::rejected();
        }
        let key = if self.constant_keys {
            "same-key".to_owned()
        } else {
            segments.join("/")
        };
        PathProfileDecision::accepted(format!("repository:{key}"), format!("platform:{key}"))
    }
}

fn ratified_path_tree_lookup(two_entries: bool) -> (RepositoryObjectLookup, ObjectRef, ObjectRef) {
    let document = scenario("tree-path-profile");
    let mut entries = lookup_entries(&document);
    let old_descriptor = reference(&document["context"]["repositoryDescriptor"]);
    let mut descriptor = decoded_entry(&entries, old_descriptor);
    replace_cbor_field(
        &mut descriptor,
        17,
        ProfileRef::from_str("path.opengamevcs/portable@1")
            .unwrap()
            .to_cbor(),
    );
    let (descriptor, descriptor_payload) =
        encoded_entry(ObjectKind::RepositoryDescriptor, &descriptor);

    let old_tree = entries
        .keys()
        .copied()
        .find(|reference| reference.kind == ObjectKind::Tree)
        .unwrap();
    let mut tree = decoded_entry(&entries, old_tree);
    replace_cbor_field(&mut tree, 16, descriptor.to_cbor());
    if two_entries {
        let Cbor::Array(tree_entries) = cbor_field(&tree, 17) else {
            panic!("tree entries")
        };
        let mut additional = tree_entries[0].clone();
        replace_cbor_field(&mut additional, 0, Cbor::Text("another".to_owned()));
        replace_cbor_field(&mut additional, 2, Cbor::Bytes(vec![0x44; 16]));
        let Cbor::Map(fields) = &mut tree else {
            panic!("tree map")
        };
        let Cbor::Array(tree_entries) = &mut fields
            .iter_mut()
            .find(|(key, _)| *key == Cbor::UInt(17))
            .unwrap()
            .1
        else {
            panic!("tree entries")
        };
        tree_entries.insert(0, additional);
    }
    let (tree, tree_payload) = encoded_entry(ObjectKind::Tree, &tree);

    entries.remove(&old_descriptor);
    entries.remove(&old_tree);
    entries.insert(descriptor, descriptor_payload);
    entries.insert(tree, tree_payload);
    let lookup = RepositoryObjectLookup::new(
        entries,
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    (lookup, tree, descriptor)
}

fn ratified_empty_repository() -> (RepositoryObjectLookup, ObjectRef, ObjectRef) {
    let document = scenario("history-zero-parent-root");
    let entries = lookup_entries(&document);
    let old_descriptor = reference(&document["context"]["repositoryDescriptor"]);
    let old_tree = entries
        .keys()
        .copied()
        .find(|reference| reference.kind == ObjectKind::Tree)
        .unwrap();
    let old_change = entries
        .keys()
        .copied()
        .find(|reference| reference.kind == ObjectKind::ChangeSet)
        .unwrap();
    let old_snapshot = entries
        .keys()
        .copied()
        .find(|reference| reference.kind == ObjectKind::Snapshot)
        .unwrap();

    let mut descriptor_value = decoded_entry(&entries, old_descriptor);
    replace_cbor_field(
        &mut descriptor_value,
        17,
        ProfileRef::from_str("path.opengamevcs/portable@1")
            .unwrap()
            .to_cbor(),
    );
    let (descriptor, descriptor_payload) =
        encoded_entry(ObjectKind::RepositoryDescriptor, &descriptor_value);
    let mut tree_value = decoded_entry(&entries, old_tree);
    replace_cbor_field(&mut tree_value, 16, descriptor.to_cbor());
    let (tree, tree_payload) = encoded_entry(ObjectKind::Tree, &tree_value);
    let mut change_value = decoded_entry(&entries, old_change);
    replace_cbor_field(&mut change_value, 16, descriptor.to_cbor());
    let (change, change_payload) = encoded_entry(ObjectKind::ChangeSet, &change_value);
    let mut snapshot_value = decoded_entry(&entries, old_snapshot);
    replace_cbor_field(&mut snapshot_value, 16, descriptor.to_cbor());
    replace_cbor_field(&mut snapshot_value, 18, tree.to_cbor());
    replace_cbor_field(&mut snapshot_value, 19, change.to_cbor());
    let (snapshot, snapshot_payload) = encoded_entry(ObjectKind::Snapshot, &snapshot_value);

    let lookup = RepositoryObjectLookup::new(
        [
            (descriptor, descriptor_payload),
            (tree, tree_payload),
            (change, change_payload),
            (snapshot, snapshot_payload),
        ],
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    (lookup, snapshot, descriptor)
}

fn replace_array_reference(value: &mut Cbor, field_key: u64, old: ObjectRef, new: ObjectRef) {
    let Cbor::Array(values) = cbor_field(value, field_key) else {
        panic!("reference array")
    };
    let slot = values
        .iter()
        .position(|value| ObjectRef::from_cbor(value).unwrap() == old)
        .unwrap();
    let Cbor::Map(fields) = value else {
        panic!("CBOR map")
    };
    let Cbor::Array(values) = &mut fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(field_key))
        .unwrap()
        .1
    else {
        panic!("reference array")
    };
    values[slot] = new.to_cbor();
}

fn try_load_lookup(
    document: &Value,
    limits: RepositoryLimits,
) -> ogvcs_object_model::Result<RepositoryObjectLookup> {
    let entries = document["context"]["objectLookup"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let path = format!(
                "{VECTOR_ROOT}/{}",
                entry["artifact"]["path"].as_str().unwrap()
            );
            (reference(&entry["ref"]), std::fs::read(path).unwrap())
        })
        .collect::<Vec<_>>();
    RepositoryObjectLookup::new(
        entries,
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        limits,
    )
}

fn parse_lifetime(value: &Value) -> LifetimeRecord {
    LifetimeRecord {
        file_id: file_id(&value["fileId"]),
        origin: match value["origin"].as_str().unwrap() {
            "native-create" => LifetimeOrigin::NativeCreate,
            "native-copy" => LifetimeOrigin::NativeCopy,
            "import" => LifetimeOrigin::Import,
            _ => panic!("origin"),
        },
        first_change_set: reference(&value["firstChangeSet"]),
        first_operation: value["firstOperation"].as_u64().unwrap(),
        import_mapping_key: value
            .get("importMappingKey")
            .map(|value| hex(value.as_str().unwrap())),
    }
}

fn parse_mapping(value: &Value) -> ImportMapping {
    ImportMapping {
        descriptor: reference(&value["descriptor"]),
        importer_profile: ProfileRef::from_str(value["importerProfile"].as_str().unwrap()).unwrap(),
        source_namespace_digest: hex(value["sourceNamespaceDigest"].as_str().unwrap()),
        source_identity_digest: hex(value["sourceIdentityDigest"].as_str().unwrap()),
        file_id: file_id(&value["fileId"]),
        state: match value["state"].as_str().unwrap() {
            "reserved" => ImportState::Reserved,
            "materialized" => ImportState::Materialized,
            "published" => ImportState::Published,
            _ => panic!("state"),
        },
        declared_mapping_key: hex(value["mappingKey"].as_str().unwrap()),
    }
}

fn records(document: &Value, key: &str) -> Vec<LifetimeRecord> {
    document["context"][key]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_lifetime)
        .collect()
}

fn mappings(document: &Value) -> Vec<ImportMapping> {
    document["context"]["importMappings"]
        .as_array()
        .unwrap()
        .iter()
        .map(parse_mapping)
        .collect()
}

fn context<'a>(
    document: &Value,
    lookup: &'a RepositoryObjectLookup,
    lifetime_records: &'a [LifetimeRecord],
    working: &'a [LifetimeRecord],
    import_mappings: &'a [ImportMapping],
) -> RepositoryContext<'a> {
    let mut result = RepositoryContext::new(
        lookup,
        reference(&document["context"]["repositoryDescriptor"]),
        reference(&document["context"]["designatedRoot"]),
        PathCaseMode::CaseSensitive,
    );
    result.lifetime_records = lifetime_records;
    result.working_lifetime_additions = working;
    result.import_mappings = import_mappings;
    result
}

fn validate(id: &str) -> Result<RepositoryValidationSummary> {
    let document = scenario(id);
    let lookup = load_lookup(&document, RepositoryLimits::default());
    let lifetime = records(&document, "lifetimeRecords");
    let working = records(&document, "workingLifetimeAdditions");
    let import_mappings = mappings(&document);
    validate_repository_candidate(
        reference(&document["context"]["candidateSnapshot"]),
        &context(&document, &lookup, &lifetime, &working, &import_mappings),
    )
}

fn first_reference(document: &Value, kind: ObjectKind) -> ObjectRef {
    document["context"]["objectLookup"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| reference(&entry["ref"]))
        .find(|reference| reference.kind == kind)
        .unwrap()
}

fn operation_input(document: &Value) -> Value {
    let artifact = document["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|input| {
            input["path"]
                .as_str()
                .unwrap()
                .contains("scenarios/operations/")
        })
        .unwrap();
    serde_json::from_slice(
        &std::fs::read(PathBuf::from(VECTOR_ROOT).join(artifact["path"].as_str().unwrap()))
            .unwrap(),
    )
    .unwrap()
}

fn tree_object(
    descriptor: ObjectRef,
    child: Option<(String, FileId, ObjectRef)>,
) -> (ObjectRef, Vec<u8>) {
    let entries = child
        .map(|(name, file_id, target)| {
            vec![Cbor::Map(vec![
                (Cbor::UInt(0), Cbor::Text(name)),
                (Cbor::UInt(1), Cbor::UInt(1)),
                (Cbor::UInt(2), file_id.to_cbor()),
                (Cbor::UInt(3), Cbor::UInt(1)),
                (Cbor::UInt(4), target.to_cbor()),
                (Cbor::UInt(5), Cbor::UInt(0)),
                (
                    Cbor::UInt(6),
                    ProfileRef::from_str("content-policy.test/opaque@1")
                        .unwrap()
                        .to_cbor(),
                ),
            ])]
        })
        .unwrap_or_default();
    let payload = encode_canonical(&Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(3)),
        (Cbor::UInt(2), Cbor::Array(vec![])),
        (Cbor::UInt(16), descriptor.to_cbor()),
        (Cbor::UInt(17), Cbor::Array(entries)),
    ]))
    .unwrap();
    let reference = ObjectRef {
        kind: ObjectKind::Tree,
        digest: object_id(ObjectKind::Tree, &payload).unwrap(),
    };
    (reference, payload)
}

fn nested_tree_lookup(
    document: &Value,
    segments: usize,
    basename: &str,
) -> (RepositoryObjectLookup, ObjectRef) {
    let descriptor = reference(&document["context"]["repositoryDescriptor"]);
    let descriptor_item = document["context"]["objectLookup"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| reference(&entry["ref"]) == descriptor)
        .unwrap();
    let descriptor_payload = std::fs::read(
        PathBuf::from(VECTOR_ROOT).join(descriptor_item["artifact"]["path"].as_str().unwrap()),
    )
    .unwrap();
    let (mut child, leaf_payload) = tree_object(descriptor, None);
    let mut entries = vec![(descriptor, descriptor_payload), (child, leaf_payload)];
    for index in (0..segments).rev() {
        let mut raw_file_id = [0u8; 16];
        raw_file_id[..8].copy_from_slice(&((index + 1) as u64).to_be_bytes());
        let (parent, payload) = tree_object(
            descriptor,
            Some((
                basename.to_owned(),
                FileId::new(raw_file_id).unwrap(),
                child,
            )),
        );
        entries.push((parent, payload));
        child = parent;
    }
    (
        RepositoryObjectLookup::new(
            entries,
            Registry::load_directory(REGISTRY_ROOT).unwrap(),
            ValidationMode::Conformance,
            RepositoryLimits::default(),
        )
        .unwrap(),
        child,
    )
}

#[test]
fn lookup_manifest_and_tree_are_identity_checked_and_bounded() {
    let document = scenario("transition-create");
    let lookup = load_lookup(&document, RepositoryLimits::default());
    lookup.validate_all().unwrap();
    assert_eq!(
        lookup.len(),
        document["context"]["objectLookup"]
            .as_array()
            .unwrap()
            .len()
    );

    let snapshot = lookup
        .resolve_expected(
            reference(&document["context"]["candidateSnapshot"]),
            ObjectKind::Snapshot,
        )
        .unwrap();
    let snapshot = snapshot.value.unwrap();
    let Cbor::Map(fields) = &*snapshot else {
        panic!("snapshot map")
    };
    let root = ObjectRef::from_cbor(
        &fields
            .iter()
            .find(|(key, _)| *key == Cbor::UInt(18))
            .unwrap()
            .1,
    )
    .unwrap();
    let expanded = expand_tree(
        root,
        &lookup,
        reference(&document["context"]["repositoryDescriptor"]),
        true,
        PathCaseMode::CaseSensitive,
    )
    .unwrap();
    assert_eq!(expanded.entries.len(), 1);
    assert_eq!(expanded.file_ids.len(), 1);

    let missing = ObjectRef::from_str(
        "ogvcs:v1:tree:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .unwrap();
    assert_eq!(
        lookup.resolve(missing).unwrap_err().code,
        ErrorCode::ObjectReferenceMissing
    );

    let bounded = try_load_lookup(
        &document,
        RepositoryLimits {
            max_objects: 0,
            ..RepositoryLimits::default()
        },
    );
    assert_eq!(bounded.err().unwrap().code, ErrorCode::LimitCount);

    let chunk_bounded = load_lookup(
        &document,
        RepositoryLimits {
            max_chunk_bytes: 0,
            ..RepositoryLimits::default()
        },
    );
    assert_eq!(
        chunk_bounded
            .resolve(first_reference(&document, ObjectKind::Chunk))
            .unwrap_err()
            .code,
        ErrorCode::LimitChunkBytes
    );

    for (segments, basename) in [(257, "x".to_owned()), (17, "x".repeat(255))] {
        let (nested_lookup, root) = nested_tree_lookup(&document, segments, &basename);
        assert_eq!(
            expand_tree(
                root,
                &nested_lookup,
                reference(&document["context"]["repositoryDescriptor"]),
                false,
                PathCaseMode::CaseSensitive,
            )
            .unwrap_err()
            .code,
            ErrorCode::PathCoreInvalid
        );
    }
}

#[test]
fn lookup_finishes_layer_one_and_ranks_schema_across_all_entries() {
    let mut manifest = decode_canonical(
        &std::fs::read(format!("{VECTOR_ROOT}/objects/02-content-manifest.cbor")).unwrap(),
        Limits::METADATA,
    )
    .unwrap();
    let Cbor::Map(manifest_fields) = &mut manifest else {
        panic!("manifest map")
    };
    manifest_fields.push((Cbor::UInt(4095), Cbor::Bool(true)));
    let (manifest_ref, manifest_payload) = encoded_entry(ObjectKind::ContentManifest, &manifest);

    let tree_payload = std::fs::read(format!("{VECTOR_ROOT}/objects/03-tree.cbor")).unwrap();
    let mut invalid_tree = decode_canonical(&tree_payload, Limits::METADATA).unwrap();
    let Cbor::Array(entries) = cbor_field(&invalid_tree, 17) else {
        panic!("tree entries")
    };
    let first = entries[0].clone();
    let Cbor::Map(fields) = &mut invalid_tree else {
        panic!("tree map")
    };
    let Cbor::Array(entries) = &mut fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(17))
        .unwrap()
        .1
    else {
        panic!("tree entries")
    };
    entries[0] = first;
    replace_cbor_field(&mut entries[0], 1, Cbor::Bool(false));
    let (invalid_tree_ref, invalid_tree_payload) = encoded_entry(ObjectKind::Tree, &invalid_tree);

    let registry = Registry::load_directory(REGISTRY_ROOT).unwrap();
    let lookup = RepositoryObjectLookup::new(
        [
            (manifest_ref, manifest_payload.clone()),
            (invalid_tree_ref, invalid_tree_payload),
        ],
        registry.clone(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let error = lookup.validate_all().unwrap_err();
    assert_eq!(
        (error.code, error.layer),
        (ErrorCode::SchemaFieldInvalid, 2)
    );

    let wrong_tree_ref = ObjectRef {
        kind: ObjectKind::Tree,
        digest: [0; 32],
    };
    let lookup = RepositoryObjectLookup::new(
        [
            (manifest_ref, manifest_payload.clone()),
            (wrong_tree_ref, tree_payload),
        ],
        registry,
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let error = lookup.validate_all().unwrap_err();
    assert_eq!((error.code, error.layer), (ErrorCode::ObjectIdMismatch, 1));

    let mut conflict = decode_canonical(
        &std::fs::read(format!("{VECTOR_ROOT}/objects/11-conflict-set.cbor")).unwrap(),
        Limits::METADATA,
    )
    .unwrap();
    let Cbor::Map(conflict_fields) = &mut conflict else {
        panic!("conflict-set map")
    };
    let Cbor::Array(records) = &mut conflict_fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(17))
        .unwrap()
        .1
    else {
        panic!("conflict records")
    };
    let Cbor::Map(record) = &mut records[0] else {
        panic!("conflict record")
    };
    let Cbor::Bytes(declared_id) = &mut record
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(0))
        .unwrap()
        .1
    else {
        panic!("conflict id")
    };
    declared_id[0] ^= 1;
    let (conflict_ref, conflict_payload) = encoded_entry(ObjectKind::ConflictSet, &conflict);
    let lookup = RepositoryObjectLookup::new(
        [
            (manifest_ref, manifest_payload),
            (conflict_ref, conflict_payload),
        ],
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let error = lookup.validate_all().unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::ConflictIdMismatch,
            2,
            ValidationStage::DeclaredIdentity
        )
    );
}

#[test]
fn duplicate_lookup_entries_are_counted_and_deadline_checked_before_coalescing() {
    let payload = std::fs::read(format!("{VECTOR_ROOT}/objects/01-chunk.bin")).unwrap();
    let reference = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: object_id(ObjectKind::Chunk, &payload).unwrap(),
    };
    let limits = RepositoryLimits {
        max_objects: 2,
        ..RepositoryLimits::default()
    };
    let error = RepositoryObjectLookup::new(
        std::iter::repeat_n((reference, payload.clone()), 3),
        Registry::bundled(),
        ValidationMode::Conformance,
        limits,
    )
    .err()
    .unwrap();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::LimitCount,
            1,
            ValidationStage::ConfiguredResourcePreflight
        )
    );

    let mut supplied = 0usize;
    let delayed_duplicate = std::iter::from_fn(move || {
        if supplied == 2 {
            return None;
        }
        if supplied == 1 {
            thread::sleep(Duration::from_millis(20));
        }
        supplied += 1;
        Some((reference, payload.clone()))
    });
    let limits = RepositoryLimits {
        max_time: Some(Duration::from_millis(5)),
        ..RepositoryLimits::default()
    };
    let error = RepositoryObjectLookup::new(
        delayed_duplicate,
        Registry::bundled(),
        ValidationMode::Conformance,
        limits,
    )
    .err()
    .unwrap();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::LimitTime,
            1,
            ValidationStage::ConfiguredResourcePreflight
        )
    );
}

#[test]
fn repository_lookup_separates_explicit_layer_two_from_semantic_authority() {
    let unread = std::iter::from_fn(|| -> Option<(ObjectRef, Vec<u8>)> {
        panic!("authority must be rejected before consuming repository objects")
    });
    let partial = Registry::load([], []).unwrap();
    let error = RepositoryObjectLookup::new(
        unread,
        partial,
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .err()
    .unwrap();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            1,
            ValidationStage::ConfiguredResourcePreflight,
        )
    );

    let error = RepositoryObjectLookup::new(
        std::iter::empty(),
        Registry::bundled(),
        ValidationMode::Read,
        RepositoryLimits::default(),
    )
    .err()
    .unwrap();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            1,
            ValidationStage::ConfiguredResourcePreflight,
        )
    );

    let layer_two =
        RepositoryObjectLookup::new_layer2(std::iter::empty(), RepositoryLimits::default())
            .unwrap();
    layer_two.validate_all().unwrap();
    let missing = ObjectRef {
        kind: ObjectKind::ContentManifest,
        digest: [0; 32],
    };
    let error = verify_manifest(missing, &layer_two).unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            1,
            ValidationStage::ConfiguredResourcePreflight,
        )
    );
}

#[test]
fn compact_lookup_metadata_is_decoded_only_within_remaining_memory() {
    let payload = encode_canonical_with_limits(
        &Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(6)),
            (Cbor::UInt(2), Cbor::Array(Vec::new())),
            (Cbor::UInt(4_095), Cbor::Array(vec![Cbor::UInt(0); 1_000])),
        ]),
        Limits::METADATA,
    )
    .unwrap();
    let reference = ObjectRef {
        kind: ObjectKind::RepositoryDescriptor,
        digest: object_id(ObjectKind::RepositoryDescriptor, &payload).unwrap(),
    };
    let validate_all_lookup = RepositoryObjectLookup::new(
        [(reference, payload.clone())],
        Registry::bundled(),
        ValidationMode::Conformance,
        RepositoryLimits {
            max_memory_bytes: 60_000,
            ..RepositoryLimits::default()
        },
    )
    .unwrap();
    let retained_input = validate_all_lookup.resource_summary().retained_bytes;
    let error = validate_all_lookup.validate_all().unwrap_err();
    assert_eq!((error.code, error.layer), (ErrorCode::LimitMemory, 1));
    assert_eq!(
        validate_all_lookup.resource_summary().retained_bytes,
        retained_input
    );

    let lookup = RepositoryObjectLookup::new(
        [(reference, payload.clone())],
        Registry::bundled(),
        ValidationMode::Conformance,
        RepositoryLimits {
            max_memory_bytes: 60_000,
            ..RepositoryLimits::default()
        },
    )
    .unwrap();
    let retained_input = lookup.resource_summary().retained_bytes;
    let error = lookup.resolve(reference).unwrap_err();
    assert_eq!((error.code, error.layer), (ErrorCode::LimitMemory, 1));
    assert_eq!(lookup.resource_summary().retained_bytes, retained_input);

    let roomy = RepositoryObjectLookup::new(
        [(reference, payload)],
        Registry::bundled(),
        ValidationMode::Conformance,
        RepositoryLimits {
            max_memory_bytes: 100_000,
            ..RepositoryLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        roomy.resolve(reference).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );
}

#[test]
fn lookup_working_memory_reservation_is_scoped() {
    let lookup = RepositoryObjectLookup::new(
        [],
        Registry::bundled(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let baseline = lookup.resource_summary();
    {
        let _reservation = lookup.reserve_working_memory(1).unwrap();
        assert_eq!(
            lookup.resource_summary().retained_bytes,
            baseline.retained_bytes + 1
        );
    }
    assert_eq!(lookup.resource_summary(), baseline);

    let constrained = RepositoryObjectLookup::new(
        [],
        Registry::bundled(),
        ValidationMode::Conformance,
        RepositoryLimits {
            max_memory_bytes: 0,
            ..RepositoryLimits::default()
        },
    )
    .unwrap();
    let constrained_baseline = constrained.resource_summary();
    assert_eq!(
        constrained.reserve_working_memory(1).err().unwrap().code,
        ErrorCode::LimitMemory
    );
    assert_eq!(constrained.resource_summary(), constrained_baseline);
}

#[test]
fn tree_expansion_releases_public_output_accounting_but_bounds_internal_construction() {
    let document = scenario("transition-create");
    let descriptor = reference(&document["context"]["repositoryDescriptor"]);

    let probe = load_lookup(&document, RepositoryLimits::default());
    probe.validate_all().unwrap();
    let candidate = reference(&document["context"]["candidateSnapshot"]);
    let snapshot = probe
        .resolve_expected(candidate, ObjectKind::Snapshot)
        .unwrap();
    let tree = ObjectRef::from_cbor(cbor_field(snapshot.value.as_deref().unwrap(), 18)).unwrap();
    let before = probe.resource_summary().retained_bytes;
    let expanded =
        expand_tree(tree, &probe, descriptor, false, PathCaseMode::CaseSensitive).unwrap();
    assert!(!expanded.entries.is_empty());
    assert_eq!(probe.resource_summary().retained_bytes, before);
    let second = expand_tree(tree, &probe, descriptor, false, PathCaseMode::CaseSensitive).unwrap();
    assert_eq!(second.entries, expanded.entries);
    assert_eq!(probe.resource_summary().retained_bytes, before);

    let constrained = load_lookup(
        &document,
        RepositoryLimits {
            max_memory_bytes: before + 511,
            max_scratch_bytes: usize::MAX,
            ..RepositoryLimits::default()
        },
    );
    constrained.validate_all().unwrap();
    let error = expand_tree(
        tree,
        &constrained,
        descriptor,
        false,
        PathCaseMode::CaseSensitive,
    )
    .unwrap_err();
    assert_eq!((error.code, error.layer), (ErrorCode::LimitMemory, 1));
}

#[test]
fn expand_tree_dispatches_the_descriptor_path_profile_on_complete_paths() {
    let document = scenario("tree-path-profile");
    let lookup = load_lookup(&document, RepositoryLimits::default());
    let error = expand_tree(
        first_reference(&document, ObjectKind::Tree),
        &lookup,
        reference(&document["context"]["repositoryDescriptor"]),
        false,
        PathCaseMode::CaseSensitive,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PathProfileInvalid);
    assert_eq!(error.layer, 3);

    let profile = ProfileRef::from_str("path.test/reject-reserved@1").unwrap();
    let validator = TestPathProfileValidator::new(profile, true, false);
    let error = expand_tree_with_path_profile_validator(
        first_reference(&document, ObjectKind::Tree),
        &lookup,
        reference(&document["context"]["repositoryDescriptor"]),
        false,
        PathCaseMode::CaseSensitive,
        Some(&validator),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PathProfileInvalid);
    assert_eq!(validator.calls.get(), 0);

    let production = RepositoryObjectLookup::new(
        lookup_entries(&document),
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Production,
        RepositoryLimits::default(),
    )
    .unwrap();
    assert_eq!(
        expand_tree(
            first_reference(&document, ObjectKind::Tree),
            &production,
            reference(&document["context"]["repositoryDescriptor"]),
            false,
            PathCaseMode::CaseSensitive,
        )
        .unwrap_err()
        .code,
        ErrorCode::ProfileConformanceOnly
    );
}

#[test]
fn ratified_path_profiles_require_an_exact_pinned_validator() {
    let (lookup, tree, descriptor) = ratified_path_tree_lookup(false);
    let absent = expand_tree(
        tree,
        &lookup,
        descriptor,
        false,
        PathCaseMode::CaseSensitive,
    )
    .unwrap_err();
    assert_eq!(
        (absent.code, absent.layer, absent.stage),
        (
            ErrorCode::PathProfileInvalid,
            3,
            ValidationStage::RepositorySemantics
        )
    );

    let mismatched = TestPathProfileValidator::new(
        ProfileRef::from_str("path.opengamevcs/linux@1").unwrap(),
        true,
        false,
    );
    assert_eq!(
        expand_tree_with_path_profile_validator(
            tree,
            &lookup,
            descriptor,
            false,
            PathCaseMode::CaseSensitive,
            Some(&mismatched),
        )
        .unwrap_err()
        .code,
        ErrorCode::PathProfileInvalid
    );
    assert_eq!(mismatched.calls.get(), 0);

    let profile = ProfileRef::from_str("path.opengamevcs/portable@1").unwrap();
    let wrong_mode = TestPathProfileValidator::new(profile.clone(), true, false);
    assert_eq!(
        expand_tree_with_path_profile_validator(
            tree,
            &lookup,
            descriptor,
            false,
            PathCaseMode::CaseFolded,
            Some(&wrong_mode),
        )
        .unwrap_err()
        .code,
        ErrorCode::PathProfileInvalid
    );
    assert_eq!(wrong_mode.calls.get(), 0);

    let rejected = TestPathProfileValidator::new(profile.clone(), false, false);
    assert_eq!(
        expand_tree_with_path_profile_validator(
            tree,
            &lookup,
            descriptor,
            false,
            PathCaseMode::CaseSensitive,
            Some(&rejected),
        )
        .unwrap_err()
        .code,
        ErrorCode::PathProfileInvalid
    );
    assert_eq!(rejected.calls.get(), 1);

    let accepted = TestPathProfileValidator::new(profile, true, false);
    let expanded = expand_tree_with_path_profile_validator(
        tree,
        &lookup,
        descriptor,
        false,
        PathCaseMode::CaseSensitive,
        Some(&accepted),
    )
    .unwrap();
    assert_eq!(expanded.entries.len(), 1);
    assert_eq!(accepted.calls.get(), 1);
}

#[test]
fn ratified_path_profile_collision_keys_are_bounded_and_unique() {
    let (lookup, tree, descriptor) = ratified_path_tree_lookup(true);
    let validator = TestPathProfileValidator::new(
        ProfileRef::from_str("path.opengamevcs/portable@1").unwrap(),
        true,
        true,
    );
    let error = expand_tree_with_path_profile_validator(
        tree,
        &lookup,
        descriptor,
        false,
        PathCaseMode::CaseSensitive,
        Some(&validator),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::PathProfileInvalid,
            3,
            ValidationStage::RepositorySemantics
        )
    );
    assert_eq!(validator.calls.get(), 2);
}

#[test]
fn repository_candidate_propagates_the_ratified_path_profile_validator() {
    let (lookup, candidate, descriptor) = ratified_empty_repository();
    let context =
        RepositoryContext::new(&lookup, descriptor, candidate, PathCaseMode::CaseSensitive);
    assert_eq!(
        validate_repository_candidate(candidate, &context)
            .unwrap_err()
            .code,
        ErrorCode::PathProfileInvalid
    );

    let validator = TestPathProfileValidator::new(
        ProfileRef::from_str("path.opengamevcs/portable@1").unwrap(),
        true,
        false,
    );
    let context = RepositoryContext {
        path_profile_validator: Some(&validator),
        path_case_mode: PathCaseMode::CaseSensitive,
        ..RepositoryContext::new(&lookup, descriptor, candidate, PathCaseMode::CaseSensitive)
    };
    let summary = validate_repository_candidate(candidate, &context).unwrap();
    assert_eq!((summary.entries, summary.groups), (0, 0));
    // Empty trees still require an exact adapter pin, but have no composed
    // path on which to invoke it.
    assert_eq!(validator.calls.get(), 0);
}

#[test]
fn semantic_object_validation_preserves_layer_two_precedence() {
    let registry = Registry::bundled();
    let malformed = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(2)),
        (
            Cbor::UInt(2),
            Cbor::Array(vec![Cbor::UInt(u32::MAX as u64)]),
        ),
    ]);
    let payload = encode_canonical(&malformed).unwrap();
    let scanned = scan_metadata(&payload, Limits::METADATA).unwrap();
    assert_eq!(
        validate_semantic_object(&scanned, &registry, ValidationMode::Conformance)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );

    let descriptor = std::fs::read(format!(
        "{VECTOR_ROOT}/objects/06-repository-descriptor.cbor"
    ))
    .unwrap();
    let descriptor = scan_metadata(&descriptor, Limits::METADATA).unwrap();
    assert_eq!(
        validate_semantic_object(&descriptor, &registry, ValidationMode::Conformance).unwrap(),
        SemanticObjectValidation {
            kind: ObjectKind::RepositoryDescriptor,
            highest_layer: 3,
        }
    );

    let reference = ObjectRef {
        kind: ObjectKind::ContentManifest,
        digest: object_id(ObjectKind::ContentManifest, &payload).unwrap(),
    };
    let lookup = RepositoryObjectLookup::new(
        [(reference, payload)],
        registry,
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    assert_eq!(
        lookup.resolve(reference).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );
}

#[test]
fn exact_operation_families_replay_to_declared_roots() {
    for id in [
        "transition-create",
        "transition-modify",
        "transition-copy",
        "transition-move",
        "transition-rename",
        "transition-delete",
        "transition-restore",
        "transition-group-create",
        "transition-group-update",
        "transition-group-delete",
        "transition-merge-resolution",
    ] {
        let result = validate(id).unwrap_or_else(|error| panic!("{id}: {}", error.code.as_str()));
        assert_eq!(result.highest_layer, 3, "{id}");
    }
}

#[test]
fn manifest_tree_and_history_failures_keep_their_semantic_codes() {
    for (id, code) in [
        (
            "manifest-chunk-length",
            ErrorCode::ManifestChunkLengthInvalid,
        ),
        (
            "manifest-length-sum-mismatch",
            ErrorCode::ManifestLengthMismatch,
        ),
        (
            "manifest-corrupt-chunk",
            ErrorCode::ManifestFileDigestMismatch,
        ),
    ] {
        let document = scenario(id);
        let lookup = load_lookup(&document, RepositoryLimits::default());
        let error = verify_manifest(
            first_reference(&document, ObjectKind::ContentManifest),
            &lookup,
        )
        .unwrap_err();
        assert_eq!(error.code, code, "{id}");
        if code == ErrorCode::ManifestLengthMismatch {
            assert_eq!(
                (error.layer, error.stage),
                (2, ValidationStage::KnownSchema),
                "{id}"
            );
        }
    }
    let duplicate = scenario("fileid-duplicate-expanded-tree");
    let duplicate_lookup = load_lookup(&duplicate, RepositoryLimits::default());
    assert_eq!(
        expand_tree(
            first_reference(&duplicate, ObjectKind::Tree),
            &duplicate_lookup,
            reference(&duplicate["context"]["repositoryDescriptor"]),
            true,
            PathCaseMode::CaseSensitive,
        )
        .unwrap_err()
        .code,
        ErrorCode::FileIdDuplicateInTree
    );
    for (id, code) in [
        ("history-base-mismatch", ErrorCode::ChangeSetBaseMismatch),
        ("history-second-root", ErrorCode::SnapshotRootInvalid),
        ("history-missing-parent", ErrorCode::ObjectReferenceMissing),
        (
            "history-cross-repository-parent",
            ErrorCode::SnapshotParentCrossRepository,
        ),
    ] {
        let error = validate(id).unwrap_err();
        assert_eq!(error.code, code, "{id}");
        if code == ErrorCode::ChangeSetSequenceInvalid {
            assert_eq!(
                (error.layer, error.stage),
                (2, ValidationStage::KnownSchema),
                "{id}"
            );
        }
    }
    validate("provenance-acyclic").unwrap();
}

#[test]
fn later_missing_manifest_chunk_outranks_earlier_raw_length_disagreement() {
    let chunk_payload = std::fs::read(format!("{VECTOR_ROOT}/objects/01-chunk.bin")).unwrap();
    let existing_chunk = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: object_id(ObjectKind::Chunk, &chunk_payload).unwrap(),
    };
    let missing_chunk = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: [0xff; 32],
    };
    let mut manifest = decode_canonical(
        &std::fs::read(format!("{VECTOR_ROOT}/objects/02-content-manifest.cbor")).unwrap(),
        Limits::METADATA,
    )
    .unwrap();
    replace_cbor_field(&mut manifest, 16, Cbor::UInt(24));
    replace_cbor_field(
        &mut manifest,
        19,
        Cbor::Array(vec![
            Cbor::Map(vec![
                (Cbor::UInt(0), existing_chunk.to_cbor()),
                (Cbor::UInt(1), Cbor::UInt(11)),
            ]),
            Cbor::Map(vec![
                (Cbor::UInt(0), missing_chunk.to_cbor()),
                (Cbor::UInt(1), Cbor::UInt(13)),
            ]),
        ]),
    );
    let (manifest_ref, manifest_payload) = encoded_entry(ObjectKind::ContentManifest, &manifest);
    let lookup = RepositoryObjectLookup::new(
        [
            (existing_chunk, chunk_payload),
            (manifest_ref, manifest_payload),
        ],
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let error = verify_manifest(manifest_ref, &lookup).unwrap_err();
    assert_eq!(
        (error.code, error.layer),
        (ErrorCode::ObjectReferenceMissing, 2)
    );
}

#[test]
fn import_retry_conflict_and_native_collision_are_deterministic() {
    for (id, expected) in [
        ("fileid-import-lost-ack-retry", None),
        (
            "fileid-import-conflict",
            Some(ErrorCode::FileIdImportMappingConflict),
        ),
        (
            "fileid-import-native-collision",
            Some(ErrorCode::FileIdImportMappingConflict),
        ),
    ] {
        let document = scenario(id);
        let lookup = load_lookup(&document, RepositoryLimits::default());
        let lifetime = records(&document, "lifetimeRecords");
        let working = records(&document, "workingLifetimeAdditions");
        let imported = mappings(&document);
        let mut context = RepositoryContext::new(
            &lookup,
            reference(&document["context"]["repositoryDescriptor"]),
            first_reference(&document, ObjectKind::Snapshot),
            PathCaseMode::CaseSensitive,
        );
        context.lifetime_records = &lifetime;
        context.working_lifetime_additions = &working;
        context.import_mappings = &imported;
        let input = operation_input(&document);
        let request = ImportRequest {
            importer_profile: ProfileRef::from_str(input["importerProfile"].as_str().unwrap())
                .unwrap(),
            source_namespace_digest: hex(input["sourceNamespaceDigest"].as_str().unwrap()),
            source_identity_digest: hex(input["sourceIdentityDigest"].as_str().unwrap()),
            requested_file_id: file_id(&input["requestedFileId"]),
        };
        match expected {
            Some(code) => assert_eq!(
                validate_import_request(&context, &request)
                    .unwrap_err()
                    .code,
                code,
                "{id}"
            ),
            None => {
                let decision = validate_import_request(&context, &request).unwrap();
                assert!(decision.retry);
                assert_eq!(decision.state, ImportState::Materialized);
                validate_lifetime_and_imports(&context, lifetime[0].first_change_set, &[], None)
                    .unwrap();
            }
        }
    }

    let document = scenario("fileid-import-lost-ack-retry");
    let lookup = load_lookup(&document, RepositoryLimits::default());
    let lifetime = records(&document, "lifetimeRecords");
    let working = records(&document, "workingLifetimeAdditions");
    let imported = mappings(&document);
    let mut context = RepositoryContext::new(
        &lookup,
        reference(&document["context"]["repositoryDescriptor"]),
        first_reference(&document, ObjectKind::Snapshot),
        PathCaseMode::CaseSensitive,
    );
    context.lifetime_records = &lifetime;
    context.working_lifetime_additions = &working;
    context.import_mappings = &imported;
    let replayed = replay_change_set(
        lifetime[0].first_change_set,
        &RepositoryState::default(),
        &context,
        None,
    )
    .unwrap();
    assert_eq!(replayed.allocations.len(), 1);
    assert_eq!(replayed.state.entries.len(), 1);
    assert!(replayed
        .state
        .entries
        .values()
        .any(|entry| entry.file_id == lifetime[0].file_id));

    let duplicated = vec![imported[0].clone(), imported[0].clone()];
    context.import_mappings = &duplicated;
    let input = operation_input(&document);
    let mut request = ImportRequest {
        importer_profile: ProfileRef::from_str(input["importerProfile"].as_str().unwrap()).unwrap(),
        source_namespace_digest: hex(input["sourceNamespaceDigest"].as_str().unwrap()),
        source_identity_digest: hex(input["sourceIdentityDigest"].as_str().unwrap()),
        requested_file_id: file_id(&input["requestedFileId"]),
    };
    assert_eq!(
        validate_import_request(&context, &request)
            .unwrap_err()
            .code,
        ErrorCode::FileIdImportMappingConflict
    );
    context.import_mappings = &imported;
    request.importer_profile = ProfileRef::from_str("content-policy.test/opaque@1").unwrap();
    assert_eq!(
        validate_import_request(&context, &request)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );

    let in_flight_document = scenario("transition-create");
    let in_flight_lookup = load_lookup(&in_flight_document, RepositoryLimits::default());
    let in_flight_working = records(&in_flight_document, "workingLifetimeAdditions");
    assert_eq!(in_flight_working.len(), 1);
    let mut in_flight_context = RepositoryContext::new(
        &in_flight_lookup,
        reference(&in_flight_document["context"]["repositoryDescriptor"]),
        first_reference(&in_flight_document, ObjectKind::Snapshot),
        PathCaseMode::CaseSensitive,
    );
    in_flight_context.working_lifetime_additions = &in_flight_working;
    let mut unrelated = ImportRequest {
        importer_profile: ProfileRef::from_str("importer.test/fixture-adapter@1").unwrap(),
        source_namespace_digest: [0x71; 32],
        source_identity_digest: [0x72; 32],
        requested_file_id: FileId::new([0x73; 16]).unwrap(),
    };
    let decision = validate_import_request(&in_flight_context, &unrelated).unwrap();
    assert!(!decision.retry);
    assert_eq!(decision.file_id, unrelated.requested_file_id);
    unrelated.requested_file_id = in_flight_working[0].file_id;
    assert_eq!(
        validate_import_request(&in_flight_context, &unrelated)
            .unwrap_err()
            .code,
        ErrorCode::FileIdImportMappingConflict
    );
    unrelated.requested_file_id = FileId::new([0x73; 16]).unwrap();
    let duplicated_working = vec![in_flight_working[0].clone(), in_flight_working[0].clone()];
    in_flight_context.working_lifetime_additions = &duplicated_working;
    assert_eq!(
        validate_import_request(&in_flight_context, &unrelated)
            .unwrap_err()
            .code,
        ErrorCode::FileIdLifetimeEvidenceInvalid
    );
}

#[test]
fn asset_group_membership_roles_and_unique_keys_are_profile_checked() {
    for (id, code) in [
        ("group-member-invalid", ErrorCode::GroupMemberInvalid),
        (
            "group-membership-overlap",
            ErrorCode::GroupMembershipOverlap,
        ),
        (
            "group-required-role-missing",
            ErrorCode::GroupRequiredRoleMissing,
        ),
        (
            "group-external-key-duplicate",
            ErrorCode::GroupExternalKeyDuplicate,
        ),
    ] {
        assert_eq!(validate(id).unwrap_err().code, code, "{id}");
    }
}

#[test]
fn replay_failures_return_the_normative_codes() {
    for (id, code) in [
        (
            "transition-sequence-gap",
            ErrorCode::ChangeSetSequenceInvalid,
        ),
        (
            "fileid-move-source-forgery",
            ErrorCode::FileIdSourceMismatch,
        ),
        (
            "transition-exact-result-mismatch",
            ErrorCode::ChangeSetResultMismatch,
        ),
        (
            "fileid-restore-invalid-ancestry",
            ErrorCode::FileIdRestoreProofInvalid,
        ),
        (
            "fileid-restore-source-forgery",
            ErrorCode::FileIdRestoreProofInvalid,
        ),
        ("fileid-create-reuse", ErrorCode::FileIdAlreadyConsumed),
        ("fileid-copy-reuse", ErrorCode::FileIdAlreadyConsumed),
        (
            "fileid-cross-repository-proof",
            ErrorCode::FileIdCrossRepositoryProof,
        ),
    ] {
        assert_eq!(validate(id).unwrap_err().code, code, "{id}");
    }

    for id in ["transition-modify", "transition-delete"] {
        let document = scenario(id);
        let lookup = load_lookup(&document, RepositoryLimits::default());
        let working = records(&document, "workingLifetimeAdditions");
        let imported = mappings(&document);
        assert_eq!(
            validate_repository_candidate(
                reference(&document["context"]["candidateSnapshot"]),
                &context(&document, &lookup, &[], &working, &imported),
            )
            .unwrap_err()
            .code,
            ErrorCode::FileIdLifetimeEvidenceInvalid,
            "{id}"
        );
    }
}

#[test]
fn conflict_subjects_and_resolutions_are_mechanical_and_code_five_is_reserved() {
    for id in [
        "conflict-content-resolved",
        "conflict-divergent-move-resolved",
        "conflict-delete-modify-resolved",
        "conflict-type-resolved",
        "conflict-policy-resolved",
        "conflict-group-resolved",
        "conflict-path-collision-resolved",
        "conflict-choice-base",
        "conflict-choice-left",
        "conflict-choice-right",
        "conflict-choice-delete",
        "conflict-choice-custom",
        "conflict-custom-driver",
    ] {
        validate(id).unwrap_or_else(|error| panic!("{id}: {}", error.code.as_str()));
    }
    for (id, code) in [
        (
            "conflict-unresolved-published",
            ErrorCode::ConflictUnresolvedPublished,
        ),
        (
            "conflict-resolution-mismatch",
            ErrorCode::ConflictResolutionMismatch,
        ),
    ] {
        assert_eq!(validate(id).unwrap_err().code, code, "{id}");
    }
    let reserved = scenario("conflict-mode-resolved");
    let lookup = load_lookup(&reserved, RepositoryLimits::default());
    assert_eq!(
        lookup.validate_all().unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );
}

#[test]
fn history_shelves_provenance_and_abstract_cycles_are_bounded() {
    for id in [
        "history-zero-parent-root",
        "history-one-parent",
        "history-two-parent",
        "history-eight-parent",
    ] {
        let document = scenario(id);
        let lookup = load_lookup(&document, RepositoryLimits::default());
        let lifetime = records(&document, "lifetimeRecords");
        let working = records(&document, "workingLifetimeAdditions");
        let imported = mappings(&document);
        let context = context(&document, &lookup, &lifetime, &working, &imported);
        assert!(!validate_snapshot_graph(
            reference(&document["context"]["candidateSnapshot"]),
            &context
        )
        .unwrap()
        .visited
        .is_empty());
    }

    let shelf_document = scenario("shelf-revision-chain");
    let shelf_lookup = load_lookup(&shelf_document, RepositoryLimits::default());
    let shelf_reference = shelf_document["context"]["objectLookup"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| reference(&entry["ref"]))
        .find(|reference| reference.kind == ObjectKind::ShelfRevision)
        .unwrap();
    let lifetime = records(&shelf_document, "lifetimeRecords");
    let working = records(&shelf_document, "workingLifetimeAdditions");
    let imported = mappings(&shelf_document);
    let shelf_value = shelf_lookup
        .resolve_expected(shelf_reference, ObjectKind::ShelfRevision)
        .unwrap()
        .value
        .unwrap();
    let descriptor = ObjectRef::from_cbor(cbor_field(&shelf_value, 16)).unwrap();
    let designated_root = shelf_document["context"]["objectLookup"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| reference(&entry["ref"]))
        .find(|reference| reference.kind == ObjectKind::Snapshot)
        .unwrap();
    let mut shelf_context = RepositoryContext::new(
        &shelf_lookup,
        descriptor,
        designated_root,
        PathCaseMode::CaseSensitive,
    );
    shelf_context.lifetime_records = &lifetime;
    shelf_context.working_lifetime_additions = &working;
    shelf_context.import_mappings = &imported;
    assert_eq!(
        validate_shelf_revision(shelf_reference, &shelf_context)
            .unwrap()
            .highest_layer,
        3
    );

    let candidate = reference(&scenario("provenance-acyclic")["context"]["candidateSnapshot"]);
    let mut attestation = decode_canonical(
        &std::fs::read(format!("{VECTOR_ROOT}/objects/10-attestation.cbor")).unwrap(),
        Limits::METADATA,
    )
    .unwrap();
    replace_cbor_field(&mut attestation, 16, candidate.to_cbor());
    let attestation_bytes = encode_canonical(&attestation).unwrap();
    let attestation_ref = ObjectRef {
        kind: ObjectKind::Attestation,
        digest: object_id(ObjectKind::Attestation, &attestation_bytes).unwrap(),
    };
    let mut provenance = decode_canonical(
        &std::fs::read(format!("{VECTOR_ROOT}/objects/09-provenance.cbor")).unwrap(),
        Limits::METADATA,
    )
    .unwrap();
    replace_cbor_field(
        &mut provenance,
        17,
        Cbor::Array(vec![attestation_ref.to_cbor()]),
    );
    let provenance_bytes = encode_canonical(&provenance).unwrap();
    let provenance_ref = ObjectRef {
        kind: ObjectKind::Provenance,
        digest: object_id(ObjectKind::Provenance, &provenance_bytes).unwrap(),
    };
    let backlink_lookup = RepositoryObjectLookup::new(
        [
            (attestation_ref, attestation_bytes),
            (provenance_ref, provenance_bytes),
        ],
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let error =
        validate_provenance_graph(&[provenance_ref], &backlink_lookup, &[candidate]).unwrap_err();
    assert_eq!(error.code, ErrorCode::ProvenanceCycle);
    assert_eq!(error.layer, 3);

    for (id, code) in [
        ("history-parent-cycle", ErrorCode::SnapshotParentCycle),
        ("provenance-cycle", ErrorCode::ProvenanceCycle),
    ] {
        let document = scenario(id);
        let artifact = document["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|input| {
                input["mediaType"]
                    .as_str()
                    .unwrap()
                    .contains("abstract-reference-graph")
            })
            .unwrap();
        let graph: Value = serde_json::from_slice(
            &std::fs::read(PathBuf::from(VECTOR_ROOT).join(artifact["path"].as_str().unwrap()))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            validate_abstract_reference_graph(
                &graph,
                RepositoryLimits {
                    max_edges: 10,
                    ..RepositoryLimits::default()
                }
            )
            .unwrap_err()
            .code,
            code,
            "{id}"
        );
    }
}

#[test]
fn snapshot_root_validity_outranks_cross_repository_descriptor_mismatch() {
    let document = scenario("history-one-parent");
    let mut entries = lookup_entries(&document);
    let descriptor = reference(&document["context"]["repositoryDescriptor"]);
    let designated_root = reference(&document["context"]["designatedRoot"]);
    let candidate = reference(&document["context"]["candidateSnapshot"]);

    let mut other_descriptor = decoded_entry(&entries, descriptor);
    replace_cbor_field(&mut other_descriptor, 16, Cbor::Bytes(vec![0x5a; 16]));
    let (other_descriptor_ref, other_descriptor_payload) =
        encoded_entry(ObjectKind::RepositoryDescriptor, &other_descriptor);

    let mut second_root = decoded_entry(&entries, candidate);
    replace_cbor_field(&mut second_root, 16, other_descriptor_ref.to_cbor());
    replace_cbor_field(&mut second_root, 17, Cbor::Array(Vec::new()));
    let (second_root_ref, second_root_payload) = encoded_entry(ObjectKind::Snapshot, &second_root);
    entries.remove(&candidate);
    entries.insert(other_descriptor_ref, other_descriptor_payload);
    entries.insert(second_root_ref, second_root_payload);

    let lookup = RepositoryObjectLookup::new(
        entries,
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let context = RepositoryContext::new(
        &lookup,
        descriptor,
        designated_root,
        PathCaseMode::CaseSensitive,
    );
    let error = validate_snapshot_graph(second_root_ref, &context).unwrap_err();
    assert_eq!(
        (error.code, error.layer),
        (ErrorCode::SnapshotRootInvalid, 3)
    );

    // The same precedence applies to every reachable side ancestor, not just
    // the candidate or nodes already bound to the expected descriptor.
    let document = scenario("history-two-parent");
    let mut entries = lookup_entries(&document);
    let descriptor = reference(&document["context"]["repositoryDescriptor"]);
    let designated_root = reference(&document["context"]["designatedRoot"]);
    let candidate = reference(&document["context"]["candidateSnapshot"]);
    let mut candidate_value = decoded_entry(&entries, candidate);
    let Cbor::Array(parents) = cbor_field(&candidate_value, 17) else {
        panic!("parents")
    };
    let side = ObjectRef::from_cbor(&parents[1]).unwrap();
    let mut other_descriptor = decoded_entry(&entries, descriptor);
    replace_cbor_field(&mut other_descriptor, 16, Cbor::Bytes(vec![0x6b; 16]));
    let (other_descriptor_ref, other_descriptor_payload) =
        encoded_entry(ObjectKind::RepositoryDescriptor, &other_descriptor);
    let mut side_value = decoded_entry(&entries, side);
    replace_cbor_field(&mut side_value, 16, other_descriptor_ref.to_cbor());
    replace_cbor_field(&mut side_value, 17, Cbor::Array(Vec::new()));
    let (bad_side, bad_side_payload) = encoded_entry(ObjectKind::Snapshot, &side_value);
    replace_array_reference(&mut candidate_value, 17, side, bad_side);
    let (new_candidate, new_candidate_payload) =
        encoded_entry(ObjectKind::Snapshot, &candidate_value);
    entries.remove(&side);
    entries.remove(&candidate);
    entries.insert(other_descriptor_ref, other_descriptor_payload);
    entries.insert(bad_side, bad_side_payload);
    entries.insert(new_candidate, new_candidate_payload);
    let lookup = RepositoryObjectLookup::new(
        entries,
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let context = RepositoryContext::new(
        &lookup,
        descriptor,
        designated_root,
        PathCaseMode::CaseSensitive,
    );
    let error = validate_snapshot_graph(new_candidate, &context).unwrap_err();
    assert_eq!(
        (error.code, error.layer),
        (ErrorCode::SnapshotRootInvalid, 3)
    );
}

#[test]
fn repository_validation_replays_ancestor_results_and_side_parent_closure() {
    let document = scenario("transition-modify");
    let mut entries = lookup_entries(&document);
    let old_root = reference(&document["context"]["designatedRoot"]);
    let old_candidate = reference(&document["context"]["candidateSnapshot"]);
    let mut root = decoded_entry(&entries, old_root);
    let mut candidate = decoded_entry(&entries, old_candidate);
    replace_cbor_field(&mut root, 18, cbor_field(&candidate, 18).clone());
    let (new_root, root_payload) = encoded_entry(ObjectKind::Snapshot, &root);

    let old_candidate_change = ObjectRef::from_cbor(cbor_field(&candidate, 19)).unwrap();
    let mut candidate_change = decoded_entry(&entries, old_candidate_change);
    replace_cbor_field(&mut candidate_change, 17, new_root.to_cbor());
    let (new_candidate_change, candidate_change_payload) =
        encoded_entry(ObjectKind::ChangeSet, &candidate_change);
    replace_array_reference(&mut candidate, 17, old_root, new_root);
    replace_cbor_field(&mut candidate, 19, new_candidate_change.to_cbor());
    let (new_candidate, candidate_payload) = encoded_entry(ObjectKind::Snapshot, &candidate);

    entries.remove(&old_root);
    entries.remove(&old_candidate_change);
    entries.remove(&old_candidate);
    entries.insert(new_root, root_payload);
    entries.insert(new_candidate_change, candidate_change_payload);
    entries.insert(new_candidate, candidate_payload);
    let lookup = RepositoryObjectLookup::new(
        entries,
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let lifetime = records(&document, "lifetimeRecords");
    let working = records(&document, "workingLifetimeAdditions");
    let imported = mappings(&document);
    let mut validation_context = RepositoryContext::new(
        &lookup,
        reference(&document["context"]["repositoryDescriptor"]),
        new_root,
        PathCaseMode::CaseSensitive,
    );
    validation_context.lifetime_records = &lifetime;
    validation_context.working_lifetime_additions = &working;
    validation_context.import_mappings = &imported;
    assert_eq!(
        validate_repository_candidate(new_candidate, &validation_context)
            .unwrap_err()
            .code,
        ErrorCode::ChangeSetResultMismatch
    );

    let document = scenario("history-two-parent");
    let mut entries = lookup_entries(&document);
    let old_candidate = reference(&document["context"]["candidateSnapshot"]);
    let mut candidate = decoded_entry(&entries, old_candidate);
    let Cbor::Array(parents) = cbor_field(&candidate, 17) else {
        panic!("parents")
    };
    let old_side = ObjectRef::from_cbor(&parents[1]).unwrap();
    let mut side = decoded_entry(&entries, old_side);
    let missing_tree = ObjectRef {
        kind: ObjectKind::Tree,
        digest: [0xff; 32],
    };
    replace_cbor_field(&mut side, 18, missing_tree.to_cbor());
    let (new_side, side_payload) = encoded_entry(ObjectKind::Snapshot, &side);
    replace_array_reference(&mut candidate, 17, old_side, new_side);
    let (new_candidate, candidate_payload) = encoded_entry(ObjectKind::Snapshot, &candidate);
    entries.remove(&old_side);
    entries.remove(&old_candidate);
    entries.insert(new_side, side_payload);
    entries.insert(new_candidate, candidate_payload);
    let lookup = RepositoryObjectLookup::new(
        entries,
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let lifetime = records(&document, "lifetimeRecords");
    let working = records(&document, "workingLifetimeAdditions");
    let imported = mappings(&document);
    let validation_context = context(&document, &lookup, &lifetime, &working, &imported);
    assert_eq!(
        validate_repository_candidate(new_candidate, &validation_context)
            .unwrap_err()
            .code,
        ErrorCode::ObjectReferenceMissing
    );
}

#[test]
fn historical_replay_evicts_long_chain_states_under_a_reduced_memory_ceiling() {
    const EXTRA_SNAPSHOTS: usize = 64;
    let document = scenario("transition-modify");
    let descriptor = reference(&document["context"]["repositoryDescriptor"]);
    let designated_root = reference(&document["context"]["designatedRoot"]);
    let mut candidate = reference(&document["context"]["candidateSnapshot"]);
    let mut entries = lookup_entries(&document);
    let snapshot_template = decoded_entry(&entries, candidate);

    // Every added snapshot reuses the same non-empty tree and applies an
    // unchanged, empty change set. An unbounded per-snapshot state cache grows
    // linearly here; the first-parent consumer plan can move and evict each
    // predecessor state instead.
    for _ in 0..EXTRA_SNAPSHOTS {
        let change = Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(4)),
            (Cbor::UInt(2), Cbor::Array(Vec::new())),
            (Cbor::UInt(16), descriptor.to_cbor()),
            (Cbor::UInt(17), candidate.to_cbor()),
            (Cbor::UInt(18), Cbor::Array(Vec::new())),
        ]);
        let (change_reference, change_payload) = encoded_entry(ObjectKind::ChangeSet, &change);
        let mut snapshot = snapshot_template.clone();
        replace_cbor_field(&mut snapshot, 17, Cbor::Array(vec![candidate.to_cbor()]));
        replace_cbor_field(&mut snapshot, 19, change_reference.to_cbor());
        let (next_candidate, snapshot_payload) = encoded_entry(ObjectKind::Snapshot, &snapshot);
        entries.insert(change_reference, change_payload);
        entries.insert(next_candidate, snapshot_payload);
        candidate = next_candidate;
    }

    let probe = RepositoryObjectLookup::new(
        entries.clone(),
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    probe.validate_all().unwrap();
    let validated_retained = probe.resource_summary().retained_bytes;
    drop(probe);

    let lifetime = records(&document, "lifetimeRecords");
    let lookup = RepositoryObjectLookup::new(
        entries.clone(),
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits {
            max_memory_bytes: validated_retained + 64 * 1024,
            ..RepositoryLimits::default()
        },
    )
    .unwrap();
    let validation_context = RepositoryContext {
        lifetime_records: &lifetime,
        ..RepositoryContext::new(
            &lookup,
            descriptor,
            designated_root,
            PathCaseMode::CaseSensitive,
        )
    };
    let summary = validate_repository_candidate(candidate, &validation_context).unwrap();
    assert_eq!(summary.entries, 1);
    assert_eq!(lookup.resource_summary().retained_bytes, validated_retained);

    let constrained = RepositoryObjectLookup::new(
        entries,
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits {
            max_memory_bytes: validated_retained + 511,
            ..RepositoryLimits::default()
        },
    )
    .unwrap();
    let constrained_context = RepositoryContext {
        lifetime_records: &lifetime,
        ..RepositoryContext::new(
            &constrained,
            descriptor,
            designated_root,
            PathCaseMode::CaseSensitive,
        )
    };
    assert_eq!(
        validate_repository_candidate(candidate, &constrained_context)
            .unwrap_err()
            .code,
        ErrorCode::LimitMemory
    );
}

#[test]
fn shelf_validation_replays_every_prior_revision() {
    let document = scenario("shelf-revision-chain");
    let mut entries = lookup_entries(&document);
    let mut shelves = entries
        .keys()
        .copied()
        .filter(|reference| reference.kind == ObjectKind::ShelfRevision)
        .map(|reference| {
            let value = decoded_entry(&entries, reference);
            (uint_for_test(cbor_field(&value, 18)), reference, value)
        })
        .collect::<Vec<_>>();
    shelves.sort_by_key(|(revision, _, _)| *revision);
    let (_, old_prior, mut prior) = shelves.remove(0);
    let (_, old_latest, mut latest) = shelves.pop().unwrap();
    let missing_tree = ObjectRef {
        kind: ObjectKind::Tree,
        digest: [0xfe; 32],
    };
    replace_cbor_field(&mut prior, 22, missing_tree.to_cbor());
    let (new_prior, prior_payload) = encoded_entry(ObjectKind::ShelfRevision, &prior);
    replace_cbor_field(&mut latest, 19, new_prior.to_cbor());
    let (new_latest, latest_payload) = encoded_entry(ObjectKind::ShelfRevision, &latest);
    entries.remove(&old_prior);
    entries.remove(&old_latest);
    entries.insert(new_prior, prior_payload);
    entries.insert(new_latest, latest_payload);
    let lookup = RepositoryObjectLookup::new(
        entries,
        Registry::load_directory(REGISTRY_ROOT).unwrap(),
        ValidationMode::Conformance,
        RepositoryLimits::default(),
    )
    .unwrap();
    let lifetime = records(&document, "lifetimeRecords");
    let working = records(&document, "workingLifetimeAdditions");
    let imported = mappings(&document);
    let descriptor = ObjectRef::from_cbor(cbor_field(&latest, 16)).unwrap();
    let designated_root = first_reference(&document, ObjectKind::Snapshot);
    let mut validation_context = RepositoryContext::new(
        &lookup,
        descriptor,
        designated_root,
        PathCaseMode::CaseSensitive,
    );
    validation_context.lifetime_records = &lifetime;
    validation_context.working_lifetime_additions = &working;
    validation_context.import_mappings = &imported;
    assert_eq!(
        validate_shelf_revision(new_latest, &validation_context)
            .unwrap_err()
            .code,
        ErrorCode::ObjectReferenceMissing
    );
}

#[test]
fn resource_guards_report_edge_scratch_and_time_limits() {
    let graph = serde_json::json!({
        "schemaVersion": "ogvcs.repository-format/abstract-reference-graph/v1",
        "assumedValidation": "canonical-framing-schema-and-identity-prevalidated",
        "graphKind": "snapshot-parent",
        "roots": ["node-a"],
        "nodes": [
            {"id":"node-a","type":"snapshot","edges":[{"kind":"parent","target":"node-b"}]},
            {"id":"node-b","type":"snapshot","edges":[]}
        ]
    });
    assert_eq!(
        validate_abstract_reference_graph(
            &graph,
            RepositoryLimits {
                max_edges: 0,
                ..RepositoryLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitCount
    );
    assert_eq!(
        validate_abstract_reference_graph(
            &graph,
            RepositoryLimits {
                max_objects: 1,
                ..RepositoryLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitCount
    );
    assert_eq!(
        validate_abstract_reference_graph(
            &graph,
            RepositoryLimits {
                max_scratch_bytes: 0,
                ..RepositoryLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitScratch
    );
    assert_eq!(
        validate_abstract_reference_graph(
            &graph,
            RepositoryLimits {
                max_time: Some(Duration::ZERO),
                ..RepositoryLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitTime
    );
    let preflight = validate_abstract_reference_graph(
        &serde_json::Value::Null,
        RepositoryLimits {
            max_time: Some(Duration::ZERO),
            ..RepositoryLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(preflight.code, ErrorCode::LimitTime);
    assert_eq!(preflight.layer, 1);

    let timed_error = RepositoryObjectLookup::new(
        [],
        Registry::bundled(),
        ValidationMode::Conformance,
        RepositoryLimits {
            max_time: Some(Duration::ZERO),
            ..RepositoryLimits::default()
        },
    )
    .err()
    .unwrap();
    assert_eq!(timed_error.code, ErrorCode::LimitTime);
    assert_eq!(timed_error.layer, 1);

    let unreachable_edges = serde_json::json!({
        "schemaVersion": "ogvcs.repository-format/abstract-reference-graph/v1",
        "assumedValidation": "canonical-framing-schema-and-identity-prevalidated",
        "graphKind": "snapshot-parent",
        "roots": ["node-a"],
        "nodes": [
            {"id":"node-a","type":"snapshot","edges":[]},
            {"id":"node-b","type":"snapshot","edges":[
                {"kind":"parent","target":"node-c"},
                {"kind":"parent","target":"node-d"}
            ]},
            {"id":"node-c","type":"snapshot","edges":[]},
            {"id":"node-d","type":"snapshot","edges":[]}
        ]
    });
    assert_eq!(
        validate_abstract_reference_graph(
            &unreachable_edges,
            RepositoryLimits {
                max_edges: 1,
                ..RepositoryLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitCount
    );
    assert_eq!(
        validate_abstract_reference_graph(
            &unreachable_edges,
            RepositoryLimits {
                max_memory_bytes: 2_000,
                max_scratch_bytes: usize::MAX,
                ..RepositoryLimits::default()
            }
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitMemory
    );
}

#[test]
fn abstract_graph_symbolic_edges_are_charged_before_copying() {
    let long_target = "a".repeat(32_768);
    let graph = serde_json::json!({
        "schemaVersion": "ogvcs.repository-format/abstract-reference-graph/v1",
        "assumedValidation": "canonical-framing-schema-and-identity-prevalidated",
        "graphKind": "snapshot-parent",
        "roots": ["node-a"],
        "nodes": [
            {"id":"node-a","type":"snapshot","edges":[{"kind":"parent","target":long_target}]}
        ]
    });
    let error = validate_abstract_reference_graph(
        &graph,
        RepositoryLimits {
            max_memory_bytes: 1,
            max_scratch_bytes: usize::MAX,
            ..RepositoryLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitMemory);

    let long_node = "a".repeat(32_768);
    for graph in [
        serde_json::json!({
            "schemaVersion": "ogvcs.repository-format/abstract-reference-graph/v1",
            "assumedValidation": "canonical-framing-schema-and-identity-prevalidated",
            "graphKind": "snapshot-parent",
            "roots": [long_node],
            "nodes": [{"id":long_node,"type":"snapshot","edges":[]}]
        }),
        serde_json::json!({
            "schemaVersion": "ogvcs.repository-format/abstract-reference-graph/v1",
            "assumedValidation": "canonical-framing-schema-and-identity-prevalidated",
            "graphKind": "snapshot-parent",
            "roots": [long_node],
            "nodes": [{"id":"node-a","type":"snapshot","edges":[]}]
        }),
    ] {
        let error = validate_abstract_reference_graph(
            &graph,
            RepositoryLimits {
                max_memory_bytes: 5_000,
                max_scratch_bytes: usize::MAX,
                ..RepositoryLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::LimitMemory);
    }
}

#[test]
fn deep_abstract_graph_uses_an_explicit_stack() {
    const NODES: usize = 10_000;
    let nodes = (0..NODES)
        .map(|index| {
            let id = format!("node-{index:05}");
            let edges = if index + 1 == NODES {
                Vec::new()
            } else {
                vec![serde_json::json!({
                    "kind": "parent",
                    "target": format!("node-{:05}", index + 1)
                })]
            };
            serde_json::json!({"id":id,"type":"snapshot","edges":edges})
        })
        .collect::<Vec<_>>();
    let graph = serde_json::json!({
        "schemaVersion": "ogvcs.repository-format/abstract-reference-graph/v1",
        "assumedValidation": "canonical-framing-schema-and-identity-prevalidated",
        "graphKind": "snapshot-parent",
        "roots": ["node-00000"],
        "nodes": nodes
    });
    let result = validate_abstract_reference_graph(&graph, RepositoryLimits::default()).unwrap();
    assert_eq!(result.nodes, NODES);
    assert_eq!(result.edges, NODES - 1);
}
