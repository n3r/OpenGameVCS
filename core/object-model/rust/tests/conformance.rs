use std::{collections::BTreeSet, str::FromStr};

use ogvcs_object_model::*;

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{VECTOR_ROOT}/{relative}")).unwrap()
}

fn index_identity(index: &str, array: &str, path_key: &str, path: &str, id_key: &str) -> [u8; 32] {
    let value: serde_json::Value = serde_json::from_slice(&read(index)).unwrap();
    let identity = value[array]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry[path_key].as_str() == Some(path))
        .and_then(|entry| entry[id_key].as_str())
        .unwrap();
    hex(identity)
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0; N];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let nibble = |b| match b {
            b'0'..=b'9' => b - b'0',
            _ => b - b'a' + 10,
        };
        *slot = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    out
}

fn field_mut(value: &mut Cbor, wanted: u64) -> &mut Cbor {
    let Cbor::Map(entries) = value else {
        panic!("expected map")
    };
    entries
        .iter_mut()
        .find_map(|(key, value)| (*key == Cbor::UInt(wanted)).then_some(value))
        .expect("field exists")
}

fn profile(namespace: &str, id: &str) -> Cbor {
    Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::Text(namespace.to_owned())),
        (Cbor::UInt(1), Cbor::Text(id.to_owned())),
        (Cbor::UInt(2), Cbor::UInt(1)),
    ])
}

fn member(file_id: u8, role: &str) -> Cbor {
    Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::Bytes(vec![file_id; 16])),
        (Cbor::UInt(1), profile("group-role.test", role)),
    ])
}

#[test]
fn golden_objects_scan_schema_roundtrip_and_hash() {
    let cases = [
        (1, "objects/01-chunk.bin"),
        (2, "objects/02-content-manifest.cbor"),
        (3, "objects/03-tree.cbor"),
        (4, "objects/04-change-set.cbor"),
        (5, "objects/05-asset-group-set.cbor"),
        (6, "objects/06-repository-descriptor.cbor"),
        (7, "objects/07-snapshot.cbor"),
        (8, "objects/08-shelf-revision.cbor"),
        (9, "objects/09-provenance.cbor"),
        (10, "objects/10-attestation.cbor"),
        (11, "objects/11-conflict-set.cbor"),
    ];
    for (kind, path) in cases {
        let bytes = read(path);
        let object_kind = ObjectKind::from_code(kind).unwrap();
        let expected_id = index_identity(
            "objects/index.json",
            "objects",
            "payloadPath",
            path,
            "objectId",
        );
        assert_eq!(object_id(object_kind, &bytes).unwrap(), expected_id);
        if kind != 1 {
            let object = scan_metadata(&bytes, Limits::METADATA).unwrap();
            assert_eq!(object.framing().numeric_kind, object_kind.code());
            assert_eq!(
                validate_metadata_schema(&object).unwrap().code(),
                object_kind.code()
            );
            assert_eq!(object.lossless_roundtrip().unwrap(), bytes);
        }
        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert_ne!(object_id(object_kind, &changed).unwrap(), expected_id);
    }
}

#[test]
fn golden_logical_records_and_conflict_preimages() {
    let records = [
        (1, "logical-records/01-repository-root.cbor"),
        (2, "logical-records/02-mutable-ref.cbor"),
        (3, "logical-records/03-shelf-pointer.cbor"),
        (4, "logical-records/04-file-id-lifetime.cbor"),
        (5, "logical-records/05-import-mapping.cbor"),
        (6, "logical-records/06-pending-change-reference.cbor"),
        (7, "logical-records/07-lock-reference.cbor"),
        (8, "logical-records/08-annotation.cbor"),
        (9, "logical-records/09-fixture-event.cbor"),
    ];
    for (ty, path) in records {
        let bytes = read(path);
        assert_eq!(
            validate_logical_record(&bytes, Limits::METADATA).unwrap(),
            ty
        );
        assert_eq!(
            logical_record_id(ty, &bytes).unwrap(),
            index_identity(
                "logical-records/index.json",
                "records",
                "payloadPath",
                path,
                "identity"
            )
        );
        assert_eq!(
            encode_canonical(&decode_canonical(&bytes, Limits::METADATA).unwrap()).unwrap(),
            bytes
        );
    }
    let conflicts = [
        (
            "000",
            "70f3077ec004a7ea8cc2f31837f319ce4c296d1217ed4505a8c270b77d848e5c",
        ),
        (
            "001",
            "9de89d82990c38fd054e7b5aecc9c9ea9e500e5ddf8d03c37fd365f8f802bfe2",
        ),
        (
            "010",
            "daf9b32b6693a4f2378589c9392515bcb3b29825491daea387077bd5330ec213",
        ),
        (
            "011",
            "c8acc9630e0add05062a6eb49d7c261ac8ef97c8178777754749dd23992fc2f5",
        ),
        (
            "100",
            "efd8b2a7549386e4ca6ff3e46cb40e7a2d2ee15c0ae8fbd8cab876a8f436b628",
        ),
        (
            "101",
            "5134dd2abab62fa4cde0c7c5450dce7929a6437f64a1d5c9e0934e284d80c8b5",
        ),
        (
            "110",
            "b7c0984f0b9060714fad398011b4b8bf61ab9c91a82cdbfd1be6030678df0c3a",
        ),
        (
            "111",
            "0b466edafb772a01a401cf66af1ec610e2d790263c825452211e23065d5fb9ce",
        ),
    ];
    for (name, id) in conflicts {
        let bytes = read(&format!("conflicts/{name}-keyed-preimage.cbor"));
        validate_conflict_preimage(&bytes, Limits::METADATA).unwrap();
        assert_eq!(conflict_id(&bytes), hex(id));
    }
}

#[test]
fn malformed_corpus_has_stable_class() {
    let cases = [
        ("truncated", ErrorCode::CborTruncated),
        ("nonminimal-unsigned", ErrorCode::CborNonCanonical),
        ("nonminimal-negative", ErrorCode::CborNonCanonical),
        ("nonminimal-length", ErrorCode::CborNonCanonical),
        ("map-key-order", ErrorCode::CborNonCanonical),
        ("duplicate-map-key", ErrorCode::CborNonCanonical),
        ("indefinite-bytes", ErrorCode::CborNonCanonical),
        ("indefinite-text", ErrorCode::CborNonCanonical),
        ("indefinite-array", ErrorCode::CborNonCanonical),
        ("indefinite-map", ErrorCode::CborNonCanonical),
        ("float", ErrorCode::CborNonCanonical),
        ("tag", ErrorCode::CborNonCanonical),
        ("positive-bignum-tag-2", ErrorCode::CborNonCanonical),
        ("negative-bignum-tag-3", ErrorCode::CborNonCanonical),
        ("null", ErrorCode::CborNonCanonical),
        ("undefined", ErrorCode::CborNonCanonical),
        ("unassigned-simple", ErrorCode::CborNonCanonical),
        ("invalid-utf8", ErrorCode::CborNonCanonical),
        ("nonshortest-utf8", ErrorCode::CborNonCanonical),
        ("non-nfc", ErrorCode::CborNonCanonical),
        ("trailing-bytes", ErrorCode::CborTrailingBytes),
        ("nesting-33", ErrorCode::LimitNesting),
    ];
    for (name, code) in cases {
        let error = decode_canonical(&read(&format!("malformed/{name}.cbor")), Limits::METADATA)
            .unwrap_err();
        assert_eq!(error.code, code, "{name}");
    }
}

#[test]
fn refs_profiles_extensions_and_features() {
    let text =
        "ogvcs:v1:tree:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let object_ref = ObjectRef::from_str(text).unwrap();
    assert_eq!(object_ref.to_string(), text);
    assert_eq!(
        ObjectRef::from_cbor(&object_ref.to_cbor()).unwrap(),
        object_ref
    );
    for invalid in [
        text.to_uppercase(),
        text.replace(":v1:", ":v2:"),
        text.replace(":sha256:", ":sha512:"),
        format!("ogvcs:v1:{}:sha256:{}", "a".repeat(64), "0".repeat(64)),
    ] {
        let error = ObjectRef::from_str(&invalid).unwrap_err();
        assert_eq!(error.code, ErrorCode::ObjectReferenceFormatUnsupported);
        assert_eq!(error.layer, 2);
    }
    let fid = "fid:0102030405060708090a0b0c0d0e0f10";
    assert_eq!(FileId::from_str(fid).unwrap().to_string(), fid);
    assert!(FileId::from_str("fid:00000000000000000000000000000000").is_err());
    for p in [
        "path.test/opaque@1",
        "fixture-content.opengamevcs.test/asset@2",
    ] {
        let profile = ProfileRef::from_str(p).unwrap();
        assert_eq!(profile.to_string(), p);
        assert!(!profile.namespace().is_empty());
        assert!(!profile.id().is_empty());
        assert!(profile.major() > 0);
        assert_eq!(ProfileRef::from_cbor(&profile.to_cbor()).unwrap(), profile);
    }
    for p in [
        "Path.test/opaque@1",
        "path.test/opaque@01",
        "path.test/opaque@+1",
        "path/opaque@1",
        "path.test/-opaque@1",
    ] {
        assert!(ProfileRef::from_str(p).is_err(), "{p}");
    }
    let unknown = read("registries/unknown-required-feature.cbor");
    let object = scan_metadata(&unknown, Limits::METADATA).unwrap();
    assert!(validate_metadata_schema(&object).is_ok());
    assert!(!object.framing().required_features.is_empty());
    let extension = read("registries/unknown-optional-extension.cbor");
    let object = scan_metadata(&extension, Limits::METADATA).unwrap();
    assert_eq!(object.lossless_roundtrip().unwrap(), extension);
    assert!(
        validate_semantic_object(&object, &Registry::bundled(), ValidationMode::Conformance,)
            .is_ok()
    );
}

#[test]
fn framing_defers_common_envelope_schema_defects() {
    let original = decode_canonical(
        &read("objects/06-repository-descriptor.cbor"),
        Limits::METADATA,
    )
    .unwrap();

    let mut unknown_field = original.clone();
    let Cbor::Map(entries) = &mut unknown_field else {
        panic!("expected map")
    };
    entries.push((Cbor::UInt(4), Cbor::Bool(true)));

    let mut bad_extension = original.clone();
    let Cbor::Map(entries) = &mut bad_extension else {
        panic!("expected map")
    };
    entries.push((
        Cbor::UInt(3),
        Cbor::Map(vec![(
            Cbor::Text("invalid extension key".into()),
            Cbor::Bool(true),
        )]),
    ));

    let mut unsorted_features = original;
    *field_mut(&mut unsorted_features, 2) = Cbor::Array(vec![Cbor::UInt(2), Cbor::UInt(1)]);

    for (value, code) in [
        (unknown_field, ErrorCode::SchemaFieldUnknown),
        (bad_extension, ErrorCode::ExtensionKeyInvalid),
        (unsorted_features, ErrorCode::SchemaFieldInvalid),
    ] {
        let encoded = encode_canonical(&value).unwrap();
        let scanned = scan_metadata(&encoded, Limits::METADATA).unwrap();
        assert_eq!(validate_metadata_schema(&scanned).unwrap_err().code, code);
    }
}

#[test]
fn schema_error_ranking_and_mutable_ref_name_authority_are_exact() {
    let mut manifest =
        decode_canonical(&read("objects/02-content-manifest.cbor"), Limits::METADATA).unwrap();
    *field_mut(&mut manifest, 16) = Cbor::Bool(false);
    let Cbor::Map(fields) = &mut manifest else {
        panic!("manifest map")
    };
    fields.push((Cbor::UInt(4095), Cbor::Bool(true)));
    let object = scan_metadata(&encode_canonical(&manifest).unwrap(), Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );

    let mut tree = decode_canonical(&read("objects/03-tree.cbor"), Limits::METADATA).unwrap();
    let Cbor::Array(entries) = field_mut(&mut tree, 17) else {
        panic!("tree entries")
    };
    let mut duplicate = entries[0].clone();
    *field_mut(&mut duplicate, 1) = Cbor::UInt(99);
    entries.push(duplicate);
    let object = scan_metadata(&encode_canonical(&tree).unwrap(), Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );

    let mut change_set =
        decode_canonical(&read("objects/04-change-set.cbor"), Limits::METADATA).unwrap();
    let Cbor::Array(operations) = field_mut(&mut change_set, 18) else {
        panic!("change-set operations")
    };
    *field_mut(&mut operations[0], 0) = Cbor::UInt(99);
    *field_mut(&mut operations[0], 1) = Cbor::UInt(99);
    let object = scan_metadata(&encode_canonical(&change_set).unwrap(), Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );

    let mut change_set =
        decode_canonical(&read("objects/04-change-set.cbor"), Limits::METADATA).unwrap();
    let Cbor::Array(operations) = field_mut(&mut change_set, 18) else {
        panic!("change-set operations")
    };
    *field_mut(&mut operations[0], 0) = Cbor::UInt(99);
    let after = field_mut(&mut operations[0], 3);
    *field_mut(after, 3) = Cbor::UInt(4);
    let object = scan_metadata(&encode_canonical(&change_set).unwrap(), Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::TreeEntryTargetInvalid
    );

    let mut manifest =
        decode_canonical(&read("objects/02-content-manifest.cbor"), Limits::METADATA).unwrap();
    let Cbor::Array(parts) = field_mut(&mut manifest, 19) else {
        panic!("manifest parts")
    };
    *field_mut(&mut parts[0], 1) = Cbor::UInt(0);
    let mut malformed_later_part = parts[0].clone();
    *field_mut(&mut malformed_later_part, 0) = Cbor::Bool(false);
    parts.push(malformed_later_part);
    let object = scan_metadata(&encode_canonical(&manifest).unwrap(), Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );

    let mut conflict_set =
        decode_canonical(&read("objects/11-conflict-set.cbor"), Limits::METADATA).unwrap();
    let Cbor::Array(records) = field_mut(&mut conflict_set, 17) else {
        panic!("conflict records")
    };
    *field_mut(&mut records[0], 0) = Cbor::Bytes(vec![0; 32]);
    *field_mut(&mut records[0], 6) = Cbor::Bool(false);
    let object =
        scan_metadata(&encode_canonical(&conflict_set).unwrap(), Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );

    let mut lifetime = decode_canonical(
        &read("logical-records/04-file-id-lifetime.cbor"),
        Limits::METADATA,
    )
    .unwrap();
    *field_mut(&mut lifetime, 17) = Cbor::Bytes(vec![0; 16]);
    *field_mut(&mut lifetime, 20) = Cbor::Bool(false);
    assert_eq!(
        validate_logical_record(&encode_canonical(&lifetime).unwrap(), Limits::METADATA)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );

    let mut mutable_ref = decode_canonical(
        &read("logical-records/02-mutable-ref.cbor"),
        Limits::METADATA,
    )
    .unwrap();
    *field_mut(&mut mutable_ref, 18) = Cbor::Text(String::new());
    assert_eq!(
        validate_logical_record(&encode_canonical(&mutable_ref).unwrap(), Limits::METADATA)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );
}

#[test]
fn framing_enforces_extension_resource_ceilings_for_unknown_kinds() {
    for invalid in [Cbor::Bool(true), Cbor::Map(Vec::new())] {
        let value = Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(65_535)),
            (Cbor::UInt(2), Cbor::Array(Vec::new())),
            (Cbor::UInt(3), invalid),
            (Cbor::UInt(16), Cbor::Bool(true)),
        ]);
        let error =
            scan_metadata(&encode_canonical(&value).unwrap(), Limits::METADATA).unwrap_err();
        assert_eq!(error.code, ErrorCode::SchemaFieldInvalid);
        assert_eq!(error.layer, 1);
    }
    let extensions = (0..129)
        .map(|index| {
            (
                Cbor::Text(format!("extension.test/item-{index:03}@1")),
                Cbor::Bool(true),
            )
        })
        .collect();
    let count = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(65_535)),
        (Cbor::UInt(2), Cbor::Array(Vec::new())),
        (Cbor::UInt(3), Cbor::Map(extensions)),
        (Cbor::UInt(16), Cbor::Bool(true)),
    ]);
    assert_eq!(
        scan_metadata(&encode_canonical(&count).unwrap(), Limits::METADATA)
            .unwrap_err()
            .code,
        ErrorCode::LimitCount
    );

    let aggregate = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(65_535)),
        (Cbor::UInt(2), Cbor::Array(Vec::new())),
        (
            Cbor::UInt(3),
            Cbor::Map(vec![
                (
                    Cbor::Text("extension.test/left@1".into()),
                    Cbor::Bytes(vec![0; 8_388_609]),
                ),
                (
                    Cbor::Text("extension.test/right@1".into()),
                    Cbor::Bytes(vec![0; 8_388_609]),
                ),
            ]),
        ),
        (Cbor::UInt(16), Cbor::Bool(true)),
    ]);
    assert_eq!(
        scan_metadata(&encode_canonical(&aggregate).unwrap(), Limits::METADATA)
            .unwrap_err()
            .code,
        ErrorCode::LimitExtensionBytes
    );
}

#[test]
fn conformance_profile_rules_run_only_at_semantic_layer() {
    let mut snapshot =
        decode_canonical(&read("objects/07-snapshot.cbor"), Limits::METADATA).unwrap();
    *field_mut(field_mut(&mut snapshot, 26), 2) = Cbor::UInt(2);
    let encoded = encode_canonical(&snapshot).unwrap();
    let scanned = scan_metadata(&encoded, Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&scanned).unwrap(),
        ObjectKind::Snapshot
    );
    let error =
        validate_semantic_object(&scanned, &Registry::bundled(), ValidationMode::Conformance)
            .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::ProfileStateForbidden,
            3,
            ValidationStage::RegistrySemantics
        )
    );
}

#[test]
fn semantic_scalar_and_group_tuple_boundaries_are_exact() {
    let mut descriptor = decode_canonical(
        &read("objects/06-repository-descriptor.cbor"),
        Limits::METADATA,
    )
    .unwrap();
    *field_mut(&mut descriptor, 16) = Cbor::Bytes(vec![0; 16]);
    let encoded = encode_canonical(&descriptor).unwrap();
    let object = scan_metadata(&encoded, Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );

    let mut snapshot =
        decode_canonical(&read("objects/07-snapshot.cbor"), Limits::METADATA).unwrap();
    *field_mut(&mut snapshot, 23) = Cbor::UInt(i64::MAX as u64 + 1);
    let encoded = encode_canonical(&snapshot).unwrap();
    let object = scan_metadata(&encoded, Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );

    let mut group_set =
        decode_canonical(&read("objects/05-asset-group-set.cbor"), Limits::METADATA).unwrap();
    let mut empty_group_set = group_set.clone();
    let Cbor::Array(empty_groups) = field_mut(&mut empty_group_set, 17) else {
        panic!("expected groups")
    };
    *field_mut(&mut empty_groups[0], 3) = Cbor::Array(Vec::new());
    let encoded = encode_canonical(&empty_group_set).unwrap();
    let object = scan_metadata(&encoded, Limits::METADATA).unwrap();
    let error = validate_metadata_schema(&object).unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            2,
            ValidationStage::KnownSchema
        )
    );

    let Cbor::Array(groups) = field_mut(&mut group_set, 17) else {
        panic!("expected groups")
    };
    let group = &mut groups[0];
    *field_mut(group, 2) = Cbor::Bytes(vec![0xff; 16]);
    *field_mut(group, 3) = Cbor::Array(vec![member(0xff, "a"), member(1, "b")]);
    *field_mut(group, 4) = Cbor::Array(vec![
        Cbor::Map(vec![
            (Cbor::UInt(0), profile("external-key.test", "opaque")),
            (Cbor::UInt(1), Cbor::Bytes(vec![0, 0])),
        ]),
        Cbor::Map(vec![
            (Cbor::UInt(0), profile("external-key.test", "opaque")),
            (Cbor::UInt(1), Cbor::Bytes(vec![0xff])),
        ]),
    ]);
    let encoded = encode_canonical(&group_set).unwrap();
    let object = scan_metadata(&encoded, Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap(),
        ObjectKind::AssetGroupSet
    );
}

#[test]
fn reference_manifest_and_provenance_integrity_errors_are_specific() {
    let mut manifest =
        decode_canonical(&read("objects/02-content-manifest.cbor"), Limits::METADATA).unwrap();
    {
        let Cbor::Array(parts) = field_mut(&mut manifest, 19) else {
            panic!("expected parts")
        };
        *field_mut(&mut parts[0], 1) = Cbor::UInt(0);
    }
    let encoded = encode_canonical(&manifest).unwrap();
    let object = scan_metadata(&encoded, Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::ManifestChunkLengthInvalid
    );

    {
        let Cbor::Array(parts) = field_mut(&mut manifest, 19) else {
            panic!("expected parts")
        };
        let part = &mut parts[0];
        *field_mut(part, 1) = Cbor::UInt(24);
        let reference = field_mut(part, 0);
        *field_mut(reference, 1) = Cbor::UInt(3);
    }
    let encoded = encode_canonical(&manifest).unwrap();
    let object = scan_metadata(&encoded, Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::ObjectReferenceKindMismatch
    );

    let mut provenance =
        decode_canonical(&read("objects/09-provenance.cbor"), Limits::METADATA).unwrap();
    let Cbor::Bytes(statement) = field_mut(&mut provenance, 19) else {
        panic!("expected statement")
    };
    statement[0] ^= 1;
    let encoded = encode_canonical(&provenance).unwrap();
    let object = scan_metadata(&encoded, Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );
}

struct FakeEntropy {
    values: Vec<[u8; 16]>,
    at: usize,
    fail: bool,
}
impl EntropySource for FakeEntropy {
    fn fill(&mut self, out: &mut [u8]) -> std::io::Result<()> {
        if self.fail {
            return Err(std::io::Error::other("no entropy"));
        }
        out.copy_from_slice(&self.values[self.at]);
        self.at += 1;
        Ok(())
    }
}

#[test]
fn allocator_retries_zero_collision_and_exhaustion() {
    let collision = [7; 16];
    let fresh = [9; 16];
    let mut source = FakeEntropy {
        values: vec![[0; 16], collision, fresh],
        at: 0,
        fail: false,
    };
    let consumed = BTreeSet::from([collision]);
    let id =
        allocate_file_id_with(&mut source, &mut |id| consumed.contains(id.as_bytes()), 3).unwrap();
    assert_eq!(id.as_bytes(), &fresh);
    let mut source = FakeEntropy {
        values: vec![[0; 16], [0; 16]],
        at: 0,
        fail: false,
    };
    assert_eq!(
        allocate_file_id_with(&mut source, &mut |_| false, 2)
            .unwrap_err()
            .code,
        ErrorCode::FileIdAllocationExhausted
    );
    let mut source = FakeEntropy {
        values: vec![],
        at: 0,
        fail: true,
    };
    assert_eq!(
        allocate_file_id_with(&mut source, &mut |_| false, 2)
            .unwrap_err()
            .code,
        ErrorCode::FileIdEntropyUnavailable
    );
    assert_eq!(
        allocate_file_id_with(&mut source, &mut |_| false, 0)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );
    assert_eq!(
        allocate_file_id_with(
            &mut source,
            &mut |_| false,
            MAX_FILE_ID_ALLOCATION_ATTEMPTS + 1,
        )
        .unwrap_err()
        .code,
        ErrorCode::SchemaFieldInvalid
    );
}

#[test]
fn configured_limits_only_reduce_acceptance() {
    let bytes = read("objects/06-repository-descriptor.cbor");
    let small = Limits {
        max_input_bytes: bytes.len() - 1,
        ..Limits::METADATA
    };
    assert_eq!(
        scan_metadata(&bytes, small).unwrap_err().code,
        ErrorCode::LimitMetadataBytes
    );
    let nested = Cbor::Array(vec![Cbor::Array(vec![Cbor::UInt(1)])]);
    let encoded = encode_canonical(&nested).unwrap();
    let limits = Limits {
        max_nesting: 1,
        ..Limits::METADATA
    };
    assert_eq!(
        decode_canonical(&encoded, limits).unwrap_err().code,
        ErrorCode::LimitNesting
    );
    assert_eq!(
        encode_canonical_with_limits(&nested, limits)
            .unwrap_err()
            .code,
        ErrorCode::LimitNesting
    );

    let above_hard_container = [0x9a, 0x00, 0x10, 0x00, 0x01];
    let raised = Limits {
        max_container_items: 2_000_000,
        ..Limits::BUNDLE_ITEM
    };
    assert_eq!(
        decode_canonical(&above_hard_container, raised)
            .unwrap_err()
            .code,
        ErrorCode::LimitCount
    );
}

#[test]
fn chunk_bounds_typed_digest_and_registry_state() {
    let chunk = read("objects/01-chunk.bin");
    assert_eq!(
        hash_chunk(&chunk, chunk.len()).unwrap(),
        object_id(ObjectKind::Chunk, &chunk).unwrap()
    );
    assert_eq!(
        hash_chunk(&chunk, chunk.len() - 1).unwrap_err().code,
        ErrorCode::LimitChunkBytes
    );

    let typed = TypedDigest::sha256(sha256(b"typed"));
    assert_eq!(TypedDigest::from_cbor(&typed.to_cbor()).unwrap(), typed);

    let registry = Registry::bundled();
    let profile = ProfileRef::from_str("path.test/opaque@1").unwrap();
    assert_eq!(
        registry
            .check_profile(&profile, "path", Operation::Read)
            .unwrap_err()
            .code,
        ErrorCode::ProfileConformanceOnly
    );
    registry
        .check_profile(&profile, "path", Operation::ConformanceWrite)
        .unwrap();
    assert_eq!(
        registry
            .check_profile(&profile, "path", Operation::ProductionWrite)
            .unwrap_err()
            .code,
        ErrorCode::ProfileConformanceOnly
    );
    assert_eq!(
        registry
            .check_profile(&profile, "chunking", Operation::Read)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );
}
