use std::{
    collections::BTreeSet,
    io::{self, Cursor, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, Instant},
};

use ogvcs_object_model::*;

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";

fn reference(kind: ObjectKind, label: &[u8]) -> ObjectRef {
    ObjectRef {
        kind,
        digest: sha256(label),
    }
}

fn descriptor() -> ObjectRef {
    reference(ObjectKind::RepositoryDescriptor, b"scale-test-descriptor")
}

fn content_policy() -> ProfileRef {
    ProfileRef::from_str("content-policy.test/opaque@1").unwrap()
}

fn chunk_profile() -> ProfileRef {
    ProfileRef::from_str("chunking.test/external-boundaries@1").unwrap()
}

fn hex32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    let mut result = [0u8; 32];
    for (slot, pair) in result.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("lowercase hexadecimal"),
        };
        *slot = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    result
}

fn scale_descriptor() -> ObjectRef {
    ObjectRef {
        kind: ObjectKind::RepositoryDescriptor,
        digest: hex32("dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545"),
    }
}

fn scale_tree_target() -> ObjectRef {
    ObjectRef {
        kind: ObjectKind::ContentManifest,
        digest: hex32("82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12"),
    }
}

fn repeated_scale_chunk(length: usize) -> ([u8; 32], Vec<u8>) {
    let seed = hex32("860f753350ec981c19f401b44ed6a36a0ac76353a5389e31dc36048dd2d78f65");
    let mut preimage = Vec::with_capacity(seed.len() + 1 + 17);
    preimage.extend_from_slice(&seed);
    preimage.push(0x43);
    preimage.extend_from_slice(b"repeated-chunk-v1");
    let block = sha256(&preimage);
    let mut chunk = Vec::with_capacity(length);
    while chunk.len() < length {
        let remaining = length - chunk.len();
        chunk.extend_from_slice(&block[..remaining.min(block.len())]);
    }
    (block, chunk)
}

fn regular_entry(index: usize) -> TreeStreamEntry {
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&sha256(&(index as u64).to_be_bytes())[..16]);
    if file_id == [0; 16] {
        file_id[15] = 1;
    }
    TreeStreamEntry {
        basename: format!("entry-{index:06}"),
        entry_kind: 2,
        file_id,
        portable_mode: 2,
        target: reference(ObjectKind::ContentManifest, b"scale-test-manifest"),
        logical_size: index as u64,
        content_policy: content_policy(),
    }
}

fn tree_cbor(entries: &[TreeStreamEntry]) -> Cbor {
    Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(3)),
        (Cbor::UInt(2), Cbor::Array(Vec::new())),
        (Cbor::UInt(16), descriptor().to_cbor()),
        (
            Cbor::UInt(17),
            Cbor::Array(
                entries
                    .iter()
                    .map(|entry| {
                        Cbor::Map(vec![
                            (Cbor::UInt(0), Cbor::Text(entry.basename.clone())),
                            (Cbor::UInt(1), Cbor::UInt(entry.entry_kind.into())),
                            (Cbor::UInt(2), Cbor::Bytes(entry.file_id.to_vec())),
                            (Cbor::UInt(3), Cbor::UInt(entry.portable_mode.into())),
                            (Cbor::UInt(4), entry.target.to_cbor()),
                            (Cbor::UInt(5), Cbor::UInt(entry.logical_size)),
                            (Cbor::UInt(6), entry.content_policy.to_cbor()),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

#[derive(Default)]
struct PartialWriter {
    bytes: Vec<u8>,
    maximum_write: usize,
}

impl Write for PartialWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(3);
        self.maximum_write = self.maximum_write.max(count);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct TestDirectory(PathBuf);

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let mut random = [0u8; 12];
        getrandom::getrandom(&mut random).unwrap();
        let token = hex_lower(&random);
        let path = std::env::temp_dir().join(format!("ogvcs-{label}-{token}"));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn ordered_tree_matches_general_codec_and_handles_short_writes() {
    let entries = vec![regular_entry(1), regular_entry(2), regular_entry(3)];
    let expected = encode_canonical(&tree_cbor(&entries)).unwrap();
    let mut output = PartialWriter::default();
    let mut file_ids = BTreeSet::new();
    let summary = encode_ordered_tree(
        &mut output,
        descriptor(),
        entries.len() as u64,
        entries.clone(),
        &Registry::bundled(),
        Operation::ConformanceWrite,
        &mut file_ids,
        TreeStreamLimits::default(),
    )
    .unwrap();

    assert_eq!(output.bytes, expected);
    assert!(output.maximum_write <= 3);
    assert_eq!(
        summary.object_ref.digest,
        object_id(ObjectKind::Tree, &expected).unwrap()
    );
    assert_eq!(summary.entries, 3);
    assert_eq!(summary.directories, 0);
    assert_eq!(summary.nondirectories, 3);
    assert_eq!(summary.logical_bytes, 6);
    assert_eq!(summary.payload_bytes, expected.len() as u64);
    let object = scan_metadata(&expected, Limits::METADATA).unwrap();
    assert_eq!(validate_metadata_schema(&object).unwrap(), ObjectKind::Tree);

    let mut verified_file_ids = BTreeSet::new();
    let verified = verify_tree_stream(
        Cursor::new(&expected),
        summary.object_ref,
        descriptor(),
        &Registry::bundled(),
        Operation::ConformanceWrite,
        &mut verified_file_ids,
        TreeStreamLimits::default(),
    )
    .unwrap();
    assert_eq!(verified, summary);
    for prefix in 0..expected.len() {
        let mut prefix_file_ids = BTreeSet::new();
        assert_eq!(
            verify_tree_stream(
                Cursor::new(&expected[..prefix]),
                summary.object_ref,
                descriptor(),
                &Registry::bundled(),
                Operation::ConformanceWrite,
                &mut prefix_file_ids,
                TreeStreamLimits::default(),
            )
            .unwrap_err()
            .code,
            ErrorCode::CborTruncated,
            "proper prefix {prefix}"
        );
    }
}

#[test]
fn external_sort_is_byte_identical_bounded_and_cleans_scratch() {
    let directory = TestDirectory::new("tree-sort");
    let ordered = (0..64).map(regular_entry).collect::<Vec<_>>();
    let mut expected_bytes = Vec::new();
    let mut file_ids = BTreeSet::new();
    let expected_summary = encode_ordered_tree(
        &mut expected_bytes,
        descriptor(),
        ordered.len() as u64,
        ordered.clone(),
        &Registry::bundled(),
        Operation::ConformanceWrite,
        &mut file_ids,
        TreeStreamLimits::default(),
    )
    .unwrap();
    let mut unordered = ordered;
    unordered.reverse();
    let limits = TreeStreamLimits {
        max_memory_bytes: 900,
        max_scratch_bytes: 2 * 1024 * 1024,
        ..TreeStreamLimits::default()
    };
    let mut actual_bytes = Vec::new();
    let mut metrics = TreeScratchMetrics::default();
    let actual_summary = encode_tree_with_scratch(
        &mut actual_bytes,
        descriptor(),
        unordered.len() as u64,
        unordered,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        directory.path(),
        limits,
        &mut metrics,
    )
    .unwrap();

    assert_eq!(actual_bytes, expected_bytes);
    assert_eq!(actual_summary, expected_summary);
    assert!(metrics.files_created > 1);
    assert!(metrics.merge_passes > 0);
    assert!(metrics.peak_bytes <= limits.max_scratch_bytes);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn tree_rejects_order_shape_and_all_configured_resource_stops() {
    let registry = Registry::bundled();
    let base = regular_entry(1);
    let error = |entries: Vec<TreeStreamEntry>, count, limits| {
        let mut file_ids = BTreeSet::new();
        encode_ordered_tree(
            io::sink(),
            descriptor(),
            count,
            entries,
            &registry,
            Operation::ConformanceWrite,
            &mut file_ids,
            limits,
        )
        .unwrap_err()
        .code
    };

    let mut hard_limit_ids = BTreeSet::new();
    let hard_limit_error = encode_ordered_tree(
        io::sink(),
        descriptor(),
        1_000_001,
        Vec::new(),
        &registry,
        Operation::ConformanceWrite,
        &mut hard_limit_ids,
        TreeStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        (
            hard_limit_error.code,
            hard_limit_error.layer,
            hard_limit_error.stage
        ),
        (
            ErrorCode::LimitCount,
            1,
            ValidationStage::ConfiguredResourcePreflight
        )
    );
    for (entries, declared) in [(Vec::new(), 1), (vec![regular_entry(1)], 0)] {
        let mut file_ids = BTreeSet::new();
        let count_error = encode_ordered_tree(
            io::sink(),
            descriptor(),
            declared,
            entries,
            &registry,
            Operation::ConformanceWrite,
            &mut file_ids,
            TreeStreamLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            (count_error.code, count_error.layer, count_error.stage),
            (
                ErrorCode::SchemaFieldInvalid,
                2,
                ValidationStage::KnownSchema
            )
        );
    }
    for (entries, declared, label) in [
        (Vec::new(), 1, "too-few"),
        (vec![regular_entry(1)], 0, "too-many"),
    ] {
        let directory = TestDirectory::new(&format!("tree-count-{label}"));
        let mut metrics = TreeScratchMetrics::default();
        let count_error = encode_tree_with_scratch(
            io::sink(),
            descriptor(),
            declared,
            entries,
            &registry,
            Operation::ConformanceWrite,
            directory.path(),
            TreeStreamLimits::default(),
            &mut metrics,
        )
        .unwrap_err();
        assert_eq!(
            (count_error.code, count_error.layer, count_error.stage),
            (
                ErrorCode::SchemaFieldInvalid,
                2,
                ValidationStage::KnownSchema
            )
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
    assert_eq!(
        error(
            vec![regular_entry(2), regular_entry(1)],
            2,
            TreeStreamLimits::default()
        ),
        ErrorCode::TreeEntryOrderInvalid
    );
    assert_eq!(
        error(
            vec![regular_entry(1), regular_entry(1)],
            2,
            TreeStreamLimits::default()
        ),
        ErrorCode::TreeEntryOrderInvalid
    );
    let duplicate_id_left = regular_entry(1);
    let mut duplicate_id_right = regular_entry(2);
    duplicate_id_right.file_id = duplicate_id_left.file_id;
    assert_eq!(
        error(
            vec![duplicate_id_left, duplicate_id_right],
            2,
            TreeStreamLimits::default()
        ),
        ErrorCode::FileIdDuplicateInTree
    );
    let mut invalid = base.clone();
    invalid.file_id = [0; 16];
    assert_eq!(
        error(vec![invalid], 1, TreeStreamLimits::default()),
        ErrorCode::FileIdZero
    );
    let mut invalid = base.clone();
    invalid.basename = "e\u{301}".into();
    assert_eq!(
        error(vec![invalid], 1, TreeStreamLimits::default()),
        ErrorCode::PathCoreInvalid
    );
    let mut invalid = base.clone();
    invalid.portable_mode = 3;
    assert_eq!(
        error(vec![invalid], 1, TreeStreamLimits::default()),
        ErrorCode::TreeEntryTargetInvalid
    );
    let mut invalid = base.clone();
    invalid.target = reference(ObjectKind::Tree, b"wrong target");
    assert_eq!(
        error(vec![invalid], 1, TreeStreamLimits::default()),
        ErrorCode::ObjectReferenceKindMismatch
    );
    let mut invalid = base.clone();
    invalid.logical_size = 1_099_511_627_777;
    assert_eq!(
        error(vec![invalid], 1, TreeStreamLimits::default()),
        ErrorCode::LimitLogicalBytes
    );
    let mut invalid = base.clone();
    invalid.content_policy = chunk_profile();
    assert_eq!(
        error(vec![invalid], 1, TreeStreamLimits::default()),
        ErrorCode::SchemaFieldInvalid
    );
    assert_eq!(
        error(
            vec![base.clone()],
            1,
            TreeStreamLimits {
                max_memory_bytes: 1,
                ..TreeStreamLimits::default()
            }
        ),
        ErrorCode::LimitMemory
    );
    assert_eq!(
        error(
            vec![base.clone()],
            1,
            TreeStreamLimits {
                max_output_bytes: 1,
                ..TreeStreamLimits::default()
            }
        ),
        ErrorCode::LimitMetadataBytes
    );
    assert_eq!(
        error(
            vec![base],
            1,
            TreeStreamLimits {
                max_elapsed: Some(Duration::ZERO),
                ..TreeStreamLimits::default()
            }
        ),
        ErrorCode::LimitTime
    );

    let directory = TestDirectory::new("tree-scratch-stop");
    let mut metrics = TreeScratchMetrics::default();
    let scratch_error = encode_tree_with_scratch(
        io::sink(),
        descriptor(),
        2,
        vec![regular_entry(2), regular_entry(1)],
        &registry,
        Operation::ConformanceWrite,
        directory.path(),
        TreeStreamLimits {
            max_memory_bytes: 900,
            max_scratch_bytes: 1,
            ..TreeStreamLimits::default()
        },
        &mut metrics,
    )
    .unwrap_err();
    assert_eq!(scratch_error.code, ErrorCode::LimitScratch);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);

    let duplicate_directory = TestDirectory::new("tree-duplicate-id");
    let duplicate_id_left = regular_entry(1);
    let mut duplicate_id_right = regular_entry(2);
    duplicate_id_right.file_id = duplicate_id_left.file_id;
    let duplicate_error = encode_tree_with_scratch(
        io::sink(),
        descriptor(),
        2,
        vec![duplicate_id_right, duplicate_id_left],
        &registry,
        Operation::ConformanceWrite,
        duplicate_directory.path(),
        TreeStreamLimits::default(),
        &mut metrics,
    )
    .unwrap_err();
    assert_eq!(duplicate_error.code, ErrorCode::FileIdDuplicateInTree);
    assert_eq!(
        std::fs::read_dir(duplicate_directory.path())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn raw_tree_stream_rejects_duplicate_ids_trailing_bytes_and_wrong_identity() {
    let left = regular_entry(1);
    let mut right = regular_entry(2);
    right.file_id = left.file_id;
    let duplicate_bytes = encode_canonical(&tree_cbor(&[left, right])).unwrap();
    let duplicate_ref = ObjectRef {
        kind: ObjectKind::Tree,
        digest: object_id(ObjectKind::Tree, &duplicate_bytes).unwrap(),
    };
    let mut file_ids = BTreeSet::new();
    assert_eq!(
        verify_tree_stream(
            Cursor::new(&duplicate_bytes),
            duplicate_ref,
            descriptor(),
            &Registry::bundled(),
            Operation::ConformanceWrite,
            &mut file_ids,
            TreeStreamLimits::default(),
        )
        .unwrap_err()
        .code,
        ErrorCode::FileIdDuplicateInTree
    );

    let valid = encode_canonical(&tree_cbor(&[regular_entry(1)])).unwrap();
    let valid_ref = ObjectRef {
        kind: ObjectKind::Tree,
        digest: object_id(ObjectKind::Tree, &valid).unwrap(),
    };
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut file_ids = BTreeSet::new();
    assert_eq!(
        verify_tree_stream(
            Cursor::new(trailing),
            valid_ref,
            descriptor(),
            &Registry::bundled(),
            Operation::ConformanceWrite,
            &mut file_ids,
            TreeStreamLimits::default(),
        )
        .unwrap_err()
        .code,
        ErrorCode::CborTrailingBytes
    );
    let mut file_ids = BTreeSet::new();
    assert_eq!(
        verify_tree_stream(
            Cursor::new(valid),
            reference(ObjectKind::Tree, b"wrong identity"),
            descriptor(),
            &Registry::bundled(),
            Operation::ConformanceWrite,
            &mut file_ids,
            TreeStreamLimits::default(),
        )
        .unwrap_err()
        .code,
        ErrorCode::ObjectIdMismatch
    );

    for (entry, expected) in [
        (
            {
                let mut entry = regular_entry(1);
                entry.target = reference(ObjectKind::Tree, b"wrong target kind");
                entry
            },
            ErrorCode::ObjectReferenceKindMismatch,
        ),
        (
            {
                let mut entry = regular_entry(1);
                entry.logical_size = 1_099_511_627_777;
                entry
            },
            ErrorCode::LimitLogicalBytes,
        ),
    ] {
        let bytes = encode_canonical(&tree_cbor(&[entry])).unwrap();
        let object_ref = ObjectRef {
            kind: ObjectKind::Tree,
            digest: object_id(ObjectKind::Tree, &bytes).unwrap(),
        };
        let mut file_ids = BTreeSet::new();
        assert_eq!(
            verify_tree_stream(
                Cursor::new(bytes),
                object_ref,
                descriptor(),
                &Registry::bundled(),
                Operation::ConformanceWrite,
                &mut file_ids,
                TreeStreamLimits::default(),
            )
            .unwrap_err()
            .code,
            expected
        );
    }
}

#[test]
fn raw_tree_stream_verifies_the_checked_in_interoperability_tree() {
    let bytes = std::fs::read(format!("{VECTOR_ROOT}/objects/03-tree.cbor")).unwrap();
    let expected = ObjectRef::from_str(
        "ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19",
    )
    .unwrap();
    let descriptor = ObjectRef::from_str(
        "ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545",
    )
    .unwrap();
    let mut file_ids = BTreeSet::new();
    let summary = verify_tree_stream(
        Cursor::new(bytes),
        expected,
        descriptor,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        &mut file_ids,
        TreeStreamLimits::default(),
    )
    .unwrap();
    assert_eq!(summary.object_ref, expected);
    assert_eq!(summary.entries, file_ids.len() as u64);
}

#[cfg(unix)]
#[test]
fn external_sort_rejects_a_symlink_scratch_root() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new("tree-sort-link");
    let link = directory.path().join("scratch-link");
    symlink(directory.path(), &link).unwrap();
    let mut metrics = TreeScratchMetrics::default();
    let error = encode_tree_with_scratch(
        io::sink(),
        descriptor(),
        1,
        vec![regular_entry(1)],
        &Registry::bundled(),
        Operation::ConformanceWrite,
        &link,
        TreeStreamLimits::default(),
        &mut metrics,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::SchemaFieldInvalid);
}

fn manifest_cbor(
    parts: &[ManifestStreamPart],
    logical_length: u64,
    whole_digest: [u8; 32],
) -> Cbor {
    Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(2)),
        (Cbor::UInt(2), Cbor::Array(Vec::new())),
        (Cbor::UInt(16), Cbor::UInt(logical_length)),
        (Cbor::UInt(17), TypedDigest::sha256(whole_digest).to_cbor()),
        (Cbor::UInt(18), chunk_profile().to_cbor()),
        (
            Cbor::UInt(19),
            Cbor::Array(
                parts
                    .iter()
                    .map(|part| {
                        Cbor::Map(vec![
                            (Cbor::UInt(0), part.chunk.to_cbor()),
                            (Cbor::UInt(1), Cbor::UInt(part.length)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

#[test]
fn manifest_stream_matches_general_codec_and_verifies_content() {
    let payloads = [b"abc".to_vec(), b"defgh".to_vec()];
    let parts = payloads
        .iter()
        .map(|payload| ManifestStreamPart {
            chunk: ObjectRef {
                kind: ObjectKind::Chunk,
                digest: hash_chunk(payload, 67_108_864).unwrap(),
            },
            length: payload.len() as u64,
        })
        .collect::<Vec<_>>();
    let whole_digest = sha256(b"abcdefgh");
    let expected = encode_canonical(&manifest_cbor(&parts, 8, whole_digest)).unwrap();
    let mut output = PartialWriter::default();
    let mut source =
        |index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            consume(&payloads[index as usize])
        };
    let summary = encode_and_verify_content_manifest_stream(
        &mut output,
        parts.len() as u64,
        || parts.clone(),
        &chunk_profile(),
        8,
        whole_digest,
        &mut source,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap();

    assert_eq!(output.bytes, expected);
    assert!(output.maximum_write <= 3);
    assert_eq!(
        summary.object_ref.digest,
        object_id(ObjectKind::ContentManifest, &expected).unwrap()
    );
    assert_eq!(summary.parts, 2);
    assert_eq!(summary.logical_bytes, 8);
    assert_eq!(summary.whole_file_digest, whole_digest);
    let object = scan_metadata(&expected, Limits::METADATA).unwrap();
    assert_eq!(
        validate_metadata_schema(&object).unwrap(),
        ObjectKind::ContentManifest
    );
}

#[test]
fn repeated_manifest_source_is_constant_space_and_replay_stable() {
    let payload = vec![0x5a; 1024];
    let chunk = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: hash_chunk(&payload, 67_108_864).unwrap(),
    };
    let part = ManifestStreamPart {
        chunk,
        length: payload.len() as u64,
    };
    let mut source_calls = 0u64;
    let mut source =
        |_index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            source_calls += 1;
            for slice in payload.chunks(127) {
                consume(slice)?;
            }
            Ok(())
        };
    let mut output = Vec::new();
    let summary = encode_content_manifest_stream(
        &mut output,
        257,
        || std::iter::repeat_n(part, 257),
        &chunk_profile(),
        &mut source,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        ManifestStreamLimits {
            max_memory_bytes: 127,
            ..ManifestStreamLimits::default()
        },
    )
    .unwrap();
    assert_eq!(source_calls, 257);
    assert_eq!(summary.logical_bytes, 257 * 1024);
    assert_eq!(summary.parts, 257);
}

#[test]
fn repeated_manifest_source_uses_bounded_verified_chunk_cache() {
    let payload = vec![0x3c; 1024];
    let part = ManifestStreamPart {
        chunk: ObjectRef {
            kind: ObjectKind::Chunk,
            digest: hash_chunk(&payload, 67_108_864).unwrap(),
        },
        length: payload.len() as u64,
    };
    let mut source_calls = 0u64;
    let mut source =
        |_index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            source_calls += 1;
            for slice in payload.chunks(127) {
                consume(slice)?;
            }
            Ok(())
        };
    let summary = encode_content_manifest_stream(
        io::sink(),
        257,
        || std::iter::repeat_n(part, 257),
        &chunk_profile(),
        &mut source,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        ManifestStreamLimits {
            max_memory_bytes: 8_192,
            ..ManifestStreamLimits::default()
        },
    )
    .unwrap();

    assert_eq!(source_calls, 1);
    assert_eq!(summary.logical_bytes, 257 * 1024);
}

#[test]
fn invalid_repeated_chunk_is_never_admitted_to_verified_cache() {
    let expected = vec![0x4d; 1024];
    let supplied = vec![0x4e; 1024];
    let part = ManifestStreamPart {
        chunk: ObjectRef {
            kind: ObjectKind::Chunk,
            digest: hash_chunk(&expected, 67_108_864).unwrap(),
        },
        length: expected.len() as u64,
    };
    let mut source_calls = 0u64;
    let mut source =
        |_index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            source_calls += 1;
            consume(&supplied)
        };
    let error = encode_content_manifest_stream(
        io::sink(),
        3,
        || std::iter::repeat_n(part, 3),
        &chunk_profile(),
        &mut source,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        ManifestStreamLimits {
            max_memory_bytes: 4_096,
            ..ManifestStreamLimits::default()
        },
    )
    .unwrap_err();

    assert_eq!(error.code, ErrorCode::ObjectIdMismatch);
    assert_eq!(source_calls, 3);
}

#[test]
fn manifest_rejects_shape_identity_replay_and_resource_failures() {
    let payload = [7u8; 16];
    let valid_part = ManifestStreamPart {
        chunk: ObjectRef {
            kind: ObjectKind::Chunk,
            digest: hash_chunk(&payload, 67_108_864).unwrap(),
        },
        length: payload.len() as u64,
    };
    let registry = Registry::bundled();
    let mut valid_source =
        |_index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            consume(&payload)
        };

    let error = encode_content_manifest_stream(
        io::sink(),
        1_048_577,
        std::iter::empty,
        &chunk_profile(),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::LimitCount,
            1,
            ValidationStage::ConfiguredResourcePreflight
        )
    );

    for (parts, declared_parts) in [(Vec::new(), 1), (vec![valid_part, valid_part], 1)] {
        let error = encode_content_manifest_stream(
            io::sink(),
            declared_parts,
            || parts.clone(),
            &chunk_profile(),
            &mut valid_source,
            &registry,
            Operation::ConformanceWrite,
            ManifestStreamLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            (error.code, error.layer, error.stage),
            (
                ErrorCode::SchemaFieldInvalid,
                2,
                ValidationStage::KnownSchema
            )
        );
    }

    let maximum_part = ManifestStreamPart {
        chunk: valid_part.chunk,
        length: 67_108_864,
    };
    let final_part = ManifestStreamPart {
        chunk: valid_part.chunk,
        length: 1,
    };
    let mut never_source =
        |_index: u64, _part: &ManifestStreamPart, _consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            panic!("logical maximum-plus-one must fail in the metadata preflight")
        };
    let error = encode_content_manifest_stream(
        io::sink(),
        16_385,
        || std::iter::repeat_n(maximum_part, 16_384).chain(std::iter::once(final_part)),
        &chunk_profile(),
        &mut never_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitLogicalBytes);
    assert_eq!(error.layer, 2);

    let invalid_length = ManifestStreamPart {
        length: 0,
        ..valid_part
    };
    let error = encode_content_manifest_stream(
        io::sink(),
        1,
        || [invalid_length],
        &chunk_profile(),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ManifestChunkLengthInvalid);

    let wrong_kind = ManifestStreamPart {
        chunk: reference(ObjectKind::Tree, b"wrong-kind"),
        ..valid_part
    };
    let error = encode_content_manifest_stream(
        io::sink(),
        1,
        || [wrong_kind],
        &chunk_profile(),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ObjectReferenceKindMismatch);

    let wrong_id = ManifestStreamPart {
        chunk: reference(ObjectKind::Chunk, b"wrong-id"),
        ..valid_part
    };
    let error = encode_content_manifest_stream(
        io::sink(),
        1,
        || [wrong_id],
        &chunk_profile(),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ObjectIdMismatch);

    let expected_one = b"provider-one".to_vec();
    let expected_two = b"provider-two".to_vec();
    let first = ManifestStreamPart {
        chunk: ObjectRef {
            kind: ObjectKind::Chunk,
            digest: hash_chunk(&expected_one, 67_108_864).unwrap(),
        },
        length: 12,
    };
    let second = ManifestStreamPart {
        chunk: ObjectRef {
            kind: ObjectKind::Chunk,
            digest: hash_chunk(&expected_two, 67_108_864).unwrap(),
        },
        length: 12,
    };
    let mut short = expected_one.clone();
    short.pop();
    let mut wrong = expected_two.clone();
    wrong[0] ^= 1;
    for ordered in [
        vec![(first, short.clone()), (second, wrong.clone())],
        vec![(second, wrong.clone()), (first, short.clone())],
    ] {
        let parts = ordered.iter().map(|(part, _)| *part).collect::<Vec<_>>();
        let mut source = |index: u64,
                          _part: &ManifestStreamPart,
                          consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            consume(&ordered[index as usize].1)
        };
        let error = encode_and_verify_content_manifest_stream(
            io::sink(),
            2,
            || parts.clone(),
            &chunk_profile(),
            24,
            sha256(b"provider-oneprovider-two"),
            &mut source,
            &registry,
            Operation::ConformanceWrite,
            ManifestStreamLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::ObjectIdMismatch);
        assert_eq!(error.layer, 1);
    }

    let error = encode_and_verify_content_manifest_stream(
        io::sink(),
        1,
        || [valid_part],
        &chunk_profile(),
        17,
        sha256(&payload),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::ManifestLengthMismatch,
            2,
            ValidationStage::KnownSchema
        )
    );

    let error = encode_and_verify_content_manifest_stream(
        io::sink(),
        1,
        || [valid_part],
        &chunk_profile(),
        16,
        [0; 32],
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ManifestFileDigestMismatch);

    let mut short_source =
        |_index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            consume(&payload[..15])
        };
    let error = encode_content_manifest_stream(
        io::sink(),
        1,
        || [valid_part],
        &chunk_profile(),
        &mut short_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ManifestChunkLengthInvalid);

    let error = encode_content_manifest_stream(
        io::sink(),
        1,
        || [valid_part],
        &chunk_profile(),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits {
            max_memory_bytes: 8,
            ..ManifestStreamLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitMemory);

    let error = encode_content_manifest_stream(
        io::sink(),
        1,
        || [valid_part],
        &chunk_profile(),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits {
            max_logical_bytes: 15,
            ..ManifestStreamLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitLogicalBytes);

    let error = encode_content_manifest_stream(
        io::sink(),
        1,
        || [valid_part],
        &chunk_profile(),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits {
            max_elapsed: Some(Duration::ZERO),
            ..ManifestStreamLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitTime);

    let calls = std::cell::Cell::new(0);
    let error = encode_content_manifest_stream(
        io::sink(),
        1,
        || {
            let call = calls.get();
            calls.set(call + 1);
            if call == 0 {
                vec![valid_part]
            } else {
                Vec::new()
            }
        },
        &chunk_profile(),
        &mut valid_source,
        &registry,
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            2,
            ValidationStage::KnownSchema
        )
    );
}

fn scale_file_id(index: u64) -> [u8; 16] {
    let seed = hex32("a73b9b82eb035d7f2d8bbfa98a94b71be16360dacc1b22a5c2d28bf5fa56fc80");
    for attempt in 0..=u32::MAX {
        let mut preimage = Vec::with_capacity(45);
        preimage.extend_from_slice(&seed);
        preimage.push(0x46);
        preimage.extend_from_slice(&index.to_be_bytes());
        preimage.extend_from_slice(&attempt.to_be_bytes());
        let mut result = [0u8; 16];
        result.copy_from_slice(&sha256(&preimage)[..16]);
        if result != [0; 16] {
            return result;
        }
    }
    panic!("tree FileID recurrence exhausted uint32 attempts")
}

fn scale_tree_entry(index: u64) -> TreeStreamEntry {
    TreeStreamEntry {
        basename: format!("e{index:06}"),
        entry_kind: 2,
        file_id: scale_file_id(index),
        portable_mode: 2,
        target: scale_tree_target(),
        logical_size: 24,
        content_policy: content_policy(),
    }
}

#[cfg(target_os = "linux")]
fn process_max_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    kib.checked_mul(1024)
}

#[cfg(not(target_os = "linux"))]
fn process_max_rss_bytes() -> Option<u64> {
    None
}

fn files_equal(left: &Path, right: &Path) -> io::Result<bool> {
    use std::io::Read;

    let mut left = std::fs::File::open(left)?;
    let mut right = std::fs::File::open(right)?;
    let mut left_buffer = [0u8; 65_536];
    let mut right_buffer = [0u8; 65_536];
    loop {
        let left_read = left.read(&mut left_buffer)?;
        let right_read = right.read(&mut right_buffer)?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256Writer::new();
    let mut buffer = [0u8; 65_536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(hash.finish());
        }
        hash.update(&buffer[..read]);
    }
}

fn validate_scale_report_shape(report: &serde_json::Value) -> io::Result<()> {
    let object = report
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid scale report"))?;
    if object.get("schema").and_then(serde_json::Value::as_str)
        != Some("ogvcs.object-model.rust-scale-report/v1")
        || object
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            != Some("ogvcs-object-model/rust")
        || !matches!(object.get("exactV1Scale"), Some(serde_json::Value::Bool(_)))
        || !matches!(
            object.get("sourceRevision"),
            Some(serde_json::Value::String(_)) | Some(serde_json::Value::Null)
        )
        || !matches!(object.get("recurrence"), Some(serde_json::Value::Object(_)))
        || object
            .get("tree")
            .and_then(|value| value.get("payloadSha256Hex"))
            .and_then(serde_json::Value::as_str)
            .is_none_or(|value| {
                value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        || object
            .get("manifest")
            .and_then(|value| value.get("payloadSha256Hex"))
            .and_then(serde_json::Value::as_str)
            .is_none_or(|value| {
                value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        || !matches!(object.get("process"), Some(serde_json::Value::Object(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid scale report",
        ));
    }
    Ok(())
}

fn serialize_scale_report(report: &serde_json::Value, output: Option<&Path>) -> io::Result<String> {
    validate_scale_report_shape(report)?;
    let mut encoded = serde_json::to_vec(report)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid scale report"))?;
    encoded.push(b'\n');
    if let Some(path) = output {
        let parent = path
            .parent()
            .filter(|candidate| !candidate.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let metadata = std::fs::symlink_metadata(parent)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid report parent",
            ));
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
    }
    String::from_utf8(encoded)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid scale report"))
}

fn github_source_revision() -> Option<String> {
    let revision = std::env::var("GITHUB_SHA").ok()?;
    assert!(
        matches!(revision.len(), 40 | 64) && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "GITHUB_SHA must be a 40- or 64-digit hexadecimal revision"
    );
    Some(revision.to_ascii_lowercase())
}

#[test]
fn scale_implementation_constants_match_the_normative_definitions() {
    let read_json = |relative: &str| {
        serde_json::from_slice::<serde_json::Value>(
            &std::fs::read(Path::new(VECTOR_ROOT).join(relative)).unwrap(),
        )
        .unwrap()
    };
    let tree = read_json("scenarios/definitions/tree-million-entries.json");
    let manifest = read_json("scenarios/definitions/manifest-one-tib.json");
    let tree_case = read_json("scenarios/cases/tree-million-entries.json");
    let manifest_case = read_json("scenarios/cases/manifest-one-tib.json");

    assert_eq!(
        tree.pointer("/exactConstructorValues/scalePlan/recurrence/seed")
            .and_then(serde_json::Value::as_str),
        Some("a73b9b82eb035d7f2d8bbfa98a94b71be16360dacc1b22a5c2d28bf5fa56fc80")
    );
    assert_eq!(
        tree.pointer("/exactConstructorValues/scalePlan/streamCardinality")
            .and_then(serde_json::Value::as_str),
        Some("1000000")
    );
    assert_eq!(
        tree_case.get("requirementIds").unwrap(),
        &serde_json::json!(["OGVCS-002-AC-02", "OGVCS-002-FR-09", "OGVCS-002-NFR-02"])
    );
    assert_eq!(
        manifest_case.get("requirementIds").unwrap(),
        &serde_json::json!(["OGVCS-002-AC-09", "OGVCS-002-FR-09", "OGVCS-002-NFR-02"])
    );

    let plan = manifest
        .pointer("/exactConstructorValues/scalePlan")
        .unwrap();
    assert_eq!(
        plan.pointer("/fixedFields/chunkCount")
            .and_then(serde_json::Value::as_str),
        Some("1048576")
    );
    assert_eq!(
        plan.pointer("/fixedFields/chunkBytes")
            .and_then(serde_json::Value::as_str),
        Some("1048576")
    );
    assert_eq!(
        plan.pointer("/fixedFields/logicalBytes")
            .and_then(serde_json::Value::as_str),
        Some("1099511627776")
    );
    let seed = manifest
        .get("seedHex")
        .and_then(serde_json::Value::as_str)
        .unwrap();
    assert_eq!(
        seed,
        "860f753350ec981c19f401b44ed6a36a0ac76353a5389e31dc36048dd2d78f65"
    );
    let (block, chunk) = repeated_scale_chunk(1_048_576);
    assert_eq!(
        block,
        hex32(
            plan.pointer("/fixedFields/repeatedBlockSha256")
                .and_then(serde_json::Value::as_str)
                .unwrap()
        )
    );
    assert_eq!(
        sha256(&chunk),
        hex32(
            plan.pointer("/fixedFields/rawChunkSha256")
                .and_then(serde_json::Value::as_str)
                .unwrap()
        )
    );
    assert_eq!(
        ObjectRef {
            kind: ObjectKind::Chunk,
            digest: hash_chunk(&chunk, 67_108_864).unwrap(),
        }
        .to_string(),
        plan.pointer("/fixedFields/chunkObjectRef")
            .and_then(serde_json::Value::as_str)
            .unwrap()
    );
}

/// Manual release-mode performance probe for the exact campaign's repeated
/// chunk shape. This hashes 16 GiB rather than 1 TiB, does not write retained
/// evidence, and stays ignored in ordinary and monthly exact-scale gates.
#[test]
#[ignore = "manual 16 GiB repeated-manifest throughput probe"]
fn release_repeated_manifest_throughput_probe() {
    const PARTS: u64 = 16_384;
    const CHUNK_BYTES: usize = 1_048_576;
    const LOGICAL_BYTES: u64 = PARTS * CHUNK_BYTES as u64;
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "run this ignored test with --release"
    );

    let (_, repeated_chunk) = repeated_scale_chunk(CHUNK_BYTES);
    let repeated_part = ManifestStreamPart {
        chunk: ObjectRef {
            kind: ObjectKind::Chunk,
            digest: hash_chunk(&repeated_chunk, 67_108_864).unwrap(),
        },
        length: CHUNK_BYTES as u64,
    };
    let mut provider_reads = 0u64;
    let mut source =
        |_index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            provider_reads += 1;
            for slice in repeated_chunk.chunks(64 * 1024) {
                consume(slice)?;
            }
            Ok(())
        };
    let started = Instant::now();
    let summary = encode_content_manifest_stream(
        io::sink(),
        PARTS,
        || std::iter::repeat_n(repeated_part, PARTS as usize),
        &chunk_profile(),
        &mut source,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        ManifestStreamLimits {
            max_memory_bytes: 64 * 1024 * 1024,
            ..ManifestStreamLimits::default()
        },
    )
    .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(provider_reads, 1);
    assert_eq!(summary.logical_bytes, LOGICAL_BYTES);
    eprintln!(
        "{}",
        serde_json::json!({
            "elapsedNanoseconds": elapsed.as_nanos().to_string(),
            "logicalBytes": LOGICAL_BYTES.to_string(),
            "providerReads": provider_reads,
            "throughputMiBPerSecond": LOGICAL_BYTES as f64 / 1_048_576.0 / elapsed.as_secs_f64()
        })
    );
}

#[test]
fn scale_report_is_canonical_private_and_exclusive() {
    let directory = TestDirectory::new("scale-report");
    let report = serde_json::json!({
        "schema": "ogvcs.object-model.rust-scale-report/v1",
        "implementation": "ogvcs-object-model/rust",
        "exactV1Scale": false,
        "sourceRevision": null,
        "recurrence": { "manifestBlockHex": "00", "manifestSeedHex": "00", "treeSeedHex": "00" },
        "tree": {
            "entries": 2,
            "objectRef": "ogvcs:v1:tree:sha256:test",
            "payloadSha256Hex": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        "manifest": {
            "chunks": 2,
            "contentVerified": true,
            "payloadSha256Hex": "0000000000000000000000000000000000000000000000000000000000000000"
        },
        "process": { "maxRssBytes": null, "maxRssSource": null }
    });
    let path = directory.path().join("report.json");
    let encoded = serialize_scale_report(&report, Some(&path)).unwrap();
    assert_eq!(encoded, std::fs::read_to_string(&path).unwrap());
    assert_eq!(encoded.lines().count(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
        report
    );
    assert!(!encoded.contains(&directory.path().display().to_string()));
    assert!(!encoded.contains("sensitive-payload-marker"));

    let error = serialize_scale_report(&report, Some(&path)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(encoded, std::fs::read_to_string(&path).unwrap());
    let missing = directory.path().join("missing").join("report.json");
    assert_eq!(
        serialize_scale_report(&report, Some(&missing))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn frozen_scale_smoke_matches_javascript_identities() {
    const TREE_ENTRIES: u64 = 10_000;
    const PARTS: u64 = 4_096;
    const CHUNK_BYTES: usize = 4_096;

    let mut tree_bytes = Vec::new();
    let mut file_ids = BTreeSet::new();
    let tree = encode_ordered_tree(
        &mut tree_bytes,
        scale_descriptor(),
        TREE_ENTRIES,
        (0..TREE_ENTRIES).map(scale_tree_entry),
        &Registry::bundled(),
        Operation::ConformanceWrite,
        &mut file_ids,
        TreeStreamLimits::default(),
    )
    .unwrap();
    assert_eq!(tree.payload_bytes, 1_110_054);
    assert_eq!(tree.logical_bytes, 240_000);
    assert_eq!(
        tree.object_ref.to_string(),
        "ogvcs:v1:tree:sha256:ea48c887f4fa49d45a0406f8c5803fb4064d91d506acc757af593698a3a900b9"
    );

    let (block, chunk) = repeated_scale_chunk(CHUNK_BYTES);
    assert_eq!(
        block,
        hex32("8e5a7fde9a212a4bdab640aaa5541de91d981498ac28bc8d8a901722ca807a24")
    );
    let chunk_ref = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: hash_chunk(&chunk, 67_108_864).unwrap(),
    };
    assert_eq!(
        chunk_ref.to_string(),
        "ogvcs:v1:chunk:sha256:5a3ccf5db7f31560087d9cb3da5d6229723f08b978b10ab2d40e796263d2945c"
    );
    let part = ManifestStreamPart {
        chunk: chunk_ref,
        length: CHUNK_BYTES as u64,
    };
    let mut source =
        |_index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            consume(&chunk)
        };
    let mut manifest_bytes = Vec::new();
    let manifest = encode_content_manifest_stream(
        &mut manifest_bytes,
        PARTS,
        || std::iter::repeat_n(part, PARTS as usize),
        &chunk_profile(),
        &mut source,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        ManifestStreamLimits::default(),
    )
    .unwrap();
    assert_eq!(manifest.payload_bytes, 196_704);
    assert_eq!(manifest.logical_bytes, 16_777_216);
    assert_eq!(
        manifest.whole_file_digest,
        hex32("40376d650ae7549f3d575d13ca8ce8ab2a11980d73bcb11912ac1ec79de9d5e6")
    );
    assert_eq!(
        manifest.object_ref.to_string(),
        "ogvcs:v1:content-manifest:sha256:50289bdd220426d316c657279116bdacb0768147a2a98aaa1a3f40cda65a6dd6"
    );
}

/// This test performs the actual acceptance workload. It is ignored in normal
/// test runs because the manifest verifier deliberately reads and hashes the
/// full logical 1 TiB rather than extrapolating a small sample.
#[test]
#[ignore = "real 1,000,000-entry and full logical 1 TiB release-mode scale run"]
fn release_scale_tree_and_one_tib_manifest() {
    const TREE_ENTRIES: u64 = 1_000_000;
    const PARTS: u64 = 1_048_576;
    const CHUNK_BYTES: usize = 1_048_576;
    const ONE_TIB: u64 = 1_099_511_627_776;
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "run this ignored test with --release"
    );

    let directory = TestDirectory::new("real-scale");
    let ordered_path = directory.path().join("ordered-tree.cbor");
    let ordered_started = Instant::now();
    let mut ordered_file_ids =
        TreeFileIdScratchIndex::new(directory.path(), 16 * 1024 * 1024, 128 * 1024 * 1024, None)
            .unwrap();
    let ordered_summary = encode_ordered_tree(
        std::fs::File::create(&ordered_path).unwrap(),
        scale_descriptor(),
        TREE_ENTRIES,
        (0..TREE_ENTRIES).map(scale_tree_entry),
        &Registry::bundled(),
        Operation::ConformanceWrite,
        &mut ordered_file_ids,
        TreeStreamLimits {
            max_memory_bytes: 16 * 1024 * 1024,
            max_scratch_bytes: 0,
            ..TreeStreamLimits::default()
        },
    )
    .unwrap();
    let ordered_file_id_metrics = ordered_file_ids.scratch_metrics();
    let ordered_wall = ordered_started.elapsed();
    assert!(ordered_file_id_metrics.peak_bytes < 1_073_741_824);

    let verify_started = Instant::now();
    let mut verified_file_ids =
        TreeFileIdScratchIndex::new(directory.path(), 16 * 1024 * 1024, 128 * 1024 * 1024, None)
            .unwrap();
    let verified_summary = verify_tree_stream(
        std::fs::File::open(&ordered_path).unwrap(),
        ordered_summary.object_ref,
        scale_descriptor(),
        &Registry::bundled(),
        Operation::ConformanceWrite,
        &mut verified_file_ids,
        TreeStreamLimits {
            max_memory_bytes: 16 * 1024 * 1024,
            max_scratch_bytes: 0,
            ..TreeStreamLimits::default()
        },
    )
    .unwrap();
    let verified_file_id_metrics = verified_file_ids.scratch_metrics();
    let verify_wall = verify_started.elapsed();
    let verify_max_rss = process_max_rss_bytes();
    assert_eq!(verified_summary, ordered_summary);
    assert_eq!(verified_summary.object_ref, ordered_summary.object_ref);
    assert!(verified_file_id_metrics.peak_bytes < 1_073_741_824);
    if let Some(bytes) = verify_max_rss {
        assert!(bytes < 1_073_741_824, "tree verifier max RSS {bytes}");
    }

    let sorted_path = directory.path().join("scratch-tree.cbor");
    let sorted_started = Instant::now();
    let mut scratch = TreeScratchMetrics::default();
    let sorted_summary = encode_tree_with_scratch(
        std::fs::File::create(&sorted_path).unwrap(),
        scale_descriptor(),
        TREE_ENTRIES,
        (0..TREE_ENTRIES).rev().map(scale_tree_entry),
        &Registry::bundled(),
        Operation::ConformanceWrite,
        directory.path(),
        TreeStreamLimits {
            max_memory_bytes: 16 * 1024 * 1024,
            max_scratch_bytes: 768 * 1024 * 1024,
            ..TreeStreamLimits::default()
        },
        &mut scratch,
    )
    .unwrap();
    let sorted_wall = sorted_started.elapsed();
    assert_eq!(sorted_summary, ordered_summary);
    assert!(files_equal(&ordered_path, &sorted_path).unwrap());
    assert!(scratch.peak_bytes < 1_073_741_824);
    let tree_payload_digest = sha256_file(&ordered_path).unwrap();
    assert_eq!(
        tree_payload_digest,
        hex32("2b13fa2c05a014ecc14a2d0e3db3adee5f828f9aa7e223c45357f3ac52d36681")
    );

    let (manifest_block, repeated_chunk) = repeated_scale_chunk(CHUNK_BYTES);
    assert_eq!(
        manifest_block,
        hex32("8e5a7fde9a212a4bdab640aaa5541de91d981498ac28bc8d8a901722ca807a24")
    );
    let raw_chunk_digest = sha256(&repeated_chunk);
    assert_eq!(
        raw_chunk_digest,
        hex32("223066858638b498e56e28ecc6fb8a0cd5d1c7d1ac99c3c4ce286df776bedc3f")
    );
    let repeated_ref = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: hash_chunk(&repeated_chunk, 67_108_864).unwrap(),
    };
    assert_eq!(
        repeated_ref.digest,
        hex32("8d40b35dab2f8ff4305af64230cecf10c9c7616c2ca75e606ced44114aa9224a")
    );
    let repeated_part = ManifestStreamPart {
        chunk: repeated_ref,
        length: CHUNK_BYTES as u64,
    };
    let manifest_path = directory.path().join("one-tib-manifest.cbor");
    let manifest_started = Instant::now();
    let mut manifest_provider_reads = 0u64;
    let mut source =
        |_index: u64, _part: &ManifestStreamPart, consume: &mut dyn FnMut(&[u8]) -> Result<()>| {
            manifest_provider_reads += 1;
            for slice in repeated_chunk.chunks(64 * 1024) {
                consume(slice)?;
            }
            Ok(())
        };
    let manifest_summary = encode_content_manifest_stream(
        std::fs::File::create(&manifest_path).unwrap(),
        PARTS,
        || std::iter::repeat_n(repeated_part, PARTS as usize),
        &chunk_profile(),
        &mut source,
        &Registry::bundled(),
        Operation::ConformanceWrite,
        ManifestStreamLimits {
            max_memory_bytes: 64 * 1024 * 1024,
            ..ManifestStreamLimits::default()
        },
    )
    .unwrap();
    let manifest_wall = manifest_started.elapsed();
    assert_eq!(manifest_provider_reads, 1);
    assert_eq!(manifest_summary.logical_bytes, ONE_TIB);
    let manifest_payload_digest = sha256_file(&manifest_path).unwrap();
    assert_eq!(
        manifest_payload_digest,
        hex32("18fb1ac61e4c4933181dd4e001df9f8fe3069bba145e5aec44d9c7eb75349cd6")
    );

    let max_rss = process_max_rss_bytes();
    if let Some(bytes) = max_rss {
        assert!(bytes < 1_073_741_824, "process max RSS {bytes}");
    }
    let report = serde_json::json!({
        "schema": "ogvcs.object-model.rust-scale-report/v1",
        "implementation": "ogvcs-object-model/rust",
        "exactV1Scale": true,
        "sourceRevision": github_source_revision(),
        "recurrence": {
            "treeSeedHex": "a73b9b82eb035d7f2d8bbfa98a94b71be16360dacc1b22a5c2d28bf5fa56fc80",
            "manifestSeedHex": "860f753350ec981c19f401b44ed6a36a0ac76353a5389e31dc36048dd2d78f65",
            "manifestBlockHex": "8e5a7fde9a212a4bdab640aaa5541de91d981498ac28bc8d8a901722ca807a24"
        },
        "tree": {
                "entries": TREE_ENTRIES,
                "objectRef": ordered_summary.object_ref.to_string(),
                "payloadSha256Hex": hex_lower(&tree_payload_digest),
            "outputBytes": ordered_summary.payload_bytes,
            "logicalBytes": ordered_summary.logical_bytes.to_string(),
            "orderedWallTimeNanoseconds": ordered_wall.as_nanos().to_string(),
            "verifyWallTimeNanoseconds": verify_wall.as_nanos().to_string(),
            "sortedWallTimeNanoseconds": sorted_wall.as_nanos().to_string(),
            "orderedFileIdPeakScratchBytes": ordered_file_id_metrics.peak_bytes,
            "verifyFileIdPeakScratchBytes": verified_file_id_metrics.peak_bytes,
            "verifyFileIdScratchBytesWritten": verified_file_id_metrics.bytes_written,
            "verifyMaxRssBytes": verify_max_rss,
            "sortedPeakScratchBytes": scratch.peak_bytes,
            "sortedScratchBytesWritten": scratch.bytes_written,
            "byteForByteParity": true,
            "fileIdUniqueness": "verified-exact-disk-index"
        },
        "manifest": {
            "chunks": PARTS,
            "chunkBytes": CHUNK_BYTES,
            "chunkObjectRef": repeated_ref.to_string(),
                "rawChunkSha256Hex": hex_lower(&raw_chunk_digest),
                "payloadSha256Hex": hex_lower(&manifest_payload_digest),
            "logicalBytes": manifest_summary.logical_bytes.to_string(),
            "wholeFileDigestHex": hex_lower(&manifest_summary.whole_file_digest),
            "objectRef": manifest_summary.object_ref.to_string(),
            "outputBytes": manifest_summary.payload_bytes,
            "wallTimeNanoseconds": manifest_wall.as_nanos().to_string(),
            "contentVerified": true,
            "providerReads": manifest_provider_reads,
            "verifiedChunkCache": "bounded-half-memory"
        },
        "process": {
            "maxRssBytes": max_rss,
            "maxRssSource": if cfg!(target_os = "linux") {
                serde_json::Value::String("/proc/self/status VmHWM".into())
            } else {
                serde_json::Value::Null
            }
        }
    });
    let output = std::env::var_os("OGVCS_SCALE_REPORT_PATH").map(PathBuf::from);
    let encoded = serialize_scale_report(&report, output.as_deref()).unwrap();
    print!("{encoded}");
}
