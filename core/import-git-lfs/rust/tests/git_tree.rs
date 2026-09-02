use std::sync::{atomic::AtomicBool, Arc};

use ogvcs_git_import_preflight::{
    decode_git_tree_frame, GitObjectFormat, GitTreeEntryMode, GitTreeErrorCode, GitTreeFrame,
    GitTreeLimits, OperationControl, GIT_TREE_ENTRIES_HARD_MAXIMUM,
    GIT_TREE_FRAME_BYTES_HARD_MAXIMUM, GIT_TREE_NAME_BYTES_HARD_MAXIMUM,
    GIT_TREE_RETAINED_BYTES_HARD_MAXIMUM, GIT_TREE_TOTAL_NAME_BYTES_HARD_MAXIMUM,
    GIT_TREE_WORK_UNITS_HARD_MAXIMUM,
};
use ogvcs_object_model::sha256;

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut frame = format!("tree {}\0", payload.len()).into_bytes();
    frame.extend_from_slice(payload);
    frame
}

fn entry(payload: &mut Vec<u8>, mode: &str, name: &[u8], oid_byte: u8, width: usize) {
    payload.extend_from_slice(mode.as_bytes());
    payload.push(b' ');
    payload.extend_from_slice(name);
    payload.push(0);
    payload.extend(std::iter::repeat_n(oid_byte, width));
}

fn decode(
    bytes: &[u8],
    format: GitObjectFormat,
) -> Result<ogvcs_git_import_preflight::GitTreeProjection, ogvcs_git_import_preflight::GitTreeError>
{
    decode_with_limits(bytes, format, GitTreeLimits::default())
}

fn decode_with_limits(
    bytes: &[u8],
    format: GitObjectFormat,
    limits: GitTreeLimits,
) -> Result<ogvcs_git_import_preflight::GitTreeProjection, ogvcs_git_import_preflight::GitTreeError>
{
    decode_git_tree_frame(
        GitTreeFrame {
            bytes,
            staged_sha256: sha256(bytes),
            object_format: format,
        },
        limits,
        &OperationControl::default(),
    )
}

fn error_for(bytes: &[u8], format: GitObjectFormat) -> GitTreeErrorCode {
    decode(bytes, format)
        .expect_err("hostile frame unexpectedly decoded")
        .code()
}

#[test]
fn empty_mixed_mode_and_sha256_width_frames_decode_exactly() {
    let empty = framed(&[]);
    let decoded = decode(&empty, GitObjectFormat::Sha1).unwrap();
    assert!(decoded.entries().is_empty());
    assert_eq!(decoded.ledger().payload_bytes, 0);

    let mut payload = Vec::new();
    entry(&mut payload, "40000", b"alpha", 1, 20);
    entry(&mut payload, "100644", b"beta", 2, 20);
    entry(&mut payload, "100755", b"delta", 3, 20);
    entry(&mut payload, "120000", b"epsilon", 4, 20);
    entry(&mut payload, "160000", b"gamma", 5, 20);
    entry(&mut payload, "100644", &[0xff, b'z'], 6, 20);
    let frame = framed(&payload);
    let decoded = decode(&frame, GitObjectFormat::Sha1).unwrap();
    assert_eq!(decoded.object_format(), GitObjectFormat::Sha1);
    assert_eq!(decoded.staged_sha256(), sha256(&frame));
    assert_eq!(decoded.entries().len(), 6);
    assert_eq!(decoded.entries()[0].mode(), GitTreeEntryMode::Tree);
    assert_eq!(decoded.entries()[1].mode(), GitTreeEntryMode::Regular);
    assert_eq!(decoded.entries()[2].mode(), GitTreeEntryMode::Executable);
    assert_eq!(decoded.entries()[3].mode(), GitTreeEntryMode::Symlink);
    assert_eq!(decoded.entries()[4].mode(), GitTreeEntryMode::Gitlink);
    assert_eq!(decoded.entries()[5].name(), &[0xff, b'z']);
    assert_eq!(decoded.entries()[0].object_id().algorithm(), "sha1");

    let mut sha256_payload = Vec::new();
    entry(&mut sha256_payload, "100644", b"asset.bin", 9, 32);
    let sha256_frame = framed(&sha256_payload);
    let decoded = decode(&sha256_frame, GitObjectFormat::Sha256).unwrap();
    assert_eq!(decoded.entries()[0].object_id().algorithm(), "sha256");
    assert_eq!(
        decoded.entries()[0].object_id().sha256_bytes(),
        Some(&[9; 32])
    );
}

#[test]
fn git_directory_ordering_duplicate_and_unsorted_entries_fail_closed() {
    let mut canonical = Vec::new();
    entry(&mut canonical, "100644", b"foo.bar", 1, 20);
    entry(&mut canonical, "40000", b"foo", 2, 20);
    let decoded = decode(&framed(&canonical), GitObjectFormat::Sha1).unwrap();
    assert_eq!(decoded.entries()[0].name(), b"foo.bar");
    assert_eq!(decoded.entries()[1].name(), b"foo");

    let mut reversed = Vec::new();
    entry(&mut reversed, "40000", b"foo", 2, 20);
    entry(&mut reversed, "100644", b"foo.bar", 1, 20);
    let error = decode(&framed(&reversed), GitObjectFormat::Sha1).unwrap_err();
    assert_eq!(error.code(), GitTreeErrorCode::EntryOrderInvalid);
    assert_eq!(error.entry_ordinal(), Some(1));

    let mut duplicate = Vec::new();
    entry(&mut duplicate, "100644", b"same", 1, 20);
    entry(&mut duplicate, "40000", b"same", 2, 20);
    let error = decode(&framed(&duplicate), GitObjectFormat::Sha1).unwrap_err();
    assert_eq!(error.code(), GitTreeErrorCode::EntryDuplicate);
    assert_eq!(error.entry_ordinal(), Some(1));

    let mut file_prefix = Vec::new();
    entry(&mut file_prefix, "100644", b"foo", 1, 20);
    entry(&mut file_prefix, "100644", b"foo.bar", 2, 20);
    assert!(decode(&framed(&file_prefix), GitObjectFormat::Sha1).is_ok());

    let mut separated_duplicate = Vec::new();
    entry(&mut separated_duplicate, "100644", b"foo", 1, 20);
    entry(&mut separated_duplicate, "100644", b"foo.bar", 2, 20);
    entry(&mut separated_duplicate, "40000", b"foo", 3, 20);
    let error = decode(&framed(&separated_duplicate), GitObjectFormat::Sha1).unwrap_err();
    assert_eq!(error.code(), GitTreeErrorCode::EntryDuplicate);
    assert_eq!(error.entry_ordinal(), Some(2));

    let mut upstream_chain = Vec::new();
    entry(&mut upstream_chain, "100644", b"foo", 1, 20);
    entry(&mut upstream_chain, "100644", b"foo.bar", 2, 20);
    entry(&mut upstream_chain, "100644", b"foo.bar.baz", 3, 20);
    entry(&mut upstream_chain, "40000", b"foo.bar", 4, 20);
    entry(&mut upstream_chain, "40000", b"foo", 5, 20);
    let error = decode(&framed(&upstream_chain), GitObjectFormat::Sha1).unwrap_err();
    assert_eq!(error.code(), GitTreeErrorCode::EntryDuplicate);
    assert_eq!(error.entry_ordinal(), Some(3));

    let mut candidate_repush_without_duplicate = Vec::new();
    entry(
        &mut candidate_repush_without_duplicate,
        "100644",
        b"foo",
        1,
        20,
    );
    entry(
        &mut candidate_repush_without_duplicate,
        "100644",
        b"foo.bar.baz",
        2,
        20,
    );
    entry(
        &mut candidate_repush_without_duplicate,
        "40000",
        b"foo.bar",
        3,
        20,
    );
    assert!(decode(
        &framed(&candidate_repush_without_duplicate),
        GitObjectFormat::Sha1
    )
    .is_ok());
}

#[test]
fn git_metadata_names_and_platform_aliases_fail_closed() {
    let protected_positive: &[&[u8]] = &[
        b".git",
        b".GIT",
        b".git . . ",
        b"git~1",
        b"GIT~1... ",
        b".git::$INDEX_ALLOCATION",
        b".git\\child",
        b"prefix\\.git",
        b".git\xff",
    ];
    for name in protected_positive {
        let mut payload = Vec::new();
        entry(&mut payload, "100644", name, 1, 20);
        let error = decode(&framed(&payload), GitObjectFormat::Sha1).unwrap_err();
        assert_eq!(
            error.code(),
            GitTreeErrorCode::NameGitMetadataAlias,
            "{name:?}"
        );
        assert_eq!(error.entry_ordinal(), Some(0));
    }

    let ntfs_negative: &[&[u8]] = &[b".gitx", b".git x", b"git~2", b"git~1x", b"prefix.git"];
    for name in ntfs_negative {
        let mut payload = Vec::new();
        entry(&mut payload, "100644", name, 1, 20);
        assert!(
            decode(&framed(&payload), GitObjectFormat::Sha1).is_ok(),
            "{name:?}"
        );
    }

    let ignored = [
        '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}',
        '\u{202d}', '\u{202e}', '\u{206a}', '\u{206b}', '\u{206c}', '\u{206d}', '\u{206e}',
        '\u{206f}', '\u{feff}',
    ];
    for character in ignored {
        for boundary in 0..=4 {
            let mut name = ".GiT".to_owned();
            name.insert(boundary, character);
            let mut payload = Vec::new();
            entry(&mut payload, "100644", name.as_bytes(), 1, 20);
            let error = decode(&framed(&payload), GitObjectFormat::Sha1).unwrap_err();
            assert_eq!(
                error.code(),
                GitTreeErrorCode::NameGitMetadataAlias,
                "{name:?}"
            );
            assert_eq!(error.entry_ordinal(), Some(0));
        }
    }

    for name in [
        ".\u{200b}git".as_bytes(),
        b".gitx".as_slice(),
        b".\xffgit".as_slice(),
        b".gitx\xff".as_slice(),
    ] {
        let mut payload = Vec::new();
        entry(&mut payload, "100644", name, 1, 20);
        assert!(
            decode(&framed(&payload), GitObjectFormat::Sha1).is_ok(),
            "{name:?}"
        );
    }
}

#[test]
fn staged_digest_header_and_object_format_substitution_are_rejected() {
    let mut payload = Vec::new();
    entry(&mut payload, "100644", b"file", 1, 20);
    let frame = framed(&payload);
    let mut substituted = sha256(&frame);
    substituted[0] ^= 1;
    let error = decode_git_tree_frame(
        GitTreeFrame {
            bytes: &frame,
            staged_sha256: substituted,
            object_format: GitObjectFormat::Sha1,
        },
        GitTreeLimits::default(),
        &OperationControl::default(),
    )
    .unwrap_err();
    assert_eq!(error.code(), GitTreeErrorCode::StagedDigestMismatch);

    assert_eq!(
        error_for(&frame, GitObjectFormat::Sha256),
        GitTreeErrorCode::ObjectIdTruncated
    );

    let empty = framed(&[]);
    let sha1 = decode(&empty, GitObjectFormat::Sha1).unwrap();
    let sha256 = decode(&empty, GitObjectFormat::Sha256).unwrap();
    assert_ne!(sha1.request_commitment(), sha256.request_commitment());
    assert_ne!(sha1.projection_commitment(), sha256.projection_commitment());
    let narrowed = decode_with_limits(
        &empty,
        GitObjectFormat::Sha1,
        GitTreeLimits {
            frame_bytes_maximum: u64::try_from(empty.len()).unwrap(),
            ..GitTreeLimits::default()
        },
    )
    .unwrap();
    assert_ne!(sha1.request_commitment(), narrowed.request_commitment());

    let mut alternate_payload = Vec::new();
    entry(&mut alternate_payload, "100644", b"file", 2, 20);
    let original = decode(&frame, GitObjectFormat::Sha1).unwrap();
    let alternate = decode(&framed(&alternate_payload), GitObjectFormat::Sha1).unwrap();
    assert_ne!(
        original.request_commitment(),
        alternate.request_commitment()
    );

    for (bytes, expected) in [
        (&b""[..], GitTreeErrorCode::HeaderTypeInvalid),
        (&b"blob 0\0"[..], GitTreeErrorCode::HeaderTypeInvalid),
        (&b"tree\t0\0"[..], GitTreeErrorCode::HeaderFramingInvalid),
        (&b"tree \0"[..], GitTreeErrorCode::HeaderSizeInvalid),
        (&b"tree 00\0"[..], GitTreeErrorCode::HeaderSizeInvalid),
        (&b"tree +0\0"[..], GitTreeErrorCode::HeaderSizeInvalid),
        (&b"tree 1\0"[..], GitTreeErrorCode::HeaderSizeInvalid),
        (&b"tree 0\0x"[..], GitTreeErrorCode::HeaderSizeInvalid),
        (
            &b"tree 18446744073709551616\0"[..],
            GitTreeErrorCode::HeaderSizeInvalid,
        ),
        (
            &b"tree 184467440737095516150\0"[..],
            GitTreeErrorCode::HeaderFramingInvalid,
        ),
    ] {
        assert_eq!(
            error_for(bytes, GitObjectFormat::Sha1),
            expected,
            "{bytes:?}"
        );
    }
}

#[test]
fn malformed_modes_names_and_object_ids_are_typed_and_terminal() {
    let cases = [
        (
            {
                let mut value = Vec::new();
                entry(&mut value, "100600", b"file", 1, 20);
                value
            },
            GitTreeErrorCode::ModeUnsupported,
        ),
        (
            {
                let mut value = Vec::new();
                entry(&mut value, "10x644", b"file", 1, 20);
                value
            },
            GitTreeErrorCode::ModeFramingInvalid,
        ),
        (
            {
                let mut value = Vec::new();
                entry(&mut value, "100644", b"", 1, 20);
                value
            },
            GitTreeErrorCode::NameInvalid,
        ),
        (
            {
                let mut value = Vec::new();
                entry(&mut value, "100644", b".", 1, 20);
                value
            },
            GitTreeErrorCode::NameInvalid,
        ),
        (
            {
                let mut value = Vec::new();
                entry(&mut value, "100644", b"..", 1, 20);
                value
            },
            GitTreeErrorCode::NameInvalid,
        ),
        (
            {
                let mut value = Vec::new();
                entry(&mut value, "100644", b"a/b", 1, 20);
                value
            },
            GitTreeErrorCode::NameInvalid,
        ),
        (
            {
                let mut value = b"100644 file\0".to_vec();
                value.extend_from_slice(&[1; 19]);
                value
            },
            GitTreeErrorCode::ObjectIdTruncated,
        ),
        (
            {
                let mut value = b"100644 file\0".to_vec();
                value.extend_from_slice(&[0; 20]);
                value
            },
            GitTreeErrorCode::ObjectIdZero,
        ),
        (
            b"100644 file-without-nul".to_vec(),
            GitTreeErrorCode::NameInvalid,
        ),
    ];
    for (payload, expected) in cases {
        let error = decode(&framed(&payload), GitObjectFormat::Sha1).unwrap_err();
        assert_eq!(error.code(), expected, "{payload:?}");
        assert_eq!(error.entry_ordinal(), Some(0));
    }
}

#[test]
fn configurable_limits_accept_exact_boundary_and_reject_one_more() {
    let mut payload = Vec::new();
    entry(&mut payload, "100644", b"aa", 1, 20);
    entry(&mut payload, "100644", b"bbbb", 2, 20);
    let frame = framed(&payload);
    let defaults = GitTreeLimits::default();

    let exact_frame = GitTreeLimits {
        frame_bytes_maximum: u64::try_from(frame.len()).unwrap(),
        ..defaults
    };
    assert!(decode_with_limits(&frame, GitObjectFormat::Sha1, exact_frame).is_ok());
    assert_eq!(
        decode_with_limits(
            &frame,
            GitObjectFormat::Sha1,
            GitTreeLimits {
                frame_bytes_maximum: exact_frame.frame_bytes_maximum - 1,
                ..defaults
            }
        )
        .unwrap_err()
        .code(),
        GitTreeErrorCode::LimitFrameBytes
    );

    assert!(decode_with_limits(
        &frame,
        GitObjectFormat::Sha1,
        GitTreeLimits {
            entries_maximum: 2,
            ..defaults
        }
    )
    .is_ok());
    assert_eq!(
        decode_with_limits(
            &frame,
            GitObjectFormat::Sha1,
            GitTreeLimits {
                entries_maximum: 1,
                ..defaults
            }
        )
        .unwrap_err()
        .code(),
        GitTreeErrorCode::LimitEntries
    );

    assert!(decode_with_limits(
        &frame,
        GitObjectFormat::Sha1,
        GitTreeLimits {
            name_bytes_maximum: 4,
            ..defaults
        }
    )
    .is_ok());
    assert_eq!(
        decode_with_limits(
            &frame,
            GitObjectFormat::Sha1,
            GitTreeLimits {
                name_bytes_maximum: 3,
                ..defaults
            }
        )
        .unwrap_err()
        .code(),
        GitTreeErrorCode::LimitNameBytes
    );

    assert!(decode_with_limits(
        &frame,
        GitObjectFormat::Sha1,
        GitTreeLimits {
            total_name_bytes_maximum: 6,
            ..defaults
        }
    )
    .is_ok());
    assert_eq!(
        decode_with_limits(
            &frame,
            GitObjectFormat::Sha1,
            GitTreeLimits {
                total_name_bytes_maximum: 5,
                ..defaults
            }
        )
        .unwrap_err()
        .code(),
        GitTreeErrorCode::LimitTotalNameBytes
    );

    let baseline = decode(&frame, GitObjectFormat::Sha1).unwrap();
    let exact_work = baseline.ledger().work_units;
    assert!(decode_with_limits(
        &frame,
        GitObjectFormat::Sha1,
        GitTreeLimits {
            work_units_maximum: exact_work,
            ..defaults
        }
    )
    .is_ok());
    assert_eq!(
        decode_with_limits(
            &frame,
            GitObjectFormat::Sha1,
            GitTreeLimits {
                work_units_maximum: exact_work - 1,
                ..defaults
            }
        )
        .unwrap_err()
        .code(),
        GitTreeErrorCode::LimitWork
    );

    let exact_retained = baseline.ledger().admitted_retained_bytes;
    assert!(decode_with_limits(
        &frame,
        GitObjectFormat::Sha1,
        GitTreeLimits {
            retained_bytes_maximum: exact_retained,
            ..defaults
        }
    )
    .is_ok());
    assert_eq!(
        decode_with_limits(
            &frame,
            GitObjectFormat::Sha1,
            GitTreeLimits {
                retained_bytes_maximum: exact_retained - 1,
                ..defaults
            }
        )
        .unwrap_err()
        .code(),
        GitTreeErrorCode::LimitRetainedBytes
    );
}

#[test]
fn hard_frame_entry_and_name_boundaries_are_enforced() {
    let mut maximum_frame_payload = Vec::new();
    let target_payload = usize::try_from(GIT_TREE_FRAME_BYTES_HARD_MAXIMUM).unwrap() - 13;
    let entries = 256usize;
    let target_names = target_payload - entries * (7 + 1 + 20);
    let base_name = target_names / entries;
    let longer = target_names % entries;
    for index in 0..entries {
        let length = base_name + usize::from(index < longer);
        let mut name = format!("{index:04x}").into_bytes();
        name.resize(length, b'x');
        entry(
            &mut maximum_frame_payload,
            "100644",
            &name,
            u8::try_from(index % 255 + 1).unwrap(),
            20,
        );
    }
    let maximum_frame = framed(&maximum_frame_payload);
    assert_eq!(
        u64::try_from(maximum_frame.len()).unwrap(),
        GIT_TREE_FRAME_BYTES_HARD_MAXIMUM
    );
    assert!(decode(&maximum_frame, GitObjectFormat::Sha1).is_ok());
    let mut oversized_frame = maximum_frame;
    oversized_frame.push(b'x');
    assert_eq!(
        error_for(&oversized_frame, GitObjectFormat::Sha1),
        GitTreeErrorCode::LimitFrameBytes
    );

    let mut maximum_entries = Vec::new();
    for index in 0..usize::try_from(GIT_TREE_ENTRIES_HARD_MAXIMUM).unwrap() {
        let name = format!("{index:05x}");
        entry(
            &mut maximum_entries,
            "100644",
            name.as_bytes(),
            u8::try_from(index % 255 + 1).unwrap(),
            20,
        );
    }
    assert_eq!(
        decode(&framed(&maximum_entries), GitObjectFormat::Sha1)
            .unwrap()
            .ledger()
            .entries,
        GIT_TREE_ENTRIES_HARD_MAXIMUM
    );
    entry(&mut maximum_entries, "100644", b"10000", 1, 20);
    assert_eq!(
        error_for(&framed(&maximum_entries), GitObjectFormat::Sha1),
        GitTreeErrorCode::LimitEntries
    );

    let mut maximum_name = Vec::new();
    entry(
        &mut maximum_name,
        "100644",
        &vec![b'x'; usize::try_from(GIT_TREE_NAME_BYTES_HARD_MAXIMUM).unwrap()],
        1,
        20,
    );
    assert!(decode(&framed(&maximum_name), GitObjectFormat::Sha1).is_ok());
    let mut oversized_name = Vec::new();
    entry(
        &mut oversized_name,
        "100644",
        &vec![b'x'; usize::try_from(GIT_TREE_NAME_BYTES_HARD_MAXIMUM).unwrap() + 1],
        1,
        20,
    );
    assert_eq!(
        error_for(&framed(&oversized_name), GitObjectFormat::Sha1),
        GitTreeErrorCode::LimitNameBytes
    );
}

#[test]
fn hard_limit_configuration_cannot_be_broadened() {
    let empty = framed(&[]);
    let defaults = GitTreeLimits::default();
    for limits in [
        GitTreeLimits {
            frame_bytes_maximum: GIT_TREE_FRAME_BYTES_HARD_MAXIMUM + 1,
            ..defaults
        },
        GitTreeLimits {
            entries_maximum: GIT_TREE_ENTRIES_HARD_MAXIMUM + 1,
            ..defaults
        },
        GitTreeLimits {
            name_bytes_maximum: GIT_TREE_NAME_BYTES_HARD_MAXIMUM + 1,
            ..defaults
        },
        GitTreeLimits {
            total_name_bytes_maximum: GIT_TREE_TOTAL_NAME_BYTES_HARD_MAXIMUM + 1,
            ..defaults
        },
        GitTreeLimits {
            work_units_maximum: GIT_TREE_WORK_UNITS_HARD_MAXIMUM + 1,
            ..defaults
        },
        GitTreeLimits {
            retained_bytes_maximum: GIT_TREE_RETAINED_BYTES_HARD_MAXIMUM + 1,
            ..defaults
        },
        GitTreeLimits {
            entries_maximum: 0,
            ..defaults
        },
    ] {
        assert_eq!(
            decode_with_limits(&empty, GitObjectFormat::Sha1, limits)
                .unwrap_err()
                .code(),
            GitTreeErrorCode::InvalidLimits
        );
    }
}

#[test]
fn cancellation_replay_hostile_bytes_and_debug_are_safe() {
    let mut payload = Vec::new();
    entry(&mut payload, "100644", b"secret-name", 0xab, 20);
    let frame = framed(&payload);
    let first = decode(&frame, GitObjectFormat::Sha1).unwrap();
    let second = decode(&frame, GitObjectFormat::Sha1).unwrap();
    assert_eq!(first, second);

    let frame_debug = format!(
        "{:?}",
        GitTreeFrame {
            bytes: &frame,
            staged_sha256: sha256(&frame),
            object_format: GitObjectFormat::Sha1,
        }
    );
    let projection_debug = format!("{first:?}");
    let entry_debug = format!("{:?}", first.entries()[0]);
    assert!(!frame_debug.contains("secret-name"));
    assert!(!projection_debug.contains("secret-name"));
    assert!(!projection_debug.contains("abababab"));
    assert!(!entry_debug.contains("secret-name"));
    assert!(!entry_debug.contains("abababab"));

    let cancellation = Arc::new(AtomicBool::new(true));
    let error = decode_git_tree_frame(
        GitTreeFrame {
            bytes: &frame,
            staged_sha256: sha256(&frame),
            object_format: GitObjectFormat::Sha1,
        },
        GitTreeLimits::default(),
        &OperationControl::with_cancellation(cancellation),
    )
    .unwrap_err();
    assert_eq!(error.code(), GitTreeErrorCode::Cancelled);

    let mut state = 0x9e37_79b9u32;
    for length in 0..256usize {
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            bytes.push(state.to_le_bytes()[0]);
        }
        assert_eq!(
            decode(&bytes, GitObjectFormat::Sha1),
            decode(&bytes, GitObjectFormat::Sha1)
        );
        assert_eq!(
            decode(&bytes, GitObjectFormat::Sha256),
            decode(&bytes, GitObjectFormat::Sha256)
        );
    }
}
