mod support;

use ogvcs_git_import_preflight::{
    classify_lfs_pointer, PointerClassification, PointerErrorCode, GIT_LFS_POINTER_BYTES_MAXIMUM,
};
use support::{canonical_pointer, digest, extension_pointer, hex};

#[test]
fn canonical_v1_known_answer_is_classified() {
    let pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\nsize 12345\n";
    let classified = classify_lfs_pointer(pointer).unwrap();
    let PointerClassification::Canonical(pointer) = classified else {
        panic!("expected canonical pointer");
    };
    assert_eq!(
        pointer.oid.to_hex(),
        "4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393"
    );
    assert_eq!(pointer.size, 12_345);
    assert!(pointer.extensions.is_empty());
}

#[test]
fn empty_file_is_passed_through_not_substituted() {
    assert_eq!(
        classify_lfs_pointer(b"").unwrap(),
        PointerClassification::NotPointer
    );
}

#[test]
fn ordinary_short_and_large_bytes_are_not_pointers() {
    assert_eq!(
        classify_lfs_pointer(b"ordinary content\n").unwrap(),
        PointerClassification::NotPointer
    );
    assert_eq!(
        classify_lfs_pointer(&vec![b'x'; 1_024]).unwrap(),
        PointerClassification::NotPointer
    );
}

#[test]
fn exact_cutoff_is_parsed_and_cutoff_plus_one_is_unconditionally_not_a_pointer() {
    let content = b"x";
    let mut pointer = canonical_pointer(content);
    let padding = GIT_LFS_POINTER_BYTES_MAXIMUM - pointer.len();
    let newline = pointer.pop().unwrap();
    pointer.extend(std::iter::repeat(b' ').take(padding));
    pointer.push(newline);
    assert!(matches!(
        classify_lfs_pointer(&pointer).unwrap_err().code(),
        PointerErrorCode::NonCanonical | PointerErrorCode::SizeInvalid
    ));
    pointer.push(b'x');
    assert_eq!(
        classify_lfs_pointer(&pointer).unwrap(),
        PointerClassification::NotPointer
    );
}

#[test]
fn oversized_prefix_and_interior_lfs_markers_are_ordinary_blob_content() {
    let mut interior = vec![b'x'; 1_024];
    interior[500..507].copy_from_slice(b"git-lfs");
    assert_eq!(
        classify_lfs_pointer(&interior).unwrap(),
        PointerClassification::NotPointer
    );

    let mut prefix = b"version https://git-lfs.github.com/spec/v1\n".to_vec();
    prefix.resize(1_024, b'x');
    assert_eq!(
        classify_lfs_pointer(&prefix).unwrap(),
        PointerClassification::NotPointer
    );
}

#[test]
fn missing_trailing_lf_and_crlf_are_noncanonical() {
    let mut missing = canonical_pointer(b"x");
    missing.pop();
    assert_eq!(
        classify_lfs_pointer(&missing).unwrap_err().code(),
        PointerErrorCode::NonCanonical
    );
    let crlf = String::from_utf8(canonical_pointer(b"x"))
        .unwrap()
        .replace('\n', "\r\n");
    assert_eq!(
        classify_lfs_pointer(crlf.as_bytes()).unwrap_err().code(),
        PointerErrorCode::NonCanonical
    );
}

#[test]
fn legacy_alias_is_readable_in_git_lfs_but_rejected_as_noncanonical_here() {
    let legacy = String::from_utf8(canonical_pointer(b"x")).unwrap().replace(
        "https://git-lfs.github.com/spec/v1",
        "https://hawser.github.com/spec/v1",
    );
    assert_eq!(
        classify_lfs_pointer(legacy.as_bytes()).unwrap_err().code(),
        PointerErrorCode::NonCanonical
    );
}

#[test]
fn unknown_version_is_rejected() {
    let unknown = String::from_utf8(canonical_pointer(b"x"))
        .unwrap()
        .replace("spec/v1", "spec/v2");
    assert_eq!(
        classify_lfs_pointer(unknown.as_bytes()).unwrap_err().code(),
        PointerErrorCode::VersionUnsupported
    );
}

#[test]
fn generic_short_version_text_without_an_lfs_marker_is_not_a_pointer() {
    assert_eq!(
        classify_lfs_pointer(b"version 1.0\n").unwrap(),
        PointerClassification::NotPointer
    );
}

#[test]
fn oid_requires_sha256_lowercase_and_exact_length() {
    let canonical = String::from_utf8(canonical_pointer(b"x")).unwrap();
    for invalid in [
        canonical.replace("sha256:", "sha1:"),
        canonical.replace(&hex(&digest(b"x")), &"a".repeat(63)),
        canonical.replace('a', "A"),
    ] {
        assert!(matches!(
            classify_lfs_pointer(invalid.as_bytes()).unwrap_err().code(),
            PointerErrorCode::OidInvalid | PointerErrorCode::NonCanonical
        ));
    }
}

#[test]
fn size_has_unique_positive_i64_encoding() {
    let canonical = String::from_utf8(canonical_pointer(b"x")).unwrap();
    for replacement in ["01", "+1", "-1", "0", "9223372036854775808"] {
        let invalid = canonical.replace("size 1", &format!("size {replacement}"));
        assert!(matches!(
            classify_lfs_pointer(invalid.as_bytes()).unwrap_err().code(),
            PointerErrorCode::SizeInvalid | PointerErrorCode::NonCanonical
        ));
    }
}

#[test]
fn exactly_one_space_is_required() {
    let canonical = String::from_utf8(canonical_pointer(b"x")).unwrap();
    let two = canonical.replace("oid sha256", "oid  sha256");
    assert_eq!(
        classify_lfs_pointer(two.as_bytes()).unwrap_err().code(),
        PointerErrorCode::NonCanonical
    );
}

#[test]
fn required_keys_must_be_sorted_and_unique() {
    let canonical = String::from_utf8(canonical_pointer(b"x")).unwrap();
    let lines: Vec<_> = canonical.lines().collect();
    let reordered = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]);
    assert_eq!(
        classify_lfs_pointer(reordered.as_bytes())
            .unwrap_err()
            .code(),
        PointerErrorCode::NonCanonical
    );
    let duplicate = format!(
        "{}{}",
        canonical,
        &canonical[canonical.find("oid ").unwrap()..]
    );
    assert!(classify_lfs_pointer(duplicate.as_bytes()).is_err());
}

#[test]
fn canonical_extension_is_preserved_in_priority_order() {
    let pointer = extension_pointer(b"encrypted");
    let PointerClassification::Canonical(parsed) = classify_lfs_pointer(&pointer).unwrap() else {
        panic!("expected pointer");
    };
    assert_eq!(parsed.extensions.len(), 1);
    assert_eq!(parsed.extensions[0].priority, 0);
    assert_eq!(parsed.extensions[0].name, "crypt");
}

#[test]
fn duplicate_extension_priorities_are_rejected() {
    let content = b"x";
    let oid = hex(&digest(content));
    let pointer = format!(
        "version https://git-lfs.github.com/spec/v1\next-0-a sha256:{oid}\next-0-b sha256:{oid}\noid sha256:{oid}\nsize 1\n"
    );
    assert_eq!(
        classify_lfs_pointer(pointer.as_bytes()).unwrap_err().code(),
        PointerErrorCode::DuplicateExtensionPriority
    );
}

#[test]
fn reference_extension_names_preserve_word_case_underscore_and_suffix_punctuation() {
    let canonical = String::from_utf8(extension_pointer(b"x")).unwrap();
    for name in [
        "Crypt",
        "crypt_name",
        "crypt-name",
        "crypt.name",
        "a@b",
        "aé",
    ] {
        let encoded = canonical.replace("ext-0-crypt", &format!("ext-0-{name}"));
        let PointerClassification::Canonical(pointer) =
            classify_lfs_pointer(encoded.as_bytes()).unwrap()
        else {
            panic!("expected canonical extension pointer");
        };
        assert_eq!(pointer.extensions[0].name, name);
    }
}

#[test]
fn extension_priority_and_reference_word_prefix_remain_bounded() {
    let canonical = String::from_utf8(extension_pointer(b"x")).unwrap();
    for invalid in [
        canonical.replace("ext-0-crypt", "ext-10-crypt"),
        canonical.replace("ext-0-crypt", "ext-0-.crypt"),
        canonical.replace("ext-0-crypt", "ext-0-écrypt"),
    ] {
        assert_eq!(
            classify_lfs_pointer(invalid.as_bytes()).unwrap_err().code(),
            PointerErrorCode::ExtensionInvalid
        );
    }
}

#[test]
fn invalid_utf8_in_advertised_pointer_is_rejected() {
    let mut bytes = canonical_pointer(b"x");
    bytes[10] = 0xff;
    assert_eq!(
        classify_lfs_pointer(&bytes).unwrap_err().code(),
        PointerErrorCode::Utf8Invalid
    );
}

#[test]
fn lfs_marker_after_first_hundred_bytes_is_still_fail_closed() {
    let mut bytes = vec![b'x'; 101];
    bytes.extend_from_slice(b" git-lfs malformed\n");
    assert_eq!(
        classify_lfs_pointer(&bytes).unwrap_err().code(),
        PointerErrorCode::Malformed
    );
}

#[test]
fn classification_of_large_ordinary_blob_has_a_fixed_inspection_window() {
    let mut bytes = vec![b'x'; 1_048_576];
    bytes[1_040_000..1_040_007].copy_from_slice(b"git-lfs");
    assert_eq!(
        classify_lfs_pointer(&bytes).unwrap(),
        PointerClassification::NotPointer
    );
}
