use std::str::FromStr;

use ogvcs_git_import_preflight::{GitObjectId, GitObjectIdErrorCode};

#[test]
fn sha1_known_answer_round_trips() {
    let text = "sha1:0123456789abcdef0123456789abcdef01234567";
    let oid = GitObjectId::from_str(text).unwrap();
    assert_eq!(oid.to_string(), text);
    assert_eq!(oid.algorithm(), "sha1");
    assert_eq!(oid.byte_len(), 20);
}

#[test]
fn sha256_known_answer_round_trips() {
    let text = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let oid = GitObjectId::from_str(text).unwrap();
    assert_eq!(oid.to_string(), text);
    assert_eq!(oid.algorithm(), "sha256");
    assert_eq!(oid.byte_len(), 32);
}

#[test]
fn algorithms_are_not_interchangeable() {
    assert_ne!(
        GitObjectId::from_sha1([7; 20]).unwrap(),
        GitObjectId::from_sha256([7; 32]).unwrap()
    );
}

#[test]
fn missing_or_unknown_prefix_is_rejected() {
    for value in [
        "0123456789abcdef0123456789abcdef01234567",
        "SHA1:0123456789abcdef0123456789abcdef01234567",
        "md5:0123456789abcdef0123456789abcdef",
    ] {
        assert_eq!(
            GitObjectId::from_str(value).unwrap_err().code(),
            GitObjectIdErrorCode::PrefixInvalid
        );
    }
}

#[test]
fn exact_algorithm_lengths_are_required() {
    assert_eq!(
        GitObjectId::from_str("sha1:00").unwrap_err().code(),
        GitObjectIdErrorCode::LengthInvalid
    );
    assert_eq!(
        GitObjectId::from_str(&format!("sha256:{}", "00".repeat(31)))
            .unwrap_err()
            .code(),
        GitObjectIdErrorCode::LengthInvalid
    );
}

#[test]
fn uppercase_hex_is_valid_hex_but_noncanonical() {
    let value = format!("sha1:{}A", "0".repeat(39));
    assert_eq!(
        GitObjectId::from_str(&value).unwrap_err().code(),
        GitObjectIdErrorCode::NonCanonical
    );
}

#[test]
fn non_hex_is_rejected() {
    let value = format!("sha256:{}g", "0".repeat(63));
    assert_eq!(
        GitObjectId::from_str(&value).unwrap_err().code(),
        GitObjectIdErrorCode::HexInvalid
    );
}

#[test]
fn all_zero_null_identifiers_are_not_object_ids() {
    assert_eq!(
        GitObjectId::from_str(&format!("sha1:{}", "0".repeat(40)))
            .unwrap_err()
            .code(),
        GitObjectIdErrorCode::ZeroInvalid
    );
    assert_eq!(
        GitObjectId::from_str(&format!("sha256:{}", "0".repeat(64)))
            .unwrap_err()
            .code(),
        GitObjectIdErrorCode::ZeroInvalid
    );
}

#[test]
fn raw_framing_is_algorithm_tagged() {
    let mut sha1 = Vec::new();
    let mut sha256 = Vec::new();
    GitObjectId::from_sha1([0xaa; 20])
        .unwrap()
        .write_raw(&mut sha1);
    GitObjectId::from_sha256([0xaa; 32])
        .unwrap()
        .write_raw(&mut sha256);
    assert_eq!(sha1[0], 1);
    assert_eq!(sha256[0], 2);
    assert_eq!(sha1.len(), 21);
    assert_eq!(sha256.len(), 33);
}

#[test]
fn direct_constructors_reject_null_object_ids() {
    assert_eq!(
        GitObjectId::from_sha1([0; 20]).unwrap_err().code(),
        GitObjectIdErrorCode::ZeroInvalid
    );
    assert_eq!(
        GitObjectId::from_sha256([0; 32]).unwrap_err().code(),
        GitObjectIdErrorCode::ZeroInvalid
    );
}
