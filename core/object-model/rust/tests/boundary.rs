use ogvcs_object_model::{
    validate_bundle_claim, validate_file_id_allocation, Cbor, ErrorCode, FileId,
    FileIdAllocationRequest, TypedDigest,
};

fn file_id(byte: u8) -> FileId {
    FileId::new([byte; 16]).unwrap()
}

#[test]
fn supplied_closure_cannot_be_relabelled() {
    assert_eq!(
        validate_bundle_claim("supplied-closure").unwrap(),
        "supplied-closure"
    );
    assert_eq!(
        validate_bundle_claim("fidelity-export").unwrap_err().code,
        ErrorCode::BundleExportClaimForbidden
    );
}

#[test]
fn allocation_finalize_is_pure_and_reports_the_concurrent_loser() {
    let candidate = file_id(0x21);
    let working = [candidate];
    let request = FileIdAllocationRequest {
        candidate_file_id: candidate,
        retry_limit: 1,
    };
    assert_eq!(
        validate_file_id_allocation(request, &[], &working)
            .unwrap_err()
            .code,
        ErrorCode::FileIdAllocationCollision
    );
    assert_eq!(working, [candidate]);
    let fresh = file_id(0x22);
    assert_eq!(
        validate_file_id_allocation(
            FileIdAllocationRequest {
                candidate_file_id: fresh,
                retry_limit: 1,
            },
            &[],
            &working,
        )
        .unwrap(),
        fresh
    );
}

#[test]
fn malformed_typed_digest_algorithm_is_a_schema_error() {
    let value = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(2)),
        (Cbor::UInt(1), Cbor::Bytes(vec![0; 32])),
    ]);
    assert_eq!(
        TypedDigest::from_cbor(&value).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );
}
