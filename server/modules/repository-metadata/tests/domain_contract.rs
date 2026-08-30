use ogvcs_repository_metadata::{
    AuthorizationContext, AuthorizationPort, AuthorizationResource, CaseMode, ConsistencyToken,
    DenyAllAuthorization, DomainErrorCode, IdempotencyReservation, MetadataPermission,
    ReferenceName, RepositoryId, RepositorySettings, TenantId,
};
use std::time::{Duration, SystemTime};

#[test]
fn rust_error_assignments_match_the_domain_contract() {
    let cases = [
        (
            DomainErrorCode::RepositorySettingsImmutable,
            1001,
            "REPOSITORY_SETTINGS_IMMUTABLE",
        ),
        (DomainErrorCode::ObjectInvalid, 1002, "OBJECT_INVALID"),
        (
            DomainErrorCode::ObjectIdCollision,
            1003,
            "OBJECT_ID_COLLISION",
        ),
        (
            DomainErrorCode::ReferenceConflict,
            1004,
            "REFERENCE_CONFLICT",
        ),
        (DomainErrorCode::FileIdConflict, 1005, "FILEID_CONFLICT"),
        (
            DomainErrorCode::HistoryLimitReached,
            1006,
            "HISTORY_LIMIT_REACHED",
        ),
        (
            DomainErrorCode::ConsistencyTokenUnsatisfied,
            1007,
            "CONSISTENCY_TOKEN_UNSATISFIED",
        ),
        (
            DomainErrorCode::MigrationIncompatible,
            1008,
            "MIGRATION_INCOMPATIBLE",
        ),
        (
            DomainErrorCode::MigrationChecksumMismatch,
            1009,
            "MIGRATION_CHECKSUM_MISMATCH",
        ),
        (
            DomainErrorCode::MetadataNotFoundOrDenied,
            1010,
            "METADATA_NOT_FOUND_OR_DENIED",
        ),
        (
            DomainErrorCode::TransactionRetryExhausted,
            1011,
            "TRANSACTION_RETRY_EXHAUSTED",
        ),
    ];
    for (code, numeric, name) in cases {
        assert_eq!(code as u16, numeric);
        assert_eq!(code.name(), name);
    }
}

#[test]
fn production_default_authorizer_denies_without_disclosing_existence() {
    let context = AuthorizationContext {
        subject_digest: [1; 32],
        tenant_id: TenantId::from_bytes([2; 16]),
        authorization_epoch: 0,
    };
    let error = DenyAllAuthorization
        .authorize(
            &context,
            MetadataPermission::MetadataRead,
            &AuthorizationResource::Repository {
                repository_id: RepositoryId::from_bytes([3; 16]),
            },
        )
        .unwrap_err();
    assert_eq!(error.code, DomainErrorCode::MetadataNotFoundOrDenied);
}

#[test]
fn semantic_idempotency_keys_self_bind_issue_and_expiry() {
    let issued_at = SystemTime::UNIX_EPOCH + Duration::from_millis(1_000);
    let expires_at = issued_at + Duration::from_secs(60);
    let mut reservation = IdempotencyReservation {
        operation: "reference.cas".to_owned(),
        key: format!("ik1.1000.61000.{}", "A".repeat(22)),
        semantic_fingerprint: [2; 32],
        issued_at,
        expires_at,
    };
    assert!(reservation.is_valid_at(issued_at + Duration::from_secs(1)));
    assert!(!reservation.is_valid_at(issued_at - Duration::from_millis(1)));
    assert!(!reservation.is_valid_at(expires_at));
    reservation.key = format!("ik1.1001.61000.{}", "A".repeat(22));
    assert!(!reservation.is_valid_at(issued_at + Duration::from_secs(1)));
}

#[test]
fn opaque_tokens_and_bounded_reference_names_fail_closed() {
    assert!(ConsistencyToken::from_opaque(format!("ct1.{}", "A".repeat(43))).is_some());
    assert!(ConsistencyToken::from_opaque("ct1.repository.42".to_owned()).is_none());
    assert!(ReferenceName::new("main".to_owned()).is_some());
    assert!(ReferenceName::new(String::new()).is_none());
    assert!(ReferenceName::new("x".repeat(513)).is_none());
}

#[test]
fn repository_feature_selection_must_be_strictly_sorted() {
    let mut settings = RepositorySettings {
        repository_format: "ogvcs.repository-format@1".to_owned(),
        required_features: vec![1, 2, 9],
        case_mode: CaseMode::CaseSensitive,
        path_profile: "path.opengamevcs/portable@1".to_owned(),
        platform_profile: "path.opengamevcs/portable@1".to_owned(),
        content_policy_profile: "content-policy.test/opaque@1".to_owned(),
        structural_limits: serde_json::json!({"maxTreeEntries": 999999}),
        tenant_boundary: TenantId::from_bytes([1; 16]),
    };
    assert!(settings.has_sorted_unique_features());
    settings.required_features = vec![1, 1];
    assert!(!settings.has_sorted_unique_features());
}
