use ogvcs_identity_policy_audit_postgres::{
    AuthorizationResource, ParticipantErrorCode, PostgresTransactionAuthorizationParticipant,
    TransactionAuthorizationPageCandidate, TransactionAuthorizationParticipant,
    TransactionAuthorizedPage, TransactionAuthorizedPageQuery, TransactionAuthorizedPageRequest,
    TransactionAuthorizedView, MAXIMUM_AUTHORIZATION_PAGE_CANDIDATES,
    MAXIMUM_AUTHORIZED_PAGE_RESULTS, TRANSACTION_AUTHORIZED_PAGE_QUERY_SCHEMA,
    TRANSACTION_AUTHORIZED_PAGE_SCHEMA,
};
use postgres::Transaction;

#[allow(dead_code)]
fn derive_owned_items_then_continue_same_transaction<'page>(
    participant: &PostgresTransactionAuthorizationParticipant,
    transaction: &mut Transaction<'_>,
    view: &TransactionAuthorizedView,
    request: &TransactionAuthorizedPageRequest<'page>,
    page: &'page TransactionAuthorizedPage,
) -> Vec<(u32, TransactionAuthorizationPageCandidate)> {
    let verified = participant
        .verify_authorized_page(transaction, view, request, page)
        .expect("page verification");
    let owned = verified
        .authorized_items()
        .map(|(ordinal, candidate)| (ordinal, candidate.clone()))
        .collect();
    let _ = transaction.simple_query("SELECT 1");
    owned
}

#[test]
fn authorized_page_primitives_expose_only_typed_read_only_inputs() {
    assert_eq!(MAXIMUM_AUTHORIZATION_PAGE_CANDIDATES, 100_000);
    assert_eq!(MAXIMUM_AUTHORIZED_PAGE_RESULTS, 1_000);
    assert_eq!(
        TransactionAuthorizedPageQuery::schema_version(),
        TRANSACTION_AUTHORIZED_PAGE_QUERY_SCHEMA
    );
    assert_eq!(
        TransactionAuthorizedPage::schema_version(),
        TRANSACTION_AUTHORIZED_PAGE_SCHEMA
    );

    let query = TransactionAuthorizedPageQuery::new("history.path-page", [0xab; 32])
        .expect("typed query context");
    assert_eq!(query.operation(), "history.path-page");
    assert_eq!(query.semantic_query_digest(), "ab".repeat(32));
    assert_eq!(
        TransactionAuthorizedPageQuery::new("NOT AN OPERATION", [0; 32])
            .unwrap_err()
            .code(),
        ParticipantErrorCode::InputInvalid
    );

    let resource = AuthorizationResource {
        resource_type: "path".to_owned(),
        path: Some("Game/Public/asset.uasset".to_owned()),
        file_id: Some("ab".repeat(16)),
        object_id: None,
        name: None,
    };
    let candidate = TransactionAuthorizationPageCandidate::new(
        resource.clone(),
        Some("main".to_owned()),
        Some("snapshot.main".to_owned()),
    );
    assert_eq!(candidate.resource(), &resource);
    assert_eq!(candidate.reference(), Some("main"));
    assert_eq!(candidate.snapshot(), Some("snapshot.main"));
}
