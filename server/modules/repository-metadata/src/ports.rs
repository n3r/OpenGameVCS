use crate::{
    AuthorizationContext, CommitSequence, ConsistencyToken, FileIdReservation, ObjectPutOutcome,
    ObjectWrite, OutboxEvent, ReferenceCasRequest, ReferenceCasResult, RepositoryId, Result,
    TransactionOptions,
};

pub trait AuthorizationPort {
    type AuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        permission: &'static str,
        resource_type: &'static str,
        repository_id: RepositoryId,
    ) -> Result<Self::AuthorizedView>;
}

/// Transaction-bound operations used by OGVCS-006 and the OGVCS-010 submit
/// coordinator. Adapters must implement all methods on one database transaction.
pub trait MetadataTransaction {
    fn put_object(&mut self, write: ObjectWrite<'_>) -> Result<ObjectPutOutcome>;
    fn reserve_file_id(&mut self, reservation: FileIdReservation) -> Result<()>;
    fn compare_and_swap_reference(
        &mut self,
        request: ReferenceCasRequest,
    ) -> Result<ReferenceCasResult>;
    fn append_outbox(&mut self, event: OutboxEvent) -> Result<()>;
    fn issue_consistency_token(
        &mut self,
        repository_id: RepositoryId,
        minimum: CommitSequence,
    ) -> Result<ConsistencyToken>;
    fn commit(self) -> Result<CommitSequence>;
    fn rollback(self) -> Result<()>;
}

pub trait MetadataStore {
    type Transaction<'store>: MetadataTransaction
    where
        Self: 'store;

    fn begin(&mut self, options: TransactionOptions) -> Result<Self::Transaction<'_>>;
}
