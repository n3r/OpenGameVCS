# Repository metadata v1 semantics

The normative artifacts are the authenticated registries, schemas, and vectors.
This prose cannot widen them.

Object put/get semantic admission is limited to the nine repository-metadata
kinds owned by this service; Chunk and ShelfRevision remain outside its storage
boundary even though the shared lexical `ObjectRef` grammar can represent them.
Path and prefix segments additionally follow the pinned OGVCS-004 canonical
path contract, including both-separator, C0/DEL, and `.ogvcs` rejection. The
`ownerId` and internal `consumerId` receiver profile applies the persistence
boundary's 256 UTF-8-byte ceiling and NUL exclusion in addition to JSON Schema
`maxLength`. Reference names similarly apply their named 512 UTF-8-byte ceiling
and NUL exclusion. Repository roots and all history snapshot fields require a
Snapshot; tree paging requires Snapshot plus Tree; reference CAS present and
desired targets require Snapshot.

All protected operations receive an OGVCS-003 decision before resource lookup or
response construction. List, tree, and history operations build the authorized
input view before page limits, counts, positions, and cursor state. The default
development authorizer denies; an allow fake is isolated-test-only.

`reference.compare-and-swap` always carries an expected state. Creation uses
`absent`; update and delete use the exact prior target and generation. A mismatch
returns `REFERENCE_CONFLICT` without mutation. Current state is an optional safe
parameter only after a visibility decision.

Consistency and cursor tokens are opaque handles. Server-owned state binds all
scope, position, issue/expiry, repository generation, and authorization fields.
The token text never carries those facts.

The framework-neutral `MetadataHttpResponse` envelope discriminates JSON,
`PageResult`, canonical metadata byte-stream, and domain-error bodies. It is the
public service result carrier but assigns no route, HTTP status, or media type;
those remain owned by a future OGVCS-041 release. Every `PageResult` identifies
the operation and carries an opaque consistency token. Internal persistence
pages are not wire results until the service layer has issued that token.

Domain errors are stable module results. They are not OGVCS-041 R0
`ProblemDetails` assignments. Transport parsing, authorization, cursor, and
semantic-idempotency errors continue to use the frozen R0 authorities where
applicable; a later negotiated protocol release must define the public mapping.

Object byte streams remain staged and untrusted until complete canonical/identity
validation and transaction commit. Exact duplicate bytes are idempotent. A
different byte sequence under the same ObjectID is a security/corruption result.

`file-id.allocate` creates a fresh repository-lifetime identity and returns an
opaque allocation receipt. Server state binds the receipt digest to the exact
FileID, repository, authenticated-scope digest, issue/expiry time, and one-time
claim state. Native `create`/`copy` registration requires and atomically consumes
that receipt; neither a bare FileID nor a receipt from another authenticated
scope can claim the allocation.

`file-id.register` retains the `restore` origin assignment, but native allocation
receipts cannot authorize restoration of an existing lifetime. Restore carries a
null allocation receipt and remains unavailable until OGVCS-002/OGVCS-010 define
its separate original-lifetime proof. Import must use the mapping-bound import
operation.

Idempotency lookup is keyed by the authorization authority's authenticated-scope
digest plus repository scope, operation, and opaque key. The digest is never
caller input. `idempotency.status` returns only the record in the current
authorized scope; another scope observes `absent`. Outbox claim,
acknowledgement, and release are internal exact-lease CAS operations, not public
idempotency-key operations: they require the caller's still-live authenticated
lease and reject an ambiguous retry without repeating the transition.
