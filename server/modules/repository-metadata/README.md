# `ogvcs-repository-metadata`

This non-published Rust crate is the OGVCS-006 production-reference PostgreSQL
module. It exposes typed domain errors, authorization-gated reads, a
transaction-composable OGVCS-010 write boundary, opaque consistency/cursor
tokens, a checksummed migration runner, and deterministic keyset paging. HTTP
remains disabled until a future protocol release assigns the public error
carrier and OGVCS-009 supplies the production authorizer. The built-in
authorizer denies every request.

The Rust surface is an internal persistence/composition port, not an
implementation claim for the contract's complete 22-operation public API.
Public request parsing and UUID/FileID grammar, repository settings/list and
object-get, reference-kind filtering, ancestry/path-history traversal,
minimum-consistency fields on every paged request, idempotency status, and
outbox consumer lease/acknowledgement operations remain deferred with the HTTP
binding. The internal page ports deliberately use a stricter 1,000-item cap.
They must not be presented as the generated `MetadataOperationRequest` or
`PageResult` wire contract.

Each write transaction is bound at construction to one repository, the complete
`AuthorizationContext`, one typed operation capability, and the `AuthorizedView`
returned by the authorizer. The adapter derives the canonical OGVCS permission;
callers cannot supply a permission string. Reads authorize and revalidate an
exact repository, reference, reference collection, tree-prefix, or FileID-history
projection before SQL. Repository arguments retained for OGVCS-010 composition
are checked against that binding before validation or SQL. Idempotency scope is
derived from the same binding; callers cannot supply or reuse an authenticated-
scope digest. A
committed replay is completed with `finish_committed_replay`, which rolls back
the probe transaction and returns the stored safe result without entering the
serialization retry loop.

Tree reads bind the authorized view to the published snapshot, exact tree, and
root-relative path-segment prefix, then authorize each returned child by its
complete repository path and FileID. Reference and FileID-history collection
views likewise authorize every returned item and are revalidated before any
response or cursor is issued. A missing or non-positive snapshot publication
marker is never inferred from a live reference: exact reference/tree reads fail
closed, authorized reference listing rejects that item, and history excludes
the unproven snapshot.

Mutation recovery facts are authority-owned and tracked by exact repository,
snapshot, reference, or FileID identity. The public event input carries only
delivery identifiers. Event class, resource class, final safe payload, and the
opaque identity/payload commitment are derived from the recorded mutation;
callers cannot substitute them. Repeated transitions of one FileID or reference
coalesce to its final state, duplicate emission fails closed, and mutation after
emission poisons the transaction. `metadata.object-accepted` is emitted only
when a snapshot first crosses the publication boundary, not when it is staged.

Before a snapshot can become a reference target, the adapter validates the
bounded repository metadata closure, registry lifecycle for configured path,
platform, and content-policy profiles, the complete snapshot ancestry,
descriptor binding, expanded tree/content-policy membership, configured tree
and path limits, canonical tree/snapshot indexes, and every stored file-history
fact against the snapshot's canonical change set. Chunk bytes remain owned by
the object-storage/content boundary and are deliberately not persisted here.

Generic FileID reservation accepts native create/copy only. Import requires the
mapping-bound import method. Restore and tombstone reactivation are deliberately
unavailable until OGVCS-002/OGVCS-010 provide a proof-bound API capable of
demonstrating the original repository lifetime; an unused ID cannot manufacture
a restore lifetime through this adapter.

Run static checks and tests:

```sh
node server/modules/repository-metadata/scripts/static-check.mjs
cargo fmt --manifest-path server/modules/repository-metadata/Cargo.toml --check
cargo test --manifest-path server/modules/repository-metadata/Cargo.toml
cargo clippy --manifest-path server/modules/repository-metadata/Cargo.toml --all-targets -- -D warnings
node server/modules/repository-metadata/scripts/service-report.mjs --check
```

The migration runner takes one named PostgreSQL advisory lock, strips only the
authenticated outer transaction frame, and records each phase and checksum in
the same database transaction as its SQL. Contract phases require the explicit
compatibility fence. Existing ledger checksums are verified even while that
fence is closed, and mutation transaction construction requires every bundled
phase to be present, compatible, completed, and checksummed.

Production persistence deployment evidence, a production OGVCS-009/OIDC
adapter, public API/HTTP bindings, external chunk-store composition, and hosted
service evidence remain deferred. The built-in authorizer denies all access;
the built-in production object validator also has no external path-profile
adapter or chunk resolver, so ratified external paths and content-bearing
publication fail closed until those production adapters are injected. No live
reference is backfilled or treated as publication evidence.
The allow authorizer and conformance validator used by the live harness exist
only in the integration test target. The service report labels a missing live
database as skipped and never claims hosted or exact-scale evidence.

Live integration and concurrency evidence is opt-in:

```sh
OGVCS_METADATA_DATABASE_URL=postgresql://.../ogvcs_metadata_test_local \
  cargo test --manifest-path server/modules/repository-metadata/Cargo.toml \
  --test postgres_integration -- --nocapture --test-threads=1
```

The harness refuses to reset a database unless `current_database()` begins with
`ogvcs_metadata_test_` and contains only ASCII letters, digits, and underscores.
It covers the golden file-manifest/tree/snapshot/reference graph, 100 CAS racers,
authorized transaction/context/token isolation, FileID races/import
replay/tombstones, transaction poisoning and fault rollbacks, migration
repeat/checksum/downgrade behavior, and representable replica-lag token behavior.
The exact million-entry campaign remains excluded from ordinary presubmit.
