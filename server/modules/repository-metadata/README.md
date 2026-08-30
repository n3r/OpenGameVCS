# `ogvcs-repository-metadata`

This non-published Rust crate is the OGVCS-006 production-reference PostgreSQL
module. It exposes typed domain errors, authorization-gated reads, a
transaction-composable OGVCS-010 write boundary, opaque consistency/cursor
tokens, a checksummed migration runner, and deterministic keyset paging. HTTP
remains disabled until a future protocol release assigns the public error
carrier and OGVCS-009 supplies the production authorizer. The built-in
authorizer denies every request.

Each write transaction is bound at construction to one repository, the complete
`AuthorizationContext`, and the `AuthorizedView` returned by the authorizer.
Repository arguments retained for OGVCS-010 composition are checked against that
binding before validation or SQL. Idempotency scope is derived from the same
binding; callers cannot supply or reuse an authenticated-scope digest. A
committed replay is completed with `finish_committed_replay`, which rolls back
the probe transaction and returns the stored safe result without entering the
serialization retry loop.

Mutation recovery facts are tracked per event family and distinct snapshot,
reference, or FileID identity. An unrelated event cannot satisfy a mutation, and
one event cannot cover two distinct resources; repeated transitions of one
FileID within a transaction coalesce to its final committed-state event.
Every inserted metadata object advances the repository sequence. The v1 event
registry exposes `metadata.object-accepted` only for snapshot resources, so
supporting manifest/tree components do not fabricate snapshot notifications;
each newly inserted snapshot requires its own object-accepted event.

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
