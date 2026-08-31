# `ogvcs-repository-metadata`

This non-published Rust crate is the OGVCS-006 production-reference PostgreSQL
module. It exposes typed domain errors, authorization-gated reads, a
transaction-composable OGVCS-010 write boundary, opaque consistency/cursor
tokens, a checksummed migration runner, and deterministic keyset paging. HTTP
remains disabled until a future protocol release assigns the public error
carrier. OGVCS-009 now supplies the same-transaction PostgreSQL authorization
participant; the built-in legacy authorizer still denies every request.

The Rust surface is an internal persistence/composition port, not an
implementation claim for the contract's complete 22-operation public API. It
now implements immutable settings/object reads, project-scoped repository
listing, reference-kind filtering, minimum-consistency-aware repository pages,
bounded ancestry plus snapshot-rooted FileID/path histories, and outbox
lease/acknowledgement/release. The production persistence port also implements
idempotency-keyed `file-id.allocate` with an exact replayable one-use receipt.
Public request parsing, protocol routing, and the HTTP binding remain open. The
internal page ports deliberately use a stricter 1,000-item cap and do not yet
carry the public `PageResult` consistency-token field. They must not be
presented as generated wire-contract implementations.

The production constructor is `IdentityBoundPostgresMetadataStore::connect`;
it requires the OGVCS-009 PostgreSQL participant before returning a store and
exposes only credential-presentation entry points. It invokes OGVCS-009 authorization on
the exact live PostgreSQL transaction, derives subject, epoch, and authenticated
scope exclusively from the sealed view, accumulates exact staged resources,
rechecks that closed set, and appends the ordinary decision commitment before
commit. Any error poisons the transaction. The production wrapper neither
implements nor dereferences to the legacy `MetadataStore`, so caller-owned
`AuthorizationContext` entry points cannot be selected after binding. The
constructible compatibility adapter is compiled only with the repository's
`legacy-test-adapter` feature and is never enabled in a default production
build. Development reads authorize and
revalidate exact typed resource projections before returning data. Repository
arguments retained for OGVCS-010 composition are checked against their binding
before validation or SQL. A
committed replay is completed with `finish_committed_replay`, which rolls back
the probe transaction and returns the stored safe result without entering the
serialization retry loop.

Tree reads bind the authorized view to the published snapshot, exact tree, and
root-relative path-segment prefix, then authorize each returned child by its
complete repository path and FileID. Repository, reference, ancestry, and
FileID/path-history collection views likewise authorize every returned item and
are revalidated before any response or cursor is issued. History never exposes
an incomplete/depth reason unless the same view permits every traversed ancestry
node. A missing or non-positive snapshot publication marker is never inferred
from a live reference: exact reference/tree/history reads fail closed and
authorized reference listing rejects that item.

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

The production transaction rejects generic receiptless native create/copy and
requires the exact one-use allocation receipt returned by idempotency-keyed
`file-id.allocate`. Receipt scope comes only from the OGVCS-009 sealed view;
cross-scope use, reuse, expiry, and a failed surrounding transaction all fail
closed. The legacy reservation surface remains solely on the development
adapter. Import requires the mapping-bound import method. Restore and tombstone reactivation are deliberately
unavailable until OGVCS-002/OGVCS-010 provide a proof-bound API capable of
demonstrating the original repository lifetime; an unused ID cannot manufacture
a restore lifetime through this adapter.

Run static checks and tests:

```sh
node server/modules/repository-metadata/scripts/static-check.mjs
cargo fmt --manifest-path server/modules/repository-metadata/Cargo.toml --check
cargo test --manifest-path server/modules/repository-metadata/Cargo.toml --locked
cargo clippy --manifest-path server/modules/repository-metadata/Cargo.toml --locked --all-targets -- -D warnings
node server/modules/repository-metadata/scripts/service-report.mjs --check
```

The migration runner takes one named PostgreSQL advisory lock, strips only the
authenticated outer transaction frame, and records each phase and checksum in
the same database transaction as its SQL. Contract phases require the explicit
compatibility fence. Existing ledger checksums are verified even while that
fence is closed, and mutation transaction construction requires every bundled
phase to be present, compatible, completed, and checksummed. Schema v4 adds the
bounded deterministic ancestry primitive; v5 adds the project-list cursor
ledger; v6 adds allocation receipts; and v7 additively binds token rows to an
authority-derived authenticated scope without rewriting historical migrations.

Production persistence deployment evidence, public API/HTTP bindings, external chunk-store
composition, and hosted production-service evidence remain deferred. The
bounded workflow checks the contract package inventory, runs the live harness
against a disposable PostgreSQL 15 service on Ubuntu, and compiles the locked
crate on macOS and Windows. The built-in authorizer denies all access;
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
  --locked --test postgres_integration -- --nocapture --test-threads=1
```

The harness refuses to reset a database unless `current_database()` begins with
`ogvcs_metadata_test_` and contains only ASCII letters, digits, and underscores.
It covers the golden file-manifest/tree/snapshot/reference graph, 100 CAS racers,
project-list cursor isolation, bounded ancestry/FileID/path history,
authorization non-disclosure and revalidation, outbox delivery leases, FileID
races/import replay/tombstones, transaction poisoning and fault rollbacks,
migration repeat/checksum/downgrade behavior, and representable replica-lag
token behavior.
The current bounded three-platform result and retained PostgreSQL report are in
the [OGVCS-006 candidate evidence packet](../../../docs/evidence/OGVCS-006/README.md).
The exact million-entry campaign remains excluded from ordinary presubmit.
