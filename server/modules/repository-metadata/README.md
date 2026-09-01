# `ogvcs-repository-metadata`

This non-published Rust crate is the OGVCS-006 production-reference PostgreSQL
module. It exposes typed domain errors, authorization-gated reads, a
transaction-composable OGVCS-010 write boundary, opaque consistency/cursor
tokens, a checksummed migration runner, and deterministic keyset paging. A
framework-neutral OGVCS-006 candidate adapter now validates the complete
22-operation request registry and constructs its assigned result/error
carriers. HTTP remains disabled until a future protocol release assigns routes,
statuses, and media types. OGVCS-009 now supplies the same-transaction
PostgreSQL authorization participant; the built-in legacy authorizer still
denies every request.

The Rust surface is an internal persistence/composition port, not an
implementation claim for the contract's complete 22-operation public API. It
now implements immutable settings/object reads, project-scoped repository
listing, reference-kind filtering, minimum-consistency-aware repository pages,
bounded ancestry plus snapshot-rooted FileID/path histories, and outbox
lease/acknowledgement/release. The production persistence port also implements
idempotency-keyed `file-id.allocate` with an exact replayable one-use receipt.
Public request parsing now enforces closed duplicate-free JSON, exact operation
members, the authenticated candidate-manifest identity, semantic path/profile
rules, the 10,000-item public page cap, opaque 48-byte cursor and 47-byte
consistency-token forms, self-dating idempotency binding, and bounded
request/response resources. Object streaming is limited to the nine
persistence-owned metadata kinds; Chunk and ShelfRevision are rejected at the
adapter boundary. Canonical path checks apply the OGVCS-004 both-separator,
C0/DEL, `.ogvcs`, NFC, and UTF-8 limits. Persistence-backed `ownerId` and
internal `consumerId` values also retain their 256 UTF-8-byte receiver limit.
Protocol routing, streaming transport, and the storage dispatcher remain open.
The internal persistence page ports
deliberately retain a stricter 1,000-item cap; only the framework-neutral
adapter constructs the public `PageResult` consistency-token field.

Syntax admission is not authority. The adapter classifies every operation by
its exact permission/resource assignment and exposes an explicit
identity-bound guard. Repository creation carries an initial root publication,
so it is coordinator-required alongside reference CAS and FileID tombstone;
the restore form of `file-id.register` is dynamically coordinator-required.
The three outbox lease operations are internal-only. No dispatcher is included,
and none of those operations can enter a direct identity-bound path. Candidate
repository settings may carry authenticated conformance-only fixture profiles
for contract testing, but the future coordinator must revalidate exact
production-write profile eligibility before mutation.

The production constructor is `IdentityBoundPostgresMetadataStore::connect`;
it requires the OGVCS-009 PostgreSQL participant before returning a store and
exposes only credential-presentation entry points. The default identity-bound
transaction admits immutable `PutObject`, receipt-backed `ReserveFileId`,
`ImportFileId` staging, and consistency-token issuance. It rejects
`CreateRepository`, `Publish`, generic reference CAS, tombstone, and restore
before opening a transaction. Repository creation is coordinator-owned because
the public operation also publishes its initial root and default reference.
Those operations reopen only through a future server-derived, sealed
submit-plan/coordinator port; caller-driven incremental transactions must not
become an `advanceBranch` or protected-state oracle. The low-level
composition primitives remain available only with `legacy-test-adapter` for
coordinator tests.

Schema v9 additively reserves the repository-backed object lifecycle ledger for
the OGVCS-008/010 composition boundary. It stores exact repository/tenant,
opaque object key and `ObjectRef`, generation/state/health, immutable backend,
verification, deletion, reopen, and health-observation receipt facts, one-use
receipt consumptions, publication reachability, deletion fences, direct
application facts, and an internal protected outbox. `not-applicable` is valid
exactly when no health generation/observation exists; `available` and
`quarantined` may therefore be initially unobserved, while submit consumes only
an exact healthy available/quarantined binding. Content manifests retain their
exact production-verification receipt independently of quarantine-revival
evidence.

This is a dormant internal prerequisite, not completion evidence for OGVCS-008
or OGVCS-010. The default identity-bound API exposes no generic lifecycle or
publication bypass. Its current private metadata-transaction hook is
submit-only and rechecks the exact `Publish` authorized view; GC and transfer
variants remain closed until their own OGVCS-009 authority participants exist.
Likewise, aggregate plans can be streamed and sealed structurally in bounded
1,000-item/1 MiB chunks for storage testing, but cannot be applied until the
ratified aggregate-v3 key-ring-authenticated receipt is consumed and
revalidated in the same transaction. A structural commitment is not an HMAC
authority seal, and the internal lifecycle application receipt is not the
authenticated/durable OGVCS-010 commit receipt. The stored audit UUID is only a
future audit-correlation placeholder; it does not claim an OGVCS-009 audit
append.

For admitted operations, the adapter invokes OGVCS-009 authorization on the
exact live PostgreSQL transaction, derives subject, epoch, and authenticated
scope exclusively from the sealed view, and domain-separates metadata scope by
subject, authority epoch, tenant, repository, and capability. It accumulates
exact staged resources, rechecks that closed set, and appends the ordinary
decision commitment before commit. Any error poisons the transaction. The production wrapper neither
implements nor dereferences to the legacy `MetadataStore`, so caller-owned
`AuthorizationContext` entry points cannot be selected after binding. The
opaque compatibility type has no default-build constructor or validator/
authorizer injection path; those entry points compile only with the
repository's `legacy-test-adapter` feature. Development reads authorize and
revalidate exact typed resource projections before returning data. Repository
arguments retained for OGVCS-010 composition are checked against their binding
before validation or SQL. The sealed coordinator primitive derives full
root-relative source/before/after paths and their FileIDs from the canonical
change set, then compares expanded base and candidate trees so implicit
directory moves contribute every hidden descendant path effect. Tree-entry
basenames are never treated as repository paths. The default wrapper does not
currently expose that primitive. A committed replay first returns only
`CommittedReplayPending`; `finish_committed_replay` rolls back the probe and
returns the privately held safe result only after rollback succeeds. Stored
identity replays authenticate their canonical reference/resource/result tuple,
then recheck the exact current policy before any semantic result is exposed.
The caller-context `idempotency_status` and transaction inspection accessors
exist only under `legacy-test-adapter`.

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

Within the sealed coordinator/legacy composition primitive, before a snapshot
can become a reference target, the adapter validates the
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
Schema v8 additively binds committed identity idempotency rows to the exact
canonical reference/resource/result authority tuple. It preserves historical
authority-null legacy rows (including old near-limit JSONB layouts), while new
identity-bound rows enforce 1,000-resource, 8 MiB resource-batch, and 1 MiB
safe-result storage/text ceilings. Schema v9 is additive and deliberately does
not infer lifecycle durability, health, or reachability from legacy metadata
objects or references. Direct commands are sorted/unique and bounded to 1,024
objects; aggregate declarations are bounded to 100,000 objects and are inserted
with one set-based `UNNEST` statement per bounded chunk. Sealing recomputes
exact payload/chunk/plan digests and global key order without a 100,000-element
Rust vector or per-item database query loop.

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
token behavior. The lifecycle-v9 row adds corrected health-axis constraints,
exact receipt binding, atomic direct application facts, and reduced 1,000+1
aggregate chunk/order/tamper coverage; it is not an exact-scale campaign.
The current bounded three-platform result and retained PostgreSQL report are in
the [OGVCS-006 candidate evidence packet](../../../docs/evidence/OGVCS-006/README.md).
The exact million-entry campaign remains excluded from ordinary presubmit.
