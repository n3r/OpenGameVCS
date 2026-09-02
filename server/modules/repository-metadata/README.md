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
Protocol routing, streaming transport, and dispatch for the other twenty
operations remain open. The internal persistence page ports
deliberately retain a stricter 1,000-item cap; only the framework-neutral
adapter constructs the public `PageResult` consistency-token field.

Syntax admission is not authority. The adapter classifies every operation by
its exact permission/resource assignment and exposes an explicit
identity-bound guard. Repository creation carries an initial root publication,
so it is coordinator-required alongside reference CAS and FileID tombstone;
the restore form of `file-id.register` is dynamically coordinator-required.
The three outbox lease operations are internal-only. The sealed
`PostgresMetadataReadDispatcher` admits exactly `repository.get-settings` and
`reference.read`; no other operation can enter that path. It accepts only a
`NegotiationVerifiedMetadataRequest`, reverifies that receipt with the
dispatcher-owned key ring at the PostgreSQL clock, and accepts only
`TransactionCredentialRequest` presentation material for OGVCS-009. Candidate
repository settings may carry authenticated conformance-only fixture profiles
for contract testing, but the future coordinator must revalidate exact
production-write profile eligibility before mutation.

The read dispatcher authorizes the exact repository or kind/name reference
projection before any repository/reference existence lookup. In one
SERIALIZABLE transaction it binds the participant-derived subject, authority
epoch, tenant, repository, and authenticated scope to the negotiation brand
and parsed body; checks a subject/epoch/scope-bound minimum consistency token;
reads at one observed repository sequence; issues a current token; rechecks and
appends the identity decision commitment; and commits. Only a private committed
brand can construct a success envelope. Denied, missing, hidden, stale,
cross-subject, cross-tenant, invalid-token, and commit-fault cases all produce
the same registered authorization failure without logging adapter/database or
protected identity details.

The framework-neutral `MetadataTransportResponse` now closes one narrower
carrier gap without opening a route. It derives the HTTP status and media type
from the exact static descriptor (or the registered problem for a pre-route
failure), emits RFC 8785 canonical response-envelope bytes, rejects a success
whose operation/carrier differs from the descriptor, and enforces the complete
one-MiB control-message limit. The sealed read dispatcher validates that full
canonical envelope before committing its OGVCS-009 decision, so an individually
valid result body cannot become an unencodable post-commit response. This
carrier does not register HTTP, authenticate a principal, or map a metadata
domain error into OGVCS-041. Its default debug representation reports only the
status, media type, and byte count; it does not duplicate authorized control
bytes into logs.

Two adapter-private versioned projections close otherwise-unassigned joins:
the raw metadata `TenantId` is domain-hashed to the negotiation receipt's
opaque `tenantDigest`, and the exact reference kind plus UTF-8 name is
length-framed and domain-hashed to the identity resource/reference name. These
are not OGVCS-041 protocol mappings, are not network authorities, and do not
derive an identity participant session claim. The dispatcher is still not a
network service: `networkRegistered` remains false for every operation and
`networkRoutes` remains empty. HTTP authentication, trusted principal creation,
and a native CLI carrier remain explicit integration blockers.

The direct production constructor is `IdentityBoundPostgresMetadataStore::connect`;
it requires the OGVCS-009 PostgreSQL participant before returning a store and
exposes only credential-presentation entry points. The default identity-bound
`connect_with_aggregate_authorization` additionally requires the aggregate-v3
participant and exposes the opaque-receipt lifecycle bridge without exposing
PostgreSQL handles or signing secrets. The default identity-bound
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
Schema v10 and `apply_aggregate_lifecycle_publication` now implement that
submit-only bridge. Schema v13 corrects its formerly positional lifecycle-to-
identity join: every newly eligible lifecycle plan now requires an immutable
one-to-one seal plus an exact per-item relation to the OGVCS-009 identity plan.
Deferred composite foreign keys and validation bind both ordinals, the exact
`ObjectRef`, and the resource digest on both sides. Lifecycle locking and
application retain the canonical opaque-key/global order, while authorization
projection reconstruction follows identity item ordinal in keyset pages of at
most 1,000 rows. The mapping-seal digest is streamed in production; the bridge
does not materialize a 100,000-item mapping vector. It compares that projection
with the sealed aggregate-v3 receipt, consumes that receipt, locks and
revalidates the lifecycle plan, and applies
facts, reachability, item outbox rows, one aggregate outbox row, and immutable
cross-schema evidence in one caller-owned SERIALIZABLE transaction. Later
failure, including a deferred evidence failure, rolls back both consumption and
metadata. The API returns one aggregate result and never returns resource
identities or failure positions. GC and transfer effects remain dormant.

V13 does not fabricate mappings for historical rows. Existing committed v10
applications and their evidence remain readable, but an old unconsumed plan
without the new relation fails closed before one-use receipt consumption. The
only mapping writer in this tranche is compiled by `legacy-test-adapter` for
PostgreSQL fixtures and hostile fault injection; it is not production behavior
and is not a closure planner. No JavaScript-to-Rust subject/scope mapper,
manifest-byte reader, submit route, request-root carrier, closure traversal,
recovery service, health/GC authority, or public protocol is added here.

Schema v11 adds the first private OGVCS-010 atomic-submit candidate. Its name
and scope are intentionally narrow: `finalize_preallocated_creation_submit`
accepts only one to 1,000 server-sealed create/copy/import FileID
first-consumption operations. It does not accept modify/move/rename/delete or
restore, and it is not a general submit/finalize protocol. The coordinator uses
one caller-owned SERIALIZABLE transaction for current aggregate-receipt
consumption, lifecycle application, deterministic branch and FileID locks,
permanent ordered FileID first-consumption evidence, snapshot publication
marker, branch CAS, internal audit evidence, one metadata outbox event,
consistency token, final outcome, and reconciliation observation. Any bridge
error aborts PostgreSQL transaction state even if internal code catches it;
later failures roll every participant back. Exact durable replay revalidates
the same receipt, plan, consumption ID, and operation digest before returning
the stored outcome. A missing outcome returns only `unknown-recovering`; it
does not invent a not-present or disaster-recovery acknowledgement.

The v11 lock path acquires FileID registry rows in canonical
`(repository_id, file_id)` order and then restores operation ordinal before
checking or deriving the sealed operation evidence. This ordering is
defense-in-depth: the immutable registry `first_change_set_digest` and
`first_operation` bindings make two valid intents that reverse the same
FileIDs unreachable. A hostile reversed candidate is therefore rejected at
intent creation with no leaked intent or operation rows. The reachable
cross-branch collision keeps identical immutable ordinals and proves one
non-replay winner; the losing receipt, lifecycle plan, candidate marker,
FileID evidence, audit/outbox/token, reconciliation, and outcome remain
unconsumed or absent. A separate eight-intent race from one branch head proves
one exact publication, while replay after a new database connection returns
the same durable outcome without another publication.

Intent creation uses ordinary MVCC reads for the branch and staged FileID rows,
and preflight uses an ordinary MVCC read for the branch; only finalize reserves
those mutable publication rows. Preflight takes the opaque intent advisory lock
before the aggregate participant's repository lock. Together these rules
prevent create/preflight from holding repository authorization state while
waiting behind finalize's branch or FileID locks, without weakening the locked
finalize-time CAS, current-receipt, lifecycle, or FileID revalidation.

Every new intent, preflight, fresh finalize, and unknown-result reconciliation
also reloads the v13 one-to-one aggregate identity mapping for its lifecycle
plan and requires the same aggregate plan ID, decision digest, and
resource-projection digest from the supplied aggregate-v3 receipt. An otherwise
current receipt for the same tenant, repository, reference, snapshot,
permission, and object count cannot substitute for the receipt sealed to that
lifecycle plan. Changed expected-head or generation input on an existing
lifecycle/idempotency plan remains a denied key-reuse result and does not alter
the sealed intent. Because v13 deliberately does not fabricate mappings for
historical applications, committed v11/v12 outcomes retain their immutable
stored identity-plan/consumption revalidation path; only pending unmapped work
fails closed after upgrade.

The private fault harness now separates bridge, FileID, snapshot marker,
branch CAS, audit, metadata outbox, consistency-token, final-outcome, and
reconciliation boundaries and compares the complete durable submit projection
before and after every rollback. `BeforeCommit` is only the test boundary after
the reconciliation write and immediately before control returns to the commit
path; it is not a simulation of PostgreSQL commit-I/O failure. Actual
post-preflight credential revocation, authority-epoch promotion, and policy
promotion are each rechecked and leave the preflight and all publication state
unchanged on denial.

This v11 slice does not close OGVCS-010. There is no `spec/atomic-submit`
package, route, public error carrier, authenticated submit audit class,
production snapshot `PolicyResult`, lock/review/check proof registry, public
submit outbox contract, or recovery-boundary receipt. Existing metadata
object/profile enablement gaps remain. Outbox delivery lease/ack/release fields
remain service-mutable after commit, while event identity and payload are
immutable. GC and transfer-authority effects remain dormant. The bridge exact
100,000-object proof is not rerun by this slice because repository-metadata and
identity manifest pins are being regenerated separately; v11's FileID carrier
is deliberately capped at 1,000 operations.

The consumed aggregate receipt authenticates the lifecycle object's sealed
resource projection, publication reference, and snapshot; it does not yet
authenticate the candidate path/FileID operation set as a distinct current
authorization resource set. That authorization seam remains an explicit
blocker to exposing this coordinator as a general or public finalize boundary.
Committed replay and reconciliation also require the original aggregate plan
to remain current (including credential, authority/policy/key generations and
expiry). They deny disclosure after that receipt becomes stale or revoked and
do not yet implement fresh-scope reauthentication for durable idempotency or
disaster recovery; the already committed outcome remains immutable.

The language-neutral bridge contract is
`contracts/lifecycle-bridge/v1/manifest.json`; the Rust
`LIFECYCLE_CONTRACT_SHA256` is the SHA-256 of those exact manifest bytes, and
the manifest authenticates the artifact set. Static and Rust tests reject any
manifest, artifact, generated-pin, dependency-pin, or migration drift. This is
not a public OGVCS-010 disaster-recovery receipt, does not complete every
OGVCS-009 criterion, and does not supply the external trusted root-proof
authority. Per-item audit UUIDs remain correlation identifiers rather than a
claim that a distinct OGVCS-009 audit append occurred.

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

Candidate acquisition is rooted only at that exact Snapshot `ObjectRef`.
Metadata is discovered from the existing canonical reference walker and read
in sorted batches of at most 1,000 exact `(kind, digest)` pairs. Each batch
first returns only the stored tuple, validation-contract match, and byte length;
its canonical bytes are fetched only after that batch's lengths plus all
previously discovered candidate bytes remain within the cumulative 128 MiB
bound. Later graph nodes are discovered only from those authenticated bytes.
Both phases run in the same SERIALIZABLE snapshot, bind request
ordinal and full stored tuple, and reject missing, reordered, substituted, or
changed rows. FileID evidence is read only for the union already derived from
canonical lifetime operations and the candidate tree; import mappings are read
only for the resulting import FileIDs. These exact-key joins return one checked
row per request ordinal and never use a `LIMIT` result as evidence that a row
is absent. The existing 100,000-object, 1,000,000-edge, chunk, retained/scratch,
and 600-second repository limits remain authoritative; each acquisition
statement receives the remaining deadline without weakening a shorter caller
timeout. The budget is checked before each external chunk-resolution call and
the remaining time is passed to the final object-model lookup, but this module
cannot hard-interrupt a single blocking resolver implementation; that port must
provide its own bounded-call guarantee.

Unreachable repository rows are deliberately outside candidate publication
validation. A corrupt or foreign-contract object not referenced by the
candidate, and unrelated FileID/import registry growth, therefore cannot reject
an otherwise valid candidate. Such rows are not declared healthy or repaired;
repository-wide inventory, corruption findings, quarantine, and repair remain
the OGVCS-017 operator-integrity boundary. This acquisition refactor adds no
authorization resource, public route, request-root, submit-plan, lifecycle,
content-backend, garbage-collection, or destructive-cleanup behavior.

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
Rust vector or per-item database query loop. Schema v10 additively binds one
aggregate application to the exact identity plan, decision, one-use
consumption, operation digest, current repository settings, signer facts,
resource digests/count, lifecycle expiry/totals, and pinned lifecycle/transfer
contracts. Existing v9 rows are not rewritten or inferred to be authorized.
Schema v11 is likewise additive; it never backfills an intent, first
consumption, outcome, or reconciliation fact from existing snapshots,
references, FileID rows, or lifecycle applications.

Schema v12 is another additive private candidate. It stores one immutable,
typed content-manifest availability proof and one typed row for each exact
OGVCS-009 authorization page; it does not backfill existing lifecycle rows or
introduce generic JSON evidence. The route-less participant accepts only an
explicit, sorted, duplicate-free set of at most 4,096 ObjectIDs with
`requestRoot = null`; at most 4,095 are dependencies because the manifest is
part of the same ceiling. It authorizes every fixed 1,000-resource page before
any proof or lifecycle lookup, then revalidates dependency generations,
requires current lifecycle-contract backend and production-verification
receipts, consumes the verification receipt once, performs the staged-to-
available CAS, and writes the application, fact, outbox, proof, and identity
decision bindings in one caller-owned SERIALIZABLE transaction. A lost commit
response is reconciled from the typed proof only after the same current
authority epoch authorizes the complete set. A settled commit replay must also
name the originally accepted expected generation.

The manifest ObjectID digest and `productionStatement.manifestSha256` are not
equal by construction: OGVCS-002 domain-hashes the typed ObjectRef, while the
statement hashes the raw canonical manifest bytes. The production-statement
digest is likewise evidence, not the global lifecycle receipt identity. The
candidate derives a separate receipt from the exact tenant, repository,
object, generation, authority, and production-statement bindings; PostgreSQL
15 independently recomputes that domain-separated digest before accepting the
typed proof, while the existing ledger consumes it once. Exact retries retain
the same receipt identity and different lifecycle bindings do not collide.
PostgreSQL does not independently recompute the production-statement, committed-
proof, dependency-generation-set, or authorization-closure digests in this
candidate; the verified adapter and Rust loader remain authoritative for those
opaque commitments.

This model makes no time-freshness or expiry claim and deliberately introduces
no nonce: multiple independently expiring verifications of the same exact
transition would require a new issued-receipt contract and durable issuance
record. The shared JavaScript/Rust vector is generated by the real chunker and
proves the ObjectRef/raw-SHA inequality plus the distinct receipt, statement,
and committed-proof digests.

The OGVCS-009 identity subject and the object-transfer production-subject
digest are deliberately separate fields. The former is checked against every
identity view and the lifecycle application; the latter preserves the existing
JavaScript committed-proof projection. The additive explicit composition now
requires an already negotiation-verified OGVCS-041 `object.put` request brand,
matches its correlation, tenant, repository, authority epoch, identity subject,
manifest ObjectID, byte length, and raw SHA-256 to the v12 command, re-verifies
the receipt at the database clock, and delegates commit or reconciliation only
to the existing OGVCS-009-bound SERIALIZABLE participant. Composition handles
are instance-branded. Commit and reconciliation return only opaque composition
receipts, never the ordinary v12 proof or raw unknown-recovery observation. A
domain-separated receipt digest binds the exact correlation, semantic
fingerprint, self-dating idempotency key, deadline, negotiation receipt and
principal/session commitment; the explicit sorted object-set/authorization
closure and authority facts; the expected manifest, length, raw digest and
private command/lookup facts; and the underlying committed-proof or authorized
observation digest. New/replayed commit state and committed/unknown recovery are
also distinct receipt inputs. Receipt `Debug` output redacts every binding and
evidence digest.

That control envelope is deliberately route-less: `object.put` remains
`networkRegistered=false`, and the OGVCS-041 public transfer carrier remains
request-root-only and rejects explicit object lists. The composition therefore
does not prove that an object-transfer grant issuer/subject maps to the
OGVCS-009 identity. The private JavaScript host must still present the exact
already-verified explicit-set mapping; `tenantScopeSha256`,
`authorityBindingSha256`, and the production-subject digest remain opaque and
are exact-matched rather than derived from the OGVCS-009 credential scope. No
JS-to-Rust invocation/transport, public endpoint, or multi-object grant issuer
is added here. The OGVCS-041 self-dating idempotency carrier is reverified only
for request currentness; because no public mutation is dispatched, it is not
persisted and is not equated to the independently domain-separated private
finalize fingerprint. No raw candidate projection is exported from the
composition: the current JavaScript production-candidate schema has no field
for this new receipt, so silently dropping it would recreate a post-call
misattribution path. A future private host must preserve and verify the composed
receipt before adapting any underlying proof to that port. The private
JavaScript production-candidate port still derives the lifecycle receipt only
after the branded chunking verifier receipt has been consumed; service input
cannot select it. The older generic JavaScript lifecycle transaction participant
keeps its separate predeclared content-manifest receipt convention; changing
that OGVCS-007-owned publication contract is outside this route-less tranche
and is not production-adoption evidence.

The v12 candidate is not a public object-transfer service. The later
composition reuses an existing OGVCS-041 authentication carrier internally but
adds no route, method/path assignment, response carrier, request-root issuance,
expansion or ratification, S3/MinIO production composition, GC/delete authority,
selective-sync behavior, or sandbox behavior. Its 4,096-object bound is not
100 GiB evidence and is not an OGVCS-008 completion claim. Local PostgreSQL 16
execution is syntax/liveness evidence only. The pinned PostgreSQL 15 workflow
passed the exact v12 source in run 33500174865 and the v13 successor source in
run 33506824950; neither run covers this later composition, production
deployment, or exact-scale evidence.

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
OGVCS_METADATA_DISPATCH_DATABASE_URL=postgresql://.../ogvcs_metadata_test_dispatch \
  cargo test --manifest-path server/modules/repository-metadata/Cargo.toml \
  --locked --offline --test metadata_dispatcher_live -- --nocapture --test-threads=1

OGVCS_METADATA_DATABASE_URL=postgresql://.../ogvcs_metadata_test_local \
  cargo test --manifest-path server/modules/repository-metadata/Cargo.toml \
  --locked --test postgres_integration -- --nocapture --test-threads=1
```

The bounded aggregate bridge suite uses a separately named disposable database:

```sh
OGVCS_METADATA_AGGREGATE_DATABASE_URL=postgresql://.../ogvcs_metadata_test_bridge \
  cargo test --manifest-path server/modules/repository-metadata/Cargo.toml \
  --locked --offline --features legacy-test-adapter \
  --test aggregate_bridge_postgres_live -- --nocapture --test-threads=1

OGVCS_METADATA_OBJECT_TRANSFER_DATABASE_URL=postgresql://.../ogvcs_metadata_test_transfer \
  cargo test --manifest-path server/modules/repository-metadata/Cargo.toml \
  --locked --offline --features legacy-test-adapter \
  --test content_manifest_transfer_postgres_live -- --nocapture --test-threads=1
```

Hard-restart evidence for the private atomic-submit candidate is a separate,
feature-gated live harness. It is not a production fault-injection API. The
library never reads supervisor environment, starts a process, or selects a
database; its default feature set does not export the restart boundary. The
live test alone installs a deferred trigger in `ogvcs_restart_test` after
migrations on each fresh disposable database. That trigger provides a real
`COMMIT`/`pg_sleep` rendezvous without changing migration or contract bytes.

The bounded supervisor covers the eleven existing in-transaction boundaries,
the deferred commit-I/O boundary, and the after-commit/before-response boundary
serially. For every case it creates a uniquely named database, observes one
exact active backend at the requested fixed application name and `PgSleep`,
sends `SIGKILL` only to the explicitly supplied container, requires exit 137,
starts that same container, and requires both its Docker process ID and
`pg_postmaster_start_time()` to change. The eleven transaction boundaries must
recover to the exact old projection; `after-commit-before-response` must recover
to the complete new projection; only `commit-io` admits either exact old or
complete new. The oracle applies that boundary-specific classification before
it reconciles or replays. Any partial or boundary-inconsistent state, duplicate
durable fact, missing child result, or absent process identity change fails the
run. The supervisor deletes only the uniquely named test databases it created
and writes JSONL to stdout; it retains no local evidence file itself.

The supervisor refuses any image other than the workflow-pinned PostgreSQL
15.19 digest and requires a loopback database URL prefix plus the exact
workflow-provided 64-hex container ID. Before mutation it also requires the
fixed `hard-kill-postgres-13-times` confirmation and an exact fresh database
inventory containing only `postgres`, `template0`, and `template1`. It
hard-kills PostgreSQL thirteen times, so it must never be pointed at a shared or
production database service. A database is removed only after this invocation
successfully created that exact random name. The workflow lane is the
authoritative execution environment. The exact v13 integration source passed
that hosted lane in run 33506824950. The later exact-plan-binding and lock-order
hardening passed all four jobs, including the live PostgreSQL 15.19 matrix and
the thirteen-boundary restart lane, at exact source `3d79338` in run
33579298064. These remain bounded candidate proofs, not a production supervisor
or deployment claim.

```sh
OGVCS_METADATA_RESTART_POSTGRES_CONTAINER=<exact-disposable-container-id> \
OGVCS_METADATA_RESTART_CONFIRM_DISPOSABLE=hard-kill-postgres-13-times \
OGVCS_METADATA_RESTART_DATABASE_URL_PREFIX=postgresql://postgres:postgres@127.0.0.1:5432/ \
  node server/modules/repository-metadata/scripts/atomic-submit-restart-matrix.mjs
```

This evidence does not add a public submit route, authentication carrier,
production supervisor, migration, native watcher, telemetry, replica/failover
claim, warm million-entry latency claim, or complete fault campaign. It also
does not promote OGVCS-006 from its current roadmap state.

The real 100,000-item proof is intentionally excluded from ordinary presubmit.
It probes item 100,001 with a one-item chunk, asserts that the persisted count
remains 100,000, then reports the measured projection/protected/write page
counts and maximum materialized batch:

```sh
OGVCS_METADATA_AGGREGATE_EXACT_DATABASE_URL=postgresql://.../ogvcs_metadata_test_bridge_exact \
  cargo test --manifest-path server/modules/repository-metadata/Cargo.toml \
  --locked --offline --features legacy-test-adapter \
  --test aggregate_bridge_postgres_live \
  exact_100000_bridge_is_streamed_in_measured_bounded_pages -- --exact --nocapture
```

The harness refuses to reset a database unless `current_database()` begins with
`ogvcs_metadata_test_` and contains only ASCII letters, digits, and underscores.
It covers the golden file-manifest/tree/snapshot/reference graph, 100 CAS racers,
project-list cursor isolation, bounded ancestry/FileID/path history,
authorization non-disclosure and revalidation, outbox delivery leases, FileID
races/import replay/tombstones, transaction poisoning and fault rollbacks,
migration repeat/checksum/downgrade behavior, and representable replica-lag
token behavior. The same live harness proves that unreachable corrupt metadata
and 1,001 unrelated FileID/import rows do not enter candidate validation, while
reachable contract, identity, positional-substitution, and missing-row faults
poison and roll back without partial reference, sequence, idempotency, or
outbox state. Pure boundary tests cover exact 1,000/1,001 batching, byte-limit
overflow, ordinal/tuple substitution, and header-to-payload phase changes. The
dispatcher-specific fresh-schema harness covers both
successful reads, participant-first lookup ordering, current token issuance,
valid cross-subject token substitution, hidden/missing/cross-tenant/stale
authority failures, attacker-key negotiation forgery, exact denial-envelope
equivalence, and post-decision commit failure rollback. The lifecycle-v9 row
adds corrected health-axis constraints,
exact receipt binding, atomic direct application facts, and reduced 1,000+1
aggregate chunk/order/tamper coverage; it is not an exact-scale campaign.
The current bounded three-platform result and retained PostgreSQL report are in
the [OGVCS-006 candidate evidence packet](../../../docs/evidence/OGVCS-006/README.md).
The exact million-entry campaign remains excluded from ordinary presubmit.
