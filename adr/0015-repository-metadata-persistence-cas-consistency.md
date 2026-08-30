# ADR-0015: Repository metadata persistence, CAS, and consistency tokens

**Status:** Accepted
**Date:** 2026-08-30
**Owners:** OGVCS-006

## Context

OGVCS-006 needs one authoritative transaction boundary for immutable repository
metadata, mutable references, repository-lifetime FileIDs, idempotency outcomes,
and events. The architecture requires the physical schema, isolation strategy,
compare-and-swap behavior, and consistency token to be fixed before metadata
writes. It also requires a modular monolith whose submit coordinator can compose
one database transaction without importing another module's private tables.

The R0 repository format, authorization, path, protocol, and benchmark packages
are immutable predecessor authorities. They define canonical identities, pure
validation, protected views, bounded envelopes, idempotency fingerprints,
cursors, and test-driver behavior, but deliberately do not define this service's
database or domain errors. The R0 protocol error registry cannot be extended by
an OGVCS-006 implementation without a later protocol release authority.

## Decision

### Module and database boundary

The reference service is a Rust repository-metadata module in the server modular
monolith. PostgreSQL is the reference authoritative store. The module owns its
tables and exposes typed, versioned commands and queries plus an opaque
transaction handle. The submit coordinator may call transaction-bound object,
FileID, reference, idempotency, and outbox methods; it may not import table
layouts or call the module through HTTP while composing a publication.

The first schema owns:

- repositories and immutable repository settings;
- canonical repository metadata objects and rebuildable edge/tree/history
  indexes;
- snapshots and their ordered parents;
- versioned branches, tags, and other references;
- repository-lifetime FileID and importer mapping records;
- semantic idempotency reservations and committed outcomes;
- opaque cursor and consistency-token state;
- repository commit-sequence watermarks;
- transactional outbox events; and
- an ordered, checksummed migration ledger.

Bulk chunk bytes and transfer sessions are never stored in this schema.
Repository metadata kinds are explicitly allowlisted by the OGVCS-006 domain
contract. OGVCS-006 stores and validates kind-2 content-manifest metadata so a
file-bearing tree has a locally verifiable typed target; OGVCS-008 owns kind-1
chunk bytes plus chunk/manifest availability and lifecycle state. Object-edge
indexes may record external chunk references without a local-object foreign key.
Content availability remains an OGVCS-008 port. Draft, review, lock,
audit, and delivery-attempt tables remain with their owning modules. Those
modules reserve FileIDs and append events only through OGVCS-006 transaction
methods.

### Validation and immutable writes

The service accepts canonical repository-format objects only after exact type,
ObjectID, repository descriptor, profile/feature, path, and configured resource
validation. Canonical bytes are keyed by `(repository_id, kind, digest)`. A
duplicate insert reads and constant-time compares the complete stored bytes:
equal bytes are an idempotent success; different bytes under the same identity
return the stable `OBJECT_ID_COLLISION` domain error, emit a security signal, and
do not mutate authoritative or derived state.

Canonical objects are truth. Tree, edge, and history tables are rebuildable
indexes and never redefine object identity. Staged objects are not branch
history. A snapshot becomes published only when a committed reference names it.

### Isolation and retry

Read-only object and snapshot-bound traversal uses a repeatable-read transaction
when more than one statement is needed. Every page binds an immutable tree or
snapshot, an authorized query digest, and an opaque cursor position, so unrelated
writes cannot cause duplicates or omissions.

Repository creation, reference mutation, FileID/import reservation, and submit
finalization use serializable transactions. Serialization and deadlock failures
are retried only within a declared bounded attempt/deadline policy. Validation,
authorization, idempotency-key reuse, uniqueness conflicts, and expected-prior
conflicts are not transaction retries.

Reference creation, update, and deletion are one conditional statement after
authorization and idempotency reservation. Creation requires explicit
expected-absent state. Update/deletion match repository, reference kind/name,
expected target, and expected generation. One statement advances generation and
returns the new row. No match returns `REFERENCE_CONFLICT`; it never performs an
unconditional read-then-write. A current generation is exposed only after an
authorization decision permits it.

FileID uniqueness is a database constraint on `(repository_id, file_id)`, not a
cross-module scan. Deletion changes registry state to tombstoned and never
deletes the lifetime row. Native create/copy, restore, and import have distinct
origins. Import mapping insertion and lifetime reservation are one transaction;
retry of the same importer/source tuple returns the original FileID. Concurrent
collisions have one winner and typed losers without partial metadata.

### Idempotency and outbox

Every retryable mutation uses the OGVCS-041 semantic fingerprint. The service
atomically reserves `(authenticated_scope_digest, operation, key)`. Equal
fingerprints join or return the committed safe outcome; a different fingerprint
returns the frozen protocol idempotency-reuse error before mutation. The
committed outcome is retained through the key's embedded expiry.

Every metadata mutation requiring notification inserts an immutable outbox row
in the same transaction and commit sequence as the state change. The worker
consumes through a versioned claim/acknowledgement port. Delivery is at least
once; delivery attempts and consumer cursors are worker-owned. An event ID plus
version makes consumers idempotent. Publishing to an external broker is never
part of the metadata transaction.

### Opaque consistency tokens

Each visible repository transaction increments one repository commit sequence
and writes that watermark with the state and outbox rows. A consistency token is
an unpredictable `ct1.` handle whose SHA-256 digest, repository, minimum commit
sequence, subject/authorization epoch, issue time, and expiry are stored in the
same database. Raw repository IDs, sequence values, and positions never appear
in the token.

A primary or replica validates the token's closed syntax, looks up its digest,
checks scope and expiry, and serves only after its local snapshot observes at
least the recorded repository watermark. It may wait within the request deadline
or return `CONSISTENCY_TOKEN_UNSATISFIED`; it never silently serves an older
reference. Reference mutation and mutating-workflow branch resolution remain
leader reads. Once resolved, callers bind subsequent reads to the immutable
snapshot.

### Migrations and compatibility

Migrations are ordered triples named expand, migrate, and contract. The ledger
stores version, phase, SHA-256 checksum, start/completion state, compatibility
range, and a resumable cursor when the phase declares one. One PostgreSQL
advisory lock serializes migration runners. Reapplying an identical completed
phase is a no-op; a checksum mismatch is fatal. An interrupted safe phase resumes
from its durable cursor. Destructive contract phases require a separately
declared compatibility fence and backup gate.

The application refuses to start for mutation when the database schema is newer
than its maximum or older than its minimum. Unknown compatibility stops
reference writes. Rollback deploys the prior compatible application before a
contract phase; it never attempts an automatic database downgrade.

### Domain contract and frozen protocol

`spec/repository-metadata/v1` is the language-neutral authority for operations,
limits, events, domain errors, schemas, and contract vectors. Domain errors have
stable names and numeric assignments and are used by module APIs immediately.
They are not inserted into or serialized as members of the frozen R0
`ProblemDetails` registry. A later protocol release must explicitly bind them to
the public failure carrier before public metadata routes are enabled. Until then,
the HTTP adapter remains disabled outside isolated tests.

Production authorization is an injected OGVCS-009 port. The default development
implementation denies. An allow fake exists only in authenticated isolated test
mode. Authorized-view construction precedes pagination, counts, cursors, and
history traversal.

## Alternatives considered

- **Read committed plus application read-then-write CAS** was rejected because
  it permits lost updates and makes multi-row publication reasoning fragile.
- **A global FileID uniqueness constraint** was rejected because identical bytes
  are valid in different repositories.
- **WAL LSNs or sequence numbers in public tokens** were rejected because they
  disclose topology/position and couple the contract to PostgreSQL internals.
- **Post-filtering global tree/history pages** was rejected because it leaks
  hidden counts, positions, and cursor shape.
- **Publishing directly to a broker in the transaction** was rejected because
  it cannot be atomic with PostgreSQL and creates false acknowledgement states.
- **Adding OGVCS-006 errors to the R0 protocol registry** was rejected because
  its release preflight does not authorize those additions.

## Compatibility and data consequences

Database rows are private service state. Canonical repository bytes and IDs stay
defined solely by OGVCS-002. Rebuildable indexes may change without changing
ObjectIDs. Equal FileID bytes in different repositories remain valid. Reference,
registry, idempotency, token, and outbox schemas evolve through migrations and
versioned module contracts.

This decision creates a per-repository sequence row that may become hot; load
evidence must measure it before schema freeze. Cursor and token rows require
bounded retention and pruning that preserves expiry/non-oracle behavior.

## Threat and failure analysis

Unique constraints and serializable transactions make concurrent CAS and FileID
collisions single-winner. Exact-byte comparison detects an impossible or hostile
identity collision. Opaque scoped tokens/cursors avoid identifier and position
disclosure. Authorized-view-first queries prevent hidden-count leakage. Same-
transaction outbox and idempotency outcomes prevent a committed mutation from
being acknowledged without its recovery facts.

Fault injection covers every database write, commit request, ambiguous commit
acknowledgement, and restart. Recovery accepts only an old complete state or one
new complete state with matching reference, commit sequence, idempotency outcome,
FileID facts, and outbox event. Unknown schema compatibility and unavailable
authorization fail closed.

## Test vectors and proof

The OGVCS-006 contract includes stable vectors for repository settings,
same/different-byte object replay, reference CAS, opaque tokens, migration
compatibility, and every domain error. Service tests add one-hundred-way CAS,
FileID/import races, interrupted migrations, primary/replica token checks,
authorized pagination, and database-boundary crash recovery. Exact million-entry
evidence remains a separately controlled OGVCS-005 campaign and is not part of
ordinary presubmit.

## Rollback and migration

Before the first metadata write, the initial expand migration and checksum are
recorded. Application rollback is allowed only inside the declared schema
compatibility range. Reference writes stop before an incompatible binary or
schema is activated. No rollback rewrites acknowledged canonical objects,
reuses FileIDs, deletes outbox recovery facts, or lowers an observed repository
commit sequence.
