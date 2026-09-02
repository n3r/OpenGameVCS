# OGVCS-016 private hard-lock model rc.1

This unpublished Rust 1.82 crate is a bounded, deliberately unwired state
model for hard locks and advisory edit intent. It composes OGVCS-002 `FileId`
and `ObjectRef` values with OGVCS-004 repository path keys and prefixes. It
does not define a wire format, persistence schema, service, or production
authority.

## Bounded model boundary

One `LockModel` instance represents one caller-supplied repository and opaque
branch/domain digest. Hard locks, advisory intents, wait subscriptions,
idempotency results, availability notices, and immutable event commitments are
kept only in memory. Every transition receives a caller-supplied authority
epoch and integer server-time tick. Time may advance but never regress. The
crate reads no real wall clock and claims no lease duration unit.

Hard-lock acquisition supports three normalized target classes:

- a stable OGVCS-002 `FileId`, whose conflict identity follows a move;
- an OGVCS-004 repository prefix, including nested-prefix and configured
  case-fold overlap; the empty repository-root prefix overlaps itself and
  every descendant through the exact OGVCS-004 prefix ranges;
- an opaque asset-group ID plus a versioned, nonzero policy binding and at
  most 256 supplied FileID/path members.

The expansion envelope is versioned and generation-bound. It rejects unknown
versions, zero generations, duplicate FileIDs, repository-key collisions,
members outside a prefix, policy substitution, ambiguous groups, and
maximum-plus-one groups. It is still only a supplied projection: this crate
cannot prove prefix enumeration completeness, asset-group policy authority,
or that a FileID/path mapping is current. A production adapter must obtain the
complete expansion from its fenced metadata transaction and revalidate it
when paths or group policy change. A direct FileID lock intentionally does not
capture a new FileID created later at the same path; a prefix lock does.

Simultaneous requests at one server tick are sorted by full request commitment
and idempotency key, so conflicting acquisition has one deterministic winner
independent of input order. An identical key/request replays the exact stored
receipt without another event or transition. A changed request under an
existing key returns only `KeyReuse`. Different requests sharing a previously
unknown key in one batch reject the whole batch. Renew and same-owner workspace
transfer issue a new monotonic generation. Release, transfer, break, renew,
natural expiry, and later submit validation require the applicable current
epoch/generation fence. Epoch promotion expires every in-memory claim and
clears old-epoch idempotency authority rather than restoring exclusivity.
Every immutable operation receipt carries the supplied time at which it was
first recorded. A replay retains that original receipt time while the enclosing
batch reports the later replay time, so replay cannot be mistaken for a fresh
lease observation or a resurrected claim.

Wait subscriptions never reserve a target. Release, break, or natural expiry
may produce an opaque availability notice only after the target no longer
overlaps an active hard lock; every subsequent acquisition competes normally.
Advisory intents may overlap each other and hard locks. Outcomes expose only
bounded classes, opaque claim IDs, generations, expiries, and commitments—not
owner, workspace, path, FileID, group membership, or conflict counts.

## Supplied permission and submit facts

The constants `5`, `6`, and `10` retain the frozen OGVCS-003 assignments for
`lock.create`, `submit`, and `lock.force-unlock`. `SuppliedPermissionFact`
only checks that an opaque caller assertion binds the expected assignment,
subject, scope, epoch, policy generation, and nonzero decision digest. It has
no signature, trusted issuer, session, policy evaluator, revocation source, or
request-root authority. An affirmed fact is test/model input, not
authorization.

`validate_submit_facts` is a pure `&self` interface. It binds a private shape
parallel to the current OGVCS-010 candidate—intent, expected/candidate
snapshots, operation set, lifecycle plan, identity plan/decision/resource
projection, authenticated scope, subject, and epoch—and checks supplied
changed-target requirements against current owned workspace proofs. It never
authorizes, consumes a proof, changes a lock, constructs a snapshot, advances a
branch, or commits a transaction. The parallel fields are not an imported
OGVCS-010 type or a compatibility/public-protocol claim.

The returned validation receipt labels the model's already-supplied
`server_time`; it does not advance time or establish that the caller's time or
state view is fresh. A future submit adapter must advance/expire the lock model
from the authoritative transaction's server-time source and validate the exact
state in that same fenced transaction. Calling this pure function on a stale
copy is not submit enforcement.

Event and receipt SHA-256 commitments bind request/state facts and a chained
event sequence, including the immutable path profile, case mode, configured
resource limits, authority epoch, and supplied record time. They are not
signatures, bearer credentials, public audit records, non-disclosure tokens, or
durable receipts. Claim IDs are deterministic truncated commitments rather than
unpredictable secrets. Because claim IDs and commitments may be guessable from
target, reason, actor, generation, or idempotency material, an adapter must
never expose them to an unauthorized caller merely because the outcome class is
privacy-neutral.

## Fault and resource behavior

The pure fault adapter names exactly the OGVCS-005 registry boundaries
`policy.decision`, `lock.mutation`, `metadata.commit`, and `event.publish`.
Precommit injections preserve the exact prior model. Postcommit ambiguity
stores the normal idempotency result so an identical retry resolves without a
second owner. This is model/fault-harness alignment only; it is not database,
crash-recovery, outbox-delivery, or transaction evidence.

All retained sets and input batches have configurable ceilings no greater than
hard maxima. Target/member/path/reason shapes are bounded before full request
commitment work. The fault adapter computes ambiguity commitments only after
normal batch admission, overlap work is charged before comparison, and submit
proofs are indexed once rather than rescanned per target. Transition and
submit-validation work is charged against an explicit caller envelope.
Cancellation, work exhaustion, event/idempotency/notice capacity, and
generation overflow leave the prior model unchanged. Executable exact/max+1
tests cover target bytes/members, configured retained lock/advisory/wait sets,
batches, reasons, and submit work admission, including the 256-member asset
group and its 257-member rejection.

## Explicit nonclaims

This crate has no authentication, visibility filtering, owner disclosure,
request-root authorization, policy evaluation, storage/database schema,
transaction isolation, lock-service leadership, public protocol/CLI/route,
filesystem read-only hint, local-agent recovery, production submit
enforcement, audit persistence, notification delivery, real clock, retained
integration-domain calculation, cross-branch semantics, hosted cross-OS
evidence, latency/scale campaign, or rollout. It does not satisfy an OGVCS-016
acceptance criterion. OGVCS-016 remains Todo.

Local gates:

```text
cargo +1.82.0 fmt --manifest-path core/hard-lock/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/hard-lock/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path core/hard-lock/rust/Cargo.toml --locked --offline --release
cargo +1.82.0 clippy --manifest-path core/hard-lock/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 package --manifest-path core/hard-lock/rust/Cargo.toml --locked --offline --allow-dirty --no-verify
node --test tools/hard-lock-model-source-policy.test.mjs
npm run test:roadmap
```

The package command proves only the declared bounded archive. Its frozen
OGVCS-002/004 authorities remain local path dependencies, so this is not a
registry-resolved standalone or hosted hermetic-install claim.
