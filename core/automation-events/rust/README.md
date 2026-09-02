# Private automation event contract candidate

This unpublished Rust 1.82 crate is a bounded, unwired OGVCS-019 source
candidate. It models four pure contract seams:

- a deterministic authorized-event envelope bound to caller-supplied commit
  and outbox facts;
- ordered per-repository replay pages with scoped, expiring HMAC cursors;
- timestamped HMAC webhook envelopes with rotation and a bounded in-memory
  duplicate-attempt guard; and
- a deterministic build-provenance commitment for one immutable OGVCS-002
  Snapshot.

It opens no storage, database, socket, cache, or workspace and exposes no
route, CLI, SDK, or protocol registration. OGVCS-019 remains Todo.

## Event boundary

`seal_event` accepts fixed-size identities and commitments plus one optional
typed OGVCS-002 Snapshot reference. The event ID is SHA-256 over a private,
domain-separated, fixed-width binary projection of:

- tenant and repository commitments, repository generation, and sequence;
- transaction and acknowledgement IDs, state and outbox commitments, and
  commit/acknowledgement times;
- event schema and kind commitments;
- the declared authorization-evaluation mode, policy, subject scope, epoch,
  and evaluation time;
- optional Snapshot kind and digest; and
- an authorized payload digest and declared byte length.

The digest binds all fields but proves none of the supplied facts. In
particular, the crate does not prove that state and outbox rows were committed
atomically, that an acknowledgement is durable, that the authorization policy
was evaluated, that a payload was actually filtered, or that an event is
eventually readable. Payload bytes and paths are not accepted or retained.
The acknowledgement ID/time can only commit to a caller-declared durable result
record; it is not evidence that a client observed a network response, and a
post-commit observation cannot be retroactively made part of the outbox
transaction through this seam.
`FrozenAtCommit` requires its supplied evaluation time to be no later than the
supplied commit time; `ReevaluateAtDelivery` requires it to be no earlier. This
is temporal shape validation only, not evidence that either evaluation ran.
Cryptographic digest fields, including an OGVCS-002 ObjectRef digest, are not
reinterpreted through an all-zero sentinel rule.

The fixed commitments and derived event ID are correlation values, not
confidentiality controls. This crate cannot tell whether a caller used a keyed,
non-guessable projection or directly hashed a small identifier space. Consumers
must not expose them across an authorization boundary merely because raw names
are absent.

## Replay boundary

`replay_page` receives a caller-supplied retained floor, high watermark, and
exact page slice. It requires:

- one nonzero repository generation and a valid retained window that may
  represent an explicit empty tail;
- a configured page limit of `1..=1,024` (with zero returned events only at the
  supplied tail) and a cursor lifetime no longer than seven days;
- event/high-watermark sequences no greater than `2^64 - 2`, reserving the
  final `u64` value for the exclusive tail cursor;
- exact page cardinality derived from the requested sequence, page limit, and
  supplied high watermark;
- self-checking events in contiguous sequence order with exact tenant,
  repository, generation, and authorization-scope equality, whose supplied
  commit, durable-result acknowledgement, and authorization-evaluation times
  are no later than page issuance;
- a nonzero caller-supplied current authority/security epoch that fences the
  cursor across promotion; and
- a cursor key set of at most four unique IDs.

The next cursor HMAC covers repository/scope, authority epoch, repository
generation, next sequence, retained floor and high watermark at issue,
issue/expiry times, and key ID. Cursor authentication precedes time
classification. Its validity interval is half-open
`[issued_at, expires_at)` and its retained floor cannot exceed its next
sequence. A current retained floor above the next sequence returns an explicit
expiration; an authority/generation change or backwards retention floor/high
watermark returns stale.

Old signing keys may remain in the bounded verification set through a rotation
grace period, but a new cursor is emitted only when the exact key ID, validity
window, and constant-time-confirmed signing material are present in that set.

The page function validates every supplied event before cloning the bounded
result, so an error returns no partial page. This is not a durable cursor or
event store. The supplied floor, watermark, generation, and page are not
loaded from authority; neither is the supplied current authority epoch. The
signed prior watermark detects regression but a lying adapter can still lie
consistently about all of them from the first page. There is no long-polling,
cancellation, retention deletion, consumer registration, or at-least-once
delivery worker here.

## Webhook boundary

The webhook signature is HMAC-SHA-256 over the event/repository/scope binding,
delivery ID and attempt, sent time, endpoint-scope commitment, body digest and
length, and key ID. Cursor and webhook keys are distinct Rust types and use
different domains. Verification:

1. validates fixed structural and configured bounds;
2. selects one of at most four unique key IDs and authenticates the signature;
3. checks independently supplied expected-event, endpoint-scope, and body
   bindings;
4. checks that delivery follows the supplied commit/authorization evaluation,
   then checks configured clock skew and the key window at the signed time; and
5. records the exact authenticated envelope under its tenant/repository,
   authorization scope, endpoint scope, delivery ID, and attempt in a bounded
   replay guard.

The guard reports `FirstSeen` or `Duplicate`, caps entries at 8,192 and
retention at one day with half-open expiry, prunes expired attempts, and does
not mutate on a failed signature, conflicting authenticated envelope, capacity
failure, or retention-overflow failure. An exact authenticated repeat is a
duplicate; reuse of one active scoped `(delivery ID, attempt)` for a different
authenticated envelope projection is a typed conflict. Separate endpoint/
authorization scopes and separate attempts do not collide, while the stable
event ID lets a consumer deduplicate the logical event. The guard is
process-local volatile state, not replay authority. No HTTP request, secret
store, endpoint registration, retry/backoff scheduler, dead-letter queue,
durable replay ledger, secret
distribution, or incident workflow is implemented. Key constructors reject an
obvious all-zero secret and the key wrappers implement neither `Debug`, `Copy`,
nor `Clone`, but this does not establish entropy, custody, zeroization,
separation, or rotation policy.

Verification requires guard retention of at least one millisecond more than
twice the accepted clock skew, covering both inclusive timestamp boundaries
while guard expiry remains half-open. The relationship is checked before replay
state can change.

Capacity is global to one guard instance even though replay identities are
scope-qualified. Sharing one instance across mutually untrusted consumers can
therefore create cross-scope capacity pressure; production partitioning,
quotas, durability, and eviction policy remain outside this seam.

Default debug output redacts event, cursor, webhook, and provenance commitments,
IDs, scopes, object references, and MACs. Explicit public fields and MAC getters
remain available for deliberate private serialization; redacted `Debug` is a
logging guardrail, not an authorization control.

Verification accepts independently supplied expected endpoint scope, body
digest, and byte length; it never resolves endpoint registration or reads or
hashes an HTTP body. Passing endpoint/body values copied from the envelope
instead of trusted registration state and a digest of the received bytes
defeats those external checks and is outside this seam.

## Build-provenance boundary

The provenance digest binds tenant/repository commitments, one OGVCS-002
Snapshot reference, selection-policy digest, materialized-root digest, client
version, toolchain, input set, optional build-result digest, and start/finish
times. It does not materialize or verify a workspace, prove that the selection
was authorized, hash build inputs, validate a shared cache, run a build, or
publish the OGVCS-002 Provenance object schema. It is a private deterministic
projection only.

## Hard bounds

| Resource | Candidate maximum |
|---|---:|
| Authorized event payload declaration | 256 KiB |
| Highest event/high-watermark sequence | `2^64 - 2` |
| Events returned in one replay page | 1,024 |
| Cursor verification keys | 4 |
| Cursor lifetime | 7 days |
| Webhook body declaration | 1 MiB |
| Webhook verification keys | 4 |
| Webhook accepted clock skew | 5 minutes |
| Replay-guard entries | 8,192 |
| Replay-guard retention | 1 day |

All sequence/time additions use checked arithmetic. Fixed-width binary
projections avoid platform-sized values in durable digests. Caller allocations
made before invocation are outside the retained-memory claim.

## Residuals blocking OGVCS-019

This candidate intentionally has no OGVCS-041 automation schemas, generated
SDK, service identity, authenticated snapshot-resolution API, ephemeral CI
materializer, shared verified cache, durable transactional outbox/replay
service, authorization filter, webhook transport/retry/dead-letter service,
secret rotation system, build-provenance object publication, metrics, operator
runbook, rollout, hosted three-OS evidence, fault campaign, or scale result.

No acceptance criterion is closed. The source tests show only local
contract behavior under caller-supplied facts; they do not prove commit/outbox
atomicity, least-privilege non-disclosure, reproducible materialization, cache
corruption recovery, or production webhook behavior.

## Local gates

```text
cargo +1.82.0 fmt --manifest-path core/automation-events/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/automation-events/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path core/automation-events/rust/Cargo.toml --release --locked --offline
cargo +1.82.0 clippy --manifest-path core/automation-events/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 package --manifest-path core/automation-events/rust/Cargo.toml --locked --offline --allow-dirty --no-verify
node --test tools/automation-events-source-policy.test.mjs
npm run test:roadmap
```
