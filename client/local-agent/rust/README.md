# Private local-agent IPC fact candidate

This unpublished Rust 1.82 crate is a bounded first implementation tranche
for OGVCS-042. It is a pure protocol-fact validator and in-memory state ledger.
It is not an agent process, wire protocol, transport, authentication service,
workspace engine, lock authority, or trusted desktop client. Nothing in this
crate is wired into a public route, CLI, integration, or production runtime.
OGVCS-042 remains **Todo**, and none of OGVCS-042-AC-01 through AC-05 is closed.

## Exact boundary

The candidate provides:

- deterministic local protocol negotiation over typed major/minor versions
  and a finite capability vocabulary, pinned to the generated OGVCS-041
  protocol-manifest commitment;
- typed installation, local-endpoint, and integration identities;
- a challenge/response transcript record whose locality, restrictive-access,
  registration, anti-downgrade, signature, and challenge verdicts are supplied
  by an external adapter;
- a bounded replay, freshness, expiry, installation/key-rotation, consent,
  idempotency, event, and single-use handoff ledger;
- explicit consent capability and repository-scope narrowing, with every
  derived operation, subscription, and handoff bound to the exact active
  consent generation and grant commitment;
- operation envelopes that bind integration, workspace, repository, normalized
  scope, base/current state, state generation, idempotency, deadline,
  confirmation policy, and an optional OGVCS-016 lock fact;
- bounded status-batch validation and event subscriptions with exact sequence,
  queue backpressure, scoped cursors, polling, acknowledgement, and explicit
  externally authenticated caller facts on every enqueue/poll/ack use; and
- explicit `Granted`, `Denied`, `Lost`, `Unknown`, and `Recoverable` lock
  knowledge. Only `Granted` can carry a future lease fact, and even that fact is
  an opaque OGVCS-016 proof commitment rather than authority created here.

Every receipt and retained record is bound by a domain-separated SHA-256
commitment, including the supplied raw-frame commitment and validation time
where they affect an entry-point result. Commitments use typed wrappers for
endpoint, installation, integration, session, consent, workspace, repository,
idempotency, subscription, event, handoff, trusted-client, baseline, state,
lock-proof, and confirmation identities. The hash framing is deterministic
length-prefixed binary data; it is private candidate framing, not a repository
object, public wire encoding, MAC, signature, or bearer credential.

## Composition instead of duplication

`FileId` is the OGVCS-002 type from `ogvcs-object-model`. Exact paths and
prefixes are validated and keyed by the OGVCS-004 Rust path contract with its
existing path profile and case mode. The crate does not allocate FileIDs,
expand an asset group, infer FileID/path equivalence, or reinterpret path
collisions.

A scope normalizes exact duplicate selectors by their OGVCS-004 repository
keys (including case-equivalent spellings in folded mode) and removes exact
paths or descendant prefixes already covered by an ancestor prefix. The
canonical spelling selected for an equivalent key is independent of input
order. A root prefix covers exact paths and prefixes in the same
repository/profile/case context;
it does not silently cover a `FileId` or asset-group commitment. FileID and
asset-group selectors narrow only by exact identity. Asset groups are opaque
versioned commitments supplied after the owning expansion boundary; no group
membership or freshness claim is made here.

Negotiation selects the greatest common typed version and the sorted
intersection of capabilities after satisfying both sides' required sets.
Duplicate or zero-major versions, duplicate capabilities, missing required
capabilities, and a protocol-manifest value different from the checked-in
OGVCS-041 generated binding fail before a session is retained. A ledger freezes
one configured agent offer; a handshake cannot substitute another offer.
This does not decode, MAC-verify, or replace an OGVCS-041 negotiation receipt.

Lock knowledge is an imported fact only. Authority epoch, generation, lease,
and proof fields remain owned by OGVCS-016 and its server-time state machine.
This crate never acquires, renews, releases, transfers, breaks, expires, or
validates a lock for submit. `Unknown`, `Lost`, and `Recoverable` never become
local exclusivity, and rotation makes old sessions unusable rather than
retaining a lock promise.

## State, ordering, and rollback

Ledger mutation entry points apply this stable high-level precedence:

1. actual supplied raw-frame byte bound;
2. preflight cancellation;
3. nondecreasing supplied time;
4. collection-count, structural, identity, and typed aggregate-byte facts;
5. entry-specific temporal and current-authority checks;
6. replay/idempotency, sequence, queue, record, and retained-byte admission;
7. final cancellation; then
8. one in-memory commit with a monotonic revision.

The pure path-scope constructor similarly checks raw bytes and cancellation,
then item/work ceilings and pre-scans the complete caller-owned spelling total
before allocating path/key strings. It checks the exact running aggregate
typed-byte total before it sorts, clones, or normalizes the admitted selector
set.

All checked arithmetic and receipt construction occur before the first state
change. Errors, including cancellation, leave revision, supplied time,
retained-byte ledger, queues, replay state, and state commitment unchanged.
An exact idempotent operation replay under the same still-active consent grant
returns the original receipt without re-executing or reapplying the original
freshness/deadline checks; reuse of the key with another exact request or a
different consent generation is rejected. A verified challenge pair
cannot establish a second transcript even if the session or raw framing
changes. Expired entries remain replay fences until explicit bounded reaping.
Replayable operation and event entry points validate bounded shape and current
caller/authority/scope before consulting stored keys. Exact stored retries then
skip only the original request's temporal validation; new admissions validate
freshness, deadline or lease before capacity and final commit.

Time is a monotonically nondecreasing integer supplied by the caller. It is not
read from a real clock and is not evidence of server time. Sessions live at
most five minutes; a fresh state may be at most 30 seconds old and 30 seconds
into the future; operation deadlines are at most five minutes away; handoffs
live at most two minutes. Per-install rotation preserves the installation and
endpoint IDs, changes the installation identity commitment, and advances the
installation, endpoint, and verifier-key generations by exactly one. Existing
sessions, consents, subscriptions, operations, and handoffs then fail through
the old-session fence; no key material is rotated here.

Event delivery is at least once. Enqueue accepts only the next exact sequence;
an exact repeat of the immediately preceding event/frame is reported as a
duplicate without reapplying the original event freshness or lock-lease time
check. The subscription, session, consent generation/grant, integration,
workspace, and repository must still be current. A full queue returns
`QUEUE_FULL` without dropping or advancing. Polling never infers completion
from an empty page. Acknowledgement removes only already-delivered sequence
positions. An acknowledged old cursor returns `CURSOR_GAP`. Cursor commitments
are unkeyed integrity framing scoped to the subscription, generation,
position, path scope, state, and expiry. The ledger retains the exact expiry it
issued for each delivered position and rejects a recomputed extension or an
unissued intermediate position.

Every enqueue, poll, and acknowledgement also carries the exact session
transcript, consent generation/grant, integration/workspace/repository, and an
external request-authentication verdict/commitment. Those caller facts are
validated against the retained subscription and committed into the event or
receipt. A later legitimate poll can issue a new bounded cursor only after
both its caller facts and input cursor pass validation; every issued expiry
remains within the configured TTL and subscription lifetime. The cursor is not
authentication or bearer authority. The request-authentication verdict is a
strict external-channel precondition, not verification performed here.

A trusted-handoff record binds the exact integration, installation, consent
generation/grant, workspace, repository, path scope, action class, fresh
base/current state,
trusted-client identity, verifier generation, external confirmation/signature
verdicts, and expiry. Consumption requires the exact stored commitment and
trusted-client fact and revalidates the stored fresh-state window, then marks
the record used while retaining it until expiry to reject replay. The crate
neither signs nor opens a desktop flow and never executes submit, review, or
destructive recovery.

## Bounds

| Resource | Hard maximum |
| --- | ---: |
| Raw bytes supplied to one entry point | 1,048,576 |
| Aggregate logical typed bytes in one path-scope or status entry point | 1,048,576 |
| Generic collection items | 256 |
| Offered versions per side | 32 |
| Required or optional capabilities per side | 16 |
| Path selectors per scope before normalization | 256 |
| Status items per batch | 256 |
| Events returned per page | 64 |
| Events retained per subscription | 256 |
| Charged work units per entry point | 131,072 |
| Retained logical bytes per ledger | 4,194,304 |
| Retained records per ledger | 4,096 |
| Sessions / consents | 256 / 256 |
| Transcript replays / idempotency records | 1,024 / 1,024 |
| Subscriptions / handoffs | 64 / 256 |
| Session / consent maximum lifetime | 300,000 ms / 86,400,000 ms |
| Idempotency / subscription maximum lifetime | 86,400,000 ms / 3,600,000 ms |
| Cursor / handoff maximum lifetime | 300,000 ms / 120,000 ms |
| State age / future-validity maximum | 30,000 ms / 30,000 ms |
| Operation deadline horizon | 300,000 ms |

Counts, byte totals, cross-scope comparison work, sequence/revision/generation,
expiry arithmetic, and retained totals use checked arithmetic. `LedgerLimits`
may narrow retained bytes and record counts but cannot raise the hard maxima.
The retained-byte ledger counts deterministic logical fields and stored path
bytes, including reserved slots for bounded optional revocation, consumption,
and issued-cursor facts; it does not count allocator overhead or exact resident
memory. Raw-frame bytes are measured from the actual slice, while path-scope
and status calls also bound their separately supplied aggregate typed path
facts. This crate does not parse the frame or
prove that external decoding produced the supplied typed facts. Those are
explicit boundaries, not peak-memory or decoder-security claims.

## Known answers and tests

The contract tests pin these deterministic SHA-256 answers:

- negotiation selection:
  `1adab5f96e5d5cad26c6c08def87a30f1c86e7c37a92a13b5c868319b3d98f08`;
- handshake transcript:
  `a56601e13932bd0bb6762e514074334a61b01100ac2999ded329ec1dce30db91`.

Sixteen deterministic contract tests cover input/version/path/status/work/
retained/queue exact maxima and maximum-plus-one rejection,
root/ancestor/key-equivalent duplicate scope
normalization, negotiation ordering, configured-offer and manifest pins,
transcript/challenge-pair replay, final-cancellation precedence, time
monotonicity, exact rotation fences, consent replacement/revocation and stale
derived-state fencing, capability and scope narrowing, freshness/deadline
edges, idempotent operation replay/conflict after the original time windows,
all explicit lock states, path- and FileID-scoped status, status duplicates,
queue backpressure, full event-page/caller commitment, late exact event
duplicate/reorder, cursor caller rejection, polling/ack/gap/exact
issuance/unissued-position/TTL-extension rejection, handoff single use, expiry
reaping, redacted debug output, cancellation, and unchanged state commitments
after failure.

## Explicit nonclaims

This candidate intentionally has no:

- socket, named-pipe, loopback, endpoint discovery, service process, framing
  codec, request router, transport security, or OS endpoint creation;
- filesystem, workspace index, watcher, materialization, local mutation,
  checkpoint, revert, status producer, job executor, or million-path result;
- OS ACL/ownership verifier, keyring, credential provider, server or object
  store credential, cryptographic key custody, signing, signature/MAC
  verification, random nonce generation, or real authentication;
- server call, authorization decision, request-root grant, submit transaction,
  branch publication, lock authority, lock renewal, or durable audit/outbox;
- durable persistence, crash/restart journal, multi-process exclusion, upgrade
  reconciliation, or rollback state beyond one in-memory value;
- public protocol/schema stability, public SDK, CLI, UI/deep-link handler,
  C++/C# binding, test client, package publication, or rollout;
- protection claim against malware with the same OS-user privileges;
- confidentiality claim for SHA-256 commitments over low-entropy facts,
  privacy proof, bearer protection, identifier/cursor unguessability, or
  resistance to a caller that fabricates an external `Verified` verdict;
  specifically, the caller-authentication commitment is not internally tied
  to the raw frame or proved by this crate;
- hosted Windows/macOS/Linux endpoint evidence, red-team result, real-clock or
  key-rotation proof, performance/latency/scale evidence, acceptance-criterion
  evidence, or production-readiness claim.

Generic stable errors omit paths, identities, and protected details, but this
alone is not an OGVCS-003/009 authorization or non-disclosure proof. The caller
must trust and bind the external OS/crypto/consent/status/lock adapters before
their verdicts have meaning. Sensitive `Debug` implementations redact paths,
FileIDs, challenges, and digest values; explicit accessors and hexadecimal
conversion remain deliberate caller-visible APIs, not confidentiality controls.

## Local gates

From the repository root with cached Rust 1.82 and Node 24:

```sh
cargo +1.82.0 fmt --manifest-path client/local-agent/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path client/local-agent/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path client/local-agent/rust/Cargo.toml --locked --offline --release
cargo +1.82.0 clippy --manifest-path client/local-agent/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
sh client/local-agent/rust/scripts/test-packed.sh
node --test tools/local-agent-ipc-source-policy.test.mjs
npm run test:roadmap
```
