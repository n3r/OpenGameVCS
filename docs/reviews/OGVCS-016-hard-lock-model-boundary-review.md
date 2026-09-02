# OGVCS-016 private hard-lock model boundary review

**Decision:** SHIP only as a bounded, unpublished, unwired state-model
candidate after independent audit. Do not treat it as authorization,
persistence, production enforcement, or completion of OGVCS-016.

**Source baseline:** `a20c41f1cf4e91420085524d9f0719aaf1f3c0f1`

## Independent audit hardening

The frozen candidate received a second full source/test and predecessor-boundary
audit on 2026-09-02. The audit found and corrected four implementation defects
before integration:

1. two empty repository-root prefixes did not conflict because neither carries
   an exact path key; prefix/prefix conflict now uses the authoritative
   OGVCS-004 range intersection and has a root/root regression;
2. event, receipt, and state commitments omitted immutable path profile, case
   mode, and configured limits, while replayed operation receipts did not expose
   their original supplied record time; commitments now bind configuration and
   receipts distinguish original record time from later batch replay time;
3. overlap work was charged only after comparison and submit proofs were
   linearly rescanned for each changed target; overlap cost is admitted before
   comparison, work counters never advance beyond a rejected ceiling, and one
   bounded proof index replaces repeated scans; and
4. the fault adapter calculated ambiguity commitments before normal batch/work
   admission, permitting avoidable processing of a batch that could not commit;
   commitments are now calculated only after the normal bounded transition
   succeeds.

Additional regressions cover root, nested prefix, group/FileID/prefix overlap;
historical acquire replay after expiry; old proofs under the new epoch; supplied
permission error precedence; configuration-bound commitments; exact/max+1
target bytes and prefix members; configured retained waiter/advisory counts,
batches and reasons; fault-path batch admission; and exact submit work. These
fixes remain inside the pure, private, unwired scope and close no OGVCS-016
acceptance criterion.

### Frozen local gate result

- Rust 1.82 debug and release each passed 67/67 tests; rustfmt check and
  warning-denied Clippy passed across all targets.
- `cargo package --locked --offline --allow-dirty --no-verify` passed with a
  16-file 190.5 KiB archive (31.1 KiB compressed). The generated archive uses
  local predecessor path dependencies and is not a standalone registry-install
  claim.
- Actual local Node `v24.9.0` passed 4/4 private source-policy tests and 8/8
  roadmap tests; the roadmap remains 39 Todo / 7 Done and OGVCS-016 remains
  Todo.
- Focused predecessor replays passed the full OGVCS-002 Rust suite (134 passed,
  two explicitly ignored exact-scale cases), OGVCS-004 Rust path authority
  (8/8), OGVCS-003 language-neutral authorization authority (15/15), and
  OGVCS-005 language-neutral benchmark/fault authority (4/4).
- `git diff --check` passed. No hosted, native crash/restart, partition,
  latency, scale, database, or public-route result was produced by this audit.

## Reviewed seam

The candidate owns only deterministic in-memory transition semantics for one
supplied repository/domain scope:

1. normalize FileID, prefix, and bounded asset-group conflict footprints;
2. serialize simultaneous requests deterministically;
3. fence acquire, renew, release, same-owner workspace transfer,
   reason-bearing break, expiry, wait, and advisory intent by epoch and
   monotonic generation;
4. replay exact idempotency receipts and reject changed-key reuse;
5. retain privacy-neutral outcomes plus immutable receipt/event commitments;
6. compare current locks with supplied submit facts through a pure nonmutating
   interface; and
7. model the four exact OGVCS-005 lock fault boundaries without a durability
   claim.

`FileId` and snapshot references come from OGVCS-002. Canonical repository
keys/prefixes, case folding, NFC rejection, path profiles, and prefix ranges
come from OGVCS-004. The crate does not copy or reinterpret those contracts.

## Conflict and identity review

- Same-FileID targets conflict even when the supplied current path changes.
- Two different FileIDs at a reused path do not conflict as direct FileID
  locks. A prefix footprint still covers the new path identity.
- Prefix/prefix nesting, including root/root, and prefix/member paths use the
  exact configured OGVCS-004 repository key ranges. Folded case aliases
  collide; decomposed non-NFC spelling rejects before transition.
- Asset groups are anchored by stable opaque group ID and also overlap direct
  FileID/prefix footprints through their supplied members. Exact 256-member
  input succeeds; member 257 fails closed.
- Duplicate FileIDs, folded path collisions, group-policy substitution,
  unknown expansion versions, zero view generations, and prefix-external
  members reject.

The expansion remains untrusted and potentially stale. Completeness and
current generation must be established by the future fenced metadata adapter.
This model alone cannot prevent a production move into a prefix between an
expansion read and commit.

## Lease, generation, and idempotency review

The only time source is a supplied nondecreasing integer tick. Expiry occurs at
`server_time >= expires_at`; takeover then competes normally. Acquire allocates
one global monotonic generation, and renew/transfer rotate it. Proofs bind
claim ID, current epoch, generation, and exact receipt digest. Break uses an
admin-facing selector with exact epoch/generation plus an opaque supplied
`lock.force-unlock` fact and nonempty bounded reason.

An operation receipt retains the supplied time at which it was first recorded.
An exact replay returns that historical time even though the enclosing batch
reports its later transition time. Neither time value is a real-clock or
freshness attestation.

Batches reject cancellation, time regression, invalid authority epoch,
unbounded raw shapes, and work/capacity exhaustion without mutation. Unknown
same-key/different-request pairs reject the whole batch. Existing changed-key
reuse produces no event or idempotency mutation. Exact replays of acquire,
renew, release, transfer, break, expiry, wait, and advisory begin return the
original receipt and never resurrect or revert later state. Timer advancement
is an independent authority input: a historical successful receipt can replay
after its claim naturally expires without promising current exclusivity.

## Privacy and authority review

Public outcome structures contain no owner, workspace, path, FileID, group
member, reason, or conflict count. This is only privacy-neutral shape. The
crate has no authorized-view construction and cannot decide which outcome,
claim ID, or commitment a caller may see. Event/receipt/state digests may bind
guessable values, and deterministic claim IDs are commitments rather than
unpredictable secrets. They are explicitly forbidden as unauthorized
disclosure or bearer authority. Commitments bind the model's immutable path
profile, case mode, configured limits, epoch, and supplied record time so two
different conflict/resource semantics cannot produce an indistinguishable
receipt merely because their raw request bytes match.

OGVCS-003 permission assignments are preserved only as supplied opaque facts.
The model checks assignment/scope/subject/epoch shape but cannot verify issuer,
session, policy, signature, revocation, or request-root authority. It therefore has no
production authorization brand. The same boundary applies to supplied
asset-group policy and submit requirement facts.

## Submit seam review

`validate_submit_facts(&self, ...)` binds current owned workspace proofs and a
private OGVCS-010-shaped plan commitment. A changed FileID path still matches;
a delete/recreate with a new FileID does not consume the historical proof;
prefix locks cover member paths; stale/foreign/missing/extraneous proofs fail
with bounded classes. The state commitment and event count are unchanged.

"Current" means only the model's stored, caller-supplied `server_time`, which
is returned in the validation receipt. Validation neither advances time nor
attests freshness. A future adapter must advance expiry from its authoritative
server-time source and run validation on the exact transaction-bound state;
validating a stale clone is not enforcement.

This validates facts only. It does not evaluate authorization/policy, prove
target expansion completeness, consume a lock, apply lock disposition,
construct immutable metadata, advance a branch, append a durable audit/outbox
record, or share OGVCS-010's transaction authority.

## Fault and resource review

The model recognizes the frozen harness registry IDs:

| Registry boundary | Candidate behavior |
|---|---|
| `policy.decision` | supplied fact boundary; injected failure is precommit and inert |
| `lock.mutation` | injected failure is precommit and inert |
| `metadata.commit` | crash/error before commit is inert; crash after commit is ambiguous and idempotently recoverable |
| `event.publish` | committed state remains; delivery outcome is ambiguous and retry-safe |

This does not execute a database process or crash/restart system. Configured
caps cover hard locks, advisory intents, waiters, notices, idempotency, events,
batches, submit targets, reason bytes, lease ticks, and work. Tests prove exact
rollback when event, idempotency, notice, cancellation, and work admission
fail, including rollback of partially prepared waiter notices. Fault-only
ambiguity commitments are computed after normal batch admission, overlap work
is admitted before comparison, and submit proofs are indexed once. Exact/max+1
tests cover raw target bytes/members, retained queues/sets, batches, reasons,
and submit work; this is bounded local evidence, not a scale or latency claim.

## Acceptance interpretation

- **AC-01:** narrow model relevance only. Simultaneous overlapping acquire has
  one deterministic grant, and fault-model ambiguity cannot produce two active
  owners. There is no submit acknowledgement, partitioned service, database,
  or production branch transaction, so AC-01 remains open.
- **AC-02:** narrow target/lease relevance only. Local tests cover FileID move,
  folded case, NFC rejection, group bounds, delete/recreate, expiry, stale
  renewal/release, and prefix/group overlap. There are no normative public
  vectors or production metadata race, so AC-02 remains open.
- **AC-03:** open. Pure fault staging is not crash/restart recovery evidence.
- **AC-04:** open. No authorized owner/list/wait response exists.
- **AC-05:** narrow model relevance only. Transfer/break require supplied
  assignment facts and reasons and bind events; no policy authority, durable
  audit, or notification delivery exists.
- **AC-06:** narrow model relevance only. Epoch promotion invalidates claims
  and old messages; there is no signed recovery boundary, failover system, or
  client reacquire presentation.

## Residuals and nonclaims

OGVCS-016 remains Todo. Production identity/session authorization,
non-disclosing authorized views, authoritative expansion/revision policy,
database schema and serializable transactions, lock leader/fencing, public
protocol/CLI/routes, filesystem hints and crash recovery, atomic-submit lock
disposition, audit persistence/integrity, notification delivery, real clock
and lease/SLO selection, cross-branch retained integration domains, OGVCS-005
partition/crash campaigns, hosted three-OS evidence, scale/latency proof,
operations, rollout, and rollback remain open.
