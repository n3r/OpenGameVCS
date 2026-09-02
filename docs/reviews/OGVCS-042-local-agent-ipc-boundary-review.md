# OGVCS-042 private local-agent IPC boundary review

## Decision

Accept this exact tranche only as an unpublished, unwired, pure Rust 1.82
protocol-fact and in-memory ledger candidate. It establishes deterministic
negotiation, typed local identity commitments, external-verdict transcript
binding, bounded replay/freshness/rotation state, consent and scope narrowing,
idempotent operation admission, status/event backpressure, explicit lock
knowledge, and single-use handoff state. It does not implement the local agent
described by OGVCS-042 and does not satisfy an acceptance criterion.

The exact base before this tranche is
`0d0e455431379ffa829dbb6e9ab6c1311a53cfc9`. The worktree is intentionally
uncommitted. OGVCS-042 remains **Todo**, and OGVCS-042-AC-01 through AC-05
remain open.

## Review method and authority map

The source review treated implementation claims as untrusted and compared the
candidate with the full OGVCS-042 PRD, ADR-0006, architecture sections 4, 5,
6.7, 11.3-11.5, 12, 13, 14, and 21, and the complete OGVCS-004, OGVCS-011,
OGVCS-016, OGVCS-019, and OGVCS-041 contracts. Every changed source, test,
package, policy, and documentation file was then read as one candidate.

The resulting ownership boundary is:

| Fact | Owning authority | Candidate behavior |
| --- | --- | --- |
| File identity | OGVCS-002 | Imports `FileId`; never allocates or maps it |
| Path/profile/case semantics | OGVCS-004 | Calls the existing validator/key/prefix implementation |
| Public protocol baseline | OGVCS-041 | Pins the generated manifest digest; does not decode or MAC-verify it |
| Workspace/status truth | OGVCS-011/012 | Accepts fresh commitments and bounded item facts only |
| Lock state/lease/generation | OGVCS-016 | Retains an opaque fact; never renews or authorizes submit |
| Event durability/authorization | OGVCS-019 | Models local bounded queue/cursor facts only; no outbox claim |
| Authentication/consent/OS/crypto | External adapters and later OGVCS-042 work | Requires typed `Verified` verdicts but cannot produce them |

The crate contains no import of native CLI/server modules and no transport,
filesystem, credential, keyring, network, or clock API.

## Negotiation and identity review

The OGVCS-041 generated manifest is parsed as exact lowercase SHA-256 and must
match both offers. Versions are typed `(major, minor)` pairs; zero major,
duplicates, oversize lists, missing intersections, and required-capability
skew fail. The greatest common version and ordered capability intersection are
deterministic. A ledger retains one configured agent offer and rejects a
handshake that substitutes another offer, preventing the peer from defining
both sides of negotiation after ledger construction.

Installation, endpoint, and integration are separate typed identities.
Endpoint locality/restrictive-access, integration registration, challenge
response, transcript signature, and anti-downgrade values are external verdict
facts committed into the transcript. The transcript also binds both nonzero,
distinct challenges; negotiated selection and raw-frame commitment; endpoint,
installation and integration identities/generations; verifier generation; and
issue/expiry times. Reuse of the same verified identity/key-generation
challenge pair is rejected even if session ID or raw framing changes. No
verdict is independently proved by this crate. Every enqueue, poll, and
acknowledgement additionally supplies the exact session transcript, consent
generation/grant, integration/workspace/repository, and an external
request-authentication verdict/commitment. The ledger checks those facts
against the retained subscription before cursor or queue use and commits them
into the event or receipt. The external adapter must bind that commitment to
the actual channel/request; this pure crate cannot do so.

## Scope and consent review

Path scopes carry repository, OGVCS-004 profile, and case-mode context. Item
and work counts are capped first. A complete spelling-byte pre-scan runs before
any path/key allocation, and a running exact aggregate logical-byte total is
capped before sorting, snapshot cloning, and normalization. Deterministic
normalization removes exact
repository-key duplicates, including case-equivalent spellings in folded mode,
exact paths covered by a prefix, and descendant prefixes covered by an
ancestor/root. The representative spelling for an equivalent key is
independent of input order. Exact `FileId` and asset-group commitments
deduplicate but
are never inferred from paths or each other. Root/prefix grants cover only
path/prefix selectors. This prevents accidental cross-domain broadening and
avoids duplicating OGVCS-016 asset-group expansion.

Consent records bind session, integration, workspace, repository,
capabilities, normalized scope, generation, issue/expiry, explicit
user/administrator confirmation class, external proof verdict, and proof
commitment. Replacement requires the exact prior commitment and next
generation. Revocation is generation-fenced. An operation/status/subscription/
handoff must match the active session and consent, negotiated capability,
workspace/repository, and a bounded subset of the granted scope. Persisted
idempotency, subscription, and handoff records also bind the exact consent
generation and grant commitment, so replacement cannot silently reactivate a
stale derived record. Broadened
replacement is possible only through another explicit external consent fact;
the crate itself makes no authorization decision.

## Operation, lock, and time review

Operation commitments include all requested OGVCS-042 FR-04 local facts:
integration/session/consent, workspace, repository, operation class, normalized
scope, base and current state commitments, state generation, observed/valid
times, idempotency key and retention, confirmation policy, deadline, raw-frame
commitment, and when applicable the complete lock-knowledge variant.

The idempotency key is scoped by integration. Exact replay under the unchanged
active consent returns the original receipt without re-execution even after
the original fresh-state or deadline window has elapsed; another request
commitment returns `IDEMPOTENCY_CONFLICT`, and consent replacement returns
`STALE_GENERATION`. Expired records remain fences until bounded reaping. No
operation is executed.

Lock facts distinguish `Granted`, `Denied`, `Lost`, `Unknown`, and
`Recoverable`. A grant needs nonzero authority epoch/generation, future lease,
and opaque proof commitment. Lost needs a prior generation. Unknown and
recoverable may record a prior generation but never expose a lease or become a
grant. This is presentation/recovery knowledge only; server time, lock
transition validity, owner/workspace policy, renew/release/transfer/break,
expiry, and submit checks are not implemented.

Supplied time can stay equal or increase and can never decrease. Fresh state
age/future windows, session/consent/idempotency/subscription/cursor/handoff
lifetimes, deadlines, rotation generations, event sequences, and ledger
revisions use checked arithmetic. The time value is caller supplied and not a
real-clock or server-time attestation.

## Status, event, and cursor review

Status batches are capped at 256 facts and bind a query scope, fresh state,
FileID, OGVCS-004 validated path, item state, item commitment, and explicit
complete/more result. A FileID selector authorizes the exact stable FileID even
after a rename; exact/prefix selectors authorize by OGVCS-004 key. Asset-group
membership remains fail-closed because this tranche has no owning expansion.
Duplicate FileIDs or path keys and items outside scope fail the entire batch.
This validates a supplied page; it does not scan an index or establish clean
workspace truth.

Subscriptions have a maximum queue and expiry. Event scope must narrow the
subscription scope, fresh state must be valid, and sequence must equal the next
sequence. The immediately prior exact event/frame from the same caller facts
can be identified as an at-least-once duplicate without consuming queue
capacity, even after the original event freshness or lock-lease time has
elapsed; the current session, consent, subscription, and caller proof still
have to validate. A new next event on a full queue returns `QUEUE_FULL` without
retained-byte or queue mutation. Poll pages are bounded to 64 and advance only
a delivered-position ledger.
Acknowledgement accepts a delivered cursor, removes an ordered prefix, and
records the corresponding state commitment. Older acknowledged cursors return
`CURSOR_GAP`; fabricated positions, state commitments, or expiries fail. The
subscription retains the exact expiry issued for every cursor position that
was actually delivered. This rejects both an unissued intermediate position
and a later recomputation that extends TTL, while a legitimate poll may issue
a new bounded cursor only after its input cursor passes validation. Every
issuance is checked against the configured TTL and subscription lifetime.

Cursor framing is unkeyed. Its subscription, generation, position, scope,
state, and expiry binding detects accidental substitution within this state
machine but is not a MAC, bearer credential, secret, or unguessability proof.
The exact externally authenticated caller facts plus active session and consent
checks are required for every subscription use; a cursor alone is rejected.
There is no durable OGVCS-019 outbox, authorization-time payload filtering, or
restart cursor retention.

## Handoff review

Handoffs bind exact session/consent generation and grant/integration/
installation, workspace, repository, trusted-client, action, normalized scope, fresh state,
verifier generation, issue/expiry, confirmation/signature verdicts, and their
commitments. Registration requires the handoff capability and scope narrowing.
Consumption requires the unchanged active consent, exact trusted-client and
handoff commitments, and a still-fresh state fact, then marks the record
consumed and retains it through expiry to reject replay. Caller/commitment
mismatch is checked before exposing whether a matching record is expired,
stale, or already used.

The crate does not sign, decrypt, launch, deep link, authorize, submit, review,
or recover anything. Low-entropy commitments are guessable; a handoff ID or
digest is not authority. The external desktop/signature adapter must establish
the facts before passing `Verified`.

## Resource and rollback review

Hard limits cover raw frame bytes, aggregate typed status/path bytes, every
collection, versions, capabilities, path selectors, status/event pages, queue
depth, work, retained logical bytes, record counts, and time windows.
Cross-scope comparisons precharge the checked
Cartesian work bound. Admission checks logical bytes and record counts before
retention. Path-scope construction pre-scans all supplied spellings before
allocating OGVCS-004 canonical/key strings. `LedgerLimits` can only narrow the
two retained maxima.

Retained bytes are a deterministic logical ledger, including fixed reserved
slots for optional revocation, consumption, and cursor-issuance fields, not
allocator/RSS evidence. Raw frame length is measured from the actual slice,
but typed facts are not decoded from that frame here. Temporary replacement
maps during bounded reaping and Rust allocator overhead are outside the exact
ledger. Poll and acknowledgement do not clone the whole event queue: they
admit comparison work first and polling clones at most the bounded result page.

The review inspected each mutation boundary. All validation, checked
arithmetic, replacement totals, receipt commitments, cancellation, and map
lookups happen before queue/map/state changes. Enqueue and acknowledgement
specifically precompute post-state logical totals before touching a queue.
Reaping constructs complete replacement maps and commits them together.
Failure-regression tests compare the full state commitment, revision, time,
counts, and retained total before and after replay, idempotency conflict,
scope denial, cancellation, time reorder, retained overflow, queue full,
event reorder, consent-generation mismatch, and handoff reuse.

## Adversarial findings fixed before freeze

1. **Agent-offer substitution:** the first draft negotiated against an
   `agent_offer` carried only by the handshake. The ledger now freezes a
   validated configured offer and rejects substitution.
2. **Fallible post-mutation queue arithmetic:** initial enqueue/ack code updated
   the queue before rechecking record arithmetic. Post-state totals are now
   computed before the first mutation.
3. **Receipt commitment gaps:** event enqueue and acknowledgement initially
   lacked full receipt commitments. Both now bind disposition/position,
   event/cursor, counts, next/ack sequence, and ledger revision.
4. **State configuration omission:** the state commitment initially omitted
   configured limits and agent support. Both are now committed.
5. **Cursor-state substitution:** the first cursor check bound its own state
   field but did not compare it with the delivered/acknowledged position. The
   subscription now retains the acknowledged state and validates cursor state
   against the exact queued/delivered fact.
6. **Cross-domain root broadening audit:** regression coverage confirms a root
   path prefix does not imply FileID or asset-group membership.
7. **Folded-key duplicate normalization:** equality originally included the
   caller spelling, so two case-equivalent prefixes could remove each other
   during ancestor reduction. Normalization now sorts by semantic key plus a
   deterministic representative and deduplicates by OGVCS-004 key/range.
8. **Typed status byte aggregation:** the raw-frame cap cannot bound separately
   supplied typed facts. Status validation now checks the full logical query
   scope and item/path aggregate against the same one-call ceiling.
9. **Cursor lifetime horizon:** an unkeyed cursor digest can be recomputed. The
   first fix rejected expiry beyond the configured TTL horizon and subscription
   expiry; finding 16 closes the remaining sliding-expiry gap.
10. **Constructed hard-limit bypass:** public `LedgerLimits` fields allowed a
    struct literal above the hard caps. The fields are now private, getters are
    read-only, and both construction paths validate the hard ceiling.
11. **Challenge reuse under transcript variation:** the replay fence originally
    keyed the full transcript, which changes with session ID or raw framing.
    It now keys the verified identity/key-generation challenge pair so the
    same pair cannot establish a distinct transcript.
12. **Partial event-page commitment:** the first page receipt selected event
    ID, sequence, scope, and current state but omitted kind and other facts. It
    now binds each complete stored enqueue commitment; a regression varies only
    event kind across otherwise identical fixtures.
13. **Under-counted normalized path storage:** the first logical-byte estimate
    counted caller spellings but not retained OGVCS-004 key/range strings. The
    checked ledger now includes canonical paths, encoded keys, prefix bounds,
    and non-root prefix keys.
14. **Stale handoff consumption:** registration checked fresh state, but a
    longer-lived handoff could be consumed after that state window elapsed.
    Unused handoffs now revalidate their stored fresh-state facts at consume
    time; an already-used record still deterministically returns
    `HANDOFF_USED`.
15. **Flat session retention estimate:** session accounting did not explicitly
    charge both offer vectors and the negotiated capability vector. Each
    retained session now stores its checked logical total, and bounded reaping
    recomputes from those per-record totals.
16. **Self-asserted cursor extension:** checking a recomputed cursor only
    against `now + ttl` still allowed its original expiry to slide forward.
    The ledger now retains the exact issued expiry per acknowledged or queued
    position and rejects unissued positions and changed expiries.
17. **Pre-admission queue clones:** polling and acknowledgement cloned an entire
    retained subscription, including every queued event, before charging work.
    Both paths now validate and scan a borrow; polling clones only its admitted
    page after the queue bound is charged.
18. **Stale idempotent replay:** the original deadline and fresh-state window
    were revalidated before an exact replay lookup, making a still-retained
    idempotency record unusable. Exact authorized replay now returns the stored
    receipt without re-execution; changed requests and expired records still
    fail closed.
19. **Consent-replacement drift:** subscriptions and handoffs checked only a
    reused consent ID, while idempotency commitments omitted the grant that
    authorized them. All three now retain and verify the exact consent
    generation and grant commitment.
20. **Nested final-cancellation fence:** session establishment called the pure
    negotiation function with the caller's final-cancellation probe, so it
    could return `CANCELLED` before replay and retained-state admission. The
    enclosing mutation now owns the sole final fence after those checks.
21. **Rotation ambiguity:** rotation replaced the installation ID and accepted
    arbitrary forward endpoint-generation jumps. Per-install rotation now
    preserves the installation ID, changes its identity commitment, and
    advances installation, endpoint, and verifier generations exactly once.
22. **Commitment omissions:** consent replacement, revocation, poll,
    acknowledgement, reaping, and several receipts omitted request framing,
    validation time, consent generation, or behavior-affecting retained
    accounting. Domains and commitments now bind those exact facts, and event
    commitments include their subscription identity.
23. **Sensitive derived `Debug`:** automatic formatting exposed paths,
    FileIDs, handshake challenges, and digest bytes. The public sensitive
    carriers now use explicit redacted formatting, with regression coverage.
24. **Aggregate scope admission:** scope bytes were checked only after sorting,
    cloning, and deduplication, allowing a large duplicate typed input to evade
    the intended pre-normalization boundary. A spelling-byte pre-scan now runs
    before per-selector path/key allocation, and a running exact total rejects
    it before sorting, snapshot cloning, or normalization.
25. **Root-gate omission:** the source-policy script existed but the root test
    chain did not invoke it. `npm test` now includes `test:local-agent-ipc`.
26. **Subscription caller confusion:** enqueue accepted only a subscription ID,
    while poll/ack accepted only an explicitly unkeyed cursor. Checking the
    stored subscription's old session did not authenticate the current caller.
    Every use now supplies and binds the exact session transcript, consent
    generation/grant, integration/workspace/repository, and external request
    authentication facts. A rejected caller cannot use a stolen valid cursor.
27. **Late event duplicate drift:** event freshness and lock-lease time were
    revalidated before exact duplicate recognition. An at-least-once retry of
    the immediately prior exact event now returns the duplicate disposition
    without treating the original event as new, while current caller/session/
    consent/subscription checks still apply.
28. **FileID-scoped status denial:** item membership considered only path and
    prefix selectors, so an exact stable FileID query rejected its own item.
    Status membership now matches an exact FileID or an authorized path key;
    asset-group expansion remains fail-closed and external.
29. **Endpoint identity substitution during rotation:** exact generation checks
    still allowed rotation to replace the endpoint ID, and its receipt omitted
    the prior endpoint facts. Per-install rotation now preserves both stable
    IDs and commits the complete prior endpoint.
30. **Reap-result ambiguity:** a reap receipt bound counts and totals but not
    the exact starting ledger. It now commits the prior state commitment, which
    determines the exact expired record set for the supplied time.
31. **Handoff state disclosure ordering:** a mismatched consumer could learn
    whether a guessed record was expired, stale, or already used before proving
    its trusted-client and handoff commitment. Exact caller/commitment matching
    now precedes those state-specific errors.
32. **Idempotency-key existence oracle:** operation admission branched on a
    retained integration/key before current consent and scope authorization,
    so an unauthorized malformed request could observe different error order
    for present and absent keys. Both new and replay paths now authorize and
    bind the current grant before consulting the idempotency ledger.

No live P0/P1/P2 defect was identified after these fixes in the bounded source
model. This statement is not an external security assessment or hosted proof.

## Requirement and acceptance boundary

| OGVCS-042 item | Candidate evidence | Remaining owner work |
| --- | --- | --- |
| FR-01 | negotiation, supplied handshake verdicts, replay, bounds, deadlines, cancellation, errors | real OS-local endpoint, permissions, authentication, codec and lifecycle |
| FR-02 | no credential type or release path | secure storage, credential use and canary evidence |
| FR-03 | manifest commitment, registration verdict, explicit consent/generation | real manifest discovery, consent UI/admin authority and revocation durability |
| FR-04 | complete local operation commitment and idempotency ledger | execution and authoritative producer integration |
| FR-05 | explicit imported lock knowledge, old-generation/session fence | authoritative OGVCS-016 integration and agent renewal |
| FR-06 | bounded supplied status facts and event queue/cursors | canonical index/jobs, rate/concurrency control, durable/restart behavior and scale |
| FR-07 | exact single-use handoff ledger | signing, trusted client, UI and authorized mutation |
| FR-08 | stale generation and recoverable/unknown facts | durable restart/upgrade reconciliation |
| FR-09 | explicit same-user/adapter nonclaims | production threat docs and three-OS tests |
| FR-10 | none | schemas, generator, C++/C# bindings and test client |

AC-01 has no published schemas, C++/C# client, or end-to-end journey. AC-02 has
no real endpoint, attacker, credential, or OS evidence. AC-03 has no same-user
threat execution or trusted desktop. AC-04 has no process crash, network,
workspace byte, lock authority, or durable recovery evidence. AC-05 has no
million-path workspace or latency/memory campaign. All five remain open.

## Residuals and nonclaims

- External `Verified` values are facts, not cryptographic or OS proof. A caller
  able to fabricate them defeats this pure layer.
- No sockets, pipes, endpoint discovery, filesystem, ACL/owner inspection,
  keyring, credential, server, object store, real clock, durable database,
  agent process, or local audit exists.
- No workspace status production, sync/materialization, start-edit request,
  lock renewal, checkpoint/revert, job, submit/review/destructive operation,
  publication, or recovery mutation exists.
- No public protocol or route, CLI, UI, trusted deep link, C++/C# binding,
  hosted OS evidence, red-team result, same-user-malware defense, privacy or
  unguessability proof, scale/latency result, rollout, or package publication
  is claimed.
- Raw frame bytes and typed facts are separately committed; no decoder or proof
  of semantic equivalence connects them in this tranche.
- Subscription caller-authentication verdicts and commitments are similarly
  external facts. The real channel adapter must derive them from the request;
  a fabricated `Verified` value defeats this pure model.
- Rotation and consent replacement fence old sessions and derived records but
  do not eagerly delete them. Their bounded logical bytes/record slots remain
  occupied until their own expiry and explicit reaping.
- Queue, page, work, record, and byte ceilings exist, but there is no process
  scheduler, per-caller rate limiter, or concurrency admission controller.
- Local event IDs are caller-supplied and only the immediately prior exact
  event/frame is recognized as an at-least-once duplicate; global stable-ID
  uniqueness and durable replay remain with OGVCS-019.
- In-memory state vanishes on process loss. Reaping is local cleanup, not
  restart reconciliation or durable replay protection.

## Verdict

Ship/no-ship for this exact tranche: **SHIP only as a private, unpublished,
unwired source candidate after the pinned debug/release, formatting, Clippy,
packed-package, Node source-policy, roadmap, and focused predecessor gates
pass. HOLD for any process, endpoint, authentication, credential, workspace,
lock-renewal, trusted-client, public schema/binding, production, rollout,
acceptance-criterion, or OGVCS-042 completion claim.**
