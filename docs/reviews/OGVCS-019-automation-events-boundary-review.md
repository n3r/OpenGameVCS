# OGVCS-019 private automation-event boundary review

**Decision:** SHIP only as a private, unpublished, unwired
event/replay/webhook/provenance contract candidate. Do not treat it as an
automation API, durable outbox, CI client, authorization filter, webhook
service, or OGVCS-019 completion evidence.

**Source baseline:** `a20c41f1cf4e91420085524d9f0719aaf1f3c0f1`

## Reviewed seam

The candidate composes the frozen OGVCS-002 `ObjectRef` for Snapshot identity
and uses fixed-width private commitments for caller-supplied commit, outbox,
authorization, event, delivery and build facts. Deterministic event and
provenance hashes bind every field through versioned domains. Cursor and
webhook MACs use separate domains and distinct key types.

The replay function admits at most 1,024 exact contiguous events, checks every
event before cloning a result, and requires its supplied page length to equal
the count implied by the supplied retained floor/high watermark. Signed cursor
claims bind the closed consumer scope, generation, next sequence, retention
floor and high watermark at issuance, current authority/security epoch,
issue/expiry times, and key ID. Authentication precedes expiry classification.
Webhook verification authenticates the exact event, endpoint, body,
delivery/attempt and timestamp projection before clock-window classification
and replay-guard mutation.

## Independent adversarial hardening

The independent source audit rejected the initial frozen candidate until these
bounded defects were repaired:

- commit-frozen authorization facts had been forced to appear at or after the
  commit rather than at or before it;
- events admitted sequence `2^64 - 1` although replay could not issue its
  exclusive tail cursor;
- multiple cryptographic commitments treated the all-zero SHA-256 value as an
  implicit missing-value sentinel, contrary to OGVCS-002 semantics;
- an authenticated cursor could be used before issuance and could encode a
  retained floor above its next sequence;
- reusable cursor claims omitted the OGVCS-009 authority/security epoch fence;
- cursor claims omitted the already observed high watermark, allowing a
  later regressed watermark to masquerade as a caught-up tail;
- cursor signing-set membership compared secret arrays with ordinary equality;
- the signed webhook endpoint scope was never compared with independently
  supplied expected endpoint registration state;
- expected webhook event/endpoint/body comparisons ran before signature
  authentication, exposing an avoidable unauthenticated binding oracle;
- webhook signing/verification allowed a supplied send time before the commit
  or declared authorization evaluation it purported to deliver;
- replay could issue a page before the supplied event commit, declared durable
  acknowledgement record, or authorization evaluation time;
- the replay guard keyed only `(delivery ID, attempt)`, so unrelated tenants,
  repositories, authorization scopes, or endpoints could collide and a
  different valid envelope could be mislabeled as a duplicate;
- default debug derives exposed protected hashes, IDs, scopes, object
  references, and provenance commitments to ordinary logs;
- exact-expiry pruning was off by one, while capacity/expiry-overflow failures
  could mutate pruning state before returning an error;
- guard retention could be shorter than the accepted timestamp window, letting
  a still-valid exact replay become `FirstSeen` after premature pruning.

The repaired seam uses a half-open cursor/guard expiry boundary, a stable
`u64` page-count calculation, authority-epoch and prior-watermark fencing,
constant-time HMAC confirmation of cursor signing material, scoped
exact-envelope replay entries, conflict classification, and
mutation-free failure paths. Regression vectors cover the exact and maximum+1
boundaries, every event/webhook/provenance commitment field, cross-scope ID
collisions, valid conflicting attempts, future cursors, overflow, and the
independently recalculated event, cursor, webhook, and provenance known answers.

## Security and correctness interpretation

- Event IDs, commit/outbox commitments, and acknowledgements are supplied
  evidence, not transaction or durability authority.
- Authorization mode/policy/scope/epoch/time are supplied facts. Because no
  payload bytes or paths are admitted, this seam cannot leak them itself, but
  it also cannot prove that a real payload was filtered.
- Cursor integrity does not authenticate the supplied storage window. A
  storage adapter can still omit events by lying consistently about its high
  watermark; durable outbox integration and a commit/fault matrix remain
  required.
- HMAC verification covers the complete webhook projection and failed
  signatures do not consume replay capacity. Exact repeats are distinct from
  conflicting active delivery attempts, and replay keys include tenant,
  repository, authorization and endpoint scope. The bounded replay guard is
  volatile guidance, not durable replay protection or event deduplication.
- Rejecting an all-zero key is only a malformed-input check. It is not an
  entropy, custody, separation, revocation, or rotation proof.
- Digest fields are fixed cryptographic values, so the all-zero digest remains
  an admissible value. Only opaque identity/key sentinel fields reject zero.
- Opaque commitments and deterministic IDs can be guessable and correlatable.
  The seam does not prove keyed privacy projections and those values are not
  authorization tokens or safe public telemetry by construction.
- Webhook verification receives an independently computed expected body digest
  and length plus an independently supplied expected endpoint-scope
  commitment. It neither resolves registration nor hashes HTTP bytes, so an
  adapter that copies those signed fields instead of consulting trusted
  registration state and hashing the received body defeats those external
  checks.
- No raw payload, path, token, secret, or credential is returned. Key structs
  intentionally omit `Debug`, `Copy`, and `Clone`; event, cursor, webhook,
  replay-result, and provenance debug surfaces redact IDs, object/digest
  commitments, scopes, and MAC bytes. Explicit field access remains available,
  so this logging guardrail is not an authorization, zeroization, or
  secret-custody claim.

Every builder/validator returns no result on failure. Integer additions are
checked, stable hashes contain no `usize`, and configured maxima cannot exceed
the literal hard bounds documented in the crate README.

## Acceptance interpretation

The candidate has bounded relevance to FR-05 through FR-07 and FR-10 only: it
models commit-fact binding, ordered scoped replay, signed delivery, duplicate
attempt classification, and deterministic provenance. It establishes no
production authority or external effect.

AC-01 through AC-05 remain open. There is no materializer, shared cache,
transactional outbox integration, crash/replay campaign, webhook transport or
dead-letter service, service identity, authorization non-disclosure probe,
three-OS build, or large-workspace benchmark.

## Residual implementation

Before OGVCS-019 can advance, it still needs versioned OGVCS-041 schemas and
SDK generation, authenticated service identities, immutable snapshot
resolution, ephemeral selective materialization, a credential-free verified
shared cache, atomic OGVCS-010 outbox wiring, durable cursor/retention/replay,
per-consumer authorization projection, webhook registration/rotation/retry/
dead-letter operations, OGVCS-002 provenance publication, telemetry/runbooks,
fault and security matrices, hosted portability, scale/SLO evidence, and
rollout.

OGVCS-019 remains Todo and no acceptance criterion is closed.
