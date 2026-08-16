# Semantic idempotency

## Fingerprint

Every retryable mutation carries IdempotencyDescriptor. After bounded parsing,
duplicate rejection, schema validation, and semantic normalization, construct
the RequestEnvelope projection from fields whose assignment registry policy is
`fingerprint=true`: schemaVersion, operation, body, and the extensions map
(normalized to an empty map when absent). Correlation ID, deadline, negotiation
receipt, idempotency key, descriptor, and transport serialization are excluded.

Emit the projection with RFC 8785 and compute SHA-256 over UTF-8 bytes
`ogvcs.protocol/idempotency/v1\0 || JCS(projection)`. This is
OGVCS-SEMANTIC-JCS-SHA-256. Hashing raw received bytes is nonconformant: harmless
member reordering must produce the same fingerprint, while any operation, body,
schema, or participating extension change must produce a different one.

Keys use the closed self-dating form

`ik1.<issuedAtUnixMs>.<expiresAtUnixMs>.<base64url-entropy>`.

The two canonical-decimal components must exactly equal the descriptor fields,
expiry must be later than issue time, lifetime must not exceed
86400000 milliseconds, and the entropy component is
22..218 base64url characters. Future issue skew is zero in the deterministic
runner: issue time must be no later than the explicit evaluator time. Production
implementations may choose a separately versioned small skew policy, but cannot
widen this R0 conformance profile. The evaluator rejects keys at or after their
embedded expiry and uses the supplied bounded clock; ambient wall-clock access
is not part of conformance execution.

## Reservation and replay

The server atomically reserves `(authenticated scope, operation, key)` before
mutation. Same key and fingerprint joins or returns the original committed
outcome, including when the first response was lost. Same key with a different
fingerprint returns IDEMPOTENCY_KEY_REUSE before mutation. A failed uncommitted
attempt may release its reservation; a committed result must not. Expiry and
tombstone policy cannot allow a previously committed key to execute silently a
second time. At or after embedded expiry, every use of that exact key returns
IDEMPOTENCY_KEY_REQUIRED before a new mutation, even after its stored outcome
and tombstone have been retired; the caller must issue a new self-dating key.
Tombstones may improve replay diagnostics but are not the security authority for
key freshness. A committed outcome and any tombstone needed to prevent reuse are
retained through embedded expiry even if a shorter ordinary retention interval
elapses. The ordinary `tombstoneRetentionMs` policy may be zero because embedded
key expiry remains the non-reuse authority. Authorization is rechecked on every
join/retry before a stored result is disclosed; denial returns
AUTHORIZATION_DENIED without the stored body or a second mutation.

The idempotency execution route requires `retryableMutation=true`, a nonempty
self-dating key, and a closed IdempotencyProjectionInput containing exactly
schemaVersion, operation, body, and extensions. Embedded key timestamps must
equal the explicit issued/expires fields, and every attemptProjectionIndex must
address a carried projection. Structural or relationship violations return
PROTOCOL_MALFORMED before authorization, lookup, reservation, or mutation. An
initial authorization denial likewise occurs before reservation and reports no
mutation.

A retry-labelled attempt with a valid unexpired self-dating key and no existing
reservation or committed record is not an internal error and is not a replay.
After the ordinary authorization check it is the first execution: the server
atomically reserves the key, performs the mutation exactly once, and records the
result. Conformance reports `{firstExecution:true,replay:false}` for this path.

RunnerResult and AdapterResult define preMutation over the complete executable
case, not only its final attempt: it is true exactly when mutationCount is zero.
Thus a replay denied after an earlier commit reports false/1 even though the
denied retry itself began no additional mutation.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
