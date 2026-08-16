# Opaque cursors and completion

## Cursor state

The public Cursor schema exposes only an opaque bounded token. Implementations
use an unpredictable handle or an authenticated opaque encoding; neither may
reveal scope, identifiers, generation, or position. Server-owned state binds
subject, tenant, repository, operation/query digest, generation, position,
issue time, expiry, and any authorization epoch needed by the operation.
Lookup verifies token integrity and all scope fields before reading or
disclosing page state. Cursor TTL is strictly positive; a zero TTL is malformed
before token issuance or lifecycle evaluation.

CursorScopeInput is the closed conformance carrier for the five scope
dimensions: subject, tenant, repository, operation, and queryDigest. Both the
issue and read scopes are schema-validated before any token selection, lookup,
mutation, expiry, generation, or lifecycle decision. Missing or unknown scope
members return PROTOCOL_MALFORMED before those later stages.

Invalid/tampered or unknown tokens return CURSOR_INVALID. A valid cursor used
under another subject, tenant, repository, operation, or query returns
CURSOR_SCOPE_MISMATCH without revealing the original scope. Expiry returns
CURSOR_EXPIRED. A valid position no longer retained returns CURSOR_GAP with
only the registered safe gap class. R0 never emits a current generation because
this baseline has no authenticated resource-visibility witness.

Expiry tombstones are keyed independently of unrelated cursor issuance and
pruning. A once-valid token read during the declared tombstone-retention window
returns CURSOR_EXPIRED even if another cursor was issued or a prune interleaved.
After that retention window the implementation may discard the tombstone, and
the same token then transitions to the non-oracular CURSOR_INVALID result.

## Explicit completion

Page state is `more`, `complete`, or `gap`; an empty item array does not imply
completion. `more` supplies an opaque next cursor. `complete` is authoritative
without relying on socket closure. `gap` is explicit and carries only a safe
registered problem. Streaming uses the same rule: terminal state is an explicit
typed semantic frame, with no separate R0 transcript digest or MAC; EOF or
transport closure is STREAM_INCOMPLETE. Empty EOF and EOF within an unterminated
frame are incomplete rather than malformed; a complete decoded frame with a
missing/unknown member is instead PROTOCOL_MALFORMED before sequence checks.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
