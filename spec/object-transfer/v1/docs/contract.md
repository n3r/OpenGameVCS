# Filesystem transfer candidate

## Imported authorities

- Object references and identity verification are OGVCS-002 format v1.
- Grant envelopes, claims, request roots, audience, authority epoch, key
  generation, expiry, and replay outcomes are OGVCS-003 authorization v1.
- Idempotency keys/fingerprints and half-open range digest/validator behavior are
  OGVCS-041 protocol `1.0.0-rc.1`.
- OGVCS-007 manifests/chunks are ordinary OGVCS-002 objects to this backend.

## Backend behavior

The filesystem profile derives each tenant-scoped key as lowercase HMAC-SHA-256.
The exact HMAC message is the ASCII bytes `OGVCS-OBJECT-BACKEND-KEY-V1`, one NUL
byte, the UTF-8 tenant, one NUL byte, and the ASCII canonical ObjectID, with no
trailing byte. The key is the only object pathname input and is split into fixed
two-byte/two-byte hexadecimal fanout directories. Storage directories are
private and identity-pinned; every use rechecks the pinned device, inode,
canonical resolution, and non-symlink final component before pathname I/O.
Ancestor replacement fails closed. Create-if-absent writes and
verifies a private temporary framed object, syncs it, atomically links it into
place without replacement, removes the temporary name, and syncs the containing
directory before acknowledging durability. The directory sync is mandatory
even when a retry finds an existing link, because that link may be recovery from
a crash before the first sync. Existing bytes are verified before an idempotent
success is returned.

The portable Node adapter requires a private storage root whose ancestors are
not concurrently mutable by untrusted code running with the same operating-
system authority. Identity rechecks fail closed for detected replacement, but
pathname APIs cannot make an ancestor check and the following mutation one
indivisible operation. A deployment admitting such an actor requires a native
directory-handle-relative adapter; this development profile does not claim that
stronger boundary.

Reads validate the closed frame and stored length before returning bytes. Range
reads are half-open and bounded, return the OGVCS-041 RFC 9530 SHA-256 digest,
and bind one strong validator to the complete stored representation. Range
selection and complete identity verification use the same open file. Metadata
objects additionally pass public canonical CBOR and known-schema OGVCS-002
validation before publication and on verification. Safe deletion accepts only
a private one-use permit issued while the lifecycle authority holds the exact
`deleting` generation. The backend consumes that permit, durably records the
prior receipt/generation/authority intent, and then unlinks while create and
delete serialize on the same recoverable object lock. A response-loss retry can
finish from that intent; raw caller generation/authority values never authorize
deletion.

## Lifecycle and sessions

Lifecycle records are authoritative; backend existence never implies
availability. Every transition uses an exact expected generation and advances
it by one: `staged -> available`, `available -> quarantined`, `quarantined ->
available`, `quarantined -> deleting`, and `deleting -> deleted`. Only a durable,
fully verified backend receipt can enter `available`; only a matching deletion
receipt bound to the exact `deleting` generation and authority can enter
`deleted`. Authority binding is mandatory on every CAS. Quarantine begins a new
safety window, and `deleting` is rejected until that window has elapsed.

Multipart sessions bind the authenticated grant claims digest, authority epoch,
key generation, audience, opaque tenant/repository/subject scopes, ObjectID,
declared length, part size, and OGVCS-041 idempotency identity. A received part
is recorded only after its bytes, declared length, and SHA-256 agree and its
private file is synced. Repeating the same part is idempotent; conflicting bytes
fail closed. Finalize streams only the recorded verified parts in order.
Response loss is recoverable from the durable finalized session record, but
authorization is checked again and a later lifecycle generation/state is never
misreported as currently available. Finalize replays and verified range reads
re-read the exact lifecycle generation after backend I/O. Persisted session,
lifecycle, backend lifecycle-fence, lifecycle-transaction, delete-intent
compatibility, nonce-claim, and recoverable-lock records are schema-closed
before any authorization or mutation. Finalized receipt shape and state-
dependent nullability are part of the session schema rather than an
unconstrained embedded object.

Deleted generations are not terminal to the key forever. A new upload for the
same exact tenant/object/length may reopen only through a private one-use
reupload permit derived from the current `deleted` generation, its deletion
receipt, and the next authority binding. The backend durably records that
reopen in the same fenced object state it uses for deletion so raw caller input
cannot bypass lifecycle authority. The versioned lifecycle transaction context
and adapter result additionally define the exact same-transaction hand-off that
OGVCS-006/010 consume when a current metadata transaction needs OGVCS-008 to
link publication reachability, acquire deletion, complete deletion, revive a
deleted generation, or record availability without a second database commit.
When that hand-off would make an OGVCS-002 `content-manifest` object become
`available` (`quarantined -> available` or `staged -> available`), the public
context must carry a non-null `verificationReceiptSha256` commitment and the
same-process owner must also supply the exact OGVCS-007 one-use production
verification receipt plus the exact manifest bytes in a private companion
binding at `bind(...)`. The participant admits every required receipt through
the OGVCS-007 `commitProductionManifest()` boundary and executes the single
metadata `apply(...)` only from the shared `publication.commit(...)` barrier
after all required receipts have reached commit. A generic backend durability
receipt, manifest ObjectID, or registry row is never enough to authorize a
`content-manifest` availability CAS.

Grant expiry uses only the service clock. Caller-provided time and consumed
nonce observations are ignored. A verified single-use nonce is claimed by an
exclusive, synced persistent record before the operation proceeds, so restart
cannot restore replayability. Both signed explicit ObjectID sets and signed
request-root plans are supported; a request-root operation supplies the exact
verifier-owned plan whose root was signed.

The exact grant binding is SHA-256 over ASCII
`OGVCS-TRANSFER-GRANT-BINDING-V1`, one NUL byte, and the OGVCS-041 canonical JSON
bytes of the complete verified OGVCS-003 claims. The resumable authority binding
is SHA-256 over ASCII `OGVCS-TRANSFER-AUTHORITY-BINDING-V1`, one NUL byte, and
canonical JSON containing exactly `audience`, `authorityEpoch`, `issuer`,
`keyGeneration`, `keyId`, `objectId`, `operation`, `permission`, `repository`,
`requestRoot`, `subject`, and `tenant`. It deliberately excludes nonce and grant
times so a freshly authorized grant for the same exact authority epoch/scope can
resume, while every operation still verifies the current grant and expiry.
Session identity is HMAC-SHA-256 over ASCII `OGVCS-UPLOAD-SESSION-ID-V1`, one NUL
byte, the lowercase opaque key, one NUL byte, and the OGVCS-041 idempotency key,
with no trailing byte.

Aborted or expired staging is retained through the configured safety window for
later OGVCS-018 collection. Transfer code never immediately removes staged
bytes or decides reachability. After that deadline, bounded startup/request
cleanup removes session and part copies while leaving lifecycle reachability to
OGVCS-018. Global and per-tenant session ceilings, tenant staging bytes,
per-minute transfer bytes, nonce records, directory scans, and in-memory rate
scopes all have explicit bounds. Session and lifecycle locks carry expiring
owner records, renew while work is live, and verify their fencing token before
and after every persisted commit. Atomic stale-lock takeover rechecks a
possibly concurrent renewal after rename before reclamation.

Node on Windows reports `EPERM` for directory `fsync` even after a directory
handle was opened and identity-checked. The filesystem candidate suppresses
only that exact unsupported result on Windows. It never suppresses path-open,
ACL, identity, or non-Windows sync failures; operators requiring a literal
directory-fsync primitive must select a platform/filesystem that exposes it.
