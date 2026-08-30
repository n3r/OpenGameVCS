# `@opengamevcs/object-transfer`

Development-only OGVCS-008 filesystem backend and resumable transfer state
machine. It consumes the public OGVCS-002 object model, OGVCS-003 transfer-grant
verifier, and OGVCS-041 idempotency/range primitives.

The backend uses opaque HMAC-derived keys, pinned private directories, immutable
framed files, no-replace publication, canonical OGVCS-002 metadata validation,
same-open verified range reads, and generation-bound safe deletion. The service
persists multipart/session metadata, single-use nonce claims, and
generation-CAS lifecycle records; backend existence never means available.
Recoverable locks renew while work is live and every persisted commit verifies
the current fencing token. Physical deletion is reachable only through the
configured lifecycle authority: it issues a private one-use permit for the
exact `deleting` generation, and the backend durably records that intent before
unlink so response-loss retry can finish the lifecycle receipt. A later upload
for that same exact key can reopen only through a private reupload permit bound
to the current `deleted` generation, deletion receipt, and next authority
binding. When the shared lifecycle transaction participant would make a
`content-manifest` generation become `available`, it also requires the exact
same-process OGVCS-007 production verification receipt and manifest bytes at
`bind(...)`; it admits that receipt through `commitProductionManifest()` and
only then lets the single metadata `apply(...)` commit proceed.

Every service operation re-verifies a grant using the service clock with the configured audience,
authority epoch, key generation, tenant/repository/subject context, operation,
and request-root/object set. Atomic nonce claims survive restart. Broad
diagnostics do not return ObjectIDs or grant details.

This first cut supports objects through 64 MiB, parts through 4 MiB, ranges
through 8 MiB, and 1,024 parts/sessions, with a 256-session per-tenant default.
Expired locks and retained part/session copies are reclaimed within bounded
scans. It does not claim S3 parity, direct public production routes, GC
reachability, automatic staging cleanup, 100-GiB execution, or reference
throughput.

The portable Node adapter assumes the private storage root and its ancestors
are not concurrently renamed by untrusted code with the same OS authority.
Detected replacement fails closed; deployments that include that actor require
a stronger native directory-handle-relative adapter.

On Windows, Node exposes verified directory handles but reports `EPERM` for
directory `fsync`. The filesystem profile suppresses only that exact unsupported
operation after the directory was opened and identity-checked; ACL/open errors
and every non-Windows sync failure remain fatal.
