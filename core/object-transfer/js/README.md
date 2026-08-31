# `@opengamevcs/object-transfer`

Development-only OGVCS-008 implementation for bounded immutable object
transfer. It consumes OGVCS-002 object identity, OGVCS-003 transfer grants,
OGVCS-007 content-manifest verification receipts, and OGVCS-041 idempotency and
range primitives. It does not assign a public or wire route.

## Backends

`FilesystemObjectBackend` and `S3ObjectBackend` implement one narrow capability
profile: create-if-absent, exact head metadata, whole verification, verified
half-open ranges, bounded internal-prefix listing, and generation/permit-fenced
delete. `ObjectTransferService` accepts only an adapter explicitly constructed
and branded by this package. It captures an immutable port, rejects subclasses,
and never dispatches through caller-replaced methods or prototypes.

Both adapters receive only tenant-scoped opaque HMAC keys. The filesystem
adapter retains its pinned-directory, no-replace publication, file and directory
sync, same-open verification, recoverable lock, and durable delete-fence
behavior. The S3-compatible adapter uses SigV4, HTTPS by default, bounded
deadlines/responses/retries, `If-None-Match: *`, exact metadata, checksum and
whole-body read-back, and conditional lifecycle-fence updates. Loopback HTTP and
bucket creation require explicit test opt-in. An upload status, existence check,
or ETag is never a durability receipt; multipart ETags are opaque conditional
tokens, not content hashes.

Ordinary offline tests run the shared behavior suite against the filesystem and
a deterministic in-process S3 protocol fake. The hosted Linux job downloads one
exact MinIO release from a machine-checked URL/SHA-256 record and runs the live
bounded contract over loopback. That hosted result is still required before the
lane can claim S3 acceptance.

## Logical content transfer and batches

The canonical object ceiling remains 64 MiB. `ContentTransferPlanStore` models a
logical file of at most 100 GiB as up to 100,000 immutable chunk descriptors in
pages of at most 256. Plan pages and verified-part ledgers are durable; restart
returns only pending descriptors, so already verified chunks need not be sent
again. Reconstruction reads one bounded chunk at a time, verifies its checksum
and ObjectID, streams it to the supplied writer, and verifies the whole-file
SHA-256. No corpus-sized descriptor or payload array is required.

Batch download plans authorize the complete object set before any lifecycle or
backend existence lookup. The sealed plan binds the grant, tenant scope, exact
ordered object set, request root, generations, receipts, lengths, and pack
offsets. A tampered plan, duplicate/+1 request, or hidden object at an early,
middle, or final position returns no partial layout.

The manual `object-transfer-release-scale` workflow is the only exact 100-GiB
gate. It requires an explicit confirmation on a dedicated self-hosted runner,
injects restarts, reconstructs and whole-hash verifies the bytes, and records
throughput and peak RSS. Ordinary CI policy rejects scale execution.

## Lifecycle, quotas, and operations

Backend existence never means lifecycle availability. The service still ships a
filesystem-local lifecycle candidate, plus `createLifecycleAdapterPort()` as an
explicit captured seam for the separately owned repository-metadata lifecycle
lane. The seam advertises whether state is atomic with repository metadata; this
package does not invent repository-metadata v9 tables or claim that integration
has landed. `content-manifest` availability remains gated by the exact
same-process OGVCS-007 production receipt boundary.

Staging bytes, durable unique bytes, request rate, and transfer bytes are
accounted separately. Durable reservations and commits survive response loss;
release is an idempotent lifecycle/GC seam and is never inferred from object
absence. Internal content-available and privacy-safe integrity-failure events
are durable and bounded. Telemetry aggregates operation, bytes, duration,
retry, resume, part, backend, quota, and integrity dimensions with fixed label
sets; object IDs, backend keys, paths, grant details, and credentials are not
broad labels or error text.

## Limits and non-claims

Objects are at most 64 MiB, ranges 8 MiB, upload parts 4 MiB, batch object sets
4,096, logical plans 100 GiB, and all persisted scans/ledgers have explicit
ceilings. The portable filesystem adapter still assumes same-authority hostile
code cannot rename its private ancestors between pathname operations; such a
deployment needs a native directory-handle-relative adapter. Windows suppresses
only Node's exact verified-directory `EPERM` fsync limitation.

This candidate does not claim public HTTP completion, OGVCS-010 publication,
reachability/GC, hosted MinIO evidence, exact-scale throughput, or final
OGVCS-008 acceptance until those separate gates land.
