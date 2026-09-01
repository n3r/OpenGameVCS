# Private workspace-index candidate contract v1

This artifact freezes the private local-state semantics implemented by the
Rust OGVCS-012 candidate. It is not a public protocol, route, or completion
claim. The first-party CLI has no workspace-baseline route and no built-in
USN/FSEvents/inotify continuity authority, so it cannot currently return an
authoritative clean status through production-callable adapters.

The contract authenticates exact bounds, generation publication ordering,
current workspace bindings, lookup collision revalidation, watcher journal
continuity, status values, and every HMAC paging-cursor binding. The
owner-private cursor key is generated locally and never serialized into a
status page.

Committed generations are create-new and immutable. Each status page now
publishes an owner-HMAC-authenticated generation lease while holding the local
mutation lock, fsyncs it, and holds a shared OS file lock until the final
snapshot check and page construction finish. On Unix this is a whole-file
`flock`; on Windows it is a `LockFileEx` byte-range lock. A durable
HMAC-authenticated u64 logical epoch makes crashed, unlocked lease records reclaimable without using
wall time; a still-locked reader always pins its generation.

The private compaction API retains the current generation, its authenticated
numeric predecessor, and every locked or unexpired leased generation. It
removes at most eight older authenticated generations per call only after an
HMAC-authenticated intent is fsynced. Recovery completes that intent
idempotently. It deletes only exact local index artifacts and never workspace
content. Pagination leases last one call; a later page reacquires and may reject
its cursor as stale.

The additive retention controls leave rc.1 generation bytes readable. First
use authenticates a bounded legacy namespace only after complete artifact,
lookup, and watcher-chain verification. Concurrent mixed-version readers are
unsupported for this unpublished private candidate and require a process
restart. Same-authority lock-namespace replacement remains the existing local
lock residual; the HMAC and OS locks do not claim to solve it.

Verify this candidate contract with Node 24:

```sh
node scripts/generate.mjs --check
node validate.mjs
```

The Rust unit suite independently recomputes the authenticated cursor vector
through the production HMAC routine, pins an independently calculated
retention HMAC known answer with hostile variants, and pins the manifest
artifact-set digest.
