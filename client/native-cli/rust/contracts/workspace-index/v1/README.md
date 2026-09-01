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
status page. rc.3 uses payload schema `status-cursor/v2` and HMAC domain v2;
the `cursor-hmac-key-v1.bin` name intentionally versions the unchanged random
key-storage artifact, not cursor semantics. v1-shaped and v1-schema cursors are
rejected.

Rebuild and repair subscribe before baseline work, validate the complete
baseline receipt, write the ignore snapshot, and finish the complete
filesystem scan before asking the watcher authority for its final barrier.
The writer rejects baseline chunks after scan preparation and watcher chunks
before it, making this order executable rather than documentary. Repair holds
one mutation lock from full verification of the exact active generation
through consumption, scan, barrier, and reseal.

Each private fenced status page advances the already-open native watcher
session twice under the mutation lock: once before acquiring its reader lease
and again after every filesystem probe. Every delivered batch must continue the
exact session and prior cursor and uses the journal-fsync/state-publication
order. If the final barrier changes the event count, bytes, or tail, the page is
rejected and must restart against that newly persisted transcript. A cursor-only
idle advance is safe for the classified transcript and is bound into the page.
An authenticated prior page remains admissible when the generation,
staging/filter inputs, watcher authority, and exact event count/bytes/tail are
unchanged; its next page is rebound to the final cursor, so a volume-global
idle cursor cannot cause an unbounded restart. An unavailable, failed, gapped,
or substituted fence closes the session and forces reconciliation. The public
status function installs only the unavailable fence, so it cannot reuse test
authority or report clean. Persisted watcher liveness is accepted only as
either an open, resumable, continuous, non-reconciliation authority or a
closed, non-continuous, reconciliation-required state. A
closed-but-continuous record is invalid even if its plain payload digest is
recomputed. No built-in native adapter exists yet.

The page cursor retains the exact watcher payload digest/cursor as authenticated
predecessor audit bindings and binds a digest of the watcher generation,
adapter, session, continuity flags, and reason plus the exact event
count/bytes/tail. Only those predecessor payload/cursor values may differ at
continuation, and only while that authority digest and transcript remain exact.
It also binds the validated staging generation/full-state digest and the prior
rc.2 inputs. It discloses no staged intent plaintext.
Only fully validated `applied` intents are admitted: Add, Move, and Delete seed
status candidates before the early-clean decision. Final snapshot validation
checks both watcher and staging state, so an earlier-sorting event or staging
change between pages makes the old cursor stale rather than silently omitting
it.

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
