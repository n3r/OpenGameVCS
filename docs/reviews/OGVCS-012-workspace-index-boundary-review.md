# OGVCS-012 durable workspace-index candidate boundary review

- **Candidate base before this tranche:** `3563167763a54b97eb8166ded1db895aa3a5b7cd`
- **Private candidate contract:** `client/native-cli/rust/contracts/workspace-index/v1`
  version `0.1.0-rc.4` (generation bytes remain `0.1.0-rc.1`)
- **Verdict:** useful fail-closed native implementation slice; OGVCS-012
  remains Todo.

## What this candidate establishes

The additive public-adapter facade now requires authentication and exact
current binding validation before status or healthy repair can reach the
watcher/index boundary. It verifies the authenticated subject plus authority
and security epochs against the persisted workspace, asks the owning public
route to validate that binding, and then compares the complete verified
workspace-metadata digest and local session expiry under the mutation lock
before each status fence, reader-lease publication, or index write. Repair also
checks both before watcher subscription and again under the lock before
generation publication; a reconfigure racing after subscription fails before
index mutation. Subject substitution and an already-stale local binding fail before the watcher is
entered. This is an embeddable typed seam, not a first-party CLI/JSON route:
`UnavailablePublicRoutes` remains the binary default, and no native watcher
authority or corrupt-index discard/reseed authority is introduced. The
formerly re-exported direct watcher-batch append helper had no production
caller and bypassed the watcher-authority object, so it is now test-only.
Production batch admission remains available only through the exact
session/prior-cursor-bound sink passed to a status fence; an external adapter
still cannot construct a continuity-proving checkpoint.

The Rust participant can ingest an authenticated immutable baseline through a
bounded sink and publish a locally durable index without accepting a
million-entry caller vector. Every baseline chunk is at most 1,000 entries and
1 MiB, the full stream is canonical and duplicate/collision free, and the final
receipt binds the repository, baseline, settings, path profile/case mode,
ordered digest, count, and repository ignore digest.

The writer now enforces the reconciliation fence order. It subscribes before
baseline work; after the complete receipt it writes the ignore snapshot and
finishes the complete filesystem scan; only then can the watcher sink accept
events and advance to its final native barrier. Baseline chunks are rejected
after that preparation point and watcher chunks are rejected before it. This
covers changes before the scan through the scan and changes after it through
the subscribed watcher without treating a synthetic barrier as native proof.

Generation artifacts are create-new. The writer publishes and syncs a
transition, syncs every artifact, creates and syncs the seal, syncs the owning
directory, atomically promotes the active pointer, syncs the directory again,
and only then removes the transition. Recovery exposes the prior sealed
generation or the newly promoted sealed generation. Status does not ignore an
active transition and re-reads the active and generation-scoped watcher facts
before returning, closing both the early-clean and after-load writer races.

The lookup sidecar is fixed width and bounded. Its digest narrows the search;
it is never identity. Every digest hit is checked against the exact canonical
repository path, repository collision key, full platform collision key, and
key digest before an entry is returned.

Watcher events use strict `+1` sequence numbers and a domain-separated hash
chain. Append is limited to 1,000 events and 1 MiB per chunk and 100,000 events
per generation. The event file is synced before atomically publishing watcher
state. A crash in between is detected from the persisted byte-count/tail
mismatch and cannot yield clean status. Missing cursors, gaps, overflow,
unsupported watchers, corrupt state, and an unmatched absent delete all force
reconciliation. A same-path transient untracked create/delete is the narrow
case that can collapse to no finding.

The bounded same-path coalescer now retains creation and rename-destination
history after later modifications or deletions, and conflict state is sticky.
Consequently create→modify remains Added, rename→modify retains the prior path
and source-baseline FileID, and rename→delete suppresses only the transient
destination while retaining the source deletion. In the ordered watcher
journal, a later create at that deleted destination establishes a new Added
identity without the stale prior path or source FileID. Conflict remains
sticky. A rename onto a path
that already has a distinct immutable baseline identity is Conflicted without
a guessed FileID and requires reconciliation for regular changed/equal-content
and absent destinations alike. An Applied staged intent is never eligible for
transient collapse, so a watcher deletion after staged Add or Move remains
visible. These are portable classifier semantics; they do not mint native
watcher continuity.

Status hashes every event-touched regular file and never treats timestamps as
content equality. The private fenced path asks the existing session for an
opening barrier before releasing the mutation lock/read-lease publication,
then reacquires that lock for a final native barrier after every filesystem
probe. Exact session/prior-cursor batches use journal-fsync then atomic
watcher-state publication. If the final barrier drains any event, the in-flight
page is rejected and restarted against the persisted transcript; a local
watcher-file reread alone is never treated as proof. A cursor-only idle advance
with unchanged event count/bytes/tail is safe and becomes the exact cursor
recorded in the returned page. A subsequent page may carry that authenticated
prior payload/cursor while the generation, staging/filter inputs, watcher
authority digest, and exact transcript remain unchanged; the next result is
rebound to its final cursor, avoiding idle-cursor pagination livelock without
admitting an event. Unsupported, failed, gapped, or substituted authority
closes the historical session and forces reconciliation. The public wrapper
installs only the unavailable authority, so it never borrows the test-only
native proof.

Persisted watcher liveness has two accepted shapes. An authoritative state is
continuous, resumable, session-open, and not reconciliation-required; a
degraded state is non-continuous, session-closed, and reconciliation-required.
A closed-but-continuous state fails validation even when its plain payload
digest is recomputed, so it cannot skip the public unavailable fence and
produce a clean result.

Status emits the complete required vocabulary, applies deterministic
repository/local exact/subtree ignores, and pages at most 1,000 items. It
validates the exact staging snapshot before early clean; Applied Add, Move, and
Delete intents seed destinations/sources, prior path, and staged FileID without
waiting for watcher delivery. Prepared or Reverting staging requires recovery.
Watcher events and those three Applied intent kinds may overlap without losing
intent visibility when the observations are compatible. Staging records bind
no watcher cursor or sequence, so a watcher delete→create reset intersecting an
Applied Add, Move source, Move destination, or Delete source is causally
unordered. It is Conflicted with no FileID or prior path and requires
reconciliation; a staged Move's source deletion remains visible when only its
destination is ambiguous. Only the exact same staged Move source→destination
watcher edge is compatible. A different prior into a staged path, or rename-out
from any staged role, conflicts the complete staged intent plus the incompatible
watcher destination without lending identity. Before a Move/Delete FileID is lent, an immutable source baseline
must match it and the applied source must be absent; a staged Add cannot claim
an immutable baseline path. Persisted paths are structurally validated, their
repository keys are re-derived and matched under the pinned binding, and
intent IDs plus repository/platform path identities must be unique on every
load. A candidate that reuses an intent ID or shares either path identity with
an existing Applied intent is rejected again before staging-state publication
or filesystem mutation. Definitive post-stage reset semantics require a future
durable staging-to-watcher ordering binding. Broader FileID semantics and
repository-lifetime uniqueness remain unproved where no immutable local source
baseline supplies the answer.
The v2 opaque paging cursor is HMAC-SHA256 authenticated by an owner-private
local key. It retains the exact watcher payload digest/cursor as authenticated
predecessor audit bindings and binds the watcher
generation/adapter/session/continuity digest, exact event
count/bytes/tail, generation/active digest, staging generation/full-state
digest, settings, profile/mode, both ignore digests, filter, and last full
path/platform key. It contains no staged intent plaintext. Final revalidation
checks active, watcher, and staging snapshots, so a newly appended
earlier-sorting event cannot be omitted by continuing an old page cursor. Only
the authenticated predecessor payload/cursor may drift while that authority
digest and transcript stay exact.

The cursor payload schema and HMAC domain are both v2. The existing
`cursor-hmac-key-v1.bin` filename deliberately versions only the unchanged
owner-random key-storage format; v1-shaped and v1-schema cursors fail closed.

Each status page now acquires an owner-HMAC-authenticated reader lease while
the mutation lock is still held, syncs the lease, and acquires its shared OS
file lock (whole-file `flock` on Unix and a `LockFileEx` byte range on Windows)
before releasing the mutation lock or reading generation artifacts. The lease
stays live through final active/watcher revalidation and page construction. It
covers that call only: a later page must reacquire, and an otherwise authentic
cursor may fail stale after its generation is safely reclaimed.

A private compaction API advances an authenticated u64 logical epoch under the
same mutation lock. Locked readers always pin; an unlocked crashed lease is
reclaimable after two epochs. Before any unlink, compaction authenticates the
bounded control, lease, history, and generation namespace, retains the current
generation plus its authenticated numeric predecessor and every reader pin,
then fsyncs an authenticated intent. A run removes at most eight generations.
Recovery is idempotent across partial lease cleanup, partial generation
cleanup, state publication, and intent removal, and can reach only old-or-
compacted local-index state. Workspace content is outside every deletion path.

The retention/control schemas are additive. A bounded first-use migration
authenticates complete legacy `0.1.0-rc.1` generation artifacts and watcher
chains before publishing history; the active generation encoding itself is
unchanged. Mixed old/new processes are unsupported for this unpublished local
candidate: cooperating clients must be restarted before compaction, and a
downgrade rebuilds only the private index.

Repair starts its watcher subscription before locking, then holds one mutation
lock across complete hash/lookup/watch-chain verification of the exact active
generation, old-entry consumption, full scan, final barrier, and publication.
A cooperating transition, watcher append, or compaction therefore cannot
replace the generation between verify and reseal.

A bounded test-only repair oracle now derives status directly from the supplied
immutable baseline and a recursive filesystem read. It does not call the index
probe, finding, lookup, or classification path. Healthy repair and authenticated
rebuild after watcher-state or event-chain corruption produce the oracle's exact
complete paged stream, including deterministic repeat pages, ignore precedence,
materialization states, content-verification flags, and degraded watcher
uncertainty. The fixture snapshots every workspace node outside the private
index, including bytes, type, modification time, read-only state, and portable
mode, before repair and compares it afterwards. Corrupt active, seal, entry,
lookup, finding, ignore, retention, cursor-key, reader-lease, transition, and
compaction authority fails before a new generation. Reader leases are now
authenticated during rebuild capacity preflight, closing a path where a corrupt
lease could otherwise survive a successful rebuild and reject its first status
page. This added check is read-only and introduces no publication or deletion
boundary. Distinct findings, events, and rename-source candidates now enforce
the exact candidate-memory cap before insertion instead of only after a complete
source pass; duplicate keys remain admissible at the bound without allocating a
new candidate.

## Adversarial and bounded evidence

The default focused Rust suite covers:

- every implemented transition/artifact/seal/active crash point and committed
  artifact no-overwrite behavior;
- status loaded before a writer publishes a transition, status invoked during
  a transition, and the exact new generation after promotion;
- watcher gap, oversized chunk, strict journal tail, synced-unpublished tail,
  portable watcher degradation, status-time missed-event append, final-checkpoint
  session substitution, cursor-gap degradation, and an event withheld until
  the final post-probe barrier;
- digest collision substitution, path order/case collision, current
  profile/case/settings/generation binding, HMAC cursor tamper/staleness,
  v1 cursor rejection, and an earlier-sorting watcher append between pages;
- index-root/generation-artifact symlink or reparse rejection;
- reader-lease HMAC known-answer, wrong-key/domain/payload rejection,
  cross-workspace/repository rejection, exact 127/128/129 admission, locked
  reader pinning, logical-epoch abandoned-reader reclamation, and one-page
  cursor staleness;
- authenticated history max-capacity preflight before publication, current
  plus numeric-predecessor retention, malformed/unknown control rejection
  before intent, and deterministic status/repair/compaction serialization;
- every retention crash boundary: epoch, abandoned lease publication, intent,
  stale-lease directory sync, first generation unlink, generation directory
  sync, state publication, and intent removal;
- timestamp-preserving same-size file edits and same-length sealed-artifact
  corruption; and
- deleted tracked directory uncertainty, transient untracked deletion, and
  repair that leaves local work files byte-for-byte unchanged;
- independent full-scan equivalence across bounded pages for healthy repair,
  reconstructible watcher-state/event-chain rebuild, degraded continuity, and
  deterministic repeat output, plus fail-closed corruption of every remaining
  authenticated artifact/control class before publication and exact
  pre-insertion candidate-memory admission;
- subscribe/scan/final-barrier ordering with deterministic mutations on both
  sides of the scan; and
- Applied Add/Move/Delete staging visibility without watcher delivery, with no
  plaintext staging details in the cursor; and
- table-driven create→modify, create→delete, delete→create, modify→delete,
  conflict→modify, rename→modify, rename→delete, and rename→delete→create
  transitions, plus Applied Add/Move/Delete watcher overlap, all four staged
  path-role delete→create intersections, causally identical Move reset inputs
  with and without a baseline destination, incompatible incoming and outgoing
  watcher lineage across every staged role,
  directly observable Move/Delete source reoccupation, immutable-source
  FileID mismatch and staged-Add/baseline ambiguity, exact staged-path and
  candidate-intent-ID collision rejection before mutation, persisted-key
  corruption, duplicate loaded identities, and a repository-distinct/platform-
  colliding pair.

Two explicit bounded release tests produced this local candidate evidence:

| Fixture | Result | Scope |
| --- | --- | --- |
| 1,000 changed files | 1,000 modified items, every content verified, 210 ms | one local debug test run; not p95 |
| 100,000 watcher events | 100 chunks × 1,000, full-chain verification, event 100,001 rejected before append, 11.619 s | one local debug test run; not a million-path benchmark |

The current isolated source passed 74 Rust 1.82 library tests with the two
exact bounded-release tests explicitly ignored, 2 binary unit tests, 3 CLI
contract tests, 2 contract-vector tests, and 12 production-foundation
integration tests. Rustfmt, all-target Clippy with warnings denied, the
packed-crate gate, and the installed-artifact hermetic gate passed locally.
Registered workflow
[run 33538231831](https://github.com/n3r/OpenGameVCS/actions/runs/33538231831)
repeated the Node 24 contract/spec checks, Rust 1.82
format/default-test/Clippy gates, packed-crate check, and installed-artifact
hermetic check from exact integrated rc.4 source `a0c7bfd` on hosted Linux,
macOS, and Windows. The retained
[machine record](../evidence/OGVCS-012/github-actions-run-33538231831.json)
binds the source, successful steps, and actual Node 24.19.0 Linux/Windows and
24.18.0 macOS patch versions. This is cross-platform evidence for the bounded
private fence, repair-equivalence, and state-matrix implementation, not native
watcher authority or exact-scale evidence. The CLI workspace/spec gate passed
6 Node tests, the roadmap validator passed 8 tests, and the private-contract
generator/validator passed on Node 24.

The private contract manifest authenticates six artifacts with artifact-set
SHA-256 `5c679b27f3813280f6b7c3c66046b733df624bda5cbddc50a821d9fc7e334049`.
Node 24 independently recomputes the cursor and retention HMAC vectors. Rust
pins an independently calculated retention HMAC-SHA256 known answer, exercises
wrong-key/domain/payload rejection, uses the production cursor encoder, and
pins the manifest artifact set.

## Exact nonclaims and completion blockers

| Residual | Candidate behavior | Completion condition |
| --- | --- | --- |
| Public baseline/status/compaction route | Typed authenticated status and healthy-repair facades fail before watcher/index mutation on subject, epoch, route, or under-lock metadata mismatch; `UnavailablePublicRoutes` remains the first-party binary default and compaction is private local API only | Publish the owning baseline/status adapter and CLI/JSON contract, with bounded operations |
| Native watcher authority | No production constructor can mint continuity; portable watcher is always degraded | Implement and prove USN, FSEvents, and inotify adapters including resume/overflow/unclean shutdown |
| Million-path SLO | No exact one-million warm p95 result | Pass the reference p95 target without a full walk/hash on every supported OS profile |
| Full status state machine | The bounded same-path and staged-overlap tranche is covered, including exact incompatible outgoing edges, directly observable source reoccupation, and immutable-source FileID mismatch; broader multi-hop rename/reoccupation, case-only rename, and FileID semantics or repository-lifetime uniqueness without local immutable authority remain outside this tranche | Pass rename-cycle, broader multi-hop and case-only rename/reoccupation, remaining FileID semantic binding and uniqueness, directory/file replacement, locked-open, ignore transition, native-fault, and remaining revert combinations |
| Staging/watcher causal order | Staging binds no watcher cursor or sequence, so every covered non-commutative reset/lineage intersection fails closed | Durably bind each staging transition to watcher ordering before assigning definitive post-stage reset semantics |
| Repair equivalence | Authenticated healthy repair now revalidates its exact public binding before subscription and under lock; a bounded test-only independent full scan matches every page after healthy repair and reconstructible watcher/event rebuild; corrupt sealed baseline/history/control authority fails closed without changing the captured workspace bytes, node types, modification times, read-only states, or portable modes | Add a safe public discard/reseed operation for non-reconstructible private authority and retain the complete cross-OS corruption/fault matrix |
| Product operations | No public explain, repair, compaction, telemetry, rollout, or downgrade surface | Integrate bounded public commands and operational evidence |

The private reader-safe compactor closes the earlier unbounded-retention
residual, but does not establish public product integration. Owner HMACs and
kernel locks do not solve the existing malicious same-authority replacement of
the lock namespace; on Unix they also cannot promise impossible unlink-by-open-
handle semantics. The candidate must not be described as public scalable-
status completion, public watcher authority, full fault-matrix evidence,
telemetry/operations completion, exact-scale completion, or OGVCS-012 Done.

## Reproduction

Run with Rust 1.82, Node 24, an external Cargo target directory, and the checked
offline lock:

```sh
node client/native-cli/rust/contracts/workspace-index/v1/scripts/generate.mjs --check
node client/native-cli/rust/contracts/workspace-index/v1/validate.mjs
cargo +1.82.0 fmt --manifest-path client/native-cli/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path client/native-cli/rust/Cargo.toml --locked --offline
cargo +1.82.0 clippy --manifest-path client/native-cli/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 check --manifest-path client/native-cli/rust/Cargo.toml --locked --offline --target x86_64-pc-windows-gnu
cd client/native-cli/rust
./scripts/test-packed.sh
node scripts/test-hermetic.mjs
```

The exact ignored-test commands are in `client/native-cli/rust/README.md`.
