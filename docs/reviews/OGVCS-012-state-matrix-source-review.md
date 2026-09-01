# OGVCS-012 bounded status state-matrix source review

- **Candidate base:** `32ca99c7d35c4ffc949b1c21b76719a949e47a33`
- **Private contract:** `ogvcs.workspace-index/private-contract/v1`
  `0.1.0-rc.4`; committed generation format remains `0.1.0-rc.1`
- **Verdict:** bounded deterministic classifier and staging tranche only;
  OGVCS-012 remains **Todo**.

## Contract-derived outcomes

The OGVCS-004 watcher contract makes a contiguous journal an acceleration
input, requires gaps to reconcile, and forbids false clean. OGVCS-012 requires
Added, Modified, Deleted, move hints, conflicts, and FileID-aware staging to
survive event coalescing. The private rc.4 contract therefore fixes these
same-path outcomes:

| Ordered observation | Final workspace state | Bounded status outcome |
| --- | --- | --- |
| create → modify | regular untracked file | Added, content verified |
| create → delete | absent untracked path | no item; exact transient only |
| delete → create | changed tracked replacement | Modified with baseline FileID |
| modify → delete | absent tracked path | Deleted with baseline FileID |
| conflict → modify | changed tracked file | Conflicted; conflict is sticky |
| rename → modify | destination regular, source absent | move hint with prior path and source FileID, plus source Deleted |
| rename → delete | source and destination absent | source Deleted; unstaged transient destination omitted |
| rename → delete → create | destination reoccupied by a new file | Added without prior path or source FileID, plus source Deleted |
| rename onto independently baselined destination | destination regular (changed or equal content) or absent | Conflicted without a FileID; reconciliation required, plus source Deleted |

An Applied Add, Move, or Delete supplies staged identity and cannot be erased by
the transient rule when compatible watcher events overlap it. Staging records
do not bind a watcher cursor or sequence, so an Applied Add, Move source, Move
destination, or Delete source intersecting watcher delete→create is causally
unordered. Every such path is Conflicted without FileID/prior and requires
reconciliation; a Move source deletion remains visible when only its
destination is ambiguous. Only the exact same staged Move source→destination
watcher edge is compatible; different incoming lineage or rename-out from any
staged role conflicts the complete intent and incompatible watcher destination.
Directly
observable source reoccupation, immutable-source/staged FileID mismatch, and a
staged Add on a baseline path also fail closed. Persisted intent paths are
structurally validated, their repository keys are re-derived and matched, and duplicate
intent IDs or repository/platform path identities fail closed on every load. A
candidate that reuses an intent ID or shares either path identity with an
existing Applied intent is outside the current compositional staging contract
and fails with `STAGED_PATH_CONFLICT` before staging publication or filesystem
mutation. Definitive post-stage reset semantics require a durable future
staging-to-watcher order binding. This does not establish FileID semantic
binding or repository-lifetime uniqueness without an immutable local source.

## Source correction

The former last-event classifier overwrote Created and Renamed with a later
Modified event. It also treated a rename destination followed by deletion as
an unmatched delete, and could collapse a deleted Applied Add as if it were an
unstaged transient. The correction retains creation/rename history, makes
conflict sticky, clears stale rename lineage when an ordered watcher-only
post-deletion create establishes a new destination identity, uses the prior
baseline entry only to infer a missing watcher
rename FileID, and distinguishes a real staged owner from that inferred ID
before applying transient or reconciliation rules. A destination with its own
immutable baseline identity is now explicitly ambiguous rather than borrowing
that destination FileID or disappearing on equal content. Staging admission
now re-derives persisted repository keys, rejects duplicate intent IDs or
repository/platform path identities on every load, and repeats candidate
intent-ID/path overlap checks before journal publication. Its staged overlay
tracks the exact path role, conflicts unordered identity resets or differing
lineage without lending an identity, checks an immutable source FileID when
available, and probes an Applied Move/Delete source before lending the staged
identity. Cursor bindings, watcher fencing, and memory bounds are unchanged.
The outgoing-edge comparison retains no additional path copies: its borrowed
indices are bounded by the existing 10,000-intent and 100,000-event ceilings.

## Evidence boundary

Fourteen focused Rust tests exercise the eight original watcher transitions,
three baseline-destination materialization outcomes, watcher/staged reset
intersections across every path role and both conceptual orderings, five
watcher/staging overlaps, incompatible incoming and outgoing lineage for every staged role, directly
observable source reoccupation, immutable-source identity checks, three
healthy staged-path collision orders, persisted-key corruption, duplicate loaded identities, a
repository-distinct/platform-colliding pair, and duplicate candidate intent-ID
admission. They assert
complete/clean/reconciliation flags and reason, exact item counts and
vocabulary, prior paths, FileIDs, content verification, unchanged staging
digests, and unchanged filesystem placement after rejected admission.

On the isolated candidate, Rust 1.82 passed 72 library tests with 2 exact
bounded-release tests ignored, 2 binary unit tests, 3 CLI contract tests, 2
contract-vector tests, and 12 production-foundation tests. Rustfmt, all-target
Clippy with warnings denied, packed-crate tests, and the installed-artifact
hermetic gate passed. Node 24 passed the rc.4 generator/validator, the 6-test
CLI workspace/spec gate, and the 8-test roadmap gate. This is local source
evidence, not hosted cross-OS evidence.

This source review does **not** establish USN/FSEvents/inotify authority,
hosted three-OS execution of this exact candidate, the complete OGVCS-004
operation/fault matrix, rename cycles, case-only rename, directory/file
replacement, multi-hop rename/source reoccupation, FileID semantic binding and
repository-lifetime uniqueness beyond immutable local sources, durable staged-
intent/watcher ordering, locked-open behavior,
ignore transitions, public status or repair routes, the million-path SLO,
telemetry, rollout, or OGVCS-012 completion.
