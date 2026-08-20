# ADR-0009: Format-v1 object graph and FileID validation

**Status:** Accepted
**Date:** 2026-08-15
**Owners:** OGVCS-002, OGVCS-006, OGVCS-010

## Context

ADR-0001 fixes root-snapshot and FileID lifetime principles, but clean-room implementations still need exact object reachability, directory identity, parent bounds, transition replay, group membership, conflict placement, restore proof, and cross-repository behavior. The fixture contract is useful input but its deterministic IDs and workload events are not native repository objects or allocation evidence.

## Decision

The immutable graph contains repository descriptors, snapshots, one-directory trees, content manifests/chunks, change sets, asset-group sets, shelf revisions, conflict sets, provenance, and attestations. Canonical logical exchange/reference projections may represent branch/tag pointers, pending-change references, latest-shelf pointers, lock references, and FileID lifetime/import registry facts; none is required to interpret immutable snapshot bytes. These projections neither exhaust nor constrain the authoritative mutable schemas and state machines owned by OGVCS-006, OGVCS-010, OGVCS-016, OGVCS-018, and OGVCS-025. Review, audit/outbox, and lifecycle-receipt state remain solely with those owners unless a later additive registry assignment defines a bounded exchange projection.

A repository descriptor binds a nonzero repository ID and registered path, content-policy, group, and optional chunk-profile references. Every repository-scoped tree, change set, group set, snapshot, conflict set, and shelf revision references that descriptor. Manifests and chunks remain path/FileID-independent content objects.

A canonical tree represents exactly one directory as a definite array ordered by NFC UTF-8 basename bytes. Entries are directory, regular, executable, or symlink; each named entry, including a directory, has a FileID. Hard links/aliases are absent in v1. Directory entries reference trees; file/executable/symlink entries reference manifests. The same FileID may appear only once across the fully expanded snapshot tree.

A repository has exactly one designated zero-parent root snapshot. Other snapshots have one to eight ordered, unique parents; parent zero is the change-set base. All parents share the descriptor and reach the designated root. Cycles, missing/wrong-kind parents, cross-repository parents, a second root, or more than eight parents are invalid.

Change sets contain ordered create, modify, copy, move, rename, delete, restore, group-transition, and merge-resolution records. Create/copy allocate a new FileID; move/rename preserve it; delete retains lifetime history; restore reactivates an existing lifetime after proving an ancestral delete/tombstone, exact historical state, and absence from the base tree. Restore never creates a new lifetime origin. Published snapshots contain only resolved conflicts and the replayed result must equal the declared tree/group roots. Conflict records use typed entry/group subjects, mechanically constrained side presence and type, and exact base/left/right/delete/custom result equality. Unresolved divergent-move, delete/modify, content, type, policy, group, and path-collision states belong to pending changes or immutable shelf revisions, not published snapshots; the former mode-conflict assignment is tombstoned and invalid in format v1.

Asset-group membership uses FileIDs, not paths, so renames preserve membership. Members are sorted and unique; every member resolves exactly once in the snapshot tree. Registered group profiles define role/cardinality and external-key uniqueness. Missing-sidecar and duplicate-GUID fixtures are representable validation failures rather than ambiguous ordinary groups.

FileID bytes are repository scoped: equal 128-bit bytes may independently exist in different repositories. Cross-repository rejection applies to source proofs, mappings, and transitions, not to global byte uniqueness. Validation is as of immediately before the candidate snapshot: immutable first-consumption records are existing context and candidate create/copy allocations are ordered working additions. A lifetime origin is exactly native create, native copy, or import; a create followed by delete still consumes the ID. Native proof carries no nonce because a nonce cannot establish registry uniqueness. Import mapping insertion and its lifetime record are atomic, and retry of the same importer namespace/source identity returns the original ID and current state. Concurrent allocation collision has one winner; every loser returns a typed conflict without advancing a reference.

OGVCS-002 owns representation, pure graph/transition validation, and normative vectors. OGVCS-006 owns the durable lifetime/import registry. OGVCS-010 owns finalize-time collision enforcement and atomic branch failure. Deterministic fixture IDs are fixed test data, not native CSPRNG allocation behavior; the adapter must reject zero, persist mappings, synthesize directory/group IDs without deriving native identity from mutable path text, and map workload-only lock/review/network events to typed non-history records.

## Alternatives considered

- **Treating database rows or branch tables as the repository graph** was rejected
  because offline readers and clean-room implementations could not reproduce the
  same history without a private service schema.
- **Deriving FileIDs from paths, clocks, counters, or fixture IDs** was rejected
  because rename/copy/import semantics and concurrent allocation would become
  ambiguous or repository-state dependent.
- **Validating only the candidate root and trusting referenced history** was
  rejected because a missing, wrong-kind, cross-repository, or corrupt ancestor
  could otherwise be acknowledged.
- **Placing mutable lifetime, lock, review, or branch state in immutable snapshot
  bytes** was rejected because it would create hash cycles and collapse ownership
  boundaries with later transactional PRDs.

## Compatibility and data consequences

Immutable object bytes contain only the portable graph and replay facts described
above. Durable branch heads, FileID lifetime/import rows, locks, reviews, and
publication transactions are external authoritative state whose schemas may
evolve without changing ObjectIDs. A repository-scoped object always binds the
same descriptor; an incompatible graph or transition rule requires a new format
version, while new bounded logical projections require additive registered
assignments. Equal FileID bytes in separate repositories remain valid and never
imply shared lifetime state.

## Threat and failure analysis

Validation fails closed on missing and wrong-kind edges, duplicate or forged
FileIDs, invalid restore/import evidence, cross-repository proofs, parent or
provenance cycles, replay/result mismatch, unresolved published conflicts, and
group membership or external-key collisions. Whole-set phase ordering prevents
traversal order from hiding a higher-precedence integrity failure. Object, edge,
time, memory, and scratch accounting bounds hostile fanout and retained replay
state; no failed candidate advances lifetime/import state or publishes a root.
The pure validator consumes authenticated prior state but does not claim to
implement the transaction that OGVCS-006/010 own.

## Test vectors and proof

Required vectors cover zero/one/two/eight-parent history; second-root, ninth-parent, duplicate/cross-repository parents; every entry kind; duplicate FileIDs across directories; create/copy/move/rename/delete/delete-recreate/restore; import lost-ack retry; forged and cross-repository proof; concurrent collision; rename-stable groups; sidecar failures; resolved and unresolved conflicts; shelf chains; missing/wrong-kind graph edges; and exact change-set replay. Parent/provenance cycle algorithms use an explicitly typed prevalidated abstract-reference-graph scenario: content-addressed canonical bytes cannot form such a finite cycle without a SHA-256 fixed point, and an ordinary attempted-cycle mutation fails ObjectID validation first. OGVCS-001 supplies five adapter corpora, while OGVCS-002 supplies native restore/import/collision/parent/conflict cases absent from the fixture generator.

Rust and JavaScript execute the same language-neutral scenarios and compare the
registered `(code, layer, stage)` result. Reduced configured ceilings exercise
the bounded replay, lookup, FileID, group, conflict, and graph routes independently
of the separately deferred exact-scale workloads.

## Rollback and migration

If a graph writer, adapter, or transaction integration is not proved, production
publication is disabled while canonical readers and validators remain available.
No rollback reuses a consumed FileID or rewrites an acknowledged snapshot. A rule
that changes the meaning of existing canonical bytes requires a new format
version and explicit migration; a new external state fact uses its owning PRD's
versioned schema or a new additive logical-record assignment. Recovery replays
the immutable graph and authenticated lifetime/import state rather than trusting
partially published derived indexes.
