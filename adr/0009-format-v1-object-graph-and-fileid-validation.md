# ADR-0009: Format-v1 object graph and FileID validation

**Status:** Proposed
**Date:** 2026-08-15
**Owners:** OGVCS-002, OGVCS-006, OGVCS-010

## Context

ADR-0001 fixes root-snapshot and FileID lifetime principles, but clean-room implementations still need exact object reachability, directory identity, parent bounds, transition replay, group membership, conflict placement, restore proof, and cross-repository behavior. The fixture contract is useful input but its deterministic IDs and workload events are not native repository objects or allocation evidence.

## Decision

The immutable graph contains repository descriptors, snapshots, one-directory trees, content manifests/chunks, change sets, asset-group sets, shelf revisions, conflict sets, provenance, and attestations. Canonical logical exchange/reference projections may represent branch/tag pointers, pending-change references, latest-shelf pointers, lock references, and FileID lifetime/import registry facts; none is required to interpret immutable snapshot bytes. These projections neither exhaust nor constrain the authoritative mutable schemas and state machines owned by OGVCS-006, OGVCS-010, OGVCS-016, OGVCS-018, and OGVCS-025. Review, audit/outbox, and lifecycle-receipt state remain solely with those owners unless a later additive registry assignment defines a bounded exchange projection.

A repository descriptor binds a nonzero repository ID and registered path, content-policy, group, and optional chunk-profile references. Every repository-scoped tree, change set, group set, snapshot, conflict set, and shelf revision references that descriptor. Manifests and chunks remain path/FileID-independent content objects.

A canonical tree represents exactly one directory as a definite array ordered by NFC UTF-8 basename bytes. Entries are directory, regular, executable, or symlink; each named entry, including a directory, has a FileID. Hard links/aliases are absent in v1. Directory entries reference trees; file/executable/symlink entries reference manifests. The same FileID may appear only once across the fully expanded snapshot tree.

A repository has exactly one designated zero-parent root snapshot. Other snapshots have one to eight ordered, unique parents; parent zero is the change-set base. All parents share the descriptor and reach the designated root. Cycles, missing/wrong-kind parents, cross-repository parents, a second root, or more than eight parents are invalid.

Change sets contain ordered create, modify, copy, move, rename, delete, restore, group-transition, and merge-resolution records. Create/copy allocate a new FileID; move/rename preserve it; delete retains lifetime history; restore reactivates an existing lifetime after proving an ancestral delete/tombstone, exact historical state, and absence from the base tree. Restore never creates a new lifetime origin. Published snapshots contain only resolved conflicts and the replayed result must equal the declared tree/group roots. Conflict records use typed entry/group subjects, mechanically constrained side presence and type, and exact base/left/right/delete/custom result equality. Unresolved divergent-move, delete/modify, content, type, mode, policy, group, and path-collision states belong to pending changes or immutable shelf revisions, not published snapshots.

Asset-group membership uses FileIDs, not paths, so renames preserve membership. Members are sorted and unique; every member resolves exactly once in the snapshot tree. Registered group profiles define role/cardinality and external-key uniqueness. Missing-sidecar and duplicate-GUID fixtures are representable validation failures rather than ambiguous ordinary groups.

FileID bytes are repository scoped: equal 128-bit bytes may independently exist in different repositories. Cross-repository rejection applies to source proofs, mappings, and transitions, not to global byte uniqueness. Validation is as of immediately before the candidate snapshot: immutable first-consumption records are existing context and candidate create/copy allocations are ordered working additions. A lifetime origin is exactly native create, native copy, or import; a create followed by delete still consumes the ID. Native proof carries no nonce because a nonce cannot establish registry uniqueness. Import mapping insertion and its lifetime record are atomic, and retry of the same importer namespace/source identity returns the original ID and current state. Concurrent allocation collision has one winner; every loser returns a typed conflict without advancing a reference.

OGVCS-002 owns representation, pure graph/transition validation, and normative vectors. OGVCS-006 owns the durable lifetime/import registry. OGVCS-010 owns finalize-time collision enforcement and atomic branch failure. Deterministic fixture IDs are fixed test data, not native CSPRNG allocation behavior; the adapter must reject zero, persist mappings, synthesize directory/group IDs without deriving native identity from mutable path text, and map workload-only lock/review/network events to typed non-history records.

## Consequences and proof

Required vectors cover zero/one/two/eight-parent history; second-root, ninth-parent, duplicate/cross-repository parents; every entry kind; duplicate FileIDs across directories; create/copy/move/rename/delete/delete-recreate/restore; import lost-ack retry; forged and cross-repository proof; concurrent collision; rename-stable groups; sidecar failures; resolved and unresolved conflicts; shelf chains; missing/wrong-kind graph edges; and exact change-set replay. Parent/provenance cycle algorithms use an explicitly typed prevalidated abstract-reference-graph scenario: content-addressed canonical bytes cannot form such a finite cycle without a SHA-256 fixed point, and an ordinary attempted-cycle mutation fails ObjectID validation first. OGVCS-001 supplies five adapter corpora, while OGVCS-002 supplies native restore/import/collision/parent/conflict cases absent from the fixture generator.
