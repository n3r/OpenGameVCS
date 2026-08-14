# OGVCS-002 — Core object library and open repository format

**Status:** Todo  
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-001  
**Blocks:** OGVCS-005, OGVCS-006, OGVCS-007, OGVCS-017, OGVCS-020, OGVCS-029, OGVCS-033, OGVCS-036, OGVCS-041  
**Source:** [Architecture ADR-0001](../../adr/0001-format-v1-root-snapshots-and-fileid.md)  
**Last updated:** 2026-08-14

## Outcome

Developers have versioned object-model libraries, an inspector/verifier CLI, public schemas, and golden vectors that create, hash, serialize, exchange, inspect, and verify identical repository objects. The implemented format represents code and asset history, stable identity, branches, merges, shelves, locks, and export without a proprietary service.

## Problem

Storage and client teams cannot develop independently until object identity, canonical encoding, graph reachability, rename/copy semantics, and compatibility rules are stable. An implementation-defined database would also undermine the promised exit path.

## Scope

### In scope

- Domain entities and invariants for tenant, repository, snapshot, tree, tree entry, stable FileID, content manifest, chunk, branch, pending change, shelf, lock reference, identity reference, policy result, and audit reference.
- Canonical byte encoding, hash domains, object IDs, version negotiation, and test vectors.
- Logical export envelope and reachability rules.
- Rename, copy, delete, case-only rename, merge parent, and sidecar-group representation.
- Forward-compatible extension fields and unknown-field behavior.

### Out of scope

- Network transport and API endpoint design.
- Database schema or vendor selection.
- Authorization policy decisions, owned by OGVCS-003/009.
- Physical pack/chunk algorithm, owned by OGVCS-007/008.

## Users and journeys

- **Server engineer:** persists internal indexes while proving they implement the canonical logical model.
- **Client engineer:** computes object IDs and validates responses without server-private knowledge.
- **Tool vendor:** reads an export using the public specification and reconstructs every authorized file.
- **Operator:** verifies reachability and corruption independently of the running service.

## Requirements

### Functional

- **OGVCS-002-FR-01:** The specification SHALL define canonical serialization for every hashed object, including byte order, string normalization, field ordering, optional values, and domain-separated hash preimages.
- **OGVCS-002-FR-02:** SHA-256 SHALL be the required interoperable identifier in version 1; the format SHALL reserve explicit algorithm identifiers without allowing silent algorithm substitution.
- **OGVCS-002-FR-03:** A snapshot SHALL reference zero or more ordered parents, a root tree, author/committer references, timestamps, message, ordered operations, policy result, and optional signature/provenance references; a repository root has zero parents.
- **OGVCS-002-FR-04:** A tree entry SHALL contain canonical name, entry kind, stable FileID, mode, manifest/object ID, logical size, and content-policy class.
- **OGVCS-002-FR-05:** Copy SHALL create a new FileID; move/rename SHALL preserve FileID. Merge rules SHALL specify how divergent moves and delete/modify conflicts are represented.
- **OGVCS-002-FR-06:** The graph SHALL never require lock state, branch pointers, or mutable audit indexes to reconstruct immutable snapshot contents.
- **OGVCS-002-FR-07:** The export envelope SHALL carry all immutable objects plus versioned mutable-reference/audit records required for full-fidelity restoration.
- **OGVCS-002-FR-08:** Every format version SHALL declare required features; readers MUST reject unsupported required features and preserve supported unknown optional fields where round-trip is promised.
- **OGVCS-002-FR-09:** Golden test vectors SHALL cover empty trees, very large files, Unicode, all entry kinds, moves/copies, two-parent merges, sidecar groups, and hash-tamper failures.
- **OGVCS-002-FR-10:** Format-v1 FileID SHALL be an opaque nonzero 128-bit value; native create/copy allocation SHALL use a cryptographically secure random source, and deletion SHALL never make an ID reusable in that repository.
- **OGVCS-002-FR-11:** Validation SHALL reject duplicate FileIDs in one tree, reuse by create/copy, forged move/restore, cross-repository identity, zero/reserved values, and malformed root/parent cardinality.

### Quality attributes

- **OGVCS-002-NFR-01:** Two clean-room implementations MUST generate byte-identical encodings and object IDs for every golden vector.
- **OGVCS-002-NFR-02:** The logical format MUST be streamable and must not require loading a million-entry tree or full export into memory.
- **OGVCS-002-NFR-03:** Object identity and canonical encoding changes after R0 require a new format version and migration PRD; they may not be changed in place.

## Interfaces and data

The output is a normative, versioned repository-format specification, a schema package, golden vectors, malformed vectors, and a small standalone inspector library/API. Implementations may use optimized internal database layouts, but export and protocol objects must map losslessly to the logical model.

## Development plan

1. Implement canonical scalar/container encoding, domain-separated hashing, schema/version envelopes, and a minimal object library with golden empty/tree/blob vectors.
2. Add root and multi-parent snapshots, trees, FileID allocation/lifetime operations, parent DAGs, sidecar groups, copy/move/delete/restore semantics, reachability, and malformed-object validation.
3. Build the streaming inspector/verifier CLI and bounded decoder/fuzzer surfaces, then consume OGVCS-001 identity/history fixtures through a public adapter.
4. Implement the second-language codec independently, reconcile every byte/ID difference, publish versioned packages/specification/vectors, and freeze format version 1.

## Acceptance criteria

- **OGVCS-002-AC-01:** Rust and one independently implemented language encode/decode all golden vectors with identical IDs.
- **OGVCS-002-AC-02:** A streaming verifier reconstructs a million-entry fixture within the benchmark memory ceiling.
- **OGVCS-002-AC-03:** Mutation of any covered byte produces a digest or structural-validation failure.
- **OGVCS-002-AC-04:** The model represents every identity/history/lock/migration fixture emitted by OGVCS-001 without an unversioned escape field.
- **OGVCS-002-AC-05:** Architecture and portability review finds no server-private data required for full export verification.
- **OGVCS-002-AC-06:** Zero-parent root, one-parent commit, bounded multi-parent merge, and malformed parent-cardinality vectors encode identically in both implementations.
- **OGVCS-002-AC-07:** Duplicate, reused, forged, zero, cross-repository, restore, delete/recreate, import-retry, and concurrent-collision FileID vectors produce the normative result.

## Verification plan

- Cross-language golden and malformed-vector tests.
- Property tests for round-trip, determinism, graph reachability, root/parent cardinality, and FileID create/copy/move/restore lifetime.
- Fuzz decoding with memory, recursion, and object-count bounds.
- Compatibility tests across at least two draft format versions.

## Telemetry and operations

Runtime consumers will expose format version, required features, decode failures, unsupported features, and verification time. No content, path, or message is included in diagnostics by default.

## Rollout and rollback

Version 1 remains draft until all R0 consumers pass. Servers write only the ratified version; experimental versions require a repository feature flag. Downgrade is export/reimport unless an explicit reversible migration exists.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Premature format freezes implementation mistakes | Draft feature bit, golden vectors, two implementations, and R0 ratification gate |
| Stable FileID conflicts with branch/copy semantics | Normative copy/move/merge cases and property tests |
| Open format is technically published but unusable | Standalone inspector/verifier and clean-room implementation requirement |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
