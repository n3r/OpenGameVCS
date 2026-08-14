# ADR-0001: Format-v1 root snapshots and FileID

**Status:** Accepted  
**Date:** 2026-08-14  
**Owners:** OGVCS-002, OGVCS-006, OGVCS-010

## Context

The architecture allowed a root snapshot with no parent while OGVCS-002 required at least one. FileID was also essential to history and locks but lacked allocation, uniqueness, and reuse rules.

## Decision

- A snapshot has zero or more ordered parents. A repository root has zero; ordinary commits normally have one; merges may have two or more within bounded format limits.
- Format-v1 FileID is an opaque nonzero 128-bit value. Native clients allocate it with a cryptographically secure random source.
- FileID is repository scoped and unique for the repository's lifetime across history, drafts, shelves, and tombstones. It is not reused after deletion.
- Create/copy introduces a new ID; move preserves an existing ID; restore may reuse a historical ID only through the explicit restore operation.
- A repository registry and finalize-time unique constraints reject duplicate, forged, cross-repository, and concurrent collision attempts.
- Importers allocate once and persist source-to-target mappings; paths are never an identity generator.

## Consequences and proof

The format must include root, multi-parent, duplicate-in-tree, reuse-after-delete, forged-move, concurrent-create, restore, and import-retry vectors. A collision returns a typed conflict and never mutates published history.

