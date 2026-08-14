# OGVCS-006 — Repository metadata and snapshot service

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-002, OGVCS-003, OGVCS-004, OGVCS-005, OGVCS-041  
**Blocks:** OGVCS-009, OGVCS-010, OGVCS-011, OGVCS-015, OGVCS-016, OGVCS-018, OGVCS-021, OGVCS-028  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Clients can create repositories, store and retrieve immutable snapshot/tree metadata, and manage versioned branch pointers through a transactional, paginated service that implements the open logical format without storing bulk file bytes.

## Problem

Every workflow needs a reliable authority for immutable history and mutable references. Combining it prematurely with payload transfer, workspace state, or UI would prevent independent testing and scaling.

## Scope

### In scope

- Tenant/project/repository lifecycle and immutable repository settings.
- Immutable object ingestion/read for snapshots and trees.
- Branch/tag/reference creation, read, list, and compare-and-swap update primitive.
- Stable FileID/path lookup and paginated tree/history traversal.
- Transactional database schema, migrations, idempotency records, and event outbox primitive.

### Out of scope

- File payload storage/transfer, submit orchestration, authorization implementation, merging, search, and reviews.

## Users and journeys

- **Client:** resolves a branch to a snapshot and walks only the required tree pages.
- **Service developer:** atomically advances a reference only from an expected previous value.
- **Operator:** migrates the schema forward, inspects health, and detects dangling/corrupt metadata.

## Requirements

### Functional

- **OGVCS-006-FR-01:** Repository creation SHALL persist immutable case/platform/format settings and reject later mutation outside a migration.
- **OGVCS-006-FR-02:** Immutable objects SHALL be accepted only when canonical encoding, ID, type, required features, and structural limits validate.
- **OGVCS-006-FR-03:** Duplicate immutable-object writes SHALL be idempotent; different bytes under the same ID SHALL trigger a corruption/security error.
- **OGVCS-006-FR-04:** Reference mutation SHALL require expected prior value, enforce repository scope, and return a stable conflict response on compare-and-swap failure.
- **OGVCS-006-FR-05:** Tree traversal SHALL support deterministic pagination, prefix bounds, and continuation tokens without returning duplicate or skipped entries under concurrent unrelated writes.
- **OGVCS-006-FR-06:** History APIs SHALL traverse snapshot parents and FileID/path changes with bounded work and explicit incomplete/depth limits.
- **OGVCS-006-FR-07:** Every metadata transaction that must emit a later event SHALL write an outbox record in the same transaction.
- **OGVCS-006-FR-08:** Schema migrations SHALL be ordered, checksummed, restartable where safe, and reject an unsupported downgrade.
- **OGVCS-006-FR-09:** The service SHALL maintain a repository-lifetime FileID registry/tombstone and unique constraints across published history, active drafts, and shelves so deleted, forged, duplicate, or concurrently colliding IDs cannot be accepted as new identities.

### Quality attributes

- **OGVCS-006-NFR-01:** Immutable reads and branch resolution SHALL remain available under read-replica operation without serving a reference older than its declared consistency token.
- **OGVCS-006-NFR-02:** A one-million-entry tree SHALL be traversable with bounded server/client memory under OGVCS-005.
- **OGVCS-006-NFR-03:** Database restart at any named transaction fault point MUST leave either the old or new complete reference state, never a partial state.

## Interfaces and data

Publish versioned metadata APIs for repository settings, object put/get, tree page, reference read/list/CAS, ancestry, FileID allocate/register/history/tombstone, idempotency status, consistency token, and outbox consumption. Authorization is a required middleware contract supplied by OGVCS-009; development fakes default to deny except in isolated tests.

## Development plan

1. Implement the metadata schema/migration framework and OGVCS-002 object mapping with repository creation and immutable snapshot/tree persistence.
2. Add bounded authorized read APIs, traversal/pagination, corruption/reference validation, and storage-engine transaction/retry handling.
3. Add branch/tag pointer operations, compare-and-swap, idempotency records, repository-lifetime FileID registry/tombstones, policy/audit hooks, and stable OGVCS-041 API/error schemas.
4. Complete concurrency/fault/load/migration tests, operational metrics and backup hooks, package the service, and roll it out read-only before enabling pointer mutations.

## Acceptance criteria

- **OGVCS-006-AC-01:** Golden OGVCS-002 objects round-trip and malformed/collision objects are rejected.
- **OGVCS-006-AC-02:** One hundred concurrent CAS attempts from one head produce exactly one winner and ninety-nine explicit conflicts.
- **OGVCS-006-AC-03:** Fault injection at each database write/commit boundary preserves reference and outbox atomicity.
- **OGVCS-006-AC-04:** Million-entry pagination returns every authorized entry exactly once within the memory threshold.
- **OGVCS-006-AC-05:** Upgrade from the previous supported schema preserves all golden histories and a repeated migration is safe or explicitly refused.
- **OGVCS-006-AC-06:** Concurrent create/copy, delete/recreate, forged move/restore, import retry, and duplicate-tree tests preserve one repository-lifetime FileID identity or return a typed conflict without partial metadata.

## Verification plan

Property tests for immutable graphs and pagination; database concurrency/isolation tests; migration upgrade tests; crash injection; performance profiles for large trees and deep histories.

## Telemetry and operations

Expose request/result class, transaction latency/retries, CAS conflicts, object validation failures, pagination cost, replica consistency lag, outbox lag, database capacity, and migration status. Protected paths/messages are excluded.

## Rollout and rollback

Ship behind a developer-preview API version. Apply expand/migrate/contract schema changes; rollback application before contraction. Reference writes stop safely if schema compatibility is unknown.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Tree model creates hot or oversized rows | Page/structural benchmarks before schema freeze |
| Reference race loses history | Mandatory compare-and-swap and concurrency tests |
| Internal schema becomes de facto export | Maintain strict mapping to OGVCS-002 and test open export independently |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
