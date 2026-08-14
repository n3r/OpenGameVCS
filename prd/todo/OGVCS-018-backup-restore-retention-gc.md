# OGVCS-018 — Backup, restore, retention, and garbage collection

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-006, OGVCS-008, OGVCS-009, OGVCS-010, OGVCS-017  
**Blocks:** OGVCS-021, OGVCS-025, OGVCS-028, OGVCS-032, OGVCS-033  
**Source:** [Architecture ADR-0003](../../adr/0003-object-lifecycle-and-gc-fencing.md)  
**Last updated:** 2026-08-14

## Outcome

Operators can recover a repository to a declared point in time with verified history and content, enforce retention/legal holds, and reclaim only provably unreachable data through a conservative, auditable collector.

## Problem

Object storage durability is not a backup, and content-addressing does not make deletion safe by itself. Metadata and content must be captured at a consistent boundary, restored together, and protected against garbage-collection races, compromised credentials, and unnoticed backup corruption.

## Scope

### In scope

- Consistent metadata backups, referenced-content inventory, backup manifests, encryption, retention, restore, validation, and recurring drills.
- Snapshot/tag/hold pins and two-phase mark/quarantine/sweep garbage collection with dry-run estimates.
- Single-deployment recovery objectives and operator runbooks.

### Out of scope

- Active-active metadata, automated regional failover, rolling upgrade orchestration, and full portable repository export.

## Users and journeys

- **Operator:** schedules encrypted backups, monitors freshness, and restores a chosen recovery point into a clean deployment.
- **Compliance admin:** pins named snapshots or applies a legal hold that normal retention and GC cannot bypass.
- **Capacity owner:** previews reclaimable objects, runs GC, and can explain every deletion from retained reachability evidence.

## Requirements

### Functional

- **OGVCS-018-FR-01:** A backup SHALL record a consistent metadata generation, schema/protocol version, branch/tag roots, lock/audit treatment, object-inventory boundary, configuration requirements, and cryptographic checksums.
- **OGVCS-018-FR-02:** Backup completion SHALL require verification that every content object reachable from captured roots has a copy in the designated backup target under independently scoped credentials and retention; production object storage, a cache, or a replica alone SHALL never satisfy completion.
- **OGVCS-018-FR-03:** Restore SHALL support a clean target, refuse incompatible/mixed generations, verify the reconstructed graph with OGVCS-017, and remain isolated until validation succeeds.
- **OGVCS-018-FR-04:** Backup credentials, encryption keys, and storage policy SHALL be separable from primary-service credentials; secrets SHALL not appear in manifests or logs.
- **OGVCS-018-FR-05:** Retention SHALL support time policy, protected branches/tags, explicit pins, legal holds, in-progress uploads/submits, shelves/reviews, and backup dependencies.
- **OGVCS-018-FR-06:** GC SHALL calculate reachability against a captured generation, publish a dry-run inventory, then recheck current roots and CAS each exact `available` lifecycle generation into quarantine for a configurable grace interval.
- **OGVCS-018-FR-07:** After grace, GC SHALL recheck current roots and CAS the exact quarantine generation to `deleting` before physical deletion; submit may atomically revive only quarantined objects and SHALL never reference deleting/deleted state.
- **OGVCS-018-FR-08:** Restore and GC SHALL be resumable and idempotent and SHALL emit immutable operator identity, policy, generation, counts, and result records.
- **OGVCS-018-FR-09:** The deployment SHALL expose configured recovery point objective (RPO), recovery time objective (RTO), backup freshness, last verified restore, and retention compliance.
- **OGVCS-018-FR-10:** Physical deletion SHALL carry the deleting generation as a storage precondition, append a durable deletion receipt, and resume safely after crashes without inferring authority from object-store listing alone.

### Quality attributes

- **OGVCS-018-NFR-01:** The reference single-node deployment MUST demonstrate declared RPO/RTO in an automated destructive restore drill using a clean target.
- **OGVCS-018-NFR-02:** No fault injection or concurrent mutation test may delete an object reachable from a retained root or active transaction.
- **OGVCS-018-NFR-03:** Backup/restore/GC formats and state transitions MUST be versioned, restart-safe, and inspectable without the original process memory.
- **OGVCS-018-NFR-04:** A backup whose independent target is unavailable, incomplete, corrupt, or readable only with production credentials MUST remain incomplete and MUST NOT satisfy a restore/GC gate.

## Interfaces and data

Define `BackupManifest`, independent target/retention proof, recovery point, protected content inventory, `RetentionPolicy`, pin/hold, object lifecycle generation, GC mark generation, quarantine/deleting record, deletion receipt, restore plan/result, and drill evidence. Content inventories use canonical OGVCS-002 identities.

## Development plan

1. Implement consistent backup generation/manifest and reachable-content inventory with independently credentialed/retained target copying, encryption/provider contracts, scheduling, and freshness reporting.
2. Implement clean-target restore planning/execution, schema/config/identity mapping, OGVCS-017 verification, and isolated activation.
3. Implement retention/pin/legal-hold/shelf-review roots and the current-root-checked `available → quarantined → deleting → deleted` state machine with atomic submit revival, dry run, grace and preconditioned sweep.
4. Execute restore and GC race/crash/key/corruption/capacity drills, publish RPO/RTO runbooks, and require a passing restore before bounded sweep rollout.

## Acceptance criteria

- **OGVCS-018-AC-01:** A clean deployment restored from backup produces identical authorized branch/tag roots and passes full graph/content verification.
- **OGVCS-018-AC-02:** Crashes at every backup, mark, quarantine, delete, and restore fault point recover without losing reachable or held content.
- **OGVCS-018-AC-03:** Submit/branch-delete/pin/unpin races with GC retain exactly the objects required by the documented generation and grace rules.
- **OGVCS-018-AC-04:** Expired unreachable objects are reclaimed only after dry run and grace; deleted counts/digests match the sweep receipt.
- **OGVCS-018-AC-05:** A scheduled restore drill meets configured RPO/RTO and produces evidence sufficient for an operator who did not create the backup.
- **OGVCS-018-AC-06:** Removing production storage after backup still permits a clean verified restore; a generation missing any independently retained object remains incomplete and cannot unlock GC.
- **OGVCS-018-AC-07:** Model/fault tests covering submit, shelf, pin, quarantine, revival, deleting, repair and crash interleavings never delete a published/reachable object or publish a deleting/deleted object.

## Verification plan

Reference restores with production storage unavailable, graph comparison, independent-credential/key-loss/wrong-key cases, corruption and partial-copy injection, GC lifecycle model/property tests, submit/shelf/pin/repair races, permission checks, crash matrix, and capacity/performance tests.

## Telemetry and operations

Expose backup age/duration/bytes, protected inventory lag, restore duration/stage, verification failures, retained/reclaimable/quarantined/deleted bytes, hold counts, and RPO/RTO compliance. Alerts cover stale/unverified backups and any reachable-object finding.

## Rollout and rollback

Require a successful restore before enabling GC. Run GC dry-only, then quarantine-only, then bounded sweep with long grace. Rollback disables new sweeps; quarantined objects remain recoverable until explicitly past policy.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Backup is internally consistent but lacks content | Reachability inventory and completion verification |
| GC races a new reference | Captured generation, active-transaction roots, grace, delete preconditions |
| Same credentials destroy primary and backup | Separate principals, stores, retention locks, and keys |
| Restore procedure silently rots | Scheduled clean-room drills and freshness alerts |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
