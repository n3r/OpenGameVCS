# OGVCS-014 — Local checkpoints and offline recovery

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-007, OGVCS-011, OGVCS-012, OGVCS-013  
**Blocks:** OGVCS-015, OGVCS-022  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Users can save, inspect, chain, restore, squash, and later publish immutable local checkpoints while disconnected, without implying that a hard-lockable edit remains globally exclusive offline.

## Problem

Centralized systems make local experimentation and recovery dependent on a server. Game contributors need safe work-in-progress history, but local state must not be confused with shared branches or valid online locks.

## Scope

### In scope

- Local checkpoint DAG rooted at server snapshot, using canonical manifests/chunks in shared cache.
- Create/list/show/diff/restore/delete/squash and crash recovery.
- Pinning, local metadata integrity, optional at-rest integration with OS protection, and publish handoff.
- Lock-receipt snapshot and offline exclusivity warning state.

### Out of scope

- Server shelves/reviews, shared local checkpoints, branch merge algorithm, or offline hard-lock guarantee.

## Users and journeys

- **Developer:** checkpoints an experiment on a flight, creates another checkpoint, then merges/rebases and publishes later.
- **Artist:** saves a recoverable local checkpoint before a risky DCC conversion.
- **Support engineer:** recovers the last complete checkpoint after client crash without deleting newer working files.

## Requirements

### Functional

- **OGVCS-014-FR-01:** A checkpoint SHALL record parent, base server snapshot, ordered local operations, manifests/chunks, message, time, workspace/spec identity, and lock receipts/status.
- **OGVCS-014-FR-02:** Creation SHALL be atomic: an interrupted checkpoint is either absent or discoverable as incomplete/recoverable and never replaces the last valid checkpoint.
- **OGVCS-014-FR-03:** Restore SHALL preview affected paths, preserve uncheckpointed changes by default, and require explicit action to overwrite/discard them.
- **OGVCS-014-FR-04:** Diff/list/show SHALL work without network for all locally available content and clearly mark unavailable baseline bytes.
- **OGVCS-014-FR-05:** Checkpoint chunks SHALL use the OGVCS-013 shared-cache pin contract until checkpoint deletion plus recovery grace; cache eviction, selection change and workspace removal SHALL respect pins.
- **OGVCS-014-FR-06:** Publish handoff SHALL identify the checkpoint/base and invoke normal current authorization, ancestry, content, policy, and lock validation.
- **OGVCS-014-FR-07:** When connectivity or lock lease cannot be verified, hard-lockable changes SHALL display `exclusivity unverified`; the client SHALL not claim a valid exclusive reservation.
- **OGVCS-014-FR-08:** Delete/squash SHALL be recoverable for a grace period and SHALL verify that no descendant/workspace pin is orphaned.

### Quality attributes

- **OGVCS-014-NFR-01:** Checkpoint operations MUST work with the server unreachable after the base and required bytes are local.
- **OGVCS-014-NFR-02:** Power loss at every metadata/chunk/index update MUST preserve all previously complete checkpoints.
- **OGVCS-014-NFR-03:** Local checkpoint metadata MUST be integrity-checked and must not cause writes outside the workspace/cache roots when restored.

## Interfaces and data

Define local checkpoint object/index, OGVCS-013 cache pin/eviction transition, operation list, availability marker, lock receipt state, and publish request. Reuse OGVCS-002/007 canonical identities so publish does not re-encode content.

## Development plan

1. Implement the local checkpoint object/index format, content capture through OGVCS-007, OGVCS-013 cache pin integration, atomic creation, verification, listing, and retention accounting.
2. Implement diff/inspect/restore/open-copy operations with exact local-change preflight and crash-safe workspace application.
3. Add checkpoint chains, metadata/message updates, squash, expiry/pin, later publish conversion, and explicit offline/lock-state semantics.
4. Complete corruption/disk-full/kill/restart/three-OS tests, add recovery diagnostics and documentation, and roll out creation/inspect before restore/destructive actions.

## Acceptance criteria

- **OGVCS-014-AC-01:** Create/diff/restore/squash works offline across all supported platforms and reconstructs exact bytes.
- **OGVCS-014-AC-02:** Every injected crash leaves prior checkpoints valid and recovery reports, rather than hides, incomplete state.
- **OGVCS-014-AC-03:** Restore never overwrites newer uncheckpointed work without explicit confirmed action.
- **OGVCS-014-AC-04:** OGVCS-013 cache pressure, selection change, workspace removal and eviction races cannot remove pinned checkpoint chunks; corrupt chunks are detected before restore.
- **OGVCS-014-AC-05:** Restore or publish-request generation never treats a stored lock receipt as authority; it remains explicitly untrusted metadata for later server validation.

## Verification plan

Offline integration, checkpoint DAG properties, crash/corruption tests, cache pin/eviction tests, restore obstruction matrix, and stale lock receipt tests.

## Telemetry and operations

Local-only metrics: checkpoint count/bytes, creation/restore duration, cache pins, incomplete recovery, and unverified lock warnings. Nothing is sent remotely without explicit telemetry consent.

## Rollout and rollback

Enable after local format recovery tests. Workspace clients retain read support for the previous checkpoint format; downgrade exports or restores checkpoints before rebuilding local metadata.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Users mistake checkpoint for backup/shared work | Clear local-only labels and publish/share actions |
| Checkpoints consume disk indefinitely | Quotas, visibility, graceful delete, never evict silently |
| Offline binary edits conflict | Explicit unverified state and server reconciliation |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
