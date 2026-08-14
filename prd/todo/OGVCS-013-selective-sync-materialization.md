# OGVCS-013 — Selective sync and explicit materialization

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-007, OGVCS-008, OGVCS-009, OGVCS-011, OGVCS-012  
**Blocks:** OGVCS-014, OGVCS-019, OGVCS-022, OGVCS-023, OGVCS-025, OGVCS-027, OGVCS-031, OGVCS-037, OGVCS-042, OGVCS-043  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Users define a versioned include/exclude workspace and materialize only authorized required files at an immutable snapshot. Sync is previewable, resumable, cache-aware, and never overwrites local work silently.

## Problem

Artists and CI workers should not download a terabyte depot to edit or build a small subset. Sparse behavior must remain understandable and safe across deletes, moves, permission changes, local edits, and interrupted transfer.

## Scope

### In scope

- Workspace specification with branch/baseline, include/exclude rules, and `full`, `metadata`, or absent state.
- Authorized target resolution, sync plan/dry-run, required-object negotiation, shared local cache, staging, atomic application, and index generation update.
- Modified-file/conflict policy, disk/byte estimate, cancellation/resume, cache limit/eviction.

### Out of scope

- Transparent placeholder files/on-open hydration, owned by OGVCS-037.
- Build artifact cache or regional cache implementation.

## Users and journeys

- **Artist:** selects one character subtree and gets only its source assets and sidecars.
- **Developer:** previews what sync will change and resolves local conflicts before mutation.
- **CI agent:** materializes an immutable path subset using a shared cache and no persistent server have-list.

## Requirements

### Functional

- **OGVCS-013-FR-01:** Workspace specs SHALL be canonical, versioned, diffable, and support ordered include/exclude path rules plus materialization class and platform profile.
- **OGVCS-013-FR-02:** Target resolution SHALL use an immutable snapshot/consistency token and authorization-filtered tree; permission loss SHALL remove access without leaking hidden replacements.
- **OGVCS-013-FR-03:** Dry-run SHALL report adds/updates/deletes/moves/conflicts, logical and expected transfer bytes, disk requirement, cache hits, and blockers before file mutation.
- **OGVCS-013-FR-04:** Sync SHALL stage and verify required content before an atomic/bounded workspace-generation switch; partial application after crash SHALL be detected and recoverable.
- **OGVCS-013-FR-05:** Locally modified or untracked obstructing paths SHALL never be overwritten/deleted without an explicit separately confirmed resolution action.
- **OGVCS-013-FR-06:** The shared cache SHALL be content-addressed, verify on read, track pins for active workspaces/checkpoints, and evict unpinned least-useful data within a configured bound.
- **OGVCS-013-FR-07:** Metadata-only entries SHALL be represented in the index/UI but SHALL not create deceptive ordinary files in the filesystem.
- **OGVCS-013-FR-08:** Resume SHALL reuse verified chunks/staged files and revalidate authorization/target head before application.
- **OGVCS-013-FR-09:** Sync to “latest” SHALL resolve once and report the exact resulting snapshot even if the branch advances during transfer.

### Quality attributes

- **OGVCS-013-NFR-01:** Metadata-only setup over one million paths SHALL target completion under 60 seconds on the reference workstation.
- **OGVCS-013-NFR-02:** Incremental sync overhead SHALL target under 5 seconds plus missing payload transfer time.
- **OGVCS-013-NFR-03:** Cached content corruption MUST be detected and refetched; cache loss may degrade performance but cannot lose versioned data.

## Interfaces and data

Define workspace-spec schema, resolved target, sync plan/action/conflict, cache entry/pin, resume token, staging generation, and materialization events. OGVCS-019 uses a noninteractive snapshot mode; OGVCS-022 consumes the same plan/progress API.

## Development plan

1. Implement the versioned include/exclude grammar, canonical selection evaluator, preview plan, authorization filtering, and disk/transfer estimate.
2. Implement staged workspace materialization with safe path creation, complete-object verification, atomic replacement, deletion rules, and local-change preflight.
3. Add resumable parallel transfer/cache integration, interrupted-plan recovery, selection changes, sparse metadata, and deterministic sidecar/group expansion.
4. Complete three-OS sparse/conflict/fault and million-path/WAN tests, expose CLI/client progress/diagnostics, and canary read-only sync before destructive updates.

## Acceptance criteria

- **OGVCS-013-AC-01:** Each persona spec materializes exactly the expected authorized paths and zero excluded payload bytes.
- **OGVCS-013-AC-02:** Crash/cancel at every plan/download/stage/apply/index boundary recovers without overwriting local edits or reporting a mixed generation as clean.
- **OGVCS-013-AC-03:** Warm cache sync records zero origin bytes for cached content and reproduces identical file digests.
- **OGVCS-013-AC-04:** Permission revocation during transfer prevents application and invalidates grants without revealing newly hidden paths.
- **OGVCS-013-AC-05:** Performance targets pass on the reference corpora and cache/disk estimates remain within declared error bounds.

## Verification plan

Spec-rule property tests, cross-OS filesystem cases, local obstruction matrix, auth revocation race, crash/resume injection, corrupt cache, and cold/warm million-path benchmarks.

## Telemetry and operations

Expose plan/actions, logical/transfer/cache bytes, duration by phase, resume, cache hit/eviction/corruption, disk shortfall, conflicts, and snapshot IDs in protected traces. No broad path labels.

## Rollout and rollback

Start with explicit CLI specs and full materialization; enable metadata class after UX validation. Workspace generation allows client rollback to previous baseline if content remains pinned. Spec format changes are versioned.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Sparse rules surprise users | Dry-run, explain path, versioned spec, GUI presets |
| Staging doubles disk needs | Accurate preflight, streaming apply where safe, configurable staging volume |
| Shared cache eviction breaks checkpoints | Explicit pins and verifier before eviction |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
