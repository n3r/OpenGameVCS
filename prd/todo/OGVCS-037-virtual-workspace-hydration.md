# OGVCS-037 — Virtual workspace and on-demand hydration

**Status:** Todo  
**Release:** R4 — Ecosystem  
**Priority:** P1  
**Owner:** Unassigned  
**Depends on:** OGVCS-004, OGVCS-008, OGVCS-012, OGVCS-013, OGVCS-017, OGVCS-022, OGVCS-030  
**Blocks:** None  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Users can browse a production-sized snapshot as a normal supported filesystem and hydrate verified file bytes on first access, pin working sets for offline use, and evict clean data safely—without changing repository semantics or making placeholders look like durable local content.

## Problem

Explicit partial materialization is predictable but still requires users to anticipate every needed path. OS virtualization can reduce startup disk and sync time, yet introduces failures in the filesystem read/write path, placeholder metadata, offline behavior, antivirus/build tools, locks, and eviction. It must be an optional client presentation over immutable snapshots, not a new source-of-truth model.

## Scope

### In scope

- One production-supported virtual-filesystem implementation per declared client OS in the release matrix, backed by shared workspace/index/transfer libraries.
- Placeholder enumeration, on-demand hydration, pin/unpin, safe eviction, prefetch, offline state, write/edit transition, diagnostics, recovery, and desktop integration.
- Compatibility policy/testing for representative Unreal, Unity, build, antivirus, search-indexer, backup, and DCC workloads.

### Out of scope

- Server-side workspace state per file, peer-to-peer hydration, offline lock guarantees, hiding unsupported application behavior, or replacing explicit materialization for users who prefer it.

## Users and journeys

- **Artist:** opens a large snapshot immediately, hydrates an asset on demand, starts an edit under lock policy, and pins a folder before travel.
- **Build engineer:** prefetches a manifest-declared working set and proves all required bytes are hydrated before an offline/deterministic build phase.
- **Support engineer:** explains whether a path is placeholder/hydrating/hydrated/dirty/pinned/error and repairs local state without touching repository history.

## Requirements

### Functional

- **OGVCS-037-FR-01:** A virtual workspace SHALL bind immutable snapshot, branch tracking state, selection policy, path/case rules, local state generation, cache, and provider version and SHALL expose these in diagnostics.
- **OGVCS-037-FR-02:** Placeholder names/types/sizes/modes/timestamps SHALL derive from the authorized snapshot and obey OGVCS-004; unsupported filesystem objects/attributes SHALL be rejected or transformed by documented policy before workspace creation.
- **OGVCS-037-FR-03:** Opening a placeholder SHALL obtain authorized short-lived transfer access, resume/fetch required chunks, verify framing/size/digest, then atomically expose exact bytes; partial/corrupt bytes SHALL never appear as a successful complete read.
- **OGVCS-037-FR-04:** Concurrent opens, cancellation, process crash, reboot, network loss, cache eviction, and duplicate callbacks SHALL share or safely retry hydration without deadlock, duplicate dirty identity, or false success.
- **OGVCS-037-FR-05:** A write SHALL transition through an explicit materialized/editable state, enforce start-edit/hard-lock policy where configured, preserve FileID, and never write into an immutable shared-cache object.
- **OGVCS-037-FR-06:** Dirty, locally changed, conflicted, checkpoint-only, uploading, open-for-write, or pinned files SHALL never be evicted. Clean content MAY be evicted only after authoritative local-state preconditions succeed.
- **OGVCS-037-FR-07:** Pin SHALL expand a deterministic selection, estimate bytes/disk headroom, hydrate/verify every member, and publish complete/partial/failure inventory; offline readiness SHALL never be inferred from folder appearance.
- **OGVCS-037-FR-08:** Offline reads SHALL succeed only for verified hydrated/pinned bytes and otherwise return an actionable unavailable state; offline writes SHALL follow OGVCS-014 checkpoint behavior and SHALL not claim exclusive locks.
- **OGVCS-037-FR-09:** Sync/branch switch SHALL preflight dirty/open/pinned/hydrating paths, update placeholder generations atomically, and keep the prior consistent view or explicit recovery state on failure.
- **OGVCS-037-FR-10:** The user SHALL be able to convert a virtual workspace to explicit materialization—or recreate it from server snapshot plus local checkpoint—using supported tooling.
- **OGVCS-037-FR-11:** Unsupported applications/filesystem operations SHALL be listed in the compatibility matrix and detected where practical; the provider SHALL not silently weaken semantics to appear compatible.

### Quality attributes

- **OGVCS-037-NFR-01:** A one-million-path virtual workspace MUST become browseable within the approved startup and local metadata budgets, published per OS/hardware/topology.
- **OGVCS-037-NFR-02:** Hydration adds bounded overhead beyond equivalent OGVCS-008 transfer; warm verified reads MUST approach normal filesystem performance under the reference workload.
- **OGVCS-037-NFR-03:** Provider crash/kernel callback failure/reboot MUST preserve user bytes and recover without requiring server/database intervention.

## Interfaces and data

Define virtual workspace/provider capability, placeholder record/generation, hydration job/receipt, path state machine, pin manifest/result, eviction precondition/receipt, offline-readiness report, compatibility result, and conversion/recovery plan.

## Development plan

1. Implement the virtual-workspace/provider abstraction, placeholder/path state journal, capability preflight and one supported OS adapter in read-only mode.
2. Implement authorized verified hydration, concurrent/open/range/retry/reboot handling, cache integration and precise offline/unavailable states.
3. Implement materialize-before-write/start-edit, dirty/pin/eviction guarantees, sync/branch-switch generations, prefetch and virtual→explicit recovery.
4. Complete filesystem/application/fault/disk-pressure and million-path performance matrices, then graduate each OS independently from opt-in preview.

## Acceptance criteria

- **OGVCS-037-AC-01:** Filesystem conformance covers open/read/range read/write/append/truncate/map/copy/move/delete/rename/case/Unicode/symlink/error behaviors with correct bytes/FileIDs or documented rejection on each supported OS.
- **OGVCS-037-AC-02:** Network/cache/provider/process/reboot faults at every hydration/write/sync/eviction stage never expose corrupt complete reads or lose dirty bytes.
- **OGVCS-037-AC-03:** Dirty/pinned/open/checkpointed files survive aggressive eviction and disk-pressure tests; only verified reconstructible clean bytes are reclaimed.
- **OGVCS-037-AC-04:** One-million-path startup/browse, cold/warm representative artist tasks, WAN hydration, and disk-savings benchmarks meet approved thresholds with full environment disclosure.
- **OGVCS-037-AC-05:** Declared Unreal, Unity, build, antivirus, indexer, backup, and Blender compatibility scenarios pass or are automatically blocked with documented alternatives.

## Verification plan

OS/filesystem contract suite, application compatibility lab, state-machine/property tests, fault/reboot/disk-full injection, corrupted-cache tests, lock/write races, pin/offline drills, large-workspace benchmarks, accessibility/UI checks, and virtual→explicit recovery exercises.

## Telemetry and operations

Expose local placeholder/hydrated/dirty/pinned counts and bytes, hydration latency/failures, cache hit/integrity, eviction, disk pressure, provider callbacks/errors, and compatibility version. Paths/content remain local; exported diagnostics use safe IDs and allowlisting.

## Rollout and rollback

Release as opt-in preview on one OS after explicit materialization is stable, expand only after app/OS gates, then graduate per-platform. Rollback blocks new virtual workspaces and converts/preserves existing work through supported explicit materialization/checkpoint recovery.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Placeholder looks available while offline | Explicit hydration/pin/offline readiness state |
| OS provider bug loses writes | Materialize-before-write, local journal/checkpoints, crash matrix |
| Application uses unsupported filesystem behavior | Published compatibility matrix and detection/blocking |
| Eviction removes only copy of local work | Strict reconstructible-clean preconditions |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
