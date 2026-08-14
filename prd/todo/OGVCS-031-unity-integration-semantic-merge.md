# OGVCS-031 — Unity integration and semantic merge

**Status:** Todo  
**Release:** R3 — Production Beta  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-013, OGVCS-015, OGVCS-016, OGVCS-019, OGVCS-022, OGVCS-026, OGVCS-042, OGVCS-045  
**Blocks:** OGVCS-039  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Unity teams can operate source control inside the editor with correct asset/`.meta` identity, safe generated-path policy, automatic locks for configured binaries, and a packaged, reproducible semantic-merge flow for supported text-serialized scenes and prefabs.

## Problem

Unity's GUID identity lives in `.meta` sidecars, while scenes and prefabs are mergeable only under suitable serialization settings and tool versions. Missing or duplicated sidecars silently break references; syncing dirty/open assets can lose work; invoking a semantic merge tool without version/provenance makes results irreproducible.

## Scope

### In scope

- Editor package for a declared Unity-version/platform matrix with status, start edit/lock, sync, add/delete/move, reconcile, history/diff, revert, shelf/review, and submit handoff.
- Asset + `.meta` grouping, project policy validation, generated/cache exclusions, serialization checks, and configured binary locks.
- Packaged Unity semantic-merge driver integration for supported YAML scenes/prefabs plus durable conflict handling.

### Out of scope

- Merge of arbitrary binary assets, Unity collaboration/multiplayer services, Library/cache versioning, or custom semantic parsers for every package format.

## Users and journeys

- **Unity artist:** starts editing a binary source asset and acquires its asset/sidecar group before the file becomes writable.
- **Programmer/designer:** branches and merges a text-serialized scene/prefab through a pinned semantic driver, resolves remaining conflicts, and submits reproducible output.
- **Project lead:** validates repository settings so `.meta` files are visible/tracked and generated `Library`/temporary outputs cannot enter normal submits accidentally.

## Requirements

### Functional

- **OGVCS-031-FR-01:** The package SHALL declare supported Unity editor versions, serialization/metadata modes, platforms, and OGVCS-042 local-agent profile; incompatible combinations SHALL block mutations with an upgrade/configuration action.
- **OGVCS-031-FR-02:** Every tracked asset operation SHALL treat the asset and required `.meta` sidecar as one versioned policy group while preserving stable FileID and Unity GUID relationships across moves.
- **OGVCS-031-FR-03:** Reconcile/submit SHALL block a missing, duplicate, malformed, untracked, or unexpectedly regenerated `.meta` for an affected asset unless an explicit repair policy produces and displays a safe change.
- **OGVCS-031-FR-04:** The package SHALL validate visible-meta-files/text-serialization settings and repository ignore/lock/merge policy, distinguishing required blockers from recommendations.
- **OGVCS-031-FR-05:** Generated/project-local directories such as imported caches, temporary build products, and machine settings SHALL be excluded by reviewed templates; suspicious additions SHALL be visible and policy-checkable rather than silently discarded.
- **OGVCS-031-FR-06:** Configured nonmergeable formats SHALL use OGVCS-016 start-edit/hard-lock state and clearly show granted, advisory, denied, stale, and offline/unknown status in the Project window.
- **OGVCS-031-FR-07:** Sync SHALL preflight dirty/open/importing assets and local changes, checkpoint where requested, materialize the complete selected group, and request safe refresh/reimport without claiming completion early.
- **OGVCS-031-FR-08:** Semantic merge SHALL run the supported Unity merge executable/configuration through the OGVCS-015 driver contract, OGVCS-045 runner, and OGVCS-026 derived-output policy with exact base/ours/theirs object IDs and engine/tool/config digests.
- **OGVCS-031-FR-09:** Driver output SHALL be re-parsed/validated as supported serialized asset data; unresolved conflicts SHALL remain durable, visible, and submit-blocking until explicit resolution.
- **OGVCS-031-FR-10:** Repeating a merge with identical inputs, engine/tool/config version, and options SHALL produce identical output/conflict records or the driver SHALL be marked nondeterministic and prohibited from automatic clean resolution.
- **OGVCS-031-FR-11:** Editor operations SHALL delegate durable workspace, content, lock, review, and submit behavior to OGVCS-042/shared clients and remain recoverable through desktop/CLI after package disable or crash.

### Quality attributes

- **OGVCS-031-NFR-01:** Cached status and filesystem event processing MUST not block the Unity main thread on network or whole-tree scans.
- **OGVCS-031-NFR-02:** No golden or fuzz case may publish broken asset/`.meta` pairing or silently remove a GUID/reference through a grouped operation.
- **OGVCS-031-NFR-03:** Semantic tools and project-controlled inputs MUST receive no repository credentials/network access and MUST obey declared resource limits.

## Interfaces and data

Define Unity workspace association, asset/sidecar group rule, project-policy report, GUID relationship finding, editor operation/result, semantic-driver manifest/config, merge validation result, conflict handoff, and build/editor provenance.

## Development plan

1. Implement the version-pinned Unity package against OGVCS-042, local-agent/workspace association, async status/UI framework and project policy/compatibility validator.
2. Implement asset/`.meta` group and GUID validation, generated-path rules, binary start-edit/locks, dirty-safe sync/reconcile and desktop operation handoffs.
3. Package the pinned semantic merge driver/configuration through OGVCS-045, apply OGVCS-026 output policy, validate outputs, persist conflicts and integrate branch merge/submit behavior.
4. Complete golden-project, cross-platform determinism, sandbox, dirty-sync/crash and reproducible snapshot-build tests, then stage status/policy → locks/sync → submit → semantic merge.

## Acceptance criteria

- **OGVCS-031-AC-01:** Golden Unity projects cover adds/moves/deletes, GUID preservation, missing/duplicate/malformed `.meta`, packages, Unicode/case paths, ignored generated trees, and configured binary locks with expected outcomes.
- **OGVCS-031-AC-02:** Scene/prefab semantic merge corpus produces expected clean/conflict outputs and identical digests across supported platforms for each pinned tool version.
- **OGVCS-031-AC-03:** Malicious/malformed YAML and driver crash/hang/output-corruption cases are contained, never publish automatically, and leave actionable durable conflicts.
- **OGVCS-031-AC-04:** Dirty/open/importing sync and editor crash/restart tests preserve local work and accurately recover server/workspace state.
- **OGVCS-031-AC-05:** A Unity design partner completes the P0 artist and merge journeys for the compatibility matrix and produces reproducible snapshot builds during shadow operation.
- **OGVCS-031-AC-06:** The C# plugin passes OGVCS-042 conformance without reusable credentials, and every semantic driver passes OGVCS-045 isolation/resource/revocation tests before automatic merge is enabled.

## Verification plan

Golden Unity repositories, GUID/reference validator, editor automation, merge corpus/fuzzing, cross-platform determinism, sandbox attacks, two-user lock tests, dirty-sync and kill/restart matrix, main-thread profiling, and partner shadow builds.

## Telemetry and operations

Expose safe operation/result/duration, policy finding types, group size, lock state transitions, merge tool/version/result, conflict counts, and editor/package/client versions. Project asset names, YAML, GUIDs, content, and protected paths stay local or access-controlled.

## Rollout and rollback

Deploy policy validation/status first, then lock/sync/reconcile, then submit, and finally semantic merge for pinned editor versions. Disabling/rolling back the package preserves normal desktop/CLI access; unsupported driver versions remain readable by provenance but cannot produce new automatic resolutions.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Sidecar loss silently breaks assets | Atomic groups, GUID validation, submit blockers |
| Unity tool output changes by version/platform | Pinned compatibility matrix and golden digest corpus |
| Editor refresh overwrites or destabilizes work | Dirty/importing preflight, checkpoint, staged refresh |
| “Semantic merge” implies arbitrary safety | Narrow supported formats, output validation, durable conflicts |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
