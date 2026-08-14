# OGVCS-023 — Unreal Engine integration

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-013, OGVCS-016, OGVCS-019, OGVCS-022, OGVCS-042  
**Blocks:** OGVCS-030  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Unreal users can see status, check out/lock, sync, reconcile, revert, and submit assets from the editor while OpenGameVCS correctly handles package sidecars, external actors, redirectors, and editor safety boundaries.

## Problem

Unreal asset workflows span more than the file clicked in the Content Browser. A naive plugin can lock an incomplete set, overwrite dirty packages during sync, miss external actors, or report success before a server commit. The integration must map engine intent to canonical workspace and lock operations without owning repository correctness itself.

## Scope

### In scope

- Source-control provider plugin for a declared Unreal-version compatibility matrix.
- Login/workspace association, status badges, checkout/edit intent, sync/update, add/delete/rename, reconcile, history, diff handoff, revert, and submit handoff.
- Asset-group rules for packages, maps, external actors/objects, sidecars, redirectors, configuration, and source files.
- Commandlet/headless hooks for CI validation and provenance.

### Out of scope

- Arbitrary binary/Blueprint semantic merge, multi-user editing transport, engine build distribution, or a replacement for Unreal's asset registry.

## Users and journeys

- **Artist:** checks out a map/asset in the editor and receives the complete policy-defined lock group before saving.
- **Level designer:** updates a world-partition area without overwriting dirty packages or missing external actor changes.
- **Build engineer:** runs a commandlet against one immutable snapshot and records plugin/engine/snapshot provenance.

## Requirements

### Functional

- **OGVCS-023-FR-01:** The plugin SHALL declare supported Unreal versions/platforms and OGVCS-042 local-agent profile and SHALL fail closed on an incompatible agent/API rather than bypass source control.
- **OGVCS-023-FR-02:** Engine package paths SHALL map deterministically to workspace paths/FileIDs under OGVCS-004, including case, Unicode, redirector, plugin-content, and generated-directory rules.
- **OGVCS-023-FR-03:** Checkout/start-edit SHALL resolve and atomically request the versioned asset group required by policy; partial group acquisition SHALL not make the primary asset appear safely editable.
- **OGVCS-023-FR-04:** Save interception SHALL clearly distinguish lock granted, advisory, pending, lost/unknown, and denied states and SHALL never claim offline exclusivity.
- **OGVCS-023-FR-05:** Sync/update SHALL preflight dirty, loaded, locked, deleted, and engine-generated files; unsafe updates SHALL be blocked or require an explicit save/checkpoint/close/reload flow.
- **OGVCS-023-FR-06:** Reconcile SHALL detect editor-created adds/deletes/moves and expected sidecars while filtering configured transient/generated files without hiding ambiguous changes.
- **OGVCS-023-FR-07:** Submit SHALL delegate final change enumeration, content upload, lock and branch validation, and acknowledgement to shared OpenGameVCS services and SHALL display the returned snapshot/change ID.
- **OGVCS-023-FR-08:** Provider operations SHALL be asynchronous/cancellable where the engine permits, marshal UI updates safely, and survive editor restart through the shared workspace state.
- **OGVCS-023-FR-09:** The plugin SHALL expose actionable owner/base/branch details only when authorized and SHALL use the desktop client for complex conflict/recovery flows via secure local handoff.
- **OGVCS-023-FR-10:** Headless operation SHALL pin an immutable snapshot, verify materialized inputs, and emit engine/plugin/client version and snapshot provenance.

### Quality attributes

- **OGVCS-023-NFR-01:** Cached status queries MUST not block the editor game/UI thread on network or whole-workspace scans.
- **OGVCS-023-NFR-02:** Plugin disable, crash, or version mismatch MUST leave files and server state recoverable through the desktop/CLI clients.
- **OGVCS-023-NFR-03:** Asset-group rules MUST be data-driven, versioned, bounded, and tested against representative partner projects.

## Interfaces and data

Define engine-to-workspace association, asset-group descriptors, OGVCS-042 provider operation/result schema, dirty-package sync preflight, reconcile disposition, secure desktop handoff, and commandlet provenance. The plugin calls the agent/shared client surface rather than embedding server credentials per operation.

## Development plan

1. Implement the version-pinned Unreal provider package against OGVCS-042, local-agent/workspace association, asynchronous operation framework, login and cached status badges.
2. Implement path/FileID and package/sidecar/OFPA/redirector asset-group resolution plus start-edit/checkout/lock state in editor surfaces.
3. Implement dirty-package-safe sync, add/delete/move/reconcile, history/diff/revert and desktop submit handoff, then add commandlet provenance.
4. Complete golden-project, two-editor, crash/restart, UI-thread and engine-version matrix tests, and stage status → checkout/sync → submit behind repository feature flags.

## Acceptance criteria

- **OGVCS-023-AC-01:** Golden Unreal projects cover assets, maps, world partition/external actors, redirectors, plugins, source/config, adds/moves/deletes, and sidecars with expected status and lock groups.
- **OGVCS-023-AC-02:** Two editors cannot both successfully submit an overlapping hard-locked asset group; loss/expiry is visible before the plugin claims a safe save/submit.
- **OGVCS-023-AC-03:** Sync with dirty/loaded/conflicting packages never silently overwrites bytes and completes the documented checkpoint/reload recovery flow.
- **OGVCS-023-AC-04:** Editor crash/restart during checkout, sync, reconcile, and submit leaves no false operation success and preserves recoverable local work.
- **OGVCS-023-AC-05:** The declared engine/platform compatibility matrix passes automated editor, commandlet, packaging, and upgrade smoke tests.
- **OGVCS-023-AC-06:** The plugin passes OGVCS-042 C++ binding/conformance, receives no reusable server/object-store credential, and rejects an unavailable/incompatible agent without a private fallback.

## Verification plan

Unreal automation tests with golden projects, two-client lock scenarios, dirty-package sync matrix, world-partition/redirector cases, editor kill/restart injection, UI-thread performance profiling, headless build reproducibility, and partner shadow workflow.

## Telemetry and operations

Expose safe provider operation type/result/duration, cached vs refreshed status, asset-group size, editor/plugin/client versions, and handoff failures. Never collect asset names/content or protected-path details in shared telemetry.

## Rollout and rollback

Ship to a version-pinned design-partner project in read/status mode, then checkout/sync, then submit. Plugin rollback remains compatible with the supported local-agent protocol and does not migrate repository data.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Engine version changes private behavior | Narrow compatibility matrix and automated per-version projects |
| Incomplete asset groups create split edits | Data-driven golden rules and all-or-nothing acquisition |
| Sync overwrites loaded/dirty packages | Editor-state preflight and checkpoint/close/reload flows |
| Plugin becomes a second VCS client implementation | Thin adapter over shared local/client APIs |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
