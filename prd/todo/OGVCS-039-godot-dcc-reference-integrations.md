# OGVCS-039 — Godot and DCC reference integrations

**Status:** Todo  
**Release:** R4 — Ecosystem  
**Priority:** P2  
**Owner:** Unassigned  
**Depends on:** OGVCS-026, OGVCS-031, OGVCS-038  
**Blocks:** None  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

The public SDK is proven beyond first-party Unreal/Unity clients through maintained Godot and Blender reference integrations that cover text-scene workflows, opaque DCC asset locking, previews, sidecars, and secure handoff without embedding VCS credentials.

## Problem

An SDK tested only by the team that designed it can preserve hidden assumptions. Godot exercises open engine/text resource workflows; Blender exercises native binary creative files, headless previews, and external-editor save behavior. Shipping both as real reference integrations exposes missing contracts while giving smaller studios usable patterns.

## Scope

### In scope

- Godot editor integration for project association, status, start edit/lock, sync/reconcile, history/diff, checkpoint/revert, review/submit handoff, and project policy templates.
- Blender add-on for file/linked-library status, lock-before-edit/save guidance, checkpoints, version/history/open-copy, review/submit handoff, and sandboxed preview generation.
- Shared sample code, packaging/signing, compatibility matrices, automated example projects/assets, and SDK feedback/conformance extensions.

### Out of scope

- Live multi-user scene collaboration, arbitrary semantic merge of `.blend` or binary imports, Godot/Blender replacement asset management, render farm, or support for every DCC in this PRD.

## Users and journeys

- **Godot developer/designer:** tracks text scenes/resources plus imported sources, excludes generated caches, merges supported text, and submits from a desktop handoff.
- **Blender artist:** sees that a `.blend` or linked library is locked, starts editing through the agent, checkpoints before risky save, and shares an isolated preview for review.
- **Integration developer:** compares the two small reference implementations and reuses their manifest, capability, event, error, testing, and packaging patterns.

## Requirements

### Functional

- **OGVCS-039-FR-01:** Each integration SHALL publish an exact application/version/platform and OGVCS agent/SDK compatibility matrix and SHALL block unsafe mutations on incompatible versions.
- **OGVCS-039-FR-02:** Each SHALL use only public OGVCS-038 SDK/IPC contracts, request least-privilege named capabilities, retain no server/object-store credential, and remain recoverable through desktop/CLI if disabled.
- **OGVCS-039-FR-03:** The Godot integration SHALL ship reviewed policies for source assets, `.godot`/imported/generated caches, text scenes/resources/scripts, import metadata, extensions/add-ons, case paths, mergeability, and binary lock groups.
- **OGVCS-039-FR-04:** Godot operations SHALL reconcile editor-created add/move/delete/sidecar changes, preflight dirty/open resources before sync, invoke versioned text merge through OGVCS-015, and surface unresolved conflicts without claiming semantic safety beyond tested formats.
- **OGVCS-039-FR-05:** The Blender integration SHALL associate the current file and authorized linked libraries/assets with workspace FileIDs and show granted/denied/stale/unknown lock state before edit/save actions where hooks permit.
- **OGVCS-039-FR-06:** If an application cannot guarantee pre-save interception, the integration SHALL state that limit prominently, detect/reconcile the local edit, checkpoint it, and prevent server submit without a valid required lock; it SHALL not claim prevention it cannot enforce.
- **OGVCS-039-FR-07:** Blender preview jobs SHALL use OGVCS-026 with a pinned Blender/runtime/add-on digest, no network/credentials, strict resources, sanitized output, exact source provenance, and authorization recheck.
- **OGVCS-039-FR-08:** Complex sync, conflict, review, submit, policy repair, and recovery SHALL hand off exact workspace/path/change context securely to the desktop rather than duplicate those flows.
- **OGVCS-039-FR-09:** Both integrations SHALL include deterministic simulator tests, golden projects/assets, packaging/signatures, install/update/remove docs, accessibility/keyboard considerations, and a diagnostics export that omits project content/credentials.
- **OGVCS-039-FR-10:** SDK gaps found during implementation SHALL be resolved through versioned OGVCS-038/036 changes and public conformance cases, not private endpoints or application-specific server exceptions.

### Quality attributes

- **OGVCS-039-NFR-01:** Integration UI callbacks MUST not block the host application's main thread on network or whole-workspace work.
- **OGVCS-039-NFR-02:** Application/add-on/agent crash, upgrade, or disable MUST not lose local bytes or strand uninspectable server locks/jobs.
- **OGVCS-039-NFR-03:** The repositories MUST be suitable as small auditable examples, with documented architecture and no copied proprietary SDK/code/assets.

## Interfaces and data

Deliver two integration manifests/packages, app↔workspace association, asset/group policies, host event→SDK mapping, status/error vocabulary, secure handoff, preview converter manifest, golden fixtures, and documented SDK gap/conformance log.

## Development plan

1. Implement the Godot add-on shell/workspace association, compatibility/policy checks, status and public-SDK conformance against golden projects.
2. Add Godot lock/sync/reconcile/history/conflict and desktop review/submit handoffs with dirty-resource and generated-cache protections.
3. Implement the Blender add-on for file/linked-library status, lock/edit/save/checkpoint/history/handoff plus the pinned sandboxed preview converter.
4. Complete host/version/fault/security/UI-thread/package tests, resolve every SDK gap publicly, and use both repositories as maintained third-party examples.

## Acceptance criteria

- **OGVCS-039-AC-01:** Golden Godot projects cover text scenes/resources, scripts, source imports, generated caches, add/move/delete, Unicode/case, dirty sync, merge conflicts, binary locks, and reproducible snapshot build/import.
- **OGVCS-039-AC-02:** Golden Blender work covers `.blend`, linked libraries, external textures/sidecars, save/reconcile, lock loss, checkpoint, version open-copy, preview/review, and exact desktop submit handoff.
- **OGVCS-039-AC-03:** Host/add-on/agent/network fault matrices preserve local work, recover accurate state, and never produce false lock/submit/preview success.
- **OGVCS-039-AC-04:** Both integrations pass OGVCS-038 conformance/security and OGVCS-030 signing/update tests across their declared matrices with responsive host UI.
- **OGVCS-039-AC-05:** A third party uses the reference code to build a small integration through public APIs; every discovered contract gap has a public test/spec disposition.

## Verification plan

Godot editor/headless golden projects, Blender GUI/headless golden assets, SDK simulator/conformance, host main-thread profiling, two-user locks, dirty sync/save, kill/restart/version-skew, preview sandbox attacks, signed packaging, and independent developer exercise.

## Telemetry and operations

Expose locally safe app/add-on/SDK versions, operation/result/duration, lock state class, handoff, policy finding type, preview job result, and compatibility failure. Project/asset names, content, and user identity are excluded from shared telemetry.

## Rollout and rollback

Release Godot status/policy and Blender status/lock in preview, expand to mutations/handoffs, then previews after sandbox review. Each add-on can be removed independently with desktop/CLI recovery; no repository-format rollback is required.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Host API cannot prevent an unsafe save | Disclose limitation, detect/checkpoint, enforce at server submit |
| Reference plugins gain private shortcuts | Public-SDK-only build and conformance gate |
| DCC preview expands attack surface | OGVCS-026 sandbox and pinned headless runtime |
| Scope expands to every creative tool | Two explicit reference apps; others require new PRDs |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
