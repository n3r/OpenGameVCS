# OGVCS-022 — Desktop artist client

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-011, OGVCS-012, OGVCS-013, OGVCS-014, OGVCS-015, OGVCS-016, OGVCS-019, OGVCS-043  
**Blocks:** OGVCS-023, OGVCS-030, OGVCS-031, OGVCS-037, OGVCS-038, OGVCS-044  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Artists can complete the daily source-control loop—open a workspace, sync, start an edit, understand ownership/conflicts, inspect changes, checkpoint, revert, and submit—without a terminal and without the client weakening server-side correctness.

## Problem

CLI-first version control exposes concepts and failure states that are hostile to visual workflows. A GUI can make this worse if it hides partial sync, stale locks, or failed uploads behind optimistic animations. The desktop must translate the same authoritative contracts into clear, recoverable actions at million-file scale.

## Scope

### In scope

- Signed desktop application for supported Windows, macOS, and Linux clients.
- Connection/workspace setup, branch and sync controls, scalable change/status views, edit/lock intent, checkpoints, history/diff handoff, revert, conflict resolution handoff, and submit.
- Notifications, background transfer management, diagnostics, secure credential storage, keyboard/accessibility support, and deep links for engine integrations.

### Out of scope

- Repository/server administration, review/shelf service, asset rendering, virtual filesystem hydration, or engine-specific behavior.

## Users and journeys

- **Artist:** opens a recent workspace, syncs only their feature area, starts editing a locked asset, checkpoints, reviews a visual change summary, and submits.
- **Lead:** filters team changes, identifies the owner/base of a blocked asset, and guides a safe update or lock transfer.
- **Support engineer:** receives a user-approved redacted diagnostics bundle and reproduces the recorded state transition.

## Requirements

### Functional

- **OGVCS-022-FR-01:** The client SHALL use the same versioned APIs and workspace/index semantics as the CLI; it SHALL not maintain a second authoritative model of repository, content, or lock state.
- **OGVCS-022-FR-02:** Connection and workspace creation SHALL validate identity, repository, branch, case/path policy, disk capacity, destination safety, and selection rules before materialization.
- **OGVCS-022-FR-03:** The main view SHALL expose current snapshot, pending changes, sync state, materialization state, conflicts, lock/edit intent, checkpoint state, and background failures with plain-language recovery actions.
- **OGVCS-022-FR-04:** Change and history lists SHALL be paged/virtualized, cancellable, filterable, and stable under background refresh; they SHALL not enumerate unauthorized paths.
- **OGVCS-022-FR-05:** Start-edit SHALL acquire or declare intent before making a managed file writable when policy requires it and SHALL show owner/base/lease state or a non-disclosing denial.
- **OGVCS-022-FR-06:** Submit SHALL present the exact selected changes, dependency/sidecar expansion, lock status, branch-head update needs, upload progress, policy checks, and final snapshot/change ID.
- **OGVCS-022-FR-07:** Destructive local actions SHALL show affected files/bytes and offer a checkpoint or explicit discard; remote published history SHALL never be rewritten through an ambiguous UI action.
- **OGVCS-022-FR-08:** Network loss, authentication expiry, client crash, and restart SHALL preserve safe local work and expose authoritative unknown/stale states rather than display success.
- **OGVCS-022-FR-09:** Credentials and tokens SHALL use supported OS secure storage, be scoped/rotatable, and never enter workspace files, logs, crash reports, clipboard by default, or deep-link parameters.
- **OGVCS-022-FR-10:** The app SHALL support keyboard-only operation, screen-reader names/status, scalable text, non-color-only status, and reduced-motion preferences for all P0 journeys.
- **OGVCS-022-FR-11:** Engine/DCC deep links SHALL be authenticated local requests with origin validation and SHALL require confirmation for mutations.

### Quality attributes

- **OGVCS-022-NFR-01:** Launch to usable cached workspace view p95 MUST be below three seconds; status refresh MUST preserve OGVCS-012's warm-status target and keep the UI responsive.
- **OGVCS-022-NFR-02:** No supported crash/fault sequence may lose unsubmitted bytes without a preceding explicit discard confirmation.
- **OGVCS-022-NFR-03:** The client MUST display server/client protocol incompatibility before allowing a mutation and provide a supported upgrade path.

## Interfaces and data

Define a UI-neutral application state model, background job state, notification/deep-link schema, recent connection/workspace metadata, user preference schema, and redacted diagnostic event timeline. CLI and GUI consume shared client libraries where behavior overlaps.

## Development plan

1. Implement the signed desktop shell, shared-client state model, secure connection/credential/workspace setup, background-job framework, and scalable navigation primitives.
2. Implement sync/status/my-changes/history, selection/materialization and transfer progress, notifications, filtering/virtualization, and local diagnostics.
3. Implement start-edit/lock, checkpoint/revert/conflict recovery and exact submit flows plus secure engine deep links and destructive-action safeguards.
4. Complete three-OS large-workspace, crash/network/security, accessibility and artist-usability suites, then roll out status/read actions before mutations by feature flag.

## Acceptance criteria

- **OGVCS-022-AC-01:** Representative artists complete setup, selective sync, start edit, conflict-owner lookup, checkpoint, revert, and submit without CLI or moderator help at the agreed usability threshold.
- **OGVCS-022-AC-02:** A million-path reference workspace opens, filters, scrolls, and refreshes within declared latency/memory budgets without loading all rows into the UI.
- **OGVCS-022-AC-03:** Crash/network/auth-expiry injection during every mutating journey recovers to an accurate state with local bytes intact and no false submit/lock success.
- **OGVCS-022-AC-04:** Accessibility audit passes the defined keyboard, screen-reader, scaling, contrast, focus, and reduced-motion matrix on supported platforms.
- **OGVCS-022-AC-05:** Security testing finds no credential in workspace state, logs, diagnostics, crash payloads, URLs, or clipboard defaults.

## Verification plan

Shared CLI/GUI contract tests, component and end-to-end UI tests, large-list performance, fault/restart matrix, three-OS filesystem corpus, usability sessions, accessibility audit, credential/deep-link security tests, and signed-package smoke tests.

## Telemetry and operations

Locally record an allowlisted diagnostic timeline of job states, safe error codes, durations, retries, and client/server versions. Any product analytics are opt-in and aggregated; paths, filenames, messages, content, and identities are excluded.

## Rollout and rollback

Start with design-partner opt-in and feature flags for submit/lock mutations. Preserve CLI as the documented recovery path. A bad desktop release can roll back within the supported protocol window without changing repository data formats.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Friendly UI hides stale or partial state | Explicit current/unknown/failed states and authoritative refresh |
| GUI and CLI behavior diverge | Shared client/domain libraries and cross-interface contract tests |
| Large workspaces freeze rendering | Virtualized paging, cancellable background work, performance gates |
| Recovery action destroys local work | Checkpoint-first flow and exact affected-item confirmation |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
