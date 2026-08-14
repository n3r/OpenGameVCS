# OGVCS-011 — Native CLI and workspace lifecycle foundation

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-004, OGVCS-006, OGVCS-008, OGVCS-009, OGVCS-041  
**Blocks:** OGVCS-012, OGVCS-013, OGVCS-014, OGVCS-015, OGVCS-016, OGVCS-022, OGVCS-042, OGVCS-043  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Developers and downstream feature PRDs have one cross-platform native CLI foundation for authentication, repository discovery, workspace creation/configuration, safe local operation plumbing, capability negotiation, and stable machine-readable output.

## Problem

Every later client feature needs a safe local workspace foundation. Shell-specific scripts or a GUI-owned private interface would fragment behavior, error handling, credentials, and cross-platform semantics.

## Scope

### In scope

- Command framework, configuration precedence, profiles/endpoints, authentication invocation, credential storage integration, and diagnostics.
- Workspace create/open/list/remove/configure and local metadata layout.
- Safe add/move/delete/revert command plumbing and calls to server/content APIs.
- Human and versioned JSON output, stable exit/error classes, progress/cancellation, and noninteractive mode.
- Secure self-update handoff only as an interface; packaging is OGVCS-030.

### Out of scope

- Scalable status, selective sync, local checkpoints, merge, locks, and atomic submit behavior. OGVCS-043 owns the integrated R1 commands after those feature contracts exist.
- Desktop GUI or virtual files.

## Users and journeys

- **Developer:** signs in, discovers a repository, creates/configures a workspace, stages safe local operations, and receives discoverable placeholders when a later feature command is unavailable.
- **Build script:** uses JSON and stable exit codes without parsing human text.
- **Support engineer:** runs a redacted diagnostic bundle that explains endpoint, version, workspace, auth state, and capability mismatch.

## Requirements

### Functional

- **OGVCS-011-FR-01:** Configuration precedence SHALL be command flag, environment, workspace, user profile, and system default, with a command that shows the effective source of each nonsecret value.
- **OGVCS-011-FR-02:** Secrets SHALL use OS credential storage or an explicit headless provider and SHALL never be printed by config, JSON, debug, crash, or diagnostic output.
- **OGVCS-011-FR-03:** Workspace creation SHALL preflight OGVCS-004 path/platform rules, bind repository/branch/baseline/spec, create local metadata atomically, and leave no valid-looking partial workspace after failure.
- **OGVCS-011-FR-04:** The CLI SHALL refuse to operate on a workspace whose root or metadata ownership/permissions are unsafe or whose required format/capabilities are unsupported.
- **OGVCS-011-FR-05:** Commands SHALL support cancellable progress with bytes/items/phases and resume tokens where the underlying API supports resume.
- **OGVCS-011-FR-06:** JSON schemas and exit/error codes SHALL be versioned; human text may evolve but SHALL include one actionable next step for common failures.
- **OGVCS-011-FR-07:** File mutation commands SHALL be confined to the workspace root, preserve OGVCS-004 identity semantics, and stage intent without silently uploading/submitting.
- **OGVCS-011-FR-08:** Noninteractive mode SHALL never prompt and SHALL fail clearly when authentication, conflict, force, or destructive confirmation is required.
- **OGVCS-011-FR-09:** Diagnostic bundles SHALL be previewable, redact tokens/paths/identities by policy, and require explicit user creation.

### Quality attributes

- **OGVCS-011-NFR-01:** Supported commands and JSON results MUST behave consistently on current supported Windows, macOS, and Linux versions.
- **OGVCS-011-NFR-02:** Interrupting any command MUST leave local metadata recoverable and report whether remote durable state may have changed.
- **OGVCS-011-NFR-03:** Startup for local-only commands SHALL remain below the declared reference latency and avoid network access unless required.

## Interfaces and data

Define CLI command tree, config schema, workspace metadata directory/version, OGVCS-041 JSON/protocol schemas, progress events, exit classes, capability negotiation, and diagnostic manifest. Feature PRDs extend commands through stable internal services, not duplicate implementations; OGVCS-043 owns their end-to-end assembly.

## Development plan

1. Implement the native command framework, config/profile precedence, authentication/credential adapters, capability negotiation, JSON/error schemas, and local-only diagnostics.
2. Implement atomic workspace create/open/list/configure/remove, safe metadata layout/versioning, ownership checks, and recovery of incomplete initialization.
3. Implement workspace-confined add/move/delete/revert plumbing, cancellable progress/resume handoff, noninteractive behavior, and extension seams for later sync/status/submit/lock PRDs.
4. Complete three-OS security/compatibility/packaging tests, publish the command/JSON contracts and support runbook, and ship signed-preview-ready binaries without self-update.

## Acceptance criteria

- **OGVCS-011-AC-01:** Authentication, discovery, workspace create/open/configure, safe local add/move/delete/revert plumbing, cancellation, diagnostics and JSON compatibility journeys pass on all three operating systems without claiming sync/submit completion.
- **OGVCS-011-AC-02:** Secret scanners and forced failures find no credential in logs, process arguments where avoidable, JSON, diagnostics, or crash output.
- **OGVCS-011-AC-03:** Cancellation at each workspace-creation/file-operation boundary recovers or clearly resumes without root escape.
- **OGVCS-011-AC-04:** Unsupported server/client capability combinations fail before mutation with a documented resolution.
- **OGVCS-011-AC-05:** Accessibility review confirms human errors do not rely only on color and terminal output remains usable with screen readers/plain logs.

## Verification plan

CLI golden/contract tests, cross-OS integration, credential/redaction tests, cancellation/crash tests, path confinement adversarial cases, and compatibility matrix.

## Telemetry and operations

Local opt-in diagnostics record command class, phase, duration, byte/item totals, result code, versions, and retry count. No file paths/content or command arguments are collected by default.

## Rollout and rollback

Ship developer-preview binaries with explicit server compatibility range. Destructive or force actions require opt-in flags. Self-update is disabled until OGVCS-030; rollback uses previous signed binary and compatible workspace format.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| CLI becomes business-logic duplicate | Shared client libraries and contract ownership by feature PRDs |
| JSON freezes accidental internals | Small versioned public schemas and compatibility tests |
| Local metadata corruption blocks work | Atomic writes, journal/recovery command, checkpoint integration later |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
