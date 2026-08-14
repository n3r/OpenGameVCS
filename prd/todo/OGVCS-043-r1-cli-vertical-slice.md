# OGVCS-043 — R1 CLI vertical slice

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-010, OGVCS-011, OGVCS-012, OGVCS-013, OGVCS-016, OGVCS-021, OGVCS-041  
**Blocks:** OGVCS-022, OGVCS-030  
**Source:** [OpenGameVCS delivery roadmap](../ROADMAP.md)  
**Last updated:** 2026-08-14

## Outcome

A user can install the supported starter deployment and native CLI on a clean machine, create a workspace, selectively sync, inspect status, acquire a hard lock, submit an atomic change, and fetch it from a second workspace using only public versioned contracts.

## Problem

Individual service and client-foundation PRDs can all pass without proving that their contracts compose into the Developer Preview promised by the release gate. Packaging alone also cannot own missing CLI orchestration. R1 needs one explicit integration artifact and end-to-end evidence owner.

## Scope

### In scope

- CLI command integration for authenticated repository/workspace bootstrap, selective sync/update, status, start-edit/lock, submit, result recovery, and second-workspace fetch.
- Public-contract adapters and compatibility manifest joining the independently delivered R1 components.
- Hermetic end-to-end scenario runner, clean-host fixtures, fault checkpoints, diagnostics bundle, and checksummed release-evidence command.
- Windows, macOS, and Linux client packaging/smoke coverage against the starter server topology.

### Out of scope

- New metadata, transfer, authorization, workspace, sync, lock, or deployment semantics.
- Desktop/engine UX, branches/merge UI, production HA, or performance optimizations that bypass owning contracts.
- Treating the integration harness as a substitute for component-level tests.

## Users and journeys

- **Developer:** installs the CLI, syncs only source plus one asset folder, edits code and a locked binary, submits, and sees the exact snapshot receipt.
- **Second user:** syncs that immutable snapshot into another sparse workspace and verifies byte identity and lock disposition.
- **Release owner:** runs one command on clean hosts and receives a checksummed, machine-readable R1 vertical-slice evidence bundle with artifact provenance.

## Requirements

### Functional

- **OGVCS-043-FR-01:** The CLI SHALL compose repository/workspace creation, selection, sync, status, start-edit/lock, submit, idempotency lookup, and fetch through public negotiated contracts only.
- **OGVCS-043-FR-02:** The reference scenario SHALL create two identities/workspaces, materialize different authorized selections, publish code plus a lockable binary, and reproduce exact committed bytes in the second workspace.
- **OGVCS-043-FR-03:** Submit output SHALL expose snapshot ID, authority epoch, branch generation, consistency token, lock disposition, and a command to resolve an ambiguous result.
- **OGVCS-043-FR-04:** Authentication expiry, branch advance, lock loss, missing/corrupt content, disk full, cancellation, and network loss SHALL return one typed recovery path without losing local work.
- **OGVCS-043-FR-05:** The scenario runner SHALL provision or target a supported starter deployment, avoid private database/object-store access, and cleanly isolate test repositories/workspaces.
- **OGVCS-043-FR-06:** Machine-readable CLI output and evidence SHALL identify component/protocol/format versions, scenario seed, steps, results, timings, root/object verification, and redaction status.
- **OGVCS-043-FR-07:** Clean-host preview artifacts SHALL verify published checksums/build provenance and perform capability checks before any mutation; OGVCS-030 later owns release signatures and upgrade-train policy.
- **OGVCS-043-FR-08:** The integration SHALL preserve each owning component's authorization, durability, lock, path, and state-honesty invariants; an unavailable dependency SHALL fail closed rather than use a private fallback.

### Quality attributes

- **OGVCS-043-NFR-01:** The golden scenario MUST pass on supported Windows, macOS, and Linux clients against the same declared starter server profile.
- **OGVCS-043-NFR-02:** Fault injection at every integration boundary MUST preserve local bytes and zero acknowledged snapshots with missing content or invalid lock proof.
- **OGVCS-043-NFR-03:** A clean-host run MUST require no undocumented manual configuration, source checkout, database access, or vendor service.

## Interfaces and data

Deliver integrated CLI commands, component compatibility manifest, scenario definition, clean-host runner, fault schedule, snapshot/lock/content verification report, diagnostics bundle, and checksummed R1 evidence schema. It consumes owning APIs without redefining them.

## Development plan

1. Wire repository/workspace/authentication and selective sync/status commands through negotiated public clients; add the two-workspace hermetic scenario skeleton.
2. Integrate start-edit/lock and atomic submit/result resolution, exact receipt display, second-workspace fetch, and end-to-end content/lock verification.
3. Add clean preview-artifact installation, checksum/provenance verification, three-OS orchestration, boundary fault matrix, safe diagnostics, component compatibility checks, and machine-readable evidence digesting.
4. Run the full release scenario from clean hosts, seed representative failures, remove all private test bypasses, publish the operator/user walkthrough, and make this PRD an R1 gate requirement.

## Acceptance criteria

- **OGVCS-043-AC-01:** A clean user completes install → workspace → selective sync → status → hard-lock edit → atomic submit → second-workspace fetch on all supported client OSes without private access.
- **OGVCS-043-AC-02:** The second workspace verifies the committed snapshot and every selected file byte while excluded paths remain undisclosed and unmaterialized.
- **OGVCS-043-AC-03:** Lost submit response resolves to the original receipt; branch/lock/auth/content races publish at most one valid snapshot and preserve the losing workspace.
- **OGVCS-043-AC-04:** Killing each client/server/transfer boundary, exhausting local disk, corrupting cache data, and expiring auth produce the documented safe recovery result.
- **OGVCS-043-AC-05:** The checksummed evidence bundle from each clean host validates artifact provenance, versions, steps, invariants, roots, timings, and redaction with no `TBD`, skip, or manual assertion.

## Verification plan

Hermetic end-to-end tests, three-OS clean-host package runs, protocol skew, authorization selections, crash/network/disk/cache fault matrix, submit/lock races, exact-byte verification, evidence-schema validation, and manual fresh-user walkthrough.

## Telemetry and operations

The scenario captures safe command phase/result, versions, durations, retries, transferred bytes, consistency/epoch generations, and invariant outcomes. Evidence excludes credentials, content, messages, identities, and protected paths.

## Rollout and rollback

Run against isolated repositories first, then design-partner test deployments. This PRD adds orchestration, not new durable formats; rollback returns to component CLIs while retaining drafts/workspaces and published snapshots.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Integration PRD hides component defects | Defect returns to owning PRD; no private adapter or bypass accepted |
| Clean-host test differs from supported deployment | Provision from the same immutable checksummed preview artifacts and compatibility manifest |
| Happy path passes while recovery is broken | Boundary-level fault schedule is release-blocking |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
