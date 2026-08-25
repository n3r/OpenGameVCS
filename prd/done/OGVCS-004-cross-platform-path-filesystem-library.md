# OGVCS-004 — Cross-platform path and workspace filesystem library

**Status:** Done
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Codex and OpenGameVCS maintainers
**Depends on:** OGVCS-001, OGVCS-002
**Blocks:** OGVCS-005, OGVCS-006, OGVCS-007, OGVCS-011, OGVCS-012, OGVCS-033, OGVCS-037, OGVCS-041, OGVCS-042, OGVCS-045
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-25

## Outcome

Server and client developers share a versioned path/workspace filesystem library and conformance corpus that produces deterministic semantics on Windows, macOS, and Linux. It rejects states that cannot be safely materialized and never follows or overwrites an unintended filesystem target.

## Problem

Case folding, Unicode normalization, reserved names, symlinks, long paths, mode bits, atomic replacement, and file-watch behavior differ across operating systems. A game VCS must preserve assets and avoid security failures even when teams share one repository across all three.

## Scope

### In scope

- Joined repository-path encoding and validation built from OGVCS-002 canonical segment bytes, entry kinds, modes, and profile references.
- Repository case mode and collision rules.
- Unicode normalization and display behavior.
- File, directory, symlink, executable-bit, and sidecar-group semantics.
- Platform materialization capability checks and unsafe-target prevention.
- File watching/change-journal expectations and reconciliation triggers.
- Atomic write/replace, crash remnants, read-only lock hint, timestamp, and permission behavior.

### Out of scope

- Virtual filesystem placeholders, owned by OGVCS-037.
- Workspace indexing implementation, owned by OGVCS-012.
- Engine-specific asset identity.
- Redefinition of canonical tree/object bytes, entry-kind or portable-mode codepoints, and object hash preimages.

## Users and journeys

- **Cross-platform developer:** checks out the same snapshot on Windows and Linux and receives the same logical tree and bytes.
- **Artist:** renames an asset only by case and receives a safe, visible operation rather than loss or duplication.
- **Administrator:** knows before submit whether a path cannot be materialized on a supported studio platform.
- **Security engineer:** verifies that symlinks and races cannot write outside the workspace.

## Requirements

### Functional

- **OGVCS-004-FR-01:** Repository paths SHALL consume OGVCS-002 canonical NFC UTF-8 segment bytes and SHALL be slash-separated and relative; empty segments, `.`/`..`, NUL, separators inside a segment, and noncanonical encodings SHALL be rejected without redefining tree bytes or ObjectIDs.
- **OGVCS-004-FR-02:** Repository creation SHALL choose immutable `case-sensitive` or `case-folded` mode. The canonical fold algorithm and collision comparison SHALL be versioned and platform-independent.
- **OGVCS-004-FR-03:** The server SHALL reject paths that collide under repository mode or under the declared supported-platform profile, including normalization and Windows reserved-name/trailing-dot/space cases.
- **OGVCS-004-FR-04:** Each ratified path/platform profile SHALL select explicit operational segment, joined-path, and depth limits no greater than OGVCS-002 hard parser maxima and SHALL expose preflight errors. The one-million-entry tree-object ceiling remains a core format limit rather than a platform-profile choice.
- **OGVCS-004-FR-05:** A symlink SHALL be a distinct entry whose payload is its link target. Sync/export tools SHALL not follow it while writing; materialization on a platform without permitted symlink support SHALL fail explicitly or use a declared nondefault policy.
- **OGVCS-004-FR-06:** Version 1 SHALL preserve regular-file executable intent as one portable bit and SHALL not claim to round-trip arbitrary POSIX ACLs, owners, or platform extended attributes.
- **OGVCS-004-FR-07:** Clients SHALL use race-resistant, workspace-root-confined writes and atomic replacement where supported; crash remnants SHALL be detectable and recoverable.
- **OGVCS-004-FR-08:** Read-only state for hard-lockable files SHALL be a best-effort usability hint, never an authorization guarantee and never the source of versioned file mode.
- **OGVCS-004-FR-09:** Change-journal/watch implementations SHALL persist a cursor, detect overflow/gaps/unclean shutdown, and trigger bounded reconciliation before reporting authoritative clean status.
- **OGVCS-004-FR-10:** Case-only rename, directory/file replacement, rename cycles, delete/modify, junction/reparse point, sparse file, locked-open file, and antivirus interference behavior SHALL have normative outcomes.

### Quality attributes

- **OGVCS-004-NFR-01:** The same logical snapshot MUST produce the same path identities and file digests on all supported platforms.
- **OGVCS-004-NFR-02:** No supported sync sequence may create or overwrite a file outside the canonical workspace root, including through pre-existing symlinks, junctions, or rename races.
- **OGVCS-004-NFR-03:** Platform capability failure MUST be reported before destructive workspace mutation whenever preflight can detect it.

## Interfaces and data

Outputs include joined-path functions, versioned case-fold and collision keys, ratified platform-profile registry entries, materialization preflight results, watcher cursor/gap contracts, error codes, and a cross-platform golden path corpus. The library consumes OGVCS-002 segment bytes, entry/mode codepoints, `ProfileRef`, canonical trees, and logical records without redefining their preimages.

## Development plan

1. Implement the portable joined-path/case/normalization library on the OGVCS-002 lexical-segment contract, repository platform profiles, collision detector, limits, and cross-platform golden vectors.
2. Implement workspace-confined path resolution, symlink/junction policy, safe temporary-write/atomic-replace primitives, and materialization preflight APIs.
3. Implement the watcher cursor/gap/reconciliation contract and platform adapters with crash-remnant detection and deterministic error mapping.
4. Package the shared library for server/client consumers, run the adversarial three-OS matrix, publish capability documentation, and freeze path-contract version 1.

## Acceptance criteria

- **OGVCS-004-AC-01:** Golden paths produce identical canonical values and collision decisions on Windows, macOS, and Linux.
- **OGVCS-004-AC-02:** Pre-existing symlink and Windows-junction fixtures plus target and ancestor rename-race fixtures cannot cause writes outside a disjoint temporary workspace. Linux elevated tracing SHALL cover the symlink, target-race, and ancestor-race sequence with zero outside-root filesystem references; the retained three-OS report SHALL carry the host-native junction outcome.
- **OGVCS-004-AC-03:** Case-only and canonical-NFC Unicode spelling renames round-trip through OGVCS-002 canonical tree and logical-bundle encoding with FileID preserved and exact pinned before/after tree and bundle identities. Decomposed non-NFC spellings are rejected before encoding rather than normalized; fidelity export/reimport proof remains outside this PRD.
- **OGVCS-004-AC-04:** Watcher overflow and unclean-shutdown tests force reconciliation and never falsely report a clean workspace.
- **OGVCS-004-AC-05:** Accepted Unreal- and Unity-like long/deep path fixtures materialize through one bound complete-set plan and produce exact cross-host canonical inventory digests; a paired over-limit fixture fails preflight with an exact stable actionable error.

## Verification plan

- Cross-OS table/property tests and filesystem-specific integration jobs.
- Fuzz canonicalization and path-limit handling.
- Symlink/junction/time-of-check-time-of-use adversarial tests.
- Power-loss simulation around atomic replace and index cursor update.

## Telemetry and operations

Expose platform profile, preflight failure class, watcher gaps, reconciliation duration, atomic-replace fallback, and unsafe-path denial count. Never log protected full paths by default.

## Rollout and rollback

The contract is fixed before repositories are created. Case mode and normalization version are immutable per repository. Changing them requires a new migration PRD with collision preview and verified export; clients fail closed on unsupported rules.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Strict portability rejects legitimate platform-specific trees | Explicit repository supported-platform profile and clear preflight |
| OS updates alter folding/watch behavior | Versioned internal algorithms and regression corpus independent of OS locale |
| Safe writes reduce performance | Benchmark secure primitives and optimize without relaxing confinement |

## Completion evidence

The MIT-licensed implementation source
[`4f8a5a0`](https://github.com/n3r/OpenGameVCS/commit/4f8a5a0f836ef51b4ac56cab9d795d7f5515926d)
passed 78/78 rows on Linux, macOS, and Windows with exact pure decisions and
normalized package bytes. Evidence revision
[`94f68c8`](https://github.com/n3r/OpenGameVCS/commit/94f68c80f9166ef3deb7aa65b9cb268453af714f)
retains the raw reports, comparison, packed identities, expanded Linux trace,
machine run record, and an automated independent integrity replay. The final
critical review found no live P0, P1, or P2. OGVCS-002's separately owned exact
scale campaign is complete and is not duplicated here.

- Implementation changes: the [`4f8a5a0` implementation commit](https://github.com/n3r/OpenGameVCS/commit/4f8a5a0f836ef51b4ac56cab9d795d7f5515926d) and [detailed changelog](../../docs/changelog/OGVCS-004.md#2026-08-25-final-review-hardening) deliver the versioned contract, public library/CLI, bound materialization plans, transactional recovery, safe watcher, telemetry, adapters, and generated predecessor closure.
- Test and benchmark results: the [completion evidence packet](../../docs/evidence/OGVCS-004/README.md#local-and-hosted-gates) binds 63 pure and fifteen native rows per host, 54 runtime/package tests, exact offline archive identities, dependent authority checks, and the retained comparison.
- Security/reliability review: the [independent final review](../../docs/reviews/OGVCS-004-critical-review.md#final-verdict) records every discovered gap, remediation, accepted private-root/portable-watcher boundary, full requirement matrix, and no-live-P0/P1/P2 verdict.
- Documentation/runbooks: [ADR-0012](../../adr/0012-path-and-workspace-filesystem-contract-v1.md) and the [completion evidence boundary](../../docs/evidence/OGVCS-004/README.md#completed-evidence-boundary) document immutable profiles, safety, recovery, watcher reconciliation, platform capability, compatibility, and rollback behavior.
- Rollout result: implementation [run 32831999325](https://github.com/n3r/OpenGameVCS/actions/runs/32831999325) passed the three-host package boundary, and evidence-policy [run 32833243994](https://github.com/n3r/OpenGameVCS/actions/runs/32833243994) passed independent durable-evidence validation.
- OGVCS-004-AC-01: the [retained cross-host comparison](../../docs/evidence/OGVCS-004/conformance-comparison-2026-08-25.json) proves identical canonical path/collision outcomes and normalized package identities on Linux, macOS, and Windows.
- OGVCS-004-AC-02: the [retained syscall trace and audit](../../docs/evidence/OGVCS-004/README.md#durable-reports) prove symlink-ancestor, target-race, and ancestor-race confinement with zero outside-root references; the Windows report carries the native junction result.
- OGVCS-004-AC-03: the [requirement matrix](../../docs/reviews/OGVCS-004-critical-review.md#requirement-and-acceptance-matrix) binds exact case/NFC before/after tree and logical-bundle identities, preserved `FileID`, and reject-before-encode decomposed spelling.
- OGVCS-004-AC-04: the [acceptance evidence](../../docs/evidence/OGVCS-004/README.md#acceptance-map) covers overflow, gaps, unsupported resume, corrupt/unclean state, subscribe-before-reconcile ordering, and queued notifications without false clean.
- OGVCS-004-AC-05: the [acceptance evidence](../../docs/evidence/OGVCS-004/README.md#acceptance-map) proves actual Unreal/Unity materialization through one bound plan, exact cross-host inventory digests, and the stable 257-segment depth-limit failure.
