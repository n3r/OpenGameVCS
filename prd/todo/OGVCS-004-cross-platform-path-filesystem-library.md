# OGVCS-004 — Cross-platform path and workspace filesystem library

**Status:** Validation
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Codex and OpenGameVCS maintainers
**Depends on:** OGVCS-001, OGVCS-002
**Blocks:** OGVCS-005, OGVCS-006, OGVCS-007, OGVCS-011, OGVCS-012, OGVCS-033, OGVCS-037, OGVCS-041, OGVCS-042, OGVCS-045
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-16

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
- **OGVCS-004-AC-02:** Malicious symlink/junction/race fixtures cannot cause writes outside a temporary workspace under elevated filesystem tracing.
- **OGVCS-004-AC-03:** Case-only and Unicode-normalization renames round-trip through OGVCS-002 canonical tree and logical-bundle encoding with FileID preserved and the expected changed tree ID; fidelity export/reimport proof remains outside this PRD.
- **OGVCS-004-AC-04:** Watcher overflow and unclean-shutdown tests force reconciliation and never falsely report a clean workspace.
- **OGVCS-004-AC-05:** Unreal- and Unity-like long/deep path fixtures either materialize identically or fail preflight with stable actionable errors.

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

The MIT-licensed implementation and packed validation candidate are complete.
GitHub Actions run 31939458256 passed 72/72 rows on Linux, macOS, and Windows,
accepted exact cross-host package bytes and pure decisions, and retained a
Linux syscall trace with zero outside-workspace references. Per maintainer
direction, the OGVCS-002 one-million-tree and logical-1-TiB jobs are deferred
to the final R0 campaign and do not yet have a complete accepted two-language
comparison. Those are predecessor format gates rather than OGVCS-004
materializer tests. This PRD remains in Validation only until OGVCS-002 becomes
Done.

- Implementation changes: [Detailed candidate changelog](../../docs/changelog/OGVCS-004.md)
- Test and benchmark results: [Candidate evidence packet](../../docs/evidence/OGVCS-004/README.md)
- Security/reliability review: [Independent critical review](../../docs/reviews/OGVCS-004-critical-review.md)
- Documentation/runbooks: [ADR-0012 and its normative documentation index](../../adr/0012-path-and-workspace-filesystem-contract-v1.md)
- Rollout result: [Hosted proof and deferred dependency](../../docs/evidence/OGVCS-004/README.md#deferred-roadmap-completion)
