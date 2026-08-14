# OGVCS-012 — Workspace index and scalable status

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-004, OGVCS-005, OGVCS-011  
**Blocks:** OGVCS-013, OGVCS-014, OGVCS-016, OGVCS-022, OGVCS-037, OGVCS-042, OGVCS-043  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

`status` accurately reports local adds, edits, deletes, moves, type changes, conflicts, and materialization state on million-path workspaces without routinely scanning or hashing the full tree.

## Problem

Game workspaces can contain millions of paths. A full filesystem walk/hash on every status makes the client unusable, while trusting file notifications without gap recovery can silently omit changes.

## Scope

### In scope

- Durable local baseline/materialization index and workspace generation.
- OS change-journal/watch adapters with cursor persistence and gap detection.
- Fast metadata fingerprint followed by content hashing only when required.
- Versioned ignore rules, untracked discovery boundaries, move hints, and reconciliation.
- Status API/CLI result and recovery/repair.

### Out of scope

- Sync planning/execution, file upload, virtual placeholders, or semantic diff.

## Users and journeys

- **Contributor:** receives an accurate status in seconds after changing a small working set in a million-path workspace.
- **Client:** detects missed watcher events after sleep/crash and reconciles before reporting clean.
- **Support engineer:** explains why a path is dirty, ignored, unmaterialized, conflicted, or requires hash verification.

## Requirements

### Functional

- **OGVCS-012-FR-01:** The index SHALL record baseline snapshot/tree/FileID/manifest, materialization state, portable mode, local fingerprint, watcher cursor, and pending/conflict state without storing plaintext credentials.
- **OGVCS-012-FR-02:** Windows USN, macOS FSEvents, and Linux inotify adapters SHALL persist progress and emit a mandatory reconciliation condition on overflow, unsupported filesystem, cursor loss, or unclean shutdown.
- **OGVCS-012-FR-03:** Clean status SHALL never be reported while a required reconciliation is incomplete or a watched root cannot be trusted.
- **OGVCS-012-FR-04:** Candidate changes SHALL use safe metadata fingerprints and compute full manifest/hash before submit or when ambiguity exists; timestamps alone SHALL not establish content equality.
- **OGVCS-012-FR-05:** Status SHALL distinguish modified, added, deleted, moved/renamed hint, type/mode change, untracked, ignored, conflicted, metadata-only, absent-by-spec, and inaccessible/error.
- **OGVCS-012-FR-06:** Ignore rules SHALL be versioned repository policy plus workspace-local nonshareable rules, with deterministic precedence and an explain command.
- **OGVCS-012-FR-07:** Index transactions SHALL be crash-safe and tied to workspace generation so an interrupted sync cannot mix old baseline with new files.
- **OGVCS-012-FR-08:** Repair SHALL rebuild from an immutable baseline and filesystem without discarding local files; uncertain identity becomes an explicit status.

### Quality attributes

- **OGVCS-012-NFR-01:** Warm no-change status at one million tracked paths SHALL achieve p95 under 2 seconds on the reference workstation without full-tree walk/hash.
- **OGVCS-012-NFR-02:** Status with 1,000 journaled changes SHALL target p95 under 5 seconds after required reconciliation.
- **OGVCS-012-NFR-03:** Index corruption, watcher loss, or timestamp spoofing MUST not cause a changed file to be submitted as unchanged or a dirty workspace to be declared authoritatively clean.

## Interfaces and data

Publish local index schema/version, watcher adapter contract, status entry/reason, reconciliation state/progress, ignore evaluation, and repair API. OGVCS-013/014/016 consume transactional index updates.

## Development plan

1. Implement the versioned local index/journal schema, baseline import, atomic updates, integrity checks, and safe rebuild command.
2. Implement platform watcher adapters, cursor persistence, overflow/unclean-shutdown detection, event coalescing, and bounded reconciliation.
3. Implement status classification, lazy hashing, move/FileID inference, ignore/materialization/conflict states, paging, and CLI/JSON integration.
4. Run crash/corruption/adversarial and million-path performance suites, tune bounded memory/I/O, add diagnostics, and roll out watcher acceleration behind full-scan comparison.

## Acceptance criteria

- **OGVCS-012-AC-01:** Reference performance targets pass on all supported OS profiles or a documented platform exception blocks R1.
- **OGVCS-012-AC-02:** Every OGVCS-004 file operation and watcher fault produces correct status after recovery.
- **OGVCS-012-AC-03:** Crash at every index transaction point leaves prior generation valid or triggers repair; no false clean result occurs.
- **OGVCS-012-AC-04:** Timestamp-preserving edits, rename cycles, case-only rename, locked-open files, and ignored/untracked transitions are detected correctly.
- **OGVCS-012-AC-05:** Rebuilding a corrupt index preserves local content and yields the same status as a clean authoritative scan.

## Verification plan

Cross-OS watcher matrix, state-machine/property tests, timestamp/case adversarial fixtures, index corruption/crash injection, million-path benchmarks, and repair equivalence.

## Telemetry and operations

Expose status duration, candidates/hashed paths, journal events/gaps, reconciliation reason/duration, index size/generation, repair count, and filesystem capability. Path labels are excluded.

## Rollout and rollback

Begin with watcher plus mandatory verification mode; enable optimized paths after parity measurement. Index schema supports rebuild, so downgrade discards/rebuilds index rather than rewriting user files.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Watch APIs miss changes | Gap tracking, conservative reconciliation, hash before submit |
| Reconciliation still scans too much | Sparse materialization boundaries and directory summaries with correctness tests |
| Index DB becomes corrupt/hot | WAL/atomic generations, repair, bounded transactions, profiling |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
