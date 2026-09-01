# OGVCS-012 — Workspace index and scalable status

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-004, OGVCS-005, OGVCS-011  
**Blocks:** OGVCS-013, OGVCS-014, OGVCS-016, OGVCS-022, OGVCS-037, OGVCS-042, OGVCS-043  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-09-01

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

This section records an incomplete private candidate. It is not completion
evidence sufficient to move this PRD out of Todo.

- **Implementation changes:** the Rust local CLI has a bounded authenticated
  baseline sink, sealed create-new generations, fixed-width collision-safe
  lookup, strict hash-chained watcher journal, deterministic status paging,
  HMAC cursor, per-page authenticated/kernel-locked reader leases, a durable
  logical epoch, bounded physical generation compaction, ignore evaluation,
  recovery, verification, and non-destructive repair. Compaction preserves the
  current generation, its authenticated numeric predecessor, and every locked
  or unexpired reader generation; it deletes no workspace content. Its private
  candidate contract is
  `client/native-cli/rust/contracts/workspace-index/v1` version
  `0.1.0-rc.2`, while committed generation bytes remain readable as
  `0.1.0-rc.1`.
- **Test and benchmark results:** Rust 1.82 focused tests cover crash boundaries,
  a synced journal tail without state publication, concurrent transition/status
  races, active/settings/profile/case/cursor staleness, digest collisions,
  case collisions/order, symlink/reparse rejection, timestamp-preserving edits,
  same-length index corruption, deleted-directory uncertainty, transient
  untracked create/delete, and repair preserving workspace files. Retention
  tests cover the independent HMAC known answer and hostile variants,
  cross-workspace/repository leases, exact 127/128/129 lease admission,
  prepublication history capacity, locked-reader pinning, abandoned-reader
  expiry, current/predecessor retention, malformed/unknown controls before
  intent, deterministic mutation races, one-call paging leases, and idempotent
  recovery at epoch, lease, intent, unlink, directory-sync, state, and intent-
  removal boundaries. A local
  exact 1,000 changed-file candidate run classified and content-verified every
  item in 210 ms. A local exact 100,000-event run used 100 chunks of 1,000,
  completed in 11.619 s, rejected event 100,001 before append, verified the
  complete chain, and proved a new generation resets the bound. These are
  single-host candidate measurements, not p95 or three-OS evidence.
- **Security/reliability review:** status fails closed during an in-progress
  generation and performs an after-classification active/watcher snapshot
  check. Lookup digest hits never substitute a different full path. A portable
  or safe third-party watcher implementation cannot mint native continuity.
  Cursor MACs bind both repository and local ignore digests in addition to the
  exact generation/settings/filter/path key. A status lease is created,
  synced, authenticated, and shared-locked before releasing the mutation lock;
  compaction authenticates the complete bounded control/lease/generation
  namespace before publishing intent. Forged, malformed, cross-boundary, or
  overflowing metadata fails before deletion. Owner HMACs and kernel locks do
  not solve malicious same-authority lock-namespace replacement or promise
  Unix unlink-by-open-handle semantics.
- **Documentation/runbooks:** the Rust README and
  `docs/reviews/OGVCS-012-workspace-index-boundary-review.md` describe the
  runnable gates and exact residuals.
- **Rollout result:** none. The first-party CLI still installs unavailable
  public routes, and optimized status/compaction has not been enabled. Mixed
  old/new processes are unsupported for the private candidate; restart before
  compaction, and rebuild the private index before downgrade.

### Candidate residuals blocking completion

- No authenticated public workspace-baseline/status route or public CLI/JSON
  journey exists.
- No built-in Windows USN, macOS FSEvents, or Linux inotify authority can issue
  the private continuity proof; every production-callable implementation is
  degraded.
- The exact one-million-path warm p95 target, three-OS watcher matrix, complete
  OGVCS-004 operation/fault matrix, rename cycles, locked-open files, and repair
  parity against an independently authoritative scan remain unproven.
- Telemetry, support-facing explain/repair/compaction commands, rollout
  comparison, and downgrade behavior are not wired into a public product
  surface.
