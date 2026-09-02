# OGVCS-015 — Branches, history, diff, merge, and revert

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-006, OGVCS-010, OGVCS-011, OGVCS-014  
**Blocks:** OGVCS-020, OGVCS-022, OGVCS-024, OGVCS-025, OGVCS-029, OGVCS-031, OGVCS-034  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-09-02

## Outcome

Programmers can create cheap branches, inspect authorized snapshot/FileID history, compute diffs, merge text through pluggable drivers, preserve explicit conflicts, and revert by creating new history without mutating published snapshots.

## Problem

A lock-first asset VCS still needs modern source-code workflows. Branch and merge semantics must be deterministic around moves, copies, deletes, sidecars, binary policy, sparse workspaces, and hidden paths.

## Scope

### In scope

- Branch create/delete/rename/protect primitives over snapshot pointers.
- Ancestor/merge-base, tree/FileID history, path diff, text three-way merge, driver interface, conflict records, merge submit, and revert-as-change.
- Content-policy selection for text/structured/binary and sparse-workspace preflight.

### Out of scope

- Code review/shelves, retained lock domains, semantic Unity configuration, Git mirroring, or history rewriting/force push.

## Users and journeys

- **Programmer:** branches from main, checkpoints locally, merges updated main, resolves text conflicts, and submits a two-parent snapshot.
- **Artist:** views an asset's rename-aware history and restores an earlier revision as a new change.
- **Administrator:** protects a release branch from direct submits through policy, not mutable history rewriting.

## Requirements

### Functional

- **OGVCS-015-FR-01:** Branch create SHALL be an O(1)-style metadata reference to an authorized snapshot; delete SHALL remove the reference, not immutable history still reachable elsewhere.
- **OGVCS-015-FR-02:** Merge-base and ancestry SHALL be deterministic for DAG histories and bounded against malicious depth/fanout.
- **OGVCS-015-FR-03:** Diff SHALL report ordered add/delete/modify/move/copy/mode/type/policy changes using stable FileID and authorized views.
- **OGVCS-015-FR-04:** Text merge SHALL use a versioned three-way algorithm; external drivers SHALL receive bounded declared inputs and return clean/conflict/error plus deterministic output digest.
- **OGVCS-015-FR-05:** Binary/default-nonmergeable policy SHALL never synthesize a merged file; it SHALL require identical change, choose-one with explicit user action, or a registered semantic driver.
- **OGVCS-015-FR-06:** Unresolved conflicts SHALL be durable local records that prevent submit for affected paths and survive restart/checkpoint.
- **OGVCS-015-FR-07:** Merge submit SHALL create a snapshot with all declared parents through OGVCS-010 and revalidate authorization/policy.
- **OGVCS-015-FR-08:** Revert SHALL generate inverse operations against a chosen snapshot/change and submit a new snapshot; published objects/references SHALL not be rewritten silently.
- **OGVCS-015-FR-09:** Sparse workspaces SHALL preflight required base/ours/theirs metadata/content and fetch or explicitly block rather than produce partial merge results.

### Quality attributes

- **OGVCS-015-NFR-01:** Repeating a merge with identical objects, algorithm/driver version, and options MUST produce identical result/conflicts.
- **OGVCS-015-NFR-02:** Merge drivers MUST run under the OGVCS-003 sandbox contract when repository supplied or untrusted.
- **OGVCS-015-NFR-03:** Authorized history views MUST not leak hidden path existence, counts, messages, or parents beyond OGVCS-003 rules.

## Interfaces and data

Define branch operations, ancestry/merge-base, diff entry, merge plan, driver manifest, conflict record, resolution, merge/revert submit requests, and protected-branch policy hooks. OGVCS-024 consumes branch ancestry; OGVCS-025 consumes diff.

## Development plan

1. Implement branch/ref CRUD/protection, ancestry and merge-base APIs over the immutable DAG with limits and authorized views.
2. Implement FileID-aware history and ordered diff for adds/deletes/edits/moves/copies/modes/types with sparse preflight.
3. Implement the versioned built-in text merge, external-driver contract/sandbox handoff, durable conflict records, and resolution workflow.
4. Implement merge/revert submission, protected-branch hooks, golden DAG/conflict and determinism tests, then roll out branch/history before merge mutations.

## Acceptance criteria

- **OGVCS-015-AC-01:** Golden DAGs return expected ancestry/merge bases across criss-cross and deep histories within limits.
- **OGVCS-015-AC-02:** Move/edit, rename/rename, delete/modify, sidecar, case-only rename, and binary conflicts match normative vectors.
- **OGVCS-015-AC-03:** Restart preserves unresolved conflicts and submit cannot omit them.
- **OGVCS-015-AC-04:** Revert reconstructs expected bytes/identity as a new snapshot without deleting original history.
- **OGVCS-015-AC-05:** Determinism and sandbox tests pass for built-in text and fake external drivers.

## Verification plan

DAG/diff/merge property tests, conflict golden corpus, driver sandbox/failure tests, sparse/authorization tests, restart tests, and large-tree/deep-history benchmarks.

## Telemetry and operations

Expose branch operation, ancestry work/limits, diff counts, merge result/conflict classes, driver version/duration/failure, revert, and submit correlation. Hidden paths and content are excluded.

## Rollout and rollback

Start with built-in text and explicit binary choose-one; external drivers disabled by default. Algorithm/driver versions are recorded. Rollback retains read/display support and blocks new merges with unsupported versions.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Stable FileID makes merge cases novel | Normative corpus and property tests before general use |
| External driver compromises client | Sandboxing, allowlist, signatures, resource limits |
| Sparse merge omits hidden/absent change | Server-assisted authorized preflight and explicit fetch/block |

## Completion evidence

- Implementation changes: a private, unpublished Rust 1.82 history/diff kernel
  candidate now provides generation-pinned, cursor-resumable Snapshot-parent
  traversal and fully prevalidated two-Snapshot root-Tree diffing. It reuses
  OGVCS-002 canonical object validation and OGVCS-004 path/collision validation,
  rejects duplicate identity/path/shared-Tree ambiguity, and exposes only
  deterministic metadata records and same-FileID rename/move hints. It is not
  wired to a branch service, CLI, checkpoint, submit path, or public protocol.
  A second private additive tranche provides the candidate-local
  `ogvcs.text-merge/line-diff3@1` pure built-in merge. It verifies exact
  base/ours/theirs digests, admits only a bounded UTF-8/TAB/LF text profile,
  preserves final-newline bytes, uses deterministic bounded LCS/diff3, and
  returns sealed clean output or bounded conflict span/digest commitments.
  External drivers, binary policy, durable conflicts, workspace writes, and
  branch merge orchestration remain absent.
- Test and benchmark results: the candidate carries unit, independent JSON
  golden, adversarial/table, deterministic generated-property, pagination,
  fresh-instance restart, cursor mutation, generation/cancellation, corruption,
  collision, shared-subtree, and configured-resource tests. Rust 1.82 passes
  52/52 tests in debug, 52/52 in release, and 52/52 from a 20-file packed
  fresh-consumer extraction; format and warnings-denied Clippy are clean. The
  Node boundary policy passes 2/2 and roadmap validation passes 8/8. No deep-DAG,
  million-entry, latency, branch-merge workflow, or release-scale result is
  claimed here.
  The text tranche adds independent JSON clean/conflict golden commitments,
  shortcut/overlap/insertion/adjacency/delete-modify/final-newline/Unicode
  cases, max/next-value and hostile text/digest rejection, deterministic replay,
  and cancellation fences across every phase. These combined and packed counts
  are evidence for this private candidate only, not AC closure.
- Security/reliability review: the private
  [history/diff boundary review](../../docs/reviews/OGVCS-015-history-diff-kernel-boundary-review.md)
  records generation fencing, fail-closed ambiguity/corruption, cursor and
  accounting boundaries, the OGVCS-002 production-profile gap, and all
  residuals. The source is a caller-preauthorized-view precondition and never
  an authorization brand; mixed-visibility history non-disclosure remains
  unimplemented.
  The separate
  [private text-merge review](../../docs/reviews/OGVCS-015-private-text-merge-kernel-review.md)
  records the candidate-local algorithm, literal input/LCS/work/memory limits,
  exact conflict disclosure, allocation preflight, cancellation, and remaining
  policy/driver/durability blockers.
- Documentation/runbooks: the crate README documents canonical validation,
  DFS and full-diff semantics, exact conservative charge vocabulary, cursor
  integrity (not authority), package gates, and explicit nonclaims. The
  candidate performs no operational mutation and has no rollback runbook.
- Rollout result: none. No network route, server handler, branch mutation,
  public cursor, branch merge/revert workflow, workspace write,
  authorization/grant/audit, external driver, or production reader exists.
  No OGVCS-015 acceptance criterion is closed and the PRD remains Todo.
