# OGVCS-025 — Shelves and review service

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-009, OGVCS-010, OGVCS-013, OGVCS-015, OGVCS-016, OGVCS-018, OGVCS-019  
**Blocks:** OGVCS-026, OGVCS-028, OGVCS-033, OGVCS-034, OGVCS-035, OGVCS-044  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Users can upload work without advancing a branch, request review on immutable revisions, discuss and approve the exact bytes under review, run required checks, and promote only a still-valid revision through the normal atomic-submit path.

## Problem

Review must not be a mutable set of files whose content changes after approval. It also must respect path authorization, sparse workspaces, lock policy, and branch movement. Shelves provide a durable handoff and recovery primitive, but they must not become an alternate unverified object namespace.

## Scope

### In scope

- Private/shared shelves with immutable revisions, metadata/content verification, ownership, retention, update, download/apply, and deletion.
- Review lifecycle, reviewers, comments, approvals, required checks, change summaries, events, and promotion/submit.
- CLI/API and desktop-consumable contracts.

### Out of scope

- Asset renderer/converter execution, authorization-safe full-text search, Git pull requests, project management, or arbitrary workflow scripting.

## Users and journeys

- **Contributor:** shelves selected local changes, asks for review, updates with a new immutable revision, and submits the approved revision.
- **Reviewer:** sees only authorized changes, comments on a precise file/revision/location, approves, and knows when that approval becomes stale.
- **Build service:** consumes the shelf snapshot, posts a check tied to exact inputs, and receives replay-safe events.

## Requirements

### Functional

- **OGVCS-025-FR-01:** A shelf revision SHALL be an immutable verified manifest of base snapshot, selected operations/FileIDs, content identities, author, policy version, and timestamp; updates create a new revision.
- **OGVCS-025-FR-02:** Shelf creation SHALL use resumable verified content upload and SHALL become visible only after all referenced content and metadata are durable.
- **OGVCS-025-FR-03:** Visibility SHALL be private by default and shareable only to authorized users/groups; list, counts, events, comments, and errors SHALL obey path/repository non-disclosure.
- **OGVCS-025-FR-04:** Applying a shelf SHALL preflight local changes, selection/materialization, base divergence, path policy, and conflicts, and SHALL preserve recoverable local work.
- **OGVCS-025-FR-05:** A review SHALL identify one exact shelf revision and target branch; a newer revision SHALL invalidate content-dependent approvals and checks under a versioned policy.
- **OGVCS-025-FR-06:** Comments SHALL bind to review revision and stable FileID/change location, preserve edit/delete audit history, and remain intelligible across authorized renames.
- **OGVCS-025-FR-07:** Required reviewers/checks and branch policy SHALL be evaluated server-side at promotion time; actor identity, result, revision, and policy generation SHALL be immutable.
- **OGVCS-025-FR-08:** Promotion SHALL revalidate target head, authorization, locks/domains, content, approvals, and checks through OGVCS-010 and either publish exactly one snapshot or return a rebase/conflict plan.
- **OGVCS-025-FR-09:** Lock disposition for shelving and promotion SHALL be explicit; shelving alone SHALL not implicitly release a hard/retained lock.
- **OGVCS-025-FR-10:** Review and shelf lifecycle events SHALL use OGVCS-019 envelopes/cursors and SHALL be idempotent for automation consumers.
- **OGVCS-025-FR-11:** Retention/deletion SHALL honor review state, legal holds, branch policy, and content reachability and SHALL produce an audit record.
- **OGVCS-025-FR-12:** Shelf/review create, revision update, pin/hold, promotion, expiry, and deletion SHALL update OGVCS-018 reachability roots transactionally so GC cannot quarantine or delete content referenced by a retained review revision.

### Quality attributes

- **OGVCS-025-NFR-01:** Approval/check meaning MUST be reproducible solely from immutable revision, policy generation, identities, and recorded results.
- **OGVCS-025-NFR-02:** Large shelves/reviews MUST paginate metadata and stream content without loading all changed paths or bytes into one process/UI response.
- **OGVCS-025-NFR-03:** A crash or retry at shelf publish or promotion MUST never expose missing content or create duplicate snapshots/reviews.

## Interfaces and data

Define shelf, immutable shelf revision, review, reviewer assignment, comment/thread, approval, check definition/result, staleness reason, promotion plan/result, OGVCS-018 reachability/pin transitions, and lifecycle events. OGVCS-026 attaches derived artifacts; OGVCS-035 supplies scaled indexing.

## Development plan

1. Implement verified immutable shelf revisions, private sharing/retention, resumable upload, OGVCS-018 reachability/pins, list/fetch/apply APIs, and desktop/CLI contracts.
2. Implement reviews, exact-revision comments, reviewer assignments, approvals, required checks, staleness policies, and lifecycle events.
3. Implement authorized promotion planning and OGVCS-010 finalize integration with target-head/lock/policy/check revalidation and conflict/rebase results.
4. Complete publish/promote fault races, non-disclosure, sparse/apply and large-review tests, then roll out private shelves → shared reviews → enforced promotion.

## Acceptance criteria

- **OGVCS-025-AC-01:** Creating/updating a shelf under upload and metadata fault injection exposes only complete verified revisions and resumes without duplicate content/history.
- **OGVCS-025-AC-02:** Any byte/operation/base/target/policy change invalidates exactly the approvals/checks prescribed by the versioned policy.
- **OGVCS-025-AC-03:** Promotion racing branch advance, lock loss, permission removal, or second promotion yields at most one valid target snapshot and an actionable loser result.
- **OGVCS-025-AC-04:** An unauthorized user cannot infer shelf/review/path/comment/check existence through lists, direct IDs, events, counts, errors, or timing class.
- **OGVCS-025-AC-05:** Apply to clean, sparse, dirty, diverged, and case-colliding workspaces matches golden results without unconfirmed local data loss.
- **OGVCS-025-AC-06:** Shelf/review update, expiry, legal hold, promotion, deletion and concurrent GC races retain every required revision object and reclaim only after the final root/pin is removed under OGVCS-018 rules.

## Verification plan

Immutable-revision tests, upload/publish/promote fault matrix, concurrency races, approval policy tables, authorization enumeration suite, sparse/apply corpus, event replay tests, retention/legal-hold tests, and large-review benchmarks.

## Telemetry and operations

Expose shelf bytes/revisions/age, review cycle time, approval/check staleness reasons, promotion conflict/failure class, event lag, and retained content. Shared metrics contain no path, comment, message, or identity data.

## Rollout and rollback

Begin with private shelves, then shared shelves, then review/approval, then promotion enforcement per branch. Rollback disables new promotions/features while retaining read/export/apply access to existing shelf revisions.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Review approval applies to changed bytes | Immutable revisions and policy-driven invalidation |
| Shelf namespace bypasses durability | Same upload, verification, reachability, and retention contracts |
| Promotion bypasses locks/branch checks | Single OGVCS-010 path with complete revalidation |
| Review metadata leaks protected work | Authorization filtering across every surface and event |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
