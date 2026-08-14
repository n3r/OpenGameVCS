# OGVCS-044 — Desktop shelves and review workflow

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-022, OGVCS-025  
**Blocks:** OGVCS-030  
**Source:** [OpenGameVCS delivery roadmap](../ROADMAP.md)  
**Last updated:** 2026-08-14

## Outcome

Artists and reviewers can create or apply a shelf, request review, inspect the exact immutable revision, comment, approve, observe required checks, update stale work, and promote or submit through the desktop client without using a terminal.

## Problem

The desktop foundation explicitly excludes reviews while the review service exposes only desktop-consumable contracts. Without an owned UI increment, the roadmap can meet both PRDs and still fail its promise that artists complete review without CLI.

## Scope

### In scope

- Desktop shelf create/update/share/apply/delete flows with exact selection, upload, retention, and recovery state.
- Review inbox/detail, authorized change navigation, comments, reviewer assignment, approvals, check status/staleness, source/open-external handoff, and optional preview capability rendering.
- Promotion/submit planning, branch/lock/policy conflict recovery, notifications/deep links, accessibility, large-review virtualization, and offline-safe drafts.
- Artist usability evidence for the complete no-CLI review journey.

### Out of scope

- Review-service persistence/policy, converter implementation, full-text search backend, project-management workflow, or silent approval/promotion.
- Claiming that a derived preview replaces the canonical source or that unavailable review services work offline.

## Users and journeys

- **Artist:** shelves selected asset changes, requests review, responds to a comment with a new immutable revision, and promotes after approval.
- **Reviewer:** opens an inbox notification, sees only authorized changes and exact revision/check state, comments and approves without a terminal.
- **Lead:** resolves a stale approval or branch/lock conflict through an explicit update/review plan without losing the shelf.

## Requirements

### Functional

- **OGVCS-044-FR-01:** Shelf creation/update SHALL show exact selected paths/groups, base, bytes, upload/verification state, sharing scope, retention effect, and immutable resulting revision before reporting success.
- **OGVCS-044-FR-02:** Review lists, counts, notifications, facets, comments, checks, and direct links SHALL be built only from the caller's authorized view and handle revoked access without residual disclosure.
- **OGVCS-044-FR-03:** The UI SHALL bind every comment, approval, check, comparison, and promotion action to the displayed immutable revision and make staleness reasons prominent.
- **OGVCS-044-FR-04:** Large change lists SHALL paginate/virtualize with stable cancellation and selection; source download/open and capability-provided previews SHALL retain provenance and authorization state.
- **OGVCS-044-FR-05:** Applying a shelf SHALL preview workspace/materialization/conflict effects, offer a checkpoint for local work, and never overwrite unconfirmed bytes.
- **OGVCS-044-FR-06:** Promotion/submit SHALL display target head, approvals/checks, lock/policy state, exact changes and conflict/rebase plan and use the normal atomic submit path.
- **OGVCS-044-FR-07:** Network loss, auth expiry, new revision, branch advance, lock loss, check update, and client restart SHALL preserve local drafts and display authoritative unknown/stale state.
- **OGVCS-044-FR-08:** Keyboard, screen-reader, focus, scaling, contrast, reduced-motion, and non-color status support SHALL cover every P0 shelf/review action.
- **OGVCS-044-FR-09:** The workflow SHALL provide machine-readable UI state/test hooks and a redacted diagnostic timeline without comments, paths, content, or identity in shared telemetry.

### Quality attributes

- **OGVCS-044-NFR-01:** Representative artists MUST complete the full shelf/review/update/approval/promotion journey without CLI or moderator help at the agreed task-success threshold.
- **OGVCS-044-NFR-02:** A 100,000-change review MUST remain within declared memory/interaction budgets without loading every row or source byte.
- **OGVCS-044-NFR-03:** No crash, retry, stale UI, or duplicated gesture may create duplicate reviews, approve another revision, lose a shelf, or publish without final authoritative validation.

## Interfaces and data

Deliver desktop shelf/review application state, paged inbox/change models, comment draft, approval/check/staleness presentation, source/preview capability view, promotion plan/result, notification/deep-link state, accessibility labels, and redacted diagnostic timeline.

## Development plan

1. Implement shelf create/update/list/share/apply state and UI with exact selection/upload verification, workspace safeguards, pagination, and recovery.
2. Implement review inbox/detail, immutable-revision navigation, comments, assignments, approvals/checks/staleness, source and optional preview capability rendering.
3. Implement promotion/submit and conflict/rebase/lock/policy recovery, notifications/deep links, offline drafts, accessibility, and safe diagnostics.
4. Execute large-review, authorization, revision/branch/lock race, crash/network, accessibility and observed artist-usability suites; gate R2 on the no-CLI journey.

## Acceptance criteria

- **OGVCS-044-AC-01:** Representative artists create a shelf, request review, comment, update, approve, resolve staleness, and promote without CLI or moderator intervention.
- **OGVCS-044-AC-02:** Permission removal and mixed-visibility reviews disclose no protected path/revision/comment/check existence through UI state, counts, links, cache, errors, or diagnostics.
- **OGVCS-044-AC-03:** Revision, policy, branch, lock, and check races invalidate or block the exact UI action and preserve the shelf for recovery; no stale approval publishes.
- **OGVCS-044-AC-04:** Crash/network/auth-expiry injection at every mutation recovers accurate state without losing shelf content, comment drafts, or workspace bytes.
- **OGVCS-044-AC-05:** Accessibility and 100,000-change performance matrices pass on all supported desktop platforms.

## Verification plan

Desktop/service contract tests, end-to-end UI automation, authorization enumeration, revision/branch/lock/check races, crash/network restart matrix, large-list performance, accessibility audit, and observed artist task tests.

## Telemetry and operations

Expose local workflow phase/result/duration, safe staleness/conflict class, queue/refresh latency, and client/server versions. Shared telemetry excludes repository paths, comments, content, identities, review titles, and credentials.

## Rollout and rollback

Enable private shelves first, then shared review read/comment, approval, and promotion per repository. Rollback disables mutations while preserving service-side shelves/reviews and local comment drafts for a compatible client.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Friendly UI approves stale content | Exact immutable revision binding and prominent invalidation |
| Mixed visibility leaks through counts/navigation | Authorized view construction and enumeration tests |
| Review scope overwhelms artists | Progressive disclosure, virtualized lists, observed task testing |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:

