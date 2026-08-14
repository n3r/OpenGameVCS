# OGVCS-XXX — PRD title

**Status:** Todo  
**Release:** R? — release name  
**Priority:** P0 / P1 / P2  
**Owner:** Unassigned  
**Depends on:** OGVCS-___ or None  
**Blocks:** OGVCS-___ or None  
**Source:** [OpenGameVCS proposal](../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** YYYY-MM-DD

## Outcome

One paragraph describing the independently observable result, not the implementation activity.

## Problem

Who is blocked today, under what conditions, and why existing behavior is insufficient.

## Scope

### In scope

- Bounded behaviors delivered by this PRD.

### Out of scope

- Related work intentionally owned by another PRD.

## Users and journeys

- **Persona:** trigger → actions → observable successful outcome.

## Requirements

### Functional

- **OGVCS-XXX-FR-01:** Testable behavior using MUST/SHALL language.

### Quality attributes

- **OGVCS-XXX-NFR-01:** Performance, availability, durability, security, privacy, accessibility, or compatibility bound.

## Interfaces and data

Name persisted entities, APIs/events/commands, versioning rules, consumers, and invariants. A dependent PRD must be able to build against this contract.

## Development plan

List the ordered, independently reviewable implementation slices that build the artifact. Include the contract/schema slice, core behavior, integration/hardening, and release/rollout work as applicable. External research, recruiting, legal, or governance activity cannot be an implementation slice.

## Acceptance criteria

- **OGVCS-XXX-AC-01:** Given/when/then or another objective pass condition.

## Verification plan

- Unit and property tests.
- Contract and integration tests.
- Fault, security, compatibility, and performance tests as relevant.

## Telemetry and operations

Metrics, structured events, logs/traces, dashboards, alerts, runbooks, capacity signals, and privacy restrictions.

## Rollout and rollback

Feature flag/default state, migration order, compatibility window, canary, rollback, and data downgrade/recovery behavior.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Concrete failure or delivery risk | Preventive or recovery action |

## Completion evidence

Fill this section before moving the file to `prd/done`:

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:

Add one top-level evidence line for every acceptance criterion; each general evidence line and criterion line must contain at least one durable Markdown link before the PRD can move to `done`:

- OGVCS-XXX-AC-01:
