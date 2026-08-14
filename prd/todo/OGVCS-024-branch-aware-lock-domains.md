# OGVCS-024 — Branch-aware integration domains and retained locks

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-015, OGVCS-016  
**Blocks:** None  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Studios can choose an explicit branch-aware lock policy that protects non-mergeable work through integration without turning every unrelated branch into a global bottleneck.

## Problem

A branch-local lock allows two branches to edit the same binary and discover the conflict only at integration. A repository-global lock avoids that conflict but destroys branch independence. Teams need deterministic conflict domains and optional retained ownership tied to an integration target, with understandable release and override rules.

## Scope

### In scope

- Versioned lock-domain policies: branch-local, repository-global, and integration-target domain.
- Retain-on-submit locks, integration completion/release, ancestry/base validation, queued handoff, policy transition, and deadlock avoidance.
- CLI/API visibility and server-side enforcement integrated with OGVCS-015/016.

### Out of scope

- Offline exclusivity, automated binary merge, distributed multi-master lock authorities, or workflow-specific GUI beyond shared status/action surfaces.

## Users and journeys

- **Artist on a release branch:** locks an asset in the release integration domain, submits intermediate work, and retains ownership until it is integrated or explicitly handed off.
- **Feature-team lead:** chooses branch-local locking for isolated experiments and sees the future integration conflict before work begins.
- **Administrator:** transitions a branch policy after a dry run that identifies conflicting active locks.

## Requirements

### Functional

- **OGVCS-024-FR-01:** A repository/branch policy SHALL select a versioned deterministic domain function from branch identity, configured integration target, ancestry, target FileID/group, and policy generation.
- **OGVCS-024-FR-02:** For identical authorized graph/policy inputs, all clients and servers SHALL compute or receive the same opaque domain ID; hidden branch/path data SHALL not be disclosed.
- **OGVCS-024-FR-03:** Acquisition and submit SHALL validate both lock generation and domain-policy generation atomically; stale clients SHALL refresh rather than fall back to a weaker domain.
- **OGVCS-024-FR-04:** Retain-on-submit SHALL keep ownership after an intermediate snapshot and record the submitted snapshot, intended integration target, lease, and release condition.
- **OGVCS-024-FR-05:** Integration completion SHALL release or transfer a retained lock only when the server verifies the declared source snapshot is an ancestor of the accepted integration snapshot and policy conditions hold.
- **OGVCS-024-FR-06:** Divergence, rebase, revert, branch deletion, target retargeting, lease expiry, and failed integration SHALL have explicit state transitions; none SHALL silently release a still-protected target.
- **OGVCS-024-FR-07:** Queue/handoff ordering SHALL be deterministic and starvation-bounded within policy, but notification SHALL not imply ownership until a new generation is granted.
- **OGVCS-024-FR-08:** Multi-target acquisition SHALL use canonical ordering or transactional all-or-none semantics to avoid deadlock and partial asset-group ownership.
- **OGVCS-024-FR-09:** Policy changes SHALL offer a read-only impact preview, reject unresolved domain collisions by default, and create an audited migration generation.
- **OGVCS-024-FR-10:** Authorized status SHALL explain branch/domain/retention/release state and next action in user terms; unauthorized queries SHALL remain non-disclosing.

### Quality attributes

- **OGVCS-024-NFR-01:** No graph, policy-transition, or request-order test may result in two successful submits that violate the selected domain invariant.
- **OGVCS-024-NFR-02:** Domain calculation and conflict lookup MUST be bounded against adversarial branch DAGs and group sizes.
- **OGVCS-024-NFR-03:** All policy and lock state transitions MUST be replayable from durable records for audit and repair.

## Interfaces and data

Define `LockDomainPolicy`, opaque domain ID, integration target, retained-lock state machine, release proof, queue/handoff record, policy impact report, and migration generation. Extend OGVCS-015 merge submit and OGVCS-016 validation explicitly rather than adding a parallel lock store.

## Development plan

1. Implement versioned branch-local/global/integration-target domain policies, deterministic opaque domain calculation, generations, and impact-preview tooling.
2. Implement retained-lock persistence/state transitions, queue/handoff, multi-target atomic/canonical acquisition, expiry and audited break behavior.
3. Integrate ancestry/base/integration proofs into branch merge and lock/submit validation, including rebase/revert/delete/retarget cases.
4. Complete model/concurrency/deadlock/non-disclosure and policy-migration tests, add operator diagnostics, and enable integration domains per repository after preview.

## Acceptance criteria

- **OGVCS-024-AC-01:** Normative branch DAGs demonstrate expected concurrency/conflict for branch-local, global, and integration-target policies, including nested release branches.
- **OGVCS-024-AC-02:** Retained locks survive intermediate submit/restart and release only on valid integration, explicit owner release/handoff, expiry policy, or audited break.
- **OGVCS-024-AC-03:** Rebase, revert, delete, retarget, stale policy, conflicting migration, and integration-race cases fail or transition exactly as documented.
- **OGVCS-024-AC-04:** Concurrent multi-target acquisitions complete without deadlock or partial grants and meet the declared starvation bound.
- **OGVCS-024-AC-05:** Authorization tests reveal no hidden branch/domain/target existence through calculation, queue position, errors, timing class, or notifications.

## Verification plan

State-machine/model checking, generated branch DAGs, concurrency and deadlock stress, policy migration fault injection, retained-lock integration tests, non-disclosure probes, and design-partner workflow simulations.

## Telemetry and operations

Expose contention and wait by opaque domain/policy, retained duration, integration release outcomes, handoffs, breaks, policy collision counts, and stale-generation rejects. Provide an admin-only domain diagnostic with audited sensitive detail.

## Rollout and rollback

Default remains the simpler OGVCS-016 branch-local/global policy. Enable integration domains per repository after impact preview. Rollback requires resolving retained locks and records a new policy generation; it never silently weakens active protection.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Domain policy is too complex for users | Small named modes, previews, plain-language status, partner validation |
| Retained locks become indefinitely abandoned | Leases, owner reminders, queues, escalation policy, audited breaks |
| Policy migration creates dual owners | Generation fence and collision-blocking impact phase |
| Multi-asset groups deadlock | Canonical order or atomic all-or-none acquisition |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
