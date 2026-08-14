# OGVCS-038 — Public integration SDK and local-agent ecosystem

**Status:** Todo  
**Release:** R4 — Ecosystem  
**Priority:** P1  
**Owner:** Unassigned  
**Depends on:** OGVCS-022, OGVCS-030, OGVCS-036, OGVCS-042  
**Blocks:** OGVCS-039, OGVCS-040  
**Source:** [Architecture ADR-0006](../../adr/0006-local-agent-security-boundary.md)  
**Last updated:** 2026-08-14

## Outcome

Third-party engine, DCC, shell, and studio-tool developers can build against the established OGVCS-042 local-agent contract through stable high-level SDKs, a deterministic simulator, examples, and public conformance evidence without embedding storage logic, long-lived credentials, or private client internals.

## Problem

The first-party local agent must exist before engine integrations, but a first-party IPC is not by itself a supported ecosystem. Third parties need stable language packages, simulator scenarios, extension governance, compatibility guarantees, and precise security claims without reopening or privately forking the proven local protocol.

## Scope

### In scope

- Public stabilization/extension of the OGVCS-042 local IPC profile, SDKs for at least two broadly usable languages, generated schema bindings, command-line test client, integration simulator, examples, docs, and conformance profile.
- Read/status/history, sync/materialize, start-edit/lock, checkpoint, revert, shelf/review handoff, submit handoff, notifications, file-browser/shell status, and diagnostics explanations.
- Per-integration registration, consent, capability grants, quotas, revocation, and secure desktop handoff.

### Out of scope

- Reimplementing the minimal first-party local agent, claiming isolation from malware with the same OS-user privileges, direct object-store credentials, arbitrary plugin code inside the agent, public remote plugin hosting, UI framework, or compatibility promises for undocumented internal APIs.

## Users and journeys

- **DCC developer:** asks the agent to start editing an asset group and receives a typed pending/granted/denied/unknown result without handling tokens or lock leases.
- **Studio tools engineer:** subscribes to bounded workspace events, opens desktop review/submit flows, and tests against a deterministic simulator in CI.
- **User/admin:** sees which integrations are registered and can revoke or narrow capabilities without changing repository data.

## Requirements

### Functional

- **OGVCS-038-FR-01:** Publish a versioned, language-neutral SDK and conformance profile over OGVCS-042 with capability negotiation, stable high-level operations, typed errors, cancellation, deadlines, progress, idempotency, pagination, extension rules, and compatibility policy under OGVCS-036.
- **OGVCS-038-FR-02:** Public SDKs and extensions SHALL preserve OGVCS-042 endpoint isolation, authenticated handshake, key rotation, replay, loopback, scope, consent, and restart semantics and SHALL fail conformance if a platform cannot provide a required control.
- **OGVCS-038-FR-03:** Integrations SHALL register an immutable identity (publisher/name/version/digest/origin) and request named capabilities; first use and material scope increases SHALL require user/admin consent and remain reviewable/revocable.
- **OGVCS-038-FR-04:** The agent SHALL retain server credentials and issue only operation-scoped results/capabilities; plugins SHALL never receive reusable access/refresh tokens or raw object-store credentials.
- **OGVCS-038-FR-05:** Mutations SHALL bind an explicit workspace/repository/path set, displayable integration identity, base/current state, idempotency key, and user confirmation policy; a plugin cannot silently broaden a path/group request.
- **OGVCS-038-FR-06:** Start-edit SHALL return the authoritative lock/intent state and maintain renewal through the agent; disconnect SHALL follow declared grace/loss behavior and never let the integration claim offline exclusivity.
- **OGVCS-038-FR-07:** Event subscriptions SHALL be scoped, bounded, resumable from a local cursor, coalesced where documented, and backpressure-safe; protected paths and other users' data SHALL follow OGVCS-009.
- **OGVCS-038-FR-08:** Submit/review SHALL default to a secure desktop handoff showing exact changes/policy rather than granting arbitrary silent submit; headless integrations require a separately approved service capability.
- **OGVCS-038-FR-09:** SDKs SHALL expose only documented schemas, use semantic/versioned release rules, carry generated compatibility tests, and offer migration/deprecation guidance for every breaking change.
- **OGVCS-038-FR-10:** The simulator SHALL model success, auth expiry, lock contention/loss, offline state, partial sync, conflicts, rate limits, incompatible versions, cancellation, and server errors deterministically without a real repository.
- **OGVCS-038-FR-11:** Per-integration rate/concurrency/event/output limits, audit records, safe diagnostics, and emergency disable SHALL protect agent and workspace availability.

### Quality attributes

- **OGVCS-038-NFR-01:** Another-OS-user, remote, unregistered, replay, stale-capability, and scope-escalation attacks MUST fail; documentation and tests MUST explicitly state that fully compromised same-user malware may act with that user's authority and is not defeated by IPC identity alone.
- **OGVCS-038-NFR-02:** Agent restart/upgrade MUST preserve or accurately reconstruct workspace jobs/lock state and return typed unknown/recovery states for in-flight calls.
- **OGVCS-038-NFR-03:** SDK conformance examples MUST run offline in CI and produce identical simulator results across supported SDK languages.

## Interfaces and data

Deliver public OGVCS-042 schema/profile packages, approved extension records, integration manifest/identity, consent/capability SDKs, operation/job/progress/result and event bindings, desktop handoff helpers, simulator scenario format, SDK compatibility manifest, examples, and conformance evidence.

## Development plan

1. Stabilize and publish the OGVCS-042 schemas/profile, extension process and generated core bindings; build a public test client against the existing agent.
2. Generate/package at least two high-level SDKs for capability-scoped status/sync/start-edit/checkpoint/revert/events and trusted desktop handoffs without exposing credentials.
3. Implement deterministic simulator scenarios, examples, migration guidance, extension compatibility, rate/resource diagnostics and conformance adapters.
4. Complete independent-developer, local-threat-boundary and version-skew conformance; publish read surfaces before mutation helpers and gate every package on the supported matrix.

## Acceptance criteria

- **OGVCS-038-AC-01:** An external developer builds a working start-edit/status/sync/review-handoff integration from public docs/SDK/simulator without private API guidance.
- **OGVCS-038-AC-02:** Cross-language SDKs pass the same conformance scenarios and negotiate supported/unsupported agent versions exactly as specified.
- **OGVCS-038-AC-03:** Local adversarial tests reject remote/other-user access, unregistered clients, replay, stale capabilities, capability escalation, oversized messages, event flood, and path-scope escape; the report separately demonstrates consent/confirmation limits for same-user compromise without claiming impossible process identity.
- **OGVCS-038-AC-04:** Agent/plugin crash, restart, upgrade, cancellation, network loss, and lock expiry leave server/workspace state accurate and recoverable through desktop/CLI.
- **OGVCS-038-AC-05:** Revoking an integration immediately blocks new mutations/subscriptions and removes reusable local capabilities without revoking unrelated apps or losing work.

## Verification plan

Protocol/schema conformance, multi-language golden simulator, OS IPC security/red-team tests, capability/path authorization property tests, fuzz/resource limits, lifecycle/fault injection, version-skew matrix, desktop handoff UX/accessibility, and independent developer usability exercise.

## Telemetry and operations

Expose local integration identity/version, granted capability names, operation type/result/duration, queue/rate limits, agent compatibility, and safe security failures. User paths/content/tokens are excluded; detailed local audit is user/admin readable.

## Rollout and rollback

Dogfood with first-party integrations, publish read/status/events, then start-edit/sync, then controlled mutation handoffs. Deprecate private surfaces after public equivalents prove parity. Agent/SDK rollback stays within OGVCS-036/030 compatibility windows and retains consent records.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Local IPC becomes credential exfiltration path | Agent-held credentials, peer auth, scoped capabilities, red-team suite |
| Plugins bypass human intent | Explicit path/verb grants and desktop confirmation for risky mutations |
| SDK freezes internal architecture | High-level stable contracts, independent versioning, conformance profiles |
| Event-heavy plugin degrades client | Backpressure, quotas, coalescing, emergency disable |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
