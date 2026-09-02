# OGVCS-042 — Minimal local agent and first-party IPC

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-004, OGVCS-009, OGVCS-011, OGVCS-012, OGVCS-013, OGVCS-016, OGVCS-019, OGVCS-041  
**Blocks:** OGVCS-023, OGVCS-031, OGVCS-038  
**Source:** [Architecture ADR-0006](../../adr/0006-local-agent-security-boundary.md)  
**Last updated:** 2026-09-02

## Outcome

First-party engine and desktop integrations can use one authenticated local process for workspace status, sync, start-edit/lock coordination, bounded events, and secure UI handoff without embedding server credentials or inventing private IPC.

## Problem

Engine integrations arrive before the ecosystem SDK, but they still need a stable local boundary around workspace indexes, authentication, lock renewal, and background jobs. Without an early minimal agent, each plugin would implement a private credential-bearing protocol that must later be replaced.

## Scope

### In scope

- Versioned loopback/local-socket IPC, discovery, negotiation, endpoint permissions, authenticated handshake, replay resistance, and per-install key rotation.
- First-party registration and scoped consent for read status, sync/materialize, start-edit/lock, checkpoint/revert handoff, job progress, bounded workspace events, and trusted desktop deep links.
- Agent-owned server credentials, workspace/job coordination, restart reconciliation, quotas, diagnostics, and emergency disable.
- Minimal C++ and C# first-party bindings plus a deterministic test client.

### Out of scope

- Public third-party SDK stability, broad language packages, public simulator ecosystem, shell-extension marketplace, or remote plugin hosting.
- Claims that IPC can isolate malware already executing with the same OS-user privileges.
- Silent arbitrary submit, raw object-store credentials, or plugin code executed inside the agent.

## Users and journeys

- **Engine plugin:** asks to start editing an asset group and receives authoritative granted/denied/unknown state while the agent owns renewal.
- **Desktop client:** opens a signed local context for exact changes or recovery without accepting mutation parameters from an unauthenticated URL.
- **User:** reviews and revokes a first-party integration capability without deleting a workspace or server credential.

## Requirements

### Functional

- **OGVCS-042-FR-01:** The agent SHALL expose only OS-local endpoints with restrictive permissions, version negotiation, authenticated challenge/response, replay protection, bounded messages, deadlines, cancellation, and stable errors.
- **OGVCS-042-FR-02:** Server and object-store credentials SHALL remain in supported secure storage controlled by the agent; integrations receive only scoped operation results and short-lived local capabilities.
- **OGVCS-042-FR-03:** An integration manifest SHALL bind publisher/name/version/digest/origin and named capabilities; new or broadened mutation scope SHALL require explicit user/admin consent.
- **OGVCS-042-FR-04:** Every operation SHALL bind an integration, workspace, repository, bounded path/group set, base/current state, idempotency key, and confirmation policy.
- **OGVCS-042-FR-05:** Start-edit SHALL use authoritative lock/intent contracts, keep renewal in the agent, and return explicit granted/denied/lost/unknown states; disconnect never implies offline exclusivity.
- **OGVCS-042-FR-06:** Workspace status, sync jobs, progress, and bounded event subscriptions SHALL share the canonical local index and apply backpressure, cursor, rate, and concurrency limits.
- **OGVCS-042-FR-07:** Mutating submit/review/destructive flows SHALL use a signed, single-use trusted-client handoff containing exact scoped context unless an independently authorized headless service identity is used.
- **OGVCS-042-FR-08:** Restart/upgrade SHALL reconcile in-flight jobs and lock state and return typed recovery/unknown results rather than replaying a mutation blindly.
- **OGVCS-042-FR-09:** Security documentation and responses SHALL distinguish other-user attacks, unregistered same-user clients, and a fully compromised same-user session; no control SHALL claim to defeat the latter.
- **OGVCS-042-FR-10:** C++ and C# first-party bindings and a test client SHALL be generated from the IPC schemas and pass identical deterministic scenarios.

### Quality attributes

- **OGVCS-042-NFR-01:** Other OS users, remote hosts, unregistered clients, replayed handshakes, stale capabilities, and scope-escalation attempts MUST be rejected on every supported client OS.
- **OGVCS-042-NFR-02:** Agent failure MUST NOT corrupt workspace state, lose unsubmitted bytes, create false lock ownership, or expose reusable server credentials.
- **OGVCS-042-NFR-03:** Status calls and event delivery MUST remain bounded and responsive for the million-path reference workspace without sending the entire index over IPC.

## Interfaces and data

Deliver local endpoint/discovery, handshake, integration manifest/registration, consent grant, operation/job/progress/result, lock state, event cursor, trusted-client handoff, local audit, diagnostic record, and minimal generated C++/C# bindings. The later public SDK layers on these versioned schemas.

## Development plan

1. Implement the local endpoint, schema negotiation, authenticated handshake, endpoint/key lifecycle, integration registration/consent, and read-only status test client.
2. Add scoped sync/start-edit/lock/checkpoint/revert jobs, agent-held credentials, bounded events/progress, quotas, idempotency, and crash reconciliation.
3. Add signed single-use trusted-client handoff, capability review/revocation, emergency disable, safe diagnostics, and generated C++/C# bindings.
4. Run three-OS IPC red-team, restart/network/lock/resource and million-path suites; publish the first-party contract before engine plugin development begins.

## Acceptance criteria

- **OGVCS-042-AC-01:** Reference C++ and C# clients complete status, bounded sync, start-edit, lock-loss, and trusted handoff scenarios using only published IPC schemas.
- **OGVCS-042-AC-02:** Other-user, remote, unregistered, replay, stale-grant, oversized-message, event-flood, and path-scope attacks are rejected without credential or protected-state disclosure.
- **OGVCS-042-AC-03:** Same-user threat tests prove scoped consent and trusted confirmation boundaries while documentation explicitly declines a guarantee against fully compromised same-user malware.
- **OGVCS-042-AC-04:** Agent/plugin crash, restart, upgrade, cancellation, network loss, and lock expiry preserve workspace bytes and return accurate recoverable state.
- **OGVCS-042-AC-05:** Million-path status/event tests meet declared memory/latency/backpressure budgets without serializing the full workspace index.

## Verification plan

IPC schema/golden tests, OS endpoint/ACL matrix, replay/capability/path authorization properties, credential canaries, fuzz/resource limits, agent lifecycle faults, lock loss, large-workspace performance, and security-boundary documentation review.

## Telemetry and operations

Local diagnostics expose integration/version, granted capability names, operation class/result/duration, queue/rate state, agent compatibility, and safe security failures. Paths, content, tokens, and user identity are excluded from shared telemetry.

## Rollout and rollback

Ship read/status first to first-party clients, then sync/start-edit and finally trusted mutation handoffs. Keep direct CLI recovery available. Rollback preserves consent and job journals and stays within negotiated IPC versions.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Agent becomes a credential oracle | Credentials never leave agent; operation-scoped capabilities and red-team canaries |
| Same-user malware defeats process identity | Explicit threat boundary plus confirmation for sensitive actions |
| Agent and client state diverge | Shared workspace engine, journals, idempotency and restart reconciliation |

## Completion evidence

- Implementation changes: bounded private/unpublished/unwired Rust 1.82
  protocol-fact and in-memory-ledger candidate under `client/local-agent/rust`;
  it composes the existing FileID, path, and protocol-baseline types and retains
  only opaque facts owned by the future lock contract. It implements no agent
  process, transport, credentials, workspace mutation, lock authority, or
  public binding.
- Test and benchmark results: 16 deterministic Rust contract tests plus the
  Node source-policy gate cover negotiation, challenge replay, exact rotation,
  consent-generation/scope fencing, operation idempotency after original time
  windows, status/event bounds and backpressure, exact subscription-caller
  facts, ledger-issued cursor expiry, lock-knowledge variants, single-use
  handoff, redaction, cancellation, rollback, and selected
  exact/maximum-plus-one envelopes. These are bounded model tests, not OS,
  endpoint, fuzz, benchmark, or million-path evidence.
- Security/reliability review:
  `docs/reviews/OGVCS-042-local-agent-ipc-boundary-review.md` records the
  independent authority/boundary audit, fail-closed fixes, residual risks, and
  private-candidate-only verdict; it is not an external security assessment or
  acceptance evidence for a hosted agent.
- Documentation/runbooks: `client/local-agent/rust/README.md` documents exact
  ordering, limits, known answers, composition boundaries, and nonclaims. No
  operational runbook exists because there is no process or deployment in this
  tranche.
- Rollout result: none. The candidate is retained only in integration history,
  remains unpublished, and is not wired to a route, CLI, UI, engine integration,
  or production runtime; OGVCS-042
  remains Todo and OGVCS-042-AC-01 through OGVCS-042-AC-05 remain open.
