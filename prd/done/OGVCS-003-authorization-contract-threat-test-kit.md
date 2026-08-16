# OGVCS-003 — Authorization contract package and threat test kit

**Status:** Done
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Codex and OpenGameVCS maintainers
**Depends on:** OGVCS-001  
**Blocks:** OGVCS-005, OGVCS-006, OGVCS-008, OGVCS-009, OGVCS-026, OGVCS-041, OGVCS-045  
**Source:** [ADR-0011 authorization contract v1](../../adr/0011-authorization-contract-v1.md)
**Last updated:** 2026-08-16

## Outcome

Every service and client can consume one versioned authorization-contract package and run one public negative-test kit for who may discover, read, materialize, lock, change, review, export, or administer each object and path, including caches and mixed-visibility changes.

## Problem

Content-addressed storage is easy to misuse as if a hash were a secret. Path ACLs can still leak names through history, messages, search, previews, deduplication probes, events, or audit output. Retrofitting confidentiality after APIs and caches ship would be costly and unsafe.

## Scope

### In scope

- Generated schema/binding packages and a command-line authorization/threat vector runner.
- Assets, actors, trust zones, attacker capabilities, abuse cases, and security objectives.
- Authentication trust and token/session classes.
- Permission vocabulary and authorization evaluation contract.
- Path, snapshot, review, search, event, cache, export, and object-grant confidentiality.
- Tenant-scoped deduplication and encryption/KMS boundaries.
- Hook, merge-driver, importer, and preview sandbox requirements.
- Audit requirements and privileged-operation controls.

### Out of scope

- Production identity-provider adapters, policy persistence/evaluation, and audit storage, owned by OGVCS-009.
- Selecting a particular cloud KMS, WAF, or SIEM.
- Product-specific compliance certification.

## Users and journeys

- **Studio security lead:** can determine whether a contractor may infer or retrieve a restricted asset through every supported surface.
- **Service developer:** has a mandatory authorization call and response contract for each resource operation.
- **Cache operator:** can serve immutable data only with a valid scoped grant and cannot enumerate tenant content.
- **Incident responder:** can trace privileged actions without exposing additional protected content.

## Requirements

### Functional

- **OGVCS-003-FR-01:** The threat model SHALL cover external attackers, malicious/compromised users, administrators, build identities, cache operators, import files, plugins, hooks, preview parsers, stolen devices, and confused-deputy services.
- **OGVCS-003-FR-02:** Permission verbs SHALL separately model discover, read metadata, materialize content, create lock, submit, review, export, administer policy, and force unlock.
- **OGVCS-003-FR-03:** Authorization SHALL be evaluated against tenant, repository, branch/reference, canonical path/FileID, snapshot context, actor, and operation; deny SHALL win unless a documented policy composition rule says otherwise.
- **OGVCS-003-FR-04:** A denied actor SHALL not learn protected path names, existence, size, hash, history, message, thumbnail, dependency, lock, branch, search hit, or event.
- **OGVCS-003-FR-05:** Object hashes SHALL never authorize access. Object transfer SHALL require a short-lived audience-bound grant created after policy evaluation.
- **OGVCS-003-FR-06:** Deduplication SHALL be tenant-scoped by default; cross-tenant existence queries are prohibited.
- **OGVCS-003-FR-07:** Mixed-visibility snapshots/reviews SHALL have a defined redaction model that cannot leak hidden operations through counts, ordering, messages, parents, or timing beyond an accepted documented residual risk.
- **OGVCS-003-FR-08:** Force unlock, export, retention deletion, policy change, impersonation, repair, and audit access SHALL be privileged, reason-bearing, and append-only audited.
- **OGVCS-003-FR-09:** Untrusted file parsers and repository-supplied hooks SHALL run with explicit CPU, memory, time, filesystem, and network limits.
- **OGVCS-003-FR-10:** The model SHALL define revocation and maximum-validity behavior for sessions, transfer grants, service tokens, caches, and offline lock receipts.

### Quality attributes

- **OGVCS-003-NFR-01:** No unresolved critical/high threat may remain at R0 exit; accepted medium risks require an owner and roadmap item.
- **OGVCS-003-NFR-02:** Authorization decisions MUST be deterministic for the same versioned policy inputs and produce a privacy-safe decision code.
- **OGVCS-003-NFR-03:** Security tests MUST be runnable against every conforming server implementation, not just the reference service.

## Interfaces and data

Deliver generated packages for the versioned authorization decision input/output schema, permission vocabulary, resource naming rules, transfer-grant claims and audit-event classes, plus data-flow/threat registries and an executable abuse-test catalog. OGVCS-009 owns the production evaluator/storage; all later APIs consume this implemented contract kit.

## Development plan

1. Implement the versioned permission/resource/actor/context schemas and generated bindings, plus machine-readable threat/abuse-case and audit-event registries.
2. Build a deterministic vector runner with reference policy fixtures, decision envelopes, transfer-grant signing/verification fixtures, and privacy-safe error assertions.
3. Add cross-surface non-disclosure, revocation, mixed-visibility, deduplication-probe, and sandbox-boundary negative suites consumable by future services.
4. Package the schemas/bindings/runner, integrate them into CI as a public contract kit, publish the threat model and versioning rules, and freeze contract version 1.

## Acceptance criteria

- **OGVCS-003-AC-01:** Independent security review approves trust boundaries and all critical/high mitigations.
- **OGVCS-003-AC-02:** The abuse catalog covers guessed hashes, cache replay, mixed-visibility history/review, search, events, export, deduplication probing, hook/preview escape, and token revocation.
- **OGVCS-003-AC-03:** Every planned API/resource in the roadmap maps to permission and audit behavior or is explicitly public.
- **OGVCS-003-AC-04:** Two example policies—internal team and restricted outsourcer—produce unambiguous expected decisions for the golden repository.
- **OGVCS-003-AC-05:** Privacy review documents collected identity/audit data, purpose, retention, access, and redaction.

## Verification plan

- Table-driven authorization vectors and negative enumeration tests.
- Threat-model review with storage, client, engine-plugin, and operator representatives.
- Prototype transfer-grant and revocation tests.
- Sandbox escape requirements mapped to future conformance tests.

## Telemetry and operations

Define privacy-safe authorization-denial codes, decision latency, grant issuance/revocation counts, privileged action events, and alert conditions. Paths, hashes, token claims, and policy contents are excluded from default metrics/logs.

## Rollout and rollback

This is a ratified contract. Changes use a new version and dual-evaluation test period. A policy engine may fall back only to deny; it must never fail open during upgrade or dependency outage.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Path ACL complexity makes behavior inconsistent | One shared decision contract and cross-service conformance suite |
| Metadata redaction breaks useful history | Explicit authorized views and user testing without weakening confidentiality |
| Audit becomes a new data leak | Separate audit permission, structured redaction, integrity protection, retention policy |

## Completion evidence

- Implementation changes: the frozen [`dcaae7e` product source](https://github.com/n3r/OpenGameVCS/commit/dcaae7e2c3cb966e9698cf86ee52ecc81f6381d3) and [detailed changelog](../../docs/changelog/OGVCS-003.md) deliver the language-neutral contract, JavaScript package, schemas, generated bindings, immutable registries, policies, grants, authorized views, sandbox contract, runner, and packed CI proof.
- Test and benchmark results: the [validation evidence packet](../../docs/evidence/OGVCS-003/README.md) records the bounded local presubmit, offline package installation, all 30 abuse vectors through both runner paths, and exact Linux/macOS/Windows report and archive comparison. Per maintainer direction, no million-entry or logical-1-TiB workload was run; neither is an OGVCS-003 acceptance requirement.
- Security/reliability review: the [independent critical review](../../docs/reviews/OGVCS-003-critical-review.md) records the initial gaps, adversarial remediation, trust-boundary approval, acceptance map, sole owned medium timing residual, and no unresolved P0/P1/P2 implementation or CI defect.
- Documentation/runbooks: [ADR-0011](../../adr/0011-authorization-contract-v1.md) and the [complete documentation/evidence index](../../docs/evidence/OGVCS-003/README.md) cover the threat model, privacy review, operations, runner protocol, sandbox enforcement, versioning, revocation, failure, compatibility, and rollback.
- Rollout result: [GitHub Actions run 31933804281](https://github.com/n3r/OpenGameVCS/actions/runs/31933804281) passed at the exact frozen product source on Ubuntu, macOS, and Windows; its comparator independently re-hashed the retained MIT-licensed packages and required byte-identical reference/external-adapter results.
- OGVCS-003-AC-01: the [independent security-review verdict](../../docs/reviews/OGVCS-003-critical-review.md#acceptance-verdict) approves the frozen trust boundaries and confirms that every critical/high threat has an executable mitigation; the one accepted medium timing risk names its owner, roadmap item, expiry, and controls.
- OGVCS-003-AC-02: the [abuse coverage evidence](../../docs/evidence/OGVCS-003/README.md#acceptance-map) binds all required guessed-hash, replay, mixed-visibility, search, event, export, deduplication, sandbox, preview, and revocation categories to 30 executed vectors.
- OGVCS-003-AC-03: the [roadmap-surface registry evidence](../../docs/evidence/OGVCS-003/README.md#acceptance-map) maps all 45 PRDs to exact public/protected classification, resource types, permissions, and audit behavior, with independent mutation checks.
- OGVCS-003-AC-04: the [policy decision evidence](../../docs/evidence/OGVCS-003/README.md#acceptance-map) independently reproduces all 40 golden decisions for the internal-team and restricted-outsourcer policies using deny-overrides and privacy-safe codes.
- OGVCS-003-AC-05: the [privacy-review acceptance evidence](../../docs/evidence/OGVCS-003/README.md#acceptance-map) documents identity/audit data, purpose, retention, access, minimization, redaction, authorized-view construction, subject controls, and the review outcome.
