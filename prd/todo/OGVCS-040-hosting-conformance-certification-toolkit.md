# OGVCS-040 — Hosting conformance and certification toolkit

**Status:** Todo  
**Release:** R4 — Ecosystem  
**Priority:** P1  
**Owner:** Unassigned  
**Depends on:** OGVCS-032, OGVCS-033, OGVCS-036, OGVCS-038  
**Blocks:** None  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

An independent hosting operator can run one public command-line suite against an exact OpenGameVCS deployment, produce a signed privacy-safe evidence bundle, and publish a time-bounded conformance record that studios can verify offline. Broken, expired, revoked, or out-of-scope claims fail mechanically.

## Problem

Protocol unit tests do not prove that an operated service can preserve authorization, restore data, fail over, upgrade, and export under its real topology. Conversely, a marketing badge without exact version/configuration/evidence is not trustworthy. The ecosystem needs implementation-neutral tooling that turns the existing conformance and recovery tests into a reproducible hosting assessment.

## Scope

### In scope

- A distributable `ogvcs-host-cert` runner and provider adapter protocol.
- Machine-readable Core and Production Hosting profiles composed from OGVCS-036 tests and required operational exercises.
- Synthetic tenant/repository provisioning, isolation probes, backup/restore, export/import, upgrade, and optional HA/DR orchestration.
- Canonical signed evidence bundles, offline verification, result redaction, expiry/revocation, and a signed static registry generator.
- Seeded defective-provider fixtures that prove mandatory gates cannot be skipped or misreported.

### Out of scope

- Creating or operating a legal certification body, selecting reviewers, charging fees, handling appeals, or enforcing trademarks.
- Establishing neutral project governance, contributor agreements, foundation ownership, or voting rules.
- Claiming regulatory compliance, provider financial viability, application performance beyond the declared profile, or security outside tested boundaries.
- Collecting production customer content or credentials.

## Users and journeys

- **Hosting operator:** creates an isolated synthetic assessment environment, runs the selected profile, fixes failures, and submits a signed evidence bundle tied to exact deployment identity.
- **Independent reviewer:** verifies the bundle offline, reruns selected tests, confirms mandatory coverage, and compiles a signed registry entry without accessing customer data.
- **Studio evaluator:** downloads a registry and bundle, verifies signatures/scope/expiry, and sees precisely which topology/version/profile passed or failed.
- **Tool maintainer:** adds a versioned test/profile requirement without embedding provider-specific logic in the runner.

## Requirements

### Functional

- **OGVCS-040-FR-01:** The CLI SHALL provide `profile list`, `plan`, `run`, `resume`, `verify`, `redact-preview`, and `registry build/verify` operations with stable machine output and typed exit codes.
- **OGVCS-040-FR-02:** A certification profile SHALL be a signed versioned document listing mandatory/optional test IDs, prerequisite OGVCS versions, topology claims, evidence rules, resource/time bounds, allowed skips, validity period, and pass algorithm.
- **OGVCS-040-FR-03:** The Core profile SHALL exercise OGVCS-036 protocol/security/durability conformance, signed versions, supported upgrade compatibility, verified backup restore, portable export, clean import, and absence of a runtime vendor-license dependency.
- **OGVCS-040-FR-04:** The Production Hosting profile SHALL additionally exercise declared tenant isolation, capacity/observability evidence, rolling upgrade, and each claimed OGVCS-032 HA/DR RPO/RTO behavior under injected failure.
- **OGVCS-040-FR-05:** A provider adapter SHALL expose only versioned lifecycle/test operations for an isolated synthetic assessment deployment; profile logic SHALL not depend on proprietary operator APIs or undocumented manual database edits.
- **OGVCS-040-FR-06:** The runner SHALL provision unique synthetic tenants, identities, repositories, paths, content, audit events, and fault markers and SHALL verify cleanup without reading or enumerating unrelated provider tenants.
- **OGVCS-040-FR-07:** Every mandatory test SHALL record test/vector/profile versions, target component versions and safe configuration fingerprint, timestamps, topology/region claims, inputs, result, measurements, artifact digests, retries, skip reason, and runner identity.
- **OGVCS-040-FR-08:** The runner SHALL fail a profile when any mandatory test is missing, skipped without an allowed rule, ambiguous, stale, unsigned, executed against a different target generation, or outside its declared resource/topology prerequisites.
- **OGVCS-040-FR-09:** Evidence SHALL use a canonical manifest/root digest and signatures; the standalone verifier SHALL validate completeness, test/profile compatibility, signatures, target consistency, expiry, revocation, and tamper without network or vendor service access.
- **OGVCS-040-FR-10:** Evidence collection SHALL be allowlisted and previewable and SHALL reject bearer credentials, secrets, customer paths/content, raw logs, or unrelated tenant identifiers before bundle finalization.
- **OGVCS-040-FR-11:** The registry builder SHALL consume verified evidence plus an externally authorized decision record and produce a signed deterministic registry containing provider, profile, exact scope/version/topology, issue/expiry dates, evidence digest/location, status, and supersession/revocation links.
- **OGVCS-040-FR-12:** Expired, superseded, revoked, wrong-scope, or signature-invalid registry entries SHALL be visibly invalid in machine and human verification; historical signed records SHALL remain auditable.

### Quality attributes

- **OGVCS-040-NFR-01:** Repeating the same deterministic tests against an unchanged target/profile SHALL yield the same logical pass/fail and evidence root, excluding explicitly normalized measurement/timestamp fields.
- **OGVCS-040-NFR-02:** The runner and verifier MUST be distributable under an OSI-approved license, run without vendor credentials/services, and support an offline evidence-verification workflow.
- **OGVCS-040-NFR-03:** Test execution MUST be isolated, rate/resource bounded, resumable, and incapable of mutating provider state outside the explicitly created assessment scope.
- **OGVCS-040-NFR-04:** Seeded authorization, durability, restore, export, HA, upgrade, skipped-test, and evidence-tamper defects MUST be detected before a passing registry entry can be built.

## Interfaces and data

Deliver `ogvcs-host-cert`, the provider adapter protocol, `CertificationProfile`, `AssessmentTarget`, `TestExecution`, `EvidenceManifest`, `ReviewerDecision`, `RegistryEntry`, `Revocation`, and signed registry schemas, plus synthetic assessment fixtures and intentionally failing provider adapters. Profiles reference stable OGVCS-036 test IDs rather than copying tests.

## Development plan

1. **Profile and adapter contracts:** implement schemas, CLI skeleton, target preflight, deterministic synthetic assessment identity, and a local reference-deployment adapter.
2. **Core orchestration:** integrate OGVCS-036 conformance, OGVCS-030 upgrade, OGVCS-018 restore, and OGVCS-033 export/import into resumable profile execution with mandatory-test accounting.
3. **Production exercises:** integrate tenant-isolation probes, capacity evidence, and OGVCS-032 HA/DR fault workflows behind declared capabilities and safety bounds.
4. **Evidence and verification:** implement allowlisted collection/redaction preview, canonical bundle creation/signing, offline verification, seeded defect/tamper fixtures, and reproducibility tests.
5. **Registry tooling and packaging:** implement deterministic signed registry build/verify/expiry/revocation, package the toolkit/reference adapter, and publish the complete offline operator/reviewer documentation.

Each slice runs against synthetic assessment scope and can be reviewed without creating a certification organization. External governance decides who may sign a decision/registry; the software only verifies that supplied authority and evidence follow configured rules.

## Acceptance criteria

- **OGVCS-040-AC-01:** An operator unaffiliated with the reference implementation installs the public toolkit, adapts a deployment from documentation, and completes the Core profile without private engineering APIs or vendor services.
- **OGVCS-040-AC-02:** A qualifying HA deployment completes the Production Hosting profile, including rolling upgrade, backup restore, portable export/clean import, and repeated HA/DR fault exercises with declared RPO/RTO evidence.
- **OGVCS-040-AC-03:** Seeded providers with authorization leakage, acknowledged-data loss, unverifiable restore/export, split authority, incompatible upgrade, omitted/skipped tests, or falsified topology cannot produce a passing verified bundle/registry entry.
- **OGVCS-040-AC-04:** Single-byte bundle/manifest mutation, mixed-target results, wrong profile/vector version, invalid signature, expired/superseded/revoked record, and wrong claimed scope are rejected by the offline verifier.
- **OGVCS-040-AC-05:** Automated canaries and manual review find no credential, customer content/path, unrelated tenant identifier, or unrestricted raw log in a finalized evidence bundle.
- **OGVCS-040-AC-06:** Rebuilding the registry from the same verified inputs/decision records produces the same logical registry root; offline consumers validate current and historical status from published signed artifacts.

## Verification plan

CLI/schema tests, provider-adapter contract tests, reference and deliberately defective deployments, full Core/Production profile runs, OGVCS-005 fault injection, mandatory-skip accounting, evidence mutation/fuzzing, secret/tenant canaries, deterministic registry tests, expiry/revocation/time cases, offline packaging, and independent operator usability exercise.

## Telemetry and operations

The runner records local profile/test progress, safe target/version fingerprint, duration, resource use, retry/skip/failure class, and evidence digest. It sends no analytics by default. Registry generation publishes only provider-approved scope/status metadata and evidence references; sensitive test detail remains in access-controlled bundles where necessary.

## Rollout and rollback

Ship an experimental Core profile against the reference deployment, add a second adapter, freeze profile 1, then add Production exercises and registry tooling. Consumers pin runner/profile/vector versions. A faulty profile is revoked/superseded; prior signed evidence stays inspectable but no longer validates as current.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Toolkit becomes a marketing badge generator | Mandatory machine gates, seeded failures, signed evidence, exact scope/expiry |
| Provider adapter special-cases tests | Public neutral adapter protocol, synthetic unpredictable run identity, rerun support |
| Assessment touches customer data | Isolated synthetic scope, allowlist collection, canaries, least-privilege credentials |
| Tool pretends to solve organizational trust | External signed decision is explicit input; governance remains a separate program gate |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
