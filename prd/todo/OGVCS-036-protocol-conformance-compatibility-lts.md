# OGVCS-036 — Protocol conformance, compatibility, and LTS

**Status:** Todo  
**Release:** R3 — Production Beta  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-002, OGVCS-008, OGVCS-009, OGVCS-019, OGVCS-030, OGVCS-033, OGVCS-041  
**Blocks:** OGVCS-038, OGVCS-040  
**Source:** [Architecture ADR-0005](../../adr/0005-early-public-protocol-baseline.md)  
**Last updated:** 2026-08-14

## Outcome

Clients, servers, storage implementations, and tools can prove that their established public contracts interoperate across supported versions; independent implementations can run a public black-box conformance suite; and designated LTS releases have explicit, test-enforced support commitments.

## Problem

Publishing source or schemas is insufficient if behavior depends on undocumented error, retry, authorization, serialization, or version-skew assumptions. Uncontrolled compatibility freezes defects forever, while casual breaking changes strand studios and exports. The project needs version ownership, negotiation, public vectors, and a bounded long-term support policy.

## Scope

### In scope

- Normative conformance profiles and errata for the established OGVCS-041 protocol baseline, repository/export formats, metadata and transfer behavior, automation/events, authentication/authorization behavior, and signed release compatibility.
- Public black-box conformance runner, fixtures/reference traces, implementation report, compatibility matrix, deprecation process, and LTS policy/toolchain.
- Server/client/API/event/format upgrade and skew gates used by release certification.

### Out of scope

- Redefining the initial OGVCS-041 wire/negotiation contract, guaranteeing compatibility for undocumented internals, permanent support for every prerelease, a full SDK, hosting certification/business governance, or P4/Git wire compatibility.

## Users and journeys

- **Independent implementer:** reads a stable profile, runs the suite against a client/server/backend/tool, and receives a reproducible pass/fail report without private fixtures.
- **Studio operator:** checks an exact server/client/plugin/export combination and knows the safe upgrade/deprecation dates before rollout.
- **Maintainer:** proposes an extension or break, supplies negotiation/fallback and vectors, and cannot release it until compatibility gates pass.

## Requirements

### Functional

- **OGVCS-036-FR-01:** Publish versioned normative conformance profiles using RFC-style SHALL/SHOULD/MAY language that reference OGVCS-041 and the owning format/domain specifications; ambiguity SHALL be resolved by versioned erratum or new negotiation, never by silently redefining released behavior.
- **OGVCS-036-FR-02:** Each interoperable surface SHALL retain independent protocol, schema, feature, and format versions plus owner from the baseline registry; one marketing/package version SHALL not substitute for negotiation.
- **OGVCS-036-FR-03:** The suite SHALL verify that connection/session setup negotiates an explicit compatible profile and capabilities and rejects unknown critical features/formats before mutation while handling optional extensions under documented rules.
- **OGVCS-036-FR-04:** The suite SHALL test positive behavior and adversarial cases including malformed/bounded inputs, retries, duplicate/reorder, cursor expiry, partial transfer, stale generation, unauthorized enumeration/known-object retrieval, and downgrade attempts.
- **OGVCS-036-FR-05:** Canonical formats SHALL have language-neutral golden vectors with valid/invalid boundaries and stable expected digests; released readers/verifiers SHALL remain available for every supported repository/export format.
- **OGVCS-036-FR-06:** Conformance profiles SHALL state prerequisites and separately report mandatory, optional, security, durability, performance-disclosure, and implementation-specific extensions; a partial implementation SHALL not claim the full profile.
- **OGVCS-036-FR-07:** Reports SHALL include suite/profile/vector versions, implementation/build/config/topology, test results/evidence, skips with reason, and cryptographic digest; results SHALL be reproducible locally/offline.
- **OGVCS-036-FR-08:** The production compatibility/LTS matrix SHALL extend, never retroactively supply, OGVCS-030's OGVCS-041-derived release matrix; it SHALL cover supported server↔CLI/desktop/plugin/SDK, event consumer, object backend, export/import/verifier, upgrade, downgrade, and mixed-node ranges for subsequent release preflight.
- **OGVCS-036-FR-09:** A breaking change SHALL require a new negotiated major/profile, migration/export path, security/data impact, deprecation notice, end date, and public vectors before implementation release.
- **OGVCS-036-FR-10:** Each LTS designation SHALL publish exact start/end dates, supported upgrade paths/platforms, dependency policy, severity response targets, and scope; the support term SHALL be at least 24 months from designation.
- **OGVCS-036-FR-11:** LTS SHALL include security and data-format correctness fixes and tools to verify/export data; license or vendor connectivity SHALL never disable access to existing repository data.
- **OGVCS-036-FR-12:** Conformance tests, schemas, vectors, and runner SHALL use an OSI-approved license and run without vendor credentials/services.

### Quality attributes

- **OGVCS-036-NFR-01:** The conformance suite MUST be deterministic except explicitly tagged timing/performance tests and MUST identify nondeterministic evidence/seeds.
- **OGVCS-036-NFR-02:** Security-critical authorization/durability tests MUST fail closed on unavailable fixtures, skipped prerequisites, or ambiguous responses.
- **OGVCS-036-NFR-03:** A supported version combination absent from the automated matrix MUST block release rather than rely on manual assertion.

## Interfaces and data

Deliver a versioned view of the OGVCS-041 spec/profile registry, conformance profile/errata, extension namespace review, golden-vector catalog, conformance adapter protocol, result/evidence schema, expanded compatibility matrix, deprecation record, LTS manifest/calendar, and public release-gate integration.

## Development plan

1. Import and verify the OGVCS-041 registry and released domain/format specifications; implement public conformance profiles, errata rules, extension review and language-neutral valid/invalid golden vectors.
2. Implement the offline black-box conformance runner/adapter protocol and positive, malformed, retry, authorization, durability and downgrade suites.
3. Implement machine-readable compatibility matrix/deprecation/LTS manifests, release-preflight integration and reports that separate mandatory, optional and skipped cases.
4. Validate with seeded-defect and independent adapters, automate the full supported skew grid, publish under an open license and make security/durability failures release-blocking.

## Acceptance criteria

- **OGVCS-036-AC-01:** Reference implementations pass every mandatory/security/durability case; deliberately defective clients/servers/backends/verifiers fail the intended tests without false passes.
- **OGVCS-036-AC-02:** At least one independent implementation or adapter passes a meaningful published profile using only public specifications, vectors, runner, and issue channels.
- **OGVCS-036-AC-03:** Every supported and deliberately unsupported version-skew combination produces the expected negotiated profile, safe degraded behavior, or pre-mutation rejection.
- **OGVCS-036-AC-04:** A new optional extension and a simulated breaking major change complete the documented proposal, negotiation, fallback/migration, vector, deprecation, and release-gate flow.
- **OGVCS-036-AC-05:** An LTS rehearsal ships a security/data-format fix, verifies existing data/exports, upgrades through supported paths, and remains operable in an offline environment.
- **OGVCS-036-AC-06:** Every original OGVCS-041 golden trace retains its released meaning; seeded attempts to bless incompatible behavior through a profile/erratum fail and require a negotiated version or explicit unsupported result.

## Verification plan

Cross-language golden vectors, mutation/fuzz corpus, reference-versus-seeded-defect differential tests, full compatibility grid, downgrade/extension tests, clean offline run, third-party implementation exercise, spec ambiguity review, and LTS patch/upgrade rehearsal.

## Telemetry and operations

Conformance runs emit only local evidence unless explicitly published. Product deployments expose negotiated profile/capabilities and safe incompatibility/error counts. The project maintains a public compatibility/deprecation/LTS calendar and release-blocking dashboard.

## Rollout and rollback

Freeze the initial core profile from proven R0–R2 behavior, run the suite advisory-only, then make security/durability and supported-matrix failures release-blocking. Spec corrections use errata/versioning; a released incompatible behavior is never silently redefined to make tests pass.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Tests bless one implementation bug | Normative spec, independent adapters, seeded-defect validation |
| Compatibility prevents necessary security fixes | Bounded profiles/LTS terms and explicit breaking-change process |
| “Conformant” hides skipped security cases | Separate profile claims and fail-closed mandatory reporting |
| LTS promise lacks operational proof | Patch/upgrade/offline rehearsal and public dated manifest |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
