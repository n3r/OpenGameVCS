# OGVCS-033 — Fidelity and authorized-projection export

**Status:** Todo  
**Release:** R3 — Production Beta  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-002, OGVCS-004, OGVCS-007, OGVCS-009, OGVCS-017, OGVCS-018, OGVCS-020, OGVCS-025, OGVCS-029
**Blocks:** OGVCS-034, OGVCS-036, OGVCS-040  
**Source:** [Architecture ADR-0002](../../adr/0002-export-fidelity-and-authorized-projection.md)  
**Last updated:** 2026-08-15

## Outcome

An organization can either create a repository-complete fidelity export that preserves canonical roots after proving complete authorization, or create a redacted authorized projection with explicitly distinct identities. Both modes are self-describing, independently verifiable, and impossible to confuse during import.

## Problem

Open source alone does not prevent data lock-in. If repository history, FileIDs, policies, audits, or content graphs can only be interpreted by a running vendor stack, a studio cannot independently prove recoverability or exit. But a canonical snapshot commits to its full root: removing one hidden path changes tree and snapshot IDs. Export therefore needs two honest modes instead of claiming both redaction and identical roots.

## Scope

### In scope

- Versioned public fidelity and authorized-projection profiles with streaming full/incremental containers and portable content or explicitly verified external-object mode.
- Complete snapshot/tree/FileID/version/manifest/chunk graph and selected mutable state for fidelity; newly identified authorized derived graph plus non-disclosing omission/provenance records for projection.
- Separate standalone verifier/reconstructor profiles and clean-deployment import semantics that cannot confuse projection with source truth.
- Byte-preserving embedding of OGVCS-002 canonical objects for fidelity and creation of new canonical core objects for projection without redefining core hash preimages.

### Out of scope

- Export of secrets/private keys/live credentials, conversion into every third-party VCS, live bidirectional replication, or bypass of tenant/path/export authorization.

## Users and journeys

- **Studio owner:** initiates a repository-complete fidelity export under dual control, transfers it offline, and retains a verifiable exit artifact with identical roots.
- **Restricted collaborator:** exports only an authorized projection and receives a clearly derived history that reveals nothing about hidden source records.
- **Independent operator:** validates the declared profile/signatures/hashes, reconstructs chosen snapshots and paths, and imports into a fresh deployment without vendor services.
- **Auditor:** identifies exact scope, omissions, external dependencies, tool/spec versions, principals, and evidence for every export.

## Requirements

### Functional

- **OGVCS-033-FR-01:** Publish normative, implementation-neutral fidelity and authorized-projection profiles with canonical export-manifest serialization, ordering, identity-class rules, container framing, digest/signature algorithms, version negotiation, extension rules, and test vectors. Embedded core objects SHALL retain their OGVCS-002 canonical bytes, kinds, hash domains, and IDs.
- **OGVCS-033-FR-02:** Fidelity export SHALL require authorization to every record reachable from each selected root and SHALL fail atomically on incomplete/mixed visibility before producing a usable container; it SHALL represent the complete selected graph/mutable state and preserve canonical object/snapshot/root IDs.
- **OGVCS-033-FR-03:** Secrets, password hashes, bearer tokens, private signing/encryption keys, transient leases/sessions, and provider-specific credentials SHALL never be exported; replacements/omissions SHALL be explicit in the manifest.
- **OGVCS-033-FR-04:** Every export SHALL require a dedicated mode-specific permission and explicit repository/root/time/policy selection. Authorized projection SHALL include only the caller's authorized view and create a distinct repository descriptor carrying a required projection feature, new repository identity, declared projection identity class, and public non-disclosing provenance reference. Every repository-scoped projected object SHALL bind that descriptor, while path-independent manifests/chunks MAY retain content IDs. Projection SHALL use non-disclosing omission markers and SHALL NOT redefine core hash preimages or claim source-root identity.
- **OGVCS-033-FR-05:** Portable mode SHALL embed every required content object. External-object mode SHALL record immutable provider-independent identity/size plus validated location requirements and SHALL be labeled non-self-contained.
- **OGVCS-033-FR-06:** Each mode SHALL capture a consistent repository generation, stream/resume without loading the repository in memory, support volume splitting, and produce a canonical top-level manifest/root digest that names the mode and source/projection identity class.
- **OGVCS-033-FR-07:** Incremental export SHALL name and verify its exact base export/root/generation and mode, remain within that profile, and contain enough tombstone/reference data to derive the declared result; cross-mode, missing, or out-of-order increments SHALL fail.
- **OGVCS-033-FR-08:** The standalone verifier SHALL use no running OpenGameVCS service, metadata database, network, server implementation library, or production OGVCS-002 codec package. It SHALL independently implement the public OGVCS-002 specification/vectors and validate the declared fidelity/projection profile, framing, canonical form, graph reachability, identity class, references, sizes/digests, signatures, scope consistency, and volume completeness.
- **OGVCS-033-FR-09:** The reconstructor SHALL materialize any selected exported snapshot under OGVCS-004 path safety, label projected history as derived, and emit a tree/file digest report without executing repository content.
- **OGVCS-033-FR-10:** Clean import SHALL stage and verify all records/content, map identities/providers explicitly, reject collisions/incompatibility, and publish atomically; fidelity import SHALL reconcile identical roots, while projection import SHALL publish a distinct derived namespace and SHALL NOT replace or impersonate the source repository.
- **OGVCS-033-FR-11:** Every export SHALL create an immutable audit record and evidence manifest including requester/approvers, scope, generation, bytes/objects, mode, tool/spec version, destination class, verification result, and expiry/retention guidance.
- **OGVCS-033-FR-12:** Projection provenance/redaction mappings SHALL be separately access-controlled and signed; public manifests, omissions, counts, errors, ordering, timing classes, and telemetry SHALL not disclose protected source identities or cardinality.

### Quality attributes

- **OGVCS-033-NFR-01:** Two exports of the same generation, mode, authorized scope, options, and format version MUST have identical logical root digests even when volume layout/compression differs; projection roots MUST differ from source roots whenever any record is omitted.
- **OGVCS-033-NFR-02:** The verifier/parser MUST be bounded against malicious length, nesting, fanout, path, compression, and resource inputs and MUST never execute exported hooks/content.
- **OGVCS-033-NFR-03:** Export SHALL be resumable and rate-limited without blocking normal writes beyond the documented generation-capture operation.

## Interfaces and data

Deliver the public two-profile specification, schema/test-vector repository, export request/approval and full-visibility preflight, export/volume manifests, incremental base/mode link, protected projection-provenance record, non-disclosing omission/external dependency record, verifier/reconstructor CLI profiles, import policy, and fidelity/projection reconciliation/evidence reports. Fidelity containers embed unchanged OGVCS-002 bytes; projection builders use OGVCS-002 schemas/preimages and OGVCS-004 path plus OGVCS-007 manifest semantics. Neither mode treats the OGVCS-002 caller-supplied logical bundle as completeness evidence.

## Development plan

1. Implement and publish distinct fidelity/projection container/volume schemas, identity rules, full-visibility preflight, projection builder, portable object embedding, streaming writers and normative mixed-visibility vectors.
2. Build the standalone two-profile verifier/reconstructor independently from server libraries with bounded parsers, identity/graph/hash/signature checks, safe materialization and derived labeling.
3. Implement resumable/split full exports, same-mode incremental chains, authorization/audit/approval, protected provenance, and clean-import staging with distinct fidelity/projection publication rules.
4. Complete large, adversarial, deterministic, mixed-visibility and clean-room cross-organization import tests; enable fidelity only after complete-authorization proof and projection only after non-disclosure proof.

## Acceptance criteria

- **OGVCS-033-AC-01:** The independent verifier accepts every normative fixture and rejects single-bit corruption, missing/duplicate/reordered volumes, broken graph references, noncanonical encodings, invalid signatures, and malicious bounds cases.
- **OGVCS-033-AC-02:** A repository-complete portable fidelity export reconstructs every selected snapshot with identical root/path/FileID/content digests and no network/server dependency.
- **OGVCS-033-AC-03:** An organization not operating the source deployment imports a fidelity artifact into a clean instance and obtains identical logical roots plus an explained identity/config reconciliation.
- **OGVCS-033-AC-04:** Full plus ordered same-mode incremental exports yield the same declared result as a fresh full export; wrong/missing/cross-mode base or increments fail before publication.
- **OGVCS-033-AC-05:** For a mixed-visibility fixture, fidelity export fails before a usable artifact while projection succeeds with distinct IDs; neither path/object/history/audit/review identity, count, manifest, error, timing class, nor telemetry discloses excluded state.
- **OGVCS-033-AC-06:** A public third-party/clean-room review implements or validates the spec from documentation/test vectors without private assistance or vendor service access.
- **OGVCS-033-AC-07:** Import rejects a projection relabeled as fidelity or targeted to replace its source; an authorized projection round-trip remains explicitly derived and never claims source-root equality.
- **OGVCS-033-AC-08:** A full-view projection with no omitted path still creates a distinct descriptor and different repository-scoped tree/snapshot IDs, cannot impersonate the source repository, and retains identical manifest/chunk IDs only where logical content is unchanged.

## Verification plan

Normative and adversarial two-profile corpus, deterministic reruns, mixed-visibility/non-disclosure cases, mutation/fuzz/property tests for both implementations, large streaming/volume/resume runs, same/cross-mode incremental tests, path safety, authorization review, clean-room reconstruction/import, and independent security/spec audit.

## Telemetry and operations

Expose authorized export stage, generation, object/byte progress, throttling, resumptions, verification state, and safe error classes. Export scope/content/paths/identities remain only in restricted audit/evidence, never shared operational metrics.

## Rollout and rollback

Ship spec/vectors and verifier first, then nonportable test exports, full portable exports, incremental export, and finally clean import. Formats are append/versioned; a writer version can be disabled while existing artifacts remain verifiable with retained tools/specs.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| “Export” omits product-critical metadata | Normative completeness list and clean import gate |
| Verifier shares the server's bug | Separate implementation/dependencies and independent review |
| Export becomes a bulk exfiltration path | Dedicated permission, dual control, scoped authorization, audit |
| External references undermine exit | Portable mode is gate; external mode explicitly non-self-contained |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
