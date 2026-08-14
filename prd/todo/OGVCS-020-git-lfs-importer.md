# OGVCS-020 — Git and Git LFS importer

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-002, OGVCS-007, OGVCS-008, OGVCS-010, OGVCS-015, OGVCS-017, OGVCS-045  
**Blocks:** OGVCS-029, OGVCS-033, OGVCS-034  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

A studio can import a Git repository—including reachable Git LFS content—into verifiable OpenGameVCS history with deterministic identity mapping, an actionable preflight report, and no silent fidelity loss.

## Problem

Migration is a trust boundary. Git object history, references, file modes, symlinks, unusual paths, encodings, and LFS pointer/content pairs do not map trivially to the target model. A convenient importer that silently substitutes pointer files or rewrites history differently on retry is unacceptable.

## Scope

### In scope

- Read-only Git object/reference ingestion, Git LFS discovery/fetch/verification, preflight, deterministic conversion, resume, and reconciliation reports.
- Commits, parent DAG, selected refs, authors/committers, timestamps, messages, executable mode, symlinks under policy, submodule reporting, and source-to-target mapping.
- Offline source bundles and authenticated remote LFS retrieval.

### Out of scope

- Continuous or bidirectional mirroring, pull-request migration, Git server emulation, or automatic repair of missing LFS data.

## Users and journeys

- **Migration lead:** runs dry-run, resolves blockers, imports selected refs, reruns safely, and signs off a source/target reconciliation report.
- **Developer:** finds an imported commit by original Git object ID and receives correct large-file bytes rather than an LFS pointer.
- **Auditor:** verifies which source objects were included, transformed, skipped, or rejected and why.

## Requirements

### Functional

- **OGVCS-020-FR-01:** Preflight SHALL inventory refs, commits, trees, blobs, LFS pointers/objects, byte/path extremes, modes, symlinks, submodules, invalid target paths, and estimated transfer/storage.
- **OGVCS-020-FR-02:** The user SHALL explicitly choose included refs and policies for tags, remote refs, merge parents, empty commits, symlinks, submodules, illegal paths, and identity mapping.
- **OGVCS-020-FR-03:** Conversion SHALL deterministically preserve the selected commit DAG, message bytes under a declared encoding rule, author/committer identity, timestamps/offsets, file bytes, executable mode, and parent order where representable.
- **OGVCS-020-FR-04:** Git LFS pointer syntax and object identity SHALL be verified; referenced LFS bytes SHALL be fetched from configured stores and validated before the corresponding target snapshot is acknowledged.
- **OGVCS-020-FR-05:** Missing, unauthorized, or corrupt LFS objects SHALL fail affected history explicitly; pointer text SHALL never be silently imported as the intended asset.
- **OGVCS-020-FR-06:** Invalid/colliding target paths SHALL be reported before mutation and require a deterministic recorded mapping or exclusion approved by the operator.
- **OGVCS-020-FR-07:** Every source commit/blob/LFS object and ref SHALL have a durable target ID/status mapping; repeated runs with identical inputs/policy SHALL produce identical target roots.
- **OGVCS-020-FR-08:** Import SHALL stage data into an isolated namespace and publish requested target refs only after OGVCS-017 verification and reconciliation pass.
- **OGVCS-020-FR-09:** Interrupted imports SHALL resume from verified checkpoints; retries SHALL be idempotent and SHALL not duplicate history or advance refs partially.
- **OGVCS-020-FR-10:** The final report SHALL enumerate fidelity guarantees, transformations, omissions, warnings, counts/bytes, source ref tips, target roots, and verification status.
- **OGVCS-020-FR-11:** Credentialed Git/LFS acquisition SHALL run only in the OGVCS-045 broker; pack/object/archive parsing and conversion SHALL run as credential-free, no-network, immutable-input sandbox jobs with declared resource/output policy.
- **OGVCS-020-FR-12:** Each imported file identity SHALL receive one repository-valid FileID allocation persisted in the source-to-target mapping; retries SHALL reuse it, copies SHALL allocate distinct IDs, moves SHALL preserve mapped identity, and mutable paths SHALL never generate identity.

### Quality attributes

- **OGVCS-020-NFR-01:** Importing the same immutable Git source and policy twice MUST yield byte-identical mapping/reconciliation outputs and target snapshot IDs.
- **OGVCS-020-NFR-02:** Source parsing and decompression MUST enforce object size, nesting, path, and resource limits.
- **OGVCS-020-NFR-03:** Source repository and LFS credentials MUST be read-only and redacted from logs/reports.
- **OGVCS-020-NFR-04:** Seeded parser escape, credential/network access, traversal, bomb, hang, fork, and output-flood attempts MUST fail the OGVCS-045 profile without partial target publication.

## Interfaces and data

Define import policy, source inventory, broker acquisition/staged-input request, sandbox parser job/output policy, path/FileID mapping, checkpoint, per-object disposition, reconciliation report, and original-Git-ID lookup metadata. Publish the transformation rules as versioned import-format documentation.

## Development plan

1. Implement brokered Git object/ref and LFS acquisition/inventory, immutable import-policy schema, OGVCS-045 staged-input jobs, and deterministic path/FileID mapping reports.
2. Implement credential-free sandboxed bounded Git DAG/tree/blob conversion, modes/symlinks/tags metadata, target object staging, and durable source-to-target/FileID mappings.
3. Implement verified LFS retrieval, checkpoints/resume, isolated namespace verification/reconciliation, and atomic target-ref publication.
4. Complete golden/adversarial/large-history and kill/resume suites, package the offline admin CLI and runbooks, and require dry run plus explicit publish in rollout.

## Acceptance criteria

- **OGVCS-020-AC-01:** A golden repository with branches, tags, merges, renames, executable files, legal symlinks, Unicode, empty commits, and LFS objects produces the expected target DAG and bytes.
- **OGVCS-020-AC-02:** Missing/corrupt LFS, malformed objects, path collisions, illegal symlinks, submodules, and unsupported modes fail or transform exactly as the selected policy declares.
- **OGVCS-020-AC-03:** Killing and resuming at every import stage yields the same roots/mapping as an uninterrupted run and never exposes partial refs.
- **OGVCS-020-AC-04:** Source-tip tree digests reconstructed under declared transformation rules reconcile with imported snapshot digests for every selected ref.
- **OGVCS-020-AC-05:** An independent operator can reproduce the import from source bundle, policy, tool version, and report.
- **OGVCS-020-AC-06:** OGVCS-045 canaries prove parsers cannot reach source/target credentials, network, host/control-plane state, or publish directly; escape/resource faults leave no partial refs.
- **OGVCS-020-AC-07:** Rename/copy/delete/recreate, repeated import, concurrent mapping and malicious duplicate-ID fixtures preserve the normative FileID result or fail before publication.

## Verification plan

Golden Git/LFS fixtures, OGVCS-045 sandbox/canary/adversarial pack parsing, FileID mapping properties, deterministic reruns, broker/remote failure/credential tests, path-platform matrix, kill/resume matrix, large-history benchmark, and post-import full integrity verification.

## Telemetry and operations

Expose stage progress, objects/bytes scanned/fetched/reused, LFS failures, transformation counts, checkpoint age, verification findings, and publish outcome. Logs identify objects by safe digest and never expose credentials or unauthorized path content.

## Rollout and rollback

Release as an offline/admin tool with dry-run mandatory by default. Publication is a final explicit step. Rollback deletes only the unreferenced isolated staging namespace under OGVCS-018 rules; published immutable history is removed only through normal reference/retention policy.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| LFS pointer is mistaken for asset content | Mandatory pointer resolution and digest verification |
| Cross-platform path rules alter a tree silently | Preflight collision report and explicit recorded mappings |
| Retry creates divergent target history | Immutable policy hash, durable mappings, deterministic conversion |
| Malicious source exhausts resources | Bounded parsers, quotas, isolation, adversarial corpus |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
