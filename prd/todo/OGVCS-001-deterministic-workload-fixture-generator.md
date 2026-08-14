# OGVCS-001 — Deterministic workload fixture generator

**Status:** Todo  
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** None  
**Blocks:** OGVCS-002, OGVCS-003, OGVCS-004, OGVCS-005  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Developers can install one command-line tool and deterministically generate, inspect, and verify synthetic game-repository fixtures at laptop and production-like scale. Every downstream format, path, storage, authorization, and performance test receives the same versioned inputs instead of creating private ad hoc datasets.

## Problem

Source-code fixtures do not exercise million-path projects, Unity sidecars, Unreal-style packages, mutable multi-gigabyte assets, deep history, lock contention, sparse workspaces, or high-latency transfers. If each component team invents its own data, correctness and benchmark results cannot be compared or reproduced.

## Scope

### In scope

- A distributable `ogvcs-fixture` CLI and reusable generator library.
- Versioned profile, scenario, manifest, and verification-result schemas.
- Deterministic code-heavy, Unreal-like, Unity-like, large-binary, and global-studio profiles.
- Filesystem trees, byte streams, sidecar/asset groups, history-operation streams, identity/ACL fixtures, lock-contention scenarios, and expected digests.
- Small presubmit fixtures plus parameterized scale fixtures reaching at least one million paths and 10–100 GiB mutable files.
- Resumable generation, safe destination handling, inspection, verification, and CI packaging.

### Out of scope

- Recruiting studios, conducting interviews, negotiating data-use agreements, or collecting partner source assets.
- Running product performance benchmarks or injecting service faults; OGVCS-005 owns the runner.
- Implementing OpenGameVCS repository objects; OGVCS-002 consumes the neutral fixtures.
- Shipping partner-derived raw paths, content, identities, or operational traces.

## Users and journeys

- **Feature developer:** generates a small named fixture in a temporary directory, runs focused component tests, and verifies the fixture before use.
- **CI engineer:** resolves a profile version and seed, plans disk/time requirements, resumes an interrupted scale generation, and publishes its manifest as test evidence.
- **Format/path engineer:** consumes neutral operation/path cases and maps them to the implementation under test without changing the fixture.
- **Benchmark operator:** reproduces a result from the exact generator version, profile, parameters, seed, and manifest digest recorded by OGVCS-005.

## Requirements

### Functional

- **OGVCS-001-FR-01:** The CLI SHALL provide `list`, `plan`, `generate`, `inspect`, and `verify` operations with stable machine-readable output, typed exit codes, and `--help` examples.
- **OGVCS-001-FR-02:** A fixture request SHALL bind generator version, profile version, seed, scale parameters, feature flags, destination, and expected schema versions in a canonical request document.
- **OGVCS-001-FR-03:** Generation SHALL use a specified deterministic pseudorandom algorithm and byte/path/history derivation; locale, wall clock, host name, traversal order, thread scheduling, and OS randomness SHALL not affect logical output.
- **OGVCS-001-FR-04:** The code-heavy profile SHALL include deep/wide trees, executable files, text edits, branches, merges, renames, copies, and deletes.
- **OGVCS-001-FR-05:** The Unreal-like profile SHALL include binary packages, maps, external-actor/sidecar groups, source/config paths, large-file churn, and lock-conflict scenarios without copying proprietary assets or formats.
- **OGVCS-001-FR-06:** The Unity-like profile SHALL include asset/`.meta` pairs, stable synthetic GUID relationships, text scene/prefab analogues, binary imports, generated-cache exclusions, moves, and missing/duplicate-sidecar negative cases.
- **OGVCS-001-FR-07:** The large-binary profile SHALL generate streaming deterministic content with configurable size, edit locality, compression class, duplication, and cross-version reuse without holding a complete large file in memory.
- **OGVCS-001-FR-08:** The global-studio scenario SHALL emit a neutral ordered operation stream covering selective sync, lock acquisition/contention/loss, submit, branch update, review, CI materialization, interruption, and configured network conditions.
- **OGVCS-001-FR-09:** Every completed fixture SHALL contain a canonical manifest with request digest, file/operation counts, logical bytes, expected path/content/tree digests, group relationships, history shape, schema/tool versions, and license/provenance.
- **OGVCS-001-FR-10:** Generation SHALL stage into a tool-owned temporary area, publish the final manifest last, refuse an unsafe/non-empty destination unless an explicit compatible resume is proven, and never delete paths it did not create.
- **OGVCS-001-FR-11:** Interrupted generation SHALL resume from verified checkpoints or restart a damaged item deterministically; retry SHALL produce the same final logical manifest as an uninterrupted run.
- **OGVCS-001-FR-12:** Profile inputs derived from external measurements SHALL accept only reviewed aggregate parameters; the public fixture and manifest SHALL remain wholly synthetic and carry no source identifiers.

### Quality attributes

- **OGVCS-001-NFR-01:** Identical request documents MUST produce identical logical manifests, operation streams, path bytes, and content digests on supported Windows, macOS, and Linux environments.
- **OGVCS-001-NFR-02:** Generation and verification MUST stream large content and keep peak process memory below 1 GiB for the reference million-path/100-GiB profile, excluding operating-system filesystem cache.
- **OGVCS-001-NFR-03:** Normal operation MUST require no network access, commercial VCS, vendor service, privileged host access, or secret credential.
- **OGVCS-001-NFR-04:** Malformed profiles, extreme counts/sizes/depth, symlink destinations, path traversal, and destination races MUST fail within configured resource and workspace-safety bounds.

## Interfaces and data

Deliver the `ogvcs-fixture` executable, a reusable generator package, JSON Schema (or equivalently open schemas) for `FixtureRequest`, `WorkloadProfile`, `OperationScenario`, `FixtureManifest`, `GenerationCheckpoint`, and `VerificationResult`, plus versioned small golden bundles. Downstream PRDs consume schemas and manifests, never generator-private state.

## Development plan

1. **CLI and schemas:** implement command routing, canonical request/profile schemas, validation, safe destination preflight, machine output, and a minimal file-tree fixture.
2. **Deterministic primitives:** implement versioned PRNG, path/content/history generators, streaming digests, manifests, inspection, and verification with cross-platform golden tests.
3. **Game profiles:** implement and review the code-heavy, Unreal-like, Unity-like, large-binary, and global-studio profiles with small checked-in golden bundles.
4. **Scale and recovery:** add parameterized million-path/large-file generation, checkpoints/resume, fault tests, resource limits, planning estimates, and CI artifact handling.
5. **Consumer examples:** ship two black-box sample consumers—an object-mapping example and a workload-driver example—that use only public schemas/manifests; publish packages/documentation and freeze profile version 1.

Each slice is merged behind the fixture-tool package boundary. No slice changes a product repository format, and profile version 1 is not declared complete until all acceptance criteria pass.

## Acceptance criteria

- **OGVCS-001-AC-01:** A clean environment installs/builds the tool and generates/verifies every small profile using only documented commands and no network or commercial service.
- **OGVCS-001-AC-02:** Windows, macOS, and Linux runs of every small golden request produce identical canonical manifest, operation-stream, path, and content digests.
- **OGVCS-001-AC-03:** The reference scale request generates at least one million paths and a 100-GiB streaming mutable-file fixture within the approved disk/time envelope and below the 1-GiB process-memory ceiling.
- **OGVCS-001-AC-04:** Forced termination at each checkpoint resumes to the same final manifest as an uninterrupted run; corrupt checkpoints/items are detected and regenerated without accepting bad bytes.
- **OGVCS-001-AC-05:** Unsafe destination, traversal, symlink/junction escape, invalid schema, overflow, depth, disk-full, and concurrent-generator cases fail without overwriting unrelated files or publishing a complete manifest.
- **OGVCS-001-AC-06:** The bundled object-mapping and workload-driver examples consume every profile using only the installed CLI/public schemas/manifests and no fixture-tool internal package.

## Verification plan

Unit/property tests for deterministic primitives and schema bounds; cross-OS golden-digest jobs; filesystem-safety adversarial tests; kill/resume and disk-full injection; streaming memory/time benchmarks; manifest mutation tests; package installation tests; and black-box sample-consumer contract tests.

## Telemetry and operations

The CLI emits local structured progress, item/byte counts, safe error codes, resource use, and final manifest digest. It performs no analytics or automatic upload. CI decides retention/export, and diagnostics never include generated file bytes unless explicitly requested locally.

## Rollout and rollback

Publish an experimental schema/CLI with one small profile, then add profiles and scale support. Consumers pin tool/profile versions. A defective version is withdrawn without mutating existing fixtures; their manifests remain inspectable, and consumers regenerate with a fixed version/new manifest identity.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Synthetic profiles encode expected architecture | Neutral operation/schema boundary and external aggregate review outside PRD completion |
| Scale fixtures consume excessive contributor resources | `plan`, small presets, streaming generation, explicit quotas, scheduled scale jobs |
| Cross-OS APIs change generated identity | Project-owned canonical algorithms and golden digests independent of locale/host APIs |
| Resume publishes a mixed/corrupt fixture | Verified checkpoints, temporary staging, manifest-last publication |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
