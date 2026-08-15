# ADR-0007: Replace the deficient fixture profile v1 draft with v2

**Status:** Accepted
**Date:** 2026-08-15
**Owners:** OGVCS-001

## Context

The first OGVCS-001 implementation draft emitted profile `1.0.0` goldens before independent acceptance review. The review proved that those named profiles were not faithful workload contracts: several feature flags were inert, profile-specific file semantics were absent, history and lock operations were labels rather than coherent state transitions, Unity negative relationships were incorrect, large-file versions had no derived version content, and group references dangled above an implementation cap.

Changing those outputs under the same profile version would make an existing request resolve to different logical paths, content digests, operations, groups, and manifests. That would violate the architecture's canonical-identity and version-pinning rules even though the draft was not released or committed.

## Decision

- The deficient profile `1.0.0` draft is abandoned and is not a supported alias.
- The first acceptance candidate for all five built-in profiles is `2.0.0`.
- Profile v2 defines behaviorally effective feature flags, profile-specific structured/binary content, coherent operation parameters and identity/ACL fixtures, bounded group relationships, and versioned large-file content semantics.
- The generator package remains `1.0.0`. Five pre-existing envelope schema identifiers remain `v1`: `FixtureRequest`, `WorkloadProfile`, `FixtureManifest`, `GenerationCheckpoint`, and `VerificationResult`. `OperationScenario` is identified as `v2` because its kind-discriminated parameters, FileID/path state, authorization proof, expected outcomes, and lock semantics are an incompatible replacement for the generic draft contract. The newly public inventory-record, group-relationship, and large-file-descriptor contracts are also identified as `v2` because they normatively expose the repaired semantic model.
- The deterministic content-stream algorithm is independently named/versioned in descriptors. A changed byte algorithm never reuses the v1 algorithm identifier.
- A request that explicitly names profile `1.0.0` fails as unsupported. Users regenerate draft fixtures with an explicit/current `2.0.0` request; completed fixtures remain inspectable only with the implementation that created them.

## Consequences and proof

Golden requests, examples, CLI help, documentation, and reference-scale evidence must all name profile `2.0.0`. Downstream R0 PRDs pin v2 and may not assume compatibility with draft v1 output. Future identity-affecting repairs require another profile or schema version rather than an in-place digest change. The OGVCS-001 golden-conformance and package-consumer suites are the compatibility proof; rollback is removal of the unreleased package rather than reinterpretation of v1 data.
