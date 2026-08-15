# OGVCS-001 — Deterministic workload fixture generator

**Completed:** 2026-08-15

**Release:** R0 — Engineering Foundation

**Package:** `@opengamevcs/fixture-generator` 1.0.0

**Profiles:** 2.0.0

**Frozen source:** [`d145faf1ed32d8bf6d3cfcd4e6433dc3384c9823`](https://github.com/n3r/OpenGameVCS/commit/d145faf1ed32d8bf6d3cfcd4e6433dc3384c9823)

## Delivered outcome

OpenGameVCS now has a distributable, network-independent fixture generator for reproducible format, path, storage, authorization, recovery, and performance work. Its CLI supports `list`, `plan`, `generate`, `inspect`, and `verify`; its package exposes the same bounded generation and verification primitives to programmatic consumers.

The release includes five deterministic workload profiles:

- `code-heavy` for deep/wide source trees, executable files, text history, branches, merges, moves, copies, and deletes;
- `unreal-like` for package/map analogues, external actors and sidecars, source/config paths, large-file churn, and lock conflicts;
- `unity-like` for asset/`.meta` groups, synthetic GUID relationships, scene/prefab analogues, imports, exclusions, moves, and explicit negative cases;
- `large-binary` for deterministic random-access content, compression classes, locality, duplication, sparse/full/virtual/stream-verified representations, and version reuse;
- `global-studio` for ordered selective-sync, lock, submit, branch-update, review, CI, interruption, ACL, and network-condition scenarios.

## Public contract

The package ships nine closed JSON Schemas for fixture requests, workload profiles, inventory records, group relationships, large-file descriptors, operation scenarios, manifests, checkpoints, and verification results. Generated artifacts are runtime-validated against those schemas, and the verifier adds normative cross-record semantic checks that JSON Schema cannot express.

Canonical request, content, FileID, operation, group, history, manifest, and digest derivations are versioned and independent of locale, clock, host, traversal order, scheduler, and OS randomness. Golden requests pin generator, profile, feature, scale, and schema versions. Git attributes require LF checkout for canonical text bytes on every platform.

Profile `1.0.0` is intentionally unsupported. Independent review found that draft semantically deficient, so [ADR-0007](../../adr/0007-fixture-profile-v2.md) establishes `2.0.0` as the first acceptance contract. Identity-affecting corrections require a future profile/schema version; they may not silently redefine v2.

## Reliability and safety

Generation uses conservative planning and one end-to-end resource ledger for duration, memory headroom, written bytes, durable bytes, parser bounds, and physical representation. Large content is generated and verified in bounded chunks without holding a complete version in memory.

Workspace publication is request-bound and manifest-last. The implementation uses atomic lock candidates, stale-guard recovery epochs, durable initialization/publication receipts, exact artifact allowlists, nested materialization proofs, no-replace hard-link publication, prepublication deep verification, and post-commit acknowledgement semantics. Compatible resume validates checkpoint-owned controls and regenerated artifacts; deterministic corruption restarts only proven generated state, while resource/host errors and unknown content remain preserved and fail closed.

Portable relative-path validation rejects absolute, drive, UNC, traversal, backslash, reserved DOS-device, ADS, forbidden-character, Unicode-control, non-NFC, unpaired-surrogate, trailing-dot/space, and component/full-path limit violations. Runtime safety also rejects symlink/junction escapes and ancestor/destination identity replacement within the documented same-authority workspace boundary.

## Independent-review remediation

The first candidate was not accepted. The [critical review](../reviews/OGVCS-001-critical-review.md) found inert profile flags and label-only semantics, dangling groups, schema/runtime drift, shallow verification, unsafe resume/publication cases, incomplete recovery and resource bounds, and missing installed-consumer evidence. Those findings drove profile/schema v2, coherent history/FileID/ACL/lock state, exact schema closure, streaming replay, bounded parsers, request-derived sparse verification, durable recovery/publication protocols, real-process concurrency and fault tests, and offline installed examples.

Actual Windows execution then exposed three additional portability gaps:

1. The 100,001-operation security test needed a realistic cross-platform timeout while retaining its complete workload and assertions ([`f9501ec`](https://github.com/n3r/OpenGameVCS/commit/f9501ecac95d706b66fb3cd45634742f8cee8b51)).
2. Windows checkout converted canonical golden text to CRLF; project-wide detected text now checks out as LF and raw-byte assertions remain strict ([`38cb3da`](https://github.com/n3r/OpenGameVCS/commit/38cb3dab34969e86a710e8bac480ce544b794d70)).
3. Direct `npm.cmd` spawning failed through Windows CreateProcess; npm-run children now use Node with npm's JavaScript entry point, with a narrow standalone fallback ([`d145faf`](https://github.com/n3r/OpenGameVCS/commit/d145faf1ed32d8bf6d3cfcd4e6433dc3384c9823)).

The final independent pass found no residual P0, P1, or P2 implementation or CI defect and marked FR-01–FR-12, NFR-01–NFR-04, and AC-01–AC-06 Pass.

## Validation evidence

- Exact frozen source on macOS: 128 passed, 0 failed, and 2 intentional skips in the fixture suite; 7/7 roadmap tests passed.
- Network-disabled Linux with read-only source: 127 passed, 0 failed, and 2 intentional skips on the pre-portability-fix product source; the exact final source subsequently passed the hosted Ubuntu suite.
- [GitHub Actions run 31863924721](https://github.com/n3r/OpenGameVCS/actions/runs/31863924721): exact frozen SHA passed full Windows, macOS, and Ubuntu suites; the dedicated Windows portable-path/junction test passed; all golden artifacts uploaded; Linux = macOS and Linux = Windows byte comparisons passed.
- The independently downloaded Windows, macOS, and Linux summary content is identical with SHA-256 `ca0949b76f9dcfb409148a41b588d4911af4c5b2135bc65a73821c193c61adb0`.
- Reference scale: 1,000,000 logical paths; three 100-GiB versions; 900 GiB hashed across generation, mandatory prepublication verification, and explicit standalone verification; 911.922 seconds total; 705,937,408-byte OS high-water RSS; no physical large-file bytes in stream-verified mode.
- Offline tarball installation, private-subpath rejection, and both installed black-box consumers passed for all five profiles.

The complete measurements, digests, hosted job IDs, and artifact archive digests are in the [evidence packet](../evidence/OGVCS-001/README.md) and its [machine-readable run record](../evidence/OGVCS-001/github-actions-run-31863924721.json).

## Operator and downstream impact

Downstream R0 work should pin package `1.0.0`, profile `2.0.0`, and the expected schema-version map. Consumers must use package-root exports and packaged schemas/manifests, never private `src/*` modules. The fixture path normalizer is a portable test baseline, not the final repository path policy owned by OGVCS-004.

The reference scale result is a logical/index-only and fully streamed workload. It proves deterministic million-path inventory and complete byte derivation/verification for three 100-GiB versions below the memory ceiling; it does not claim physical creation of one million inodes or three 100-GiB files. Full and sparse modes remain available when physical filesystem behavior is the subject of a bounded test.

Caller-supplied seeds and destinations are stored as uninspected request metadata. Operators must not place partner, customer, credential, or other sensitive identifiers in them. Generated fixture paths, identities, bytes, groups, and operations are wholly synthetic.

## Rollback and compatibility

The package remains an R0 foundation artifact rather than a production repository format. If version 1.0.0 is found defective before broader release, withdraw that package version and publish a corrected tool/profile/schema version; do not reinterpret existing v2 identities in place. Completed fixtures retain their request and manifest identities and remain inspectable with the implementation that created them. Consumers regenerate explicitly after upgrading and compare the new manifest identity before replacing evidence or cached fixtures.
