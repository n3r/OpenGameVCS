# OGVCS-001 validation evidence

**Evidence date:** 2026-08-15
**Candidate:** `@opengamevcs/fixture-generator` 1.0.0 with built-in profiles 2.0.0
**Status:** Frozen implementation, macOS/Linux conformance, and reference scale passed; Windows execution evidence pending

## Candidate under test

- The distributable implementation, public API, CLI, schemas, goldens, examples, and operator documentation are under [`foundation/fixture-generator/`](../../../foundation/fixture-generator/).
- [ADR-0007](../../../adr/0007-fixture-profile-v2.md) records the reviewed v2 semantic contract and rejection of the deficient draft v1 profiles.
- The independent review record is [`docs/reviews/OGVCS-001-critical-review.md`](../../reviews/OGVCS-001-critical-review.md).
- The cross-platform conformance definition is [`.github/workflows/fixture-generator.yml`](../../../.github/workflows/fixture-generator.yml).

## Presubmit and package results

| Environment | Command | Result |
|---|---|---|
| macOS 26.6.1 arm64, Node 24.9.0 | `npm test --workspace @opengamevcs/fixture-generator` | 127 passed, 0 failed, 2 intentional skips; 114.28 s |
| Linux arm64, `node:22-bookworm`, network disabled, source mounted read-only | `docker run --rm --network none … npm test --workspace @opengamevcs/fixture-generator` | 127 passed, 0 failed, 2 intentional skips; 84.96 s |
| macOS and network-disabled Linux | `node foundation/fixture-generator/scripts/golden-summary.mjs` followed by `cmp` | Byte-identical summaries; SHA-256 `ca0949b76f9dcfb409148a41b588d4911af4c5b2135bc65a73821c193c61adb0` |
| macOS | `node prd/validate-roadmap.mjs && node --test prd/validate-roadmap.test.mjs` | Roadmap valid; 7 passed, 0 failed |

The ordinary suite includes all five plan/generate/inspect/deep-verify CLI flows, v2 semantic and feature-flag checks, nine schema contracts, golden vectors, mutation detection, portable Windows-name validation, every checkpoint sequence, request-bound initialization/publication receipts, corrupt-item recovery, nested unknown-content preservation, real competing processes, stale-lock/guard arbitration and interrupted control cleanup, stage replacement detection, no-replace destination reservation, manifest-free publication recovery, exact publication allowlists, persistence-boundary rollback, end-to-end resource budgets, coherent FileID/ACL/lock transitions, kind-specific operation contracts, complete-write handling, all large-file modes, request-derived sparse-extent verification, a streamed scenario above 100,000 operations, and package installation. The package test creates a tarball, installs it offline in a clean consumer, rejects private subpath imports, and runs both installed black-box examples against all five profiles. The two ordinary-suite skips are the separately executed reference-scale test and the Windows-only junction test on non-Windows hosts.

## Reference-scale result

Platform-neutral command (including the optional Linux CI job):

```sh
npm run test:scale --workspace @opengamevcs/fixture-generator
```

PowerShell invocation:

```powershell
npm.cmd run test:scale --workspace @opengamevcs/fixture-generator
```

The acceptance test reads the operating system's process high-water RSS counter after synchronous generation and verification, rather than relying on an event-loop sampling timer. The following macOS-only wrapper was used to launch the recorded run:

```sh
/usr/bin/time -l npm run test:scale --workspace @opengamevcs/fixture-generator
```

The frozen-candidate scale test passed 1/1 on macOS arm64. The inner portable command completed successfully; after that success, `/usr/bin/time -l` itself returned an environment-only error because its final `sysctl kern.clockrate` probe was sandbox-denied. The test's `process.resourceUsage().maxRSS` value is the authoritative operating-system high-water counter and all acceptance assertions had already passed.

| Measurement | Frozen-candidate result | Approved plan/requirement |
|---|---:|---:|
| Logical paths | 1,000,000 | at least 1,000,000 |
| Mutable logical file | 107,374,182,400 bytes (100 GiB), 3 versions | 100 GiB, 3 versions |
| Initial stream-verified materialization pass | 322,122,547,200 (300 GiB) | every byte of every version |
| Mandatory prepublication deep-verification pass | 322,122,547,200 (300 GiB) | every byte of every version |
| Standalone explicit-verification pass | 322,122,547,200 (300 GiB) | every byte of every version |
| Total large-version bytes hashed by the acceptance workflow | 966,367,641,600 (900 GiB) | three complete independent passes |
| Generation duration | 591.234 s | at most 2,731 s |
| Standalone verification duration | 320.687 s | at most 1,297 s |
| Complete acceptance workflow | 911.922 s | at most 4,028 s |
| OS high-water RSS | 705,937,408 bytes | at most 970,606,592 planned and below 1 GiB |
| Apparent artifact bytes | 528,381,540 | at most 1,398,310,912 planned durable bytes |
| Allocated artifact bytes | 536,903,680 | at most 1,398,310,912 planned durable bytes |
| Physical large-file bytes | 0 | stream-verified representation |

The scale request digest is `4bc6dd10cbf46657be264a6bd60dcc86caa1694a78b9a8d3d0fb2db391254bff`; the resulting manifest digest is `c05746cf75850d14e1d64de8ed17baffa9e432bab55c57051ab86be8ff094d55`. Neither the portable test nor the macOS wrapper substitutes for actual Windows execution evidence.

## Acceptance map

| Criterion | Current verdict | Evidence |
|---|---|---|
| OGVCS-001-AC-01 | Passed on macOS and clean network-disabled Linux | Full CLI profile matrix and offline packed-install test in the presubmit results above |
| OGVCS-001-AC-02 | Pending | macOS/Linux summaries are byte-identical and the Windows CI matrix is defined, but this workspace has no Windows runtime or connected remote on which to execute it |
| OGVCS-001-AC-03 | Passed on macOS | Frozen-candidate reference-scale measurements and digests above; the workflow hashes 300 GiB during initial generation, 300 GiB in the mandatory prepublication gate, and 300 GiB during explicit verification while retaining an index-only physical representation |
| OGVCS-001-AC-04 | Passed on macOS and network-disabled Linux | Initialization/publication interruption, every checkpoint, descriptor/control/mode corruption, resource-preserving retry, and deterministic recovery matrix in [`recovery-safety.test.mjs`](../../../foundation/fixture-generator/test/recovery-safety.test.mjs) |
| OGVCS-001-AC-05 | Passed on tested hosts; Windows junction execution pending | Workspace, containment, no-replace publication, process-concurrency, schema, resource, persistence, and mutation tests in [`recovery-safety.test.mjs`](../../../foundation/fixture-generator/test/recovery-safety.test.mjs), [`resource-budget.test.mjs`](../../../foundation/fixture-generator/test/resource-budget.test.mjs), [`path-validation.test.mjs`](../../../foundation/fixture-generator/test/path-validation.test.mjs), and [`verification-security.test.mjs`](../../../foundation/fixture-generator/test/verification-security.test.mjs) |
| OGVCS-001-AC-06 | Passed | Source and offline-installed package executions in [`examples.test.mjs`](../../../foundation/fixture-generator/test/examples.test.mjs) and [`package-contract.test.mjs`](../../../foundation/fixture-generator/test/package-contract.test.mjs) |

The independent re-review is recorded and finds no remaining source defect. OGVCS-001 nevertheless remains in `prd/todo` until AC-02 has actual Windows golden evidence and the Windows-only junction portion of AC-05 executes successfully. Workflow configuration alone is not represented as a passing Windows run.
