# OGVCS-002 validation evidence

**Evidence date:** 2026-08-16
**Candidate:** repository-format-v1 0.1.0, `@opengamevcs/object-model` 0.1.0, and `ogvcs-object-model` 0.1.0
**Status:** Candidate evidence only; not frozen or complete

## Evidence boundary

This packet records the settled MIT-licensed ordinary candidate at clean commit
`6295cb54b29bc5a9ac6dadf34bc2c52a337eba49`. Local packed conformance and
[hosted run 31927048636](https://github.com/n3r/OpenGameVCS/actions/runs/31927048636)
passed; the hosted run retained clean packed artifacts and byte-identical shared
JavaScript/Rust results from Linux, macOS, and Windows. It deliberately does not
claim completion. On 2026-08-16 the maintainer explicitly deferred both
exact-scale rows to the final R0 campaign; neither workload was run for this
candidate milestone, and the hosted scale job is recorded as skipped.

The machine-readable candidate record is
[`candidate-2026-08-16.json`](candidate-2026-08-16.json).

The independent review is
[`docs/reviews/OGVCS-002-critical-review.md`](../../reviews/OGVCS-002-critical-review.md).
The three-platform and optional exact-scale workflow is
[`.github/workflows/object-model.yml`](../../../.github/workflows/object-model.yml).

## Frozen language-neutral authority

| Authority | Candidate value |
|---|---:|
| Format version | 1 |
| Registry-set SHA-256 | `6f7a67eb9616cf380d67fec07d5483abb361ef1fbee05227a6f07f39f27f8585` |
| Packaged registries | 12 |
| Reference-vector artifacts | 1,236 |
| Coverage obligations | 148 |
| Scenario envelopes | 235 |
| Stable error codes | 81 |
| Legal `(code, layer, stage)` sites | 94 |
| Ordered validation stages | 10 |
| Single-bit mutation executions per language | 58,520 |
| Proper-prefix truncations per language | 7,303 |
| Executable hard-limit max/max-plus-one cases | 50 across 25 families |

The inventory, manifests, generator provenance, registry assignments,
seed/preimage calculations, scenarios, error sites, and hard-limit relationships
are independently checked by
[`tools/verify-reference-vectors.mjs`](../../../tools/verify-reference-vectors.mjs),
which does not import either codec.

## Local candidate environment

- macOS 26.6.1 (25G76), arm64
- Node.js 24.9.0 and npm 11.6.0
- Rust 1.82.0 (`f6e511eec`, the declared MSRV and CI toolchain)
- Package and conformance executions use packed local artifacts and
  locked/offline dependency resolution.

## Ordinary presubmit results

| Command/gate | Current result |
|---|---|
| `npm test` | Passed. Fixture generator: 128 passed, 0 failed, 2 intentional skips. JavaScript: 164/164. Specification: 32/32. Vector audit: 1/1. Roadmap: 7/7. Report tooling: 2/2. |
| JavaScript mutation execution | Passed all 58,520 cases: 50,360 source, 2,832 bundle-item, and 5,328 whole-sequence mutations. |
| `cargo +1.82.0 test --locked --offline --all-targets --all-features` | Passed every ordinary Rust test; the single exact-scale test was intentionally ignored. This includes all mutations, truncations, and the scenario report. |
| `cargo +1.82.0 fmt --all -- --check` | Passed. |
| `cargo +1.82.0 clippy --locked --offline --all-targets --all-features -- -D warnings` | Passed. |
| Rust package and offline-distribution gates | Passed package verification and reproducible offline-distribution smoke/verification. |
| MIT package contract | Passed: repository, fixture, JavaScript, format, Rust crate, and offline bundle contain byte-identical MIT text and matching metadata. |
| Generator/spec/vector hygiene | Generator `--check`, spec validation, vector audit, workflow YAML parse, and `git diff --check` passed. |

The suites exercise canonical CBOR/identity, every schema and registry family,
repository closure/replay, FileID/groups/conflicts/shelves/provenance, manifests,
ordered and externally sorted trees, logical bundles, CLI operations, fixture
adaptation, hostile resource boundaries, scratch replacement, and package-only
consumers.

## Source and scenario comparison

| Implementation | Applicable execution | Result SHA-256 |
|---|---:|---|
| JavaScript | 233 executed, 2 exact-scale inventory, 0 failed | `186274844e6ae6c88c08251fe60dfbd613c413f87795e5560a9813acc04b983a` |
| Rust | 228 executed, 5 JavaScript-only N/A, 2 exact-scale inventory, 0 failed | `bd60af109a1bd449b45b89cd21c005a225e40062d53800c6478a0e8cb54cec97` |

Applicability-specific rows are excluded from the shared projection. All 230
shared rows produce conformance SHA-256
`14b34af82edc216f2d406f66cb21fe877c6e9d1c0e33b62c807ff9fbe88a15a6`.
Every executed rejection matches its actual code, layer, and stage.

## Clean packed-artifact and hosted run

[`tools/run-packed-object-model-conformance.mjs`](../../../tools/run-packed-object-model-conformance.mjs)
created fixture, JavaScript, and format tarballs; installed them offline in a
clean consumer; packaged and ran Rust; executed both scenario sets; and retained
the exact four archives beside both reports and their comparison.

| Retained archive | Hosted SHA-256 |
|---|---|
| `opengamevcs-fixture-generator-1.0.0.tgz` | `3096bb6418a774e8f0757377e4b0453adae5e53ad8c37a2a51563d4c77634b93` |
| `opengamevcs-object-model-0.1.0.tgz` | `edc36039532160f338e1e668d12ed71ba608e00afec6259ee6aca37ed8207034` |
| `opengamevcs-repository-format-v1-0.1.0.tgz` | `2f5876de7479c981c3bd014c0b2cce7b8688631a6c2f20fce45a635c745768cc` |
| `ogvcs-object-model-0.1.0.crate` | `7d669e86d11be5aa0adaeca7bea2f9377327c24f4ad672b0cc12a6e3a0e88993` |

The hosted files were downloaded, independently re-hashed, and matched the
packed comparison record. The ordinary platform jobs and comparison succeeded:

| Hosted job | Job ID | Result |
|---|---:|---|
| macOS conformance | `95116145193` | Passed |
| Windows conformance | `95116145203` | Passed |
| Linux conformance and packed proof | `95116145212` | Passed |
| Six-report cross-platform comparison | `95118086164` | Passed |
| Exact bounded-scale evidence | `95118105085` | **Skipped by maintainer decision** |

GitHub retained the platform reports, their comparison, the four-archive packed
proof, the standalone format tarball, and the Rust offline distribution. Exact
artifact IDs, GitHub archive digests, expiry times, and inner package hashes are
recorded in the machine-readable candidate record.

## Acceptance map

| Criterion | Candidate evidence | Status |
|---|---|---|
| OGVCS-002-AC-01 | Golden object/logical/bundle and typed-reference results agree across source and packed implementations on all three hosted platforms. | Hosted candidate pass |
| OGVCS-002-AC-02 | Ordered and bounded-sort implementations plus packaged CLI smoke pass at reduced scale. | **Incomplete: exact one-million-entry run pending** |
| OGVCS-002-AC-03 | 58,520 mutations execute independently in both languages. | Local pass |
| OGVCS-002-AC-04 | Installed adapter processes all five profile-v2 corpora; native semantic cases run separately. | Local pass |
| OGVCS-002-AC-05 | Public packed artifacts need no service/private import and ship byte-identical MIT license text. | Local pass |
| OGVCS-002-AC-06 | Root/parent/merge/closure/cycle scenarios execute in both languages. | Local pass |
| OGVCS-002-AC-07 | FileID transition/allocation/restore/import/concurrency cases execute in both languages. | Local pass |
| OGVCS-002-AC-08 | Malformed, truncation, hard-limit, and configured-resource cases execute with exact diagnostics. | Local pass |
| OGVCS-002-AC-09 | Ordinary manifest and repeated-content streaming cases agree. | **Incomplete: exact logical-1-TiB run pending** |
| OGVCS-002-AC-10 | Bundle ordering, identity, transcript, accounting, closure, and claim-boundary cases agree. | Local pass |
| OGVCS-002-AC-11 | Registry shape, immutability, lifecycle, and forward-preservation cases agree. | Local pass |
| OGVCS-002-AC-12 | OS-entropy allocation and collision/exhaustion cases pass in both languages on Linux, macOS, and Windows. | Hosted candidate pass |

## Required final evidence

Before this packet can be marked complete:

1. during the final R0 campaign, run the maintainer-deferred million-entry/1-TiB
   Linux release-scale job and retain both language reports and their comparison;
2. publish the final versioned artifacts with durable retention and add the scale
   measurements and final publication identities to the machine-readable record;
3. update the PRD completion map, changelog, architecture/ADR statuses, and review
   verdict only after all preceding evidence passes.

No repository path, payload, FileID, extension value, fixture seed, credential,
or customer identifier is included in the conformance summaries. Reports expose
only version/platform/runtime data, counts, stages, stable error codes, bounded
resource measurements, and cryptographic identities required for reproducibility.
