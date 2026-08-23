# OGVCS-002 validation evidence

**Evidence date:** 2026-08-21

**Boundary update:** 2026-08-23

**Candidate:** repository-format-v1 0.1.0, `@opengamevcs/object-model` 0.1.0, and `ogvcs-object-model` 0.1.0

**Status:** Ordinary validation candidate passed; final `Done` gates remain open

## Evidence boundary

This packet records the frozen MIT-licensed ordinary candidate at source revision
`3aba34da7c75a1fc9120476873ee90e382aaab80`. The pinned Node 22 and Rust 1.82
[hosted run 32420451840](https://github.com/n3r/OpenGameVCS/actions/runs/32420451840)
builds, tests, lints, packages, and reports the source on Linux, macOS, and
Windows. Linux additionally rebuilds and runs the exact retained fixture,
JavaScript, format, and Rust archives in a clean offline consumer. The six
platform reports have one identical shared projection.

This evidence advances OGVCS-002 to `Validation`; it does not mark the PRD
`Done` or ratify production writing. By maintainer decision, the exact
one-million-entry tree and logical-1-TiB manifest remain unaccepted,
authenticated inventory rows for the final R0 campaign. No reduced, partial,
or interrupted scale result is presented as a substitute.

The machine-readable candidate record is
[`candidate-2026-08-21.json`](candidate-2026-08-21.json). The independent review
is [`docs/reviews/OGVCS-002-critical-review.md`](../../reviews/OGVCS-002-critical-review.md),
and the three-platform workflow is
[`.github/workflows/object-model.yml`](../../../.github/workflows/object-model.yml).
The deferred workloads are isolated in the manually dispatched or release-tagged
[`object-model-scale.yml`](../../../.github/workflows/object-model-scale.yml)
workflow; it has no pull-request, branch-push, or scheduled trigger.
Manual dispatch requires an explicit `confirm_exact_scale` selection; the
default does not start the billed runner job.
The historical 2026-08-16 candidate remains beside this packet for provenance;
it is not the current authority.

## Frozen language-neutral authority

| Authority | Frozen value |
|---|---:|
| Format version | 1 |
| Reference-vector manifest SHA-256 | `2d0acb01a01b64c23d883d855d2802d939a8dc99622f2774de07af1c8af8d2b9` |
| Scenario-index SHA-256 | `9602b91fcac449cb420e718739e5a1a1a2059ec7872422e7bf3cdd72c727c078` |
| Coverage-matrix SHA-256 | `c5aeef73d2da337a3a250fd8c035adffb69adf33eccf30c6d42189969b83a1bf` |
| Generator-source SHA-256 | `3ef48c1c30469adaa13583e987af46fd1d2f8d04cec72e29a5f8a6ffcd3da95d` |
| Independent-auditor SHA-256 | `365d22c6f7727ed6cbb49a66fcb0eddc6c4b6739e7e15c134d26fdd5bcb25b01` |
| Registry-set SHA-256 | `6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6` |
| Packaged registries | 12 |
| Reference-vector artifacts | 2,815 |
| Coverage obligations | 486 |
| Scenario envelopes | 573: 550 shared, 23 JavaScript-only |
| Stable error codes / legal sites / ordered stages | 81 / 94 / 10 |
| Single-bit mutations / proper-prefix truncations | 58,520 / 7,303 |
| Unicode 15 compact table SHA-256 | `f720e60157290e8714986679b54f8f49ce2c863146873dc5bda491d2d44a38b2` |
| Unicode DerivedAge source SHA-256 | `7570877e0fa197c45338f7c41a02636da4e14c8dba6a3611a01cd30bf329d5ca` |

The generator `--check`, specification validator, and
[`tools/verify-reference-vectors.mjs`](../../../tools/verify-reference-vectors.mjs)
independently reproduce these identities. The auditor does not import either
codec and rejects byte drift, coverage drift, dishonest applicability, missing
route execution, or refreshed self-consistent inventory forgery.

## Ordinary local and hosted gates

The local bounded environment was macOS 26.6.1 arm64 with Node.js 24.9.0 and
npm 11.6.0. Rust is intentionally proved in hosted CI because the local host
does not carry a Rust toolchain.

| Gate | Result |
|---|---|
| Full root `npm test` | Passed, including 128/130 fixture tests with two intentional platform/scale skips, all 180 JavaScript object-model tests, all 58,520 mutation executions, dependent R0 contract suites, roadmap 7/7, and report comparison 2/2. |
| Specification validation and mutation | Passed: current specification valid and 59/59 independent mutation checks rejected. |
| Vector generation and audit | Passed: generator `--check`, independent 2,815/573/486 audit, and tamper test 1/1. |
| Protocol predecessor binding | Passed: 92 contract and 29 binding artifacts regenerate byte-for-byte with the exact OGVCS-002 manifest pin. |
| JavaScript scenario report | Passed: 571 executed, two exact-scale inventory rows, zero failed. |
| Rust 1.82 source gate | Passed on Linux, macOS, and Windows: formatting, tests, `clippy -D warnings`, package build, registry/Unicode sync, and offline distribution. |
| Packed Linux consumer | Passed from retained local archives with no repository-private runtime import or network dependency. |
| Cross-platform comparison | Passed for JavaScript and Rust source reports from all three operating systems. |
| Diff and package hygiene | `git diff --check`, MIT package contracts, distribution manifests, and bounded package dry-runs passed. |

The fresh hosted campaign found and closed two Windows-specific defects before
this passing candidate. Native recursive tree semantics overflowed the Windows
main thread; revision `1fd680d9d0a522cc6a810c48df969ff8ec4af0a1` replaced it with a
resource-charged explicit DFS stack. The next two runs proved that two complete
offline Cargo builds can exceed both five and ten minutes on Windows without a
semantic failure. Revision `3aba34da7c75a1fc9120476873ee90e382aaab80`
retains a finite fifteen-minute platform allowance beneath the workflow's
45-minute outer deadline.

## Source and packed conformance

| Implementation | Applicability | Scenario result SHA-256 | Implementation conformance SHA-256 |
|---|---:|---|---|
| JavaScript | 571 executed, 2 inventory, 0 failed | `7eeb9091263530ac5f8703adb58de71f536d96f9a541f914b7b9f6e50864d153` | `bafc5f21123cfb1d5a953f3fe035c43741931755b6ac0a41c0356f5d1d52bd07` |
| Rust | 548 executed, 2 inventory, 23 N/A, 0 failed | `56a2ae15e69c4e3e0cac954fd7655c79692cde5119ee92c52ffaeba6b68b2dee` | `408f8c1e22a2385adde5753c77075ec5677acedcbc70ba31ef51a1b4d30fd877` |

All 550 shared rows, including the same two inventory declarations, produce
normalized shared conformance SHA-256
`51d671c4622c14c29aa5b291cc49c4832dc598589438560e2d5e633bab21785a`.
The 23 JavaScript-only rows are limited to the PRD-assigned fixture adapter plus
host-shape and raw carriers that Rust's closed public types cannot represent;
all malformed byte-materialized carriers representable by Rust are shared.

The retained Linux packed comparison independently re-hashes the exact archives:

| Retained archive | SHA-256 |
|---|---|
| `opengamevcs-fixture-generator-1.0.0.tgz` | `3096bb6418a774e8f0757377e4b0453adae5e53ad8c37a2a51563d4c77634b93` |
| `opengamevcs-object-model-0.1.0.tgz` | `009275ba22ced3fe973ee5b160ce088e25e0c2d6668068fc95e7a4174ec69f9a` |
| `opengamevcs-repository-format-v1-0.1.0.tgz` | `6f11a958b1a7723df8bea1affbd5a274566d5cbef4fb5ec8ab56e71572059cea` |
| `ogvcs-object-model-0.1.0.crate` | `77cce81e26dc5a65b2bc28b87ed3eafb27b22e8b37a6fe7a61a5d06b32a5cc6a` |

GitHub retains the platform reports, six-report comparison, four-archive packed
proof, standalone format package, and Rust offline distribution. Exact job IDs,
artifact IDs, GitHub archive digests, sizes, and expiry times are bound in the
machine-readable candidate record.

## Acceptance map

| Criterion | Validation evidence | Verdict |
|---|---|---|
| OGVCS-002-AC-01 | Golden object, logical-record, bundle, and reference outcomes agree between both clean-room implementations, source and packed. | Pass |
| OGVCS-002-AC-02 | Ordered and bounded-sort paths pass ordinary and reduced-resource tests. | **Incomplete: exact one-million-entry proof deferred** |
| OGVCS-002-AC-03 | Both public implementations execute all 58,520 mutations. | Pass |
| OGVCS-002-AC-04 | The installed adapter processes all five fixture profiles; native repository routes run separately. | Pass |
| OGVCS-002-AC-05 | Public packages require no private service, schema, credential, or proprietary module and ship byte-identical MIT terms. | Pass |
| OGVCS-002-AC-06 | Root, parent, merge, closure, replay, and cycle cases execute through public routes. | Pass |
| OGVCS-002-AC-07 | FileID transition, allocation, restore, import, collision, rollback, and concurrency cases execute. | Pass |
| OGVCS-002-AC-08 | Malformed, truncation, hard-limit, resource, callback, scratch, and combined-invalid cases have exact typed outcomes and no trusted partial state. | Pass |
| OGVCS-002-AC-09 | Ordinary empty, repeated, multi-part, corrupt, ceiling, profile, and annotation manifest cases agree. | **Partially pass: exact logical-1-TiB proof deferred** |
| OGVCS-002-AC-10 | Bundle order, identity, transcript, accounting, closure, resource, and forbidden-claim boundaries agree. | Pass |
| OGVCS-002-AC-11 | Registry shape, immutability, family, lifecycle, forward-preservation, and feature behavior agree. | Pass |
| OGVCS-002-AC-12 | Entropy, zero rejection, injected collision, and exhaustion cases pass in both languages on all three hosted operating systems. | Pass |

## Deferred Done gates

Two later diagnostic attempts do not change this evidence boundary. Run
`32441880044` completed the JavaScript exact work and proved that Rust emitted
the same million-entry tree payload SHA-256
`2b13fa2c05a014ecc14a2d0e3db3adee5f828f9aa7e223c45357f3ac52d36681`,
but stopped on a stale Rust test oracle before its 1-TiB work and the required
comparison. Commit `7b4baa0` corrected that test-only constant. Corrected run
`32447152568` passed all ordinary three-platform jobs and their six-report
comparison, then was cancelled at maintainer request during the opt-in scale
job. Neither run supplies a complete retained two-language scale comparison.

Before OGVCS-002 can move to `prd/done`:

1. Run the authenticated `tree-million-entries` and `manifest-one-tib` rows in
   the final R0 campaign, retaining both language reports and their comparison,
   wall time, peak RSS, scratch high-water, processed entries/bytes, and stable
   identities.
2. Publish the final versioned artifacts under durable release retention and
   record their immutable publication identities. Current GitHub Actions
   artifacts are candidate validation evidence, not final release publication.
3. Reconcile the final scale and publication evidence into this packet, the
   PRD acceptance map, changelog, and review before changing `Validation` to
   `Done` or enabling production format-v1 writes.

ADRs 0008, 0009, and 0010 are already `Accepted`; ADR status is not an open
gate. No repository path, payload, FileID, extension value, fixture seed,
credential, or customer identifier is included in conformance summaries.
Reports contain only bounded counts, stages, stable errors, platform/runtime
metadata, resource measurements, and cryptographic identities needed for
reproduction.
