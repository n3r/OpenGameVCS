# OGVCS-002 completion evidence

**Evidence date:** 2026-08-24

**Completed artifacts:** `@opengamevcs/repository-format-v1` 0.1.0, `@opengamevcs/object-model` 0.1.0, and `ogvcs-object-model` 0.1.0

**Status:** Completed; ratified-package ordinary/packed and exact-implementation evidence passed

## Evidence boundary

This packet deliberately binds two source boundaries. The
[exact implementation revision `9d85d6e`](https://github.com/n3r/OpenGameVCS/commit/9d85d6ee959e47f8f65bca19c4ebb35687c39029)
contains the optimized JavaScript and Rust implementations. The
[ratified package revision `45d98fe`](https://github.com/n3r/OpenGameVCS/commit/45d98fe5adfff02e10745a0501123b30e56371bb)
adds only the three verbatim exact reports and format-status prose; no
implementation, CDDL, schema, registry, vector, preimage, or canonical-byte rule
changes between those revisions.

Pinned Node 22 and Rust 1.82
[ordinary run 32719990180](https://github.com/n3r/OpenGameVCS/actions/runs/32719990180)
builds, tests, lints, packages, and reports the ratified package revision on
Linux, macOS, and Windows. Linux additionally rebuilds and runs the retained
fixture, JavaScript, format, and Rust archives in a clean offline consumer. The
six platform reports have one identical shared projection. Workflow helper
actions are immutable Node 24-compatible releases; Node 22 remains the tested
library/CLI runtime rather than an accidental action-runtime upgrade.

The maintainer-authorized [exact run 32714126083](https://github.com/n3r/OpenGameVCS/actions/runs/32714126083)
uses the exact implementation revision. JavaScript and Rust independently execute the
one-million-entry tree and content-verified logical-1-TiB manifest, after which
the comparator requires one source revision, byte-identical identities and
outputs, the installed packaged CLI proof, and every RSS/scratch high-water
below 1 GiB. All three jobs passed. No reduced, extrapolated, partial, or
interrupted workload is presented as exact evidence.

The machine-readable completion record is
[`completion-2026-08-24.json`](completion-2026-08-24.json). The exact
[JavaScript](exact-scale-javascript-2026-08-24.json),
[Rust](exact-scale-rust-2026-08-24.json), and
[comparison](exact-scale-comparison-2026-08-24.json) reports are checked in
byte-for-byte, so the proof survives expiry of the corresponding Actions
archives. Earlier candidate records remain unchanged beside this packet as
historical provenance; they are not the completion authority.

The independent review is
[`docs/reviews/OGVCS-002-critical-review.md`](../../reviews/OGVCS-002-critical-review.md),
and the ordinary three-platform workflow is
[`.github/workflows/object-model.yml`](../../../.github/workflows/object-model.yml).
The exact workloads are isolated in the manually dispatched or release-tagged
[`object-model-scale.yml`](../../../.github/workflows/object-model-scale.yml)
workflow; it has no pull-request, branch-push, or scheduled trigger.
Manual dispatch requires an explicit `confirm_exact_scale` selection; the
default does not start the billed runner job.
When authorized, the JavaScript and Rust exact jobs run concurrently and upload
separate reports. A dependent comparison job downloads both, verifies the
source/identity/resource contract, and publishes the combined artifact. The
parallel layout shortens elapsed campaign time but does not reduce the sum of
billed runner minutes. Exact scale remains a manual monthly/major-release gate,
not a pull-request or ordinary-push workload.

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
| Protocol predecessor binding | [Run 32719990210](https://github.com/n3r/OpenGameVCS/actions/runs/32719990210) passed on Linux, macOS, and Windows: 92 contract and 29 binding artifacts regenerate byte-for-byte with the exact OGVCS-002 manifest pin. |
| JavaScript scenario report | Passed: 571 executed, two exact-scale inventory rows, zero failed. |
| Rust 1.82 source gate | Passed on Linux, macOS, and Windows: formatting, tests, `clippy -D warnings`, package build, registry/Unicode sync, and offline distribution. |
| Packed Linux consumer | Passed from retained local archives with no repository-private runtime import or network dependency. |
| Cross-platform comparison | Passed for JavaScript and Rust source reports from all three operating systems. |
| Diff and package hygiene | `git diff --check`, MIT package contracts, distribution manifests, and bounded package dry-runs passed. |

Earlier hosted attempts found and closed a Windows main-thread stack overflow
and undersized offline-Cargo step allowances. Current run `32719990180` proves
the explicit bounded traversal and finite fifteen-minute platform allowance on
all three operating systems beneath the workflow's 45-minute outer deadline.

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
| `opengamevcs-repository-format-v1-0.1.0.tgz` | `eaf2ad8e45e4cbac32a107606c6fb8d65b415b5aea1378202c2eefb081200d6a` |
| `ogvcs-object-model-0.1.0.crate` | `679880e40b6ed6d48e9eea61675520f365bc610eafb1b8c501afe652be8fd293` |

GitHub retains the platform reports, six-report comparison, four-archive packed
proof, standalone format package, and Rust offline distribution. Run/job IDs,
artifact archive digests, exact archive identities, sizes, and expiry times are
bound in the machine-readable completion record. The public version-controlled
package sources, source-bound retained archive hashes, reproducible package
contents, and clean offline consumer proof satisfy the durable package boundary;
external npm/crates/GitHub Release publication is not claimed or required by
this PRD.

## Acceptance map

| Criterion | Validation evidence | Verdict |
|---|---|---|
| OGVCS-002-AC-01 | Golden object, logical-record, bundle, and reference outcomes agree between both clean-room implementations, source and packed. | Pass |
| OGVCS-002-AC-02 | Exact implementation run 32714126083 proves ordered and bounded disk-sort library paths plus the offline-installed packaged CLI on the byte-identical million-entry tree, with every RSS/scratch value below 1 GiB. | Pass |
| OGVCS-002-AC-03 | Both public implementations execute all 58,520 mutations. | Pass |
| OGVCS-002-AC-04 | The installed adapter processes all five fixture profiles; native repository routes run separately. | Pass |
| OGVCS-002-AC-05 | Public packages require no private service, schema, credential, or proprietary module and ship byte-identical MIT terms. | Pass |
| OGVCS-002-AC-06 | Root, parent, merge, closure, replay, and cycle cases execute through public routes. | Pass |
| OGVCS-002-AC-07 | FileID transition, allocation, restore, import, collision, rollback, and concurrency cases execute. | Pass |
| OGVCS-002-AC-08 | Malformed, truncation, hard-limit, resource, callback, scratch, and combined-invalid cases have exact typed outcomes and no trusted partial state. | Pass |
| OGVCS-002-AC-09 | Ordinary empty, repeated, multi-part, corrupt, ceiling, profile, and annotation cases agree; exact implementation run 32714126083 retains the content-verified byte-identical logical-1-TiB result. | Pass |
| OGVCS-002-AC-10 | Bundle order, identity, transcript, accounting, closure, resource, and forbidden-claim boundaries agree. | Pass |
| OGVCS-002-AC-11 | Registry shape, immutability, family, lifecycle, forward-preservation, and feature behavior agree. | Pass |
| OGVCS-002-AC-12 | Entropy, zero rejection, injected collision, and exhaustion cases pass in both languages on all three hosted operating systems. | Pass |

## Exact campaign and completion boundary

Exact implementation run `32714126083` reported `byte-identical-and-bounded`. Its
shared tree payload SHA-256 is
`2b13fa2c05a014ecc14a2d0e3db3adee5f828f9aa7e223c45357f3ac52d36681`;
the manifest payload SHA-256 is
`18fb1ac61e4c4933181dd4e001df9f8fe3069bba145e5aec44d9c7eb75349cd6`;
and the logical whole-file digest is
`4bd995a40b5b50850812ae22899070b142b52f355f96aec8230ab39034135d09`.

JavaScript completed its exact workload step in 40m46s and its manifest in
15m45.5s. Rust completed its exact workload step in 12m17s and its manifest in
10m08.2s, with one authenticated provider read and a bounded verified-chunk
cache while still hashing all 1,048,576 logical occurrences. Rust process RSS
peaked at 55,836,672 bytes; JavaScript process RSS peaked at 655,187,968 bytes,
and its packaged CLI tree-verification process peaked at 311,992,320 bytes.

The three raw reports and completion record are durable version-controlled
evidence. The checked-in package definitions, source-bound retained packed hashes, clean
offline installs, three-OS reports, critical review, accepted ADRs 0008–0010,
and current exact campaign close the PRD Definition of Done. Format v1 is
ratified as an encoding/object-model contract. OGVCS-002 `*.test` profiles
remain conformance-only, and production chunk writing remains unavailable until
OGVCS-007 publishes a ratified chunking profile.

Future exact campaigns are maintenance evidence only: run them manually once
per month when needed or for a major release, never on every pull request. No
repository path, payload, FileID, extension value, fixture seed, credential, or
customer identifier appears in these summaries.
