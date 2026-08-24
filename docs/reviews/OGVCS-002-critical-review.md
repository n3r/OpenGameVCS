# OGVCS-002 critical review

- **Review date:** 2026-08-21
- **Boundary update:** 2026-08-24
- **Reviewer:** Independent Codex review agent (`ogvcs002_final_critical_review`)
- **Initial verdict:** Not acceptance-ready
- **Settled verdict:** No live P0, P1, or P2 defect found
- **Lifecycle verdict:** Acceptance-ready for `Done`; ratified-package ordinary/packed proof and exact-implementation proof passed

## Scope and method

The review covered the PRD, architecture, ADRs 0008–0010, normative prose,
CDDL, schemas, registries, hard limits, error precedence, vector generator and
independent auditor, JavaScript and Rust libraries, public CLI, OGVCS-001
fixture adapter, scenario reporters, package manifests, offline distribution,
and the three-platform workflow.

The reviewer used hostile and combined-invalid inputs, reversed occurrence
orders, missing and corrupt sibling references, reduced count/memory/scratch
ceilings, deadline failures, mutable and callback-bearing caller boundaries,
replaced scratch files, incomplete repository graphs, and forward/reverse
writer cases. Rejections were evaluated as the complete normative
`(code, layer, stage)` result. Inventory rows, synthetic expected-error returns,
fresh-instance retries, or tests that did not invoke the named public route were
not accepted as evidence.

The ordinary review excluded the exact million-entry tree and logical-1-TiB
workloads by maintainer decision. A later explicit campaign first established
the acceptance oracle. After the Rust performance change and parallel workflow
landed, exact implementation run `32714126083` repeated both complete workloads and
the strict comparison. Exact scale remains monthly/manual or major-release
maintenance evidence rather than pull-request work.

## Frozen authority and ordinary proof

The frozen manifest is
`2d0acb01a01b64c23d883d855d2802d939a8dc99622f2774de07af1c8af8d2b9`.
It binds 2,815 artifacts, 573 scenarios, 486 requirements/acceptance
obligations, 81 errors, 94 legal error sites, ten ordered stages, 58,520 bit
mutations, and 7,303 proper-prefix truncations. The scenario-index and coverage
digests are respectively
`9602b91fcac449cb420e718739e5a1a1a2059ec7872422e7bf3cdd72c727c078`
and `c5aeef73d2da337a3a250fd8c035adffb69adf33eccf30c6d42189969b83a1bf`.

JavaScript executes 571 rows with two exact-scale inventory rows and no
failures; its results SHA-256 is
`7eeb9091263530ac5f8703adb58de71f536d96f9a541f914b7b9f6e50864d153`.
Rust has 550 applicable rows: 548 execute, the same two remain inventory, and
23 JavaScript-only fixture-adapter, host-shape, and unrepresentable raw carriers
are N/A. All 550 shared rows, including the two common inventory declarations,
compare through one normalized cross-language projection.

Ratified package source
[`45d98fe`](https://github.com/n3r/OpenGameVCS/commit/45d98fe5adfff02e10745a0501123b30e56371bb)
is the ordinary hosted proof in
[run 32719990180](https://github.com/n3r/OpenGameVCS/actions/runs/32719990180).
Pinned Node 22 and Rust 1.82 jobs pass on Linux, macOS, and Windows; the Linux
job additionally creates and runs clean packed/offline fixture, JavaScript,
format, and Rust artifacts. The six deterministic platform reports compare
identically. This source differs from the exact implementation revision only by
three checked-in raw reports and ratification-status prose; no implementation,
schema, registry, vector, preimage, or canonical-byte rule changed. Exact scale
remains isolated from this ordinary matrix.

The separate exact implementation source
[`9d85d6e`](https://github.com/n3r/OpenGameVCS/commit/9d85d6ee959e47f8f65bca19c4ebb35687c39029)
was exercised by
[run 32714126083](https://github.com/n3r/OpenGameVCS/actions/runs/32714126083),
which passed JavaScript, Rust, and comparison jobs in parallel. JavaScript completed
its exact step in 40m46s and the manifest in 15m45.5s. Rust completed its exact
step in 12m17s and the manifest in 10m08.2s, down from about 3h01m before
hardware-accelerated SHA-256 and bounded verified-chunk caching. Rust made one
authenticated provider read but still hashed every one of the 1,048,576
logical chunk occurrences into the whole-file digest. The retained and
independently replayed comparison is `byte-identical-and-bounded`.

## Confirmed findings and remediation

| Area | Initial gap | Settled remediation |
|---|---|---|
| Diagnostic authority | Implementations and vectors could disagree on layers, stages, or traversal-selected failures. | `errors.json` freezes 81 codes, 94 legal sites, ten stages, and catalogue precedence; every executed rejection compares the exact triple. |
| Scenario honesty | Rows were previously credited without executing every declared route, retrying the same authority, or representing Rust-applicable bytes. | Both reporters dispatch named public APIs, record per-route observed recovery, enforce applicability, and share all representable malformed wire carriers. |
| Registry authority | Partial, forged, family-wrong, or lifecycle-ineligible assignments could be consulted after semantic work began. | Same-handle complete registry loading, whole-input family passes, deferred/ranked lifecycle selection, and explicit phase checkpoints prevent semantic callbacks under invalid authority. |
| Repository closure | Manifest, tree, replay, conflict, snapshot, shelf, provenance, lifetime/import, and candidate routes interleaved later-layer semantics with missing/corrupt references. | Exact route-scoped closure collectors complete and rank lower layers first; full candidate validation additionally authenticates every supplied object. |
| FileID/import state | Prior mappings, descriptor binding, mapping keys, recovery, and transaction counters were incompletely authenticated or reusable. | Exact serialized/plain boundaries, family/lifecycle checks, cross-repository proofs, operation-scoped cache/counter rollback, and same-instance recovery tests close the state contract. |
| Streaming writers | Count/order/identity/schema/lifecycle selection depended on occurrence order and some rejected staging writers remained retryable. | Complete bounded preflight/collectors select the frozen winner; resource stops remain terminal; rejected staging attempts are poisoned and cannot later commit. |
| Tree and manifest resources | FileID indexes, scratch state, provider failures, and nested tree traversal could exceed aggregate limits or mutate caller state. | Shared composite admission, reusable transactions, full provider-error ranking, and explicit bounded tree stacks replace independent budgets and native recursion. |
| Logical bundles | Section order, identity, schema, lifecycle, closure, map-key capture memory, and scratch integrity differed across APIs/languages. | Both codecs use the same staged precedence; active/retained captures and replacement transients are charged; scratch runs bind same-handle identity and whole-run digests. |
| JavaScript hostile inputs | Proxies, accessors, sparse arrays, hostile iterables, and configuration callbacks could run before inert validation. | Exact data snapshots and branded adapter boundaries reject caller code with typed preflight errors. |
| Package/offline boundary | Source-only results, mutable action tags, incomplete archive retention, and inconsistent licenses weakened reproducibility. | Actions use pinned SHAs; clean offline consumers exercise exact archives; distribution manifests bind dependencies/licenses; the maintainer-selected MIT text is identical throughout. |
| Scale scheduling | Exact scale was opt-in, but its job depended on the complete ordinary three-OS matrix and later ran JavaScript and Rust serially. | `.github/workflows/object-model-scale.yml` is release-only, has no PR, branch, schedule, or ordinary-matrix dependency; manual runs require explicit billed-work confirmation. JavaScript and Rust now run as independent concurrent jobs, while one dependent job compares their retained artifacts. The policy test protects triggers, independence, minimal toolchains, dependency shape, and evidence handoff. |
| Hosted portability | The first fresh Windows run overflowed its native stack on the bounded deep-tree route; later runs exposed five- and ten-minute test timeouts for two offline Cargo builds. | Rust semantic expansion now uses a resource-charged explicit DFS stack. Windows receives a finite fifteen-minute offline-test allowance beneath the 45-minute job ceiling; the replacement three-OS run passes. |
| Exact-scale oracle | A diagnostic run exposed a stale Rust-only expected tree digest even though both paths agreed on emitted bytes. | Commit `7b4baa0` corrected the oracle; run `32648023755` established it, and exact implementation run `32714126083` repeated both exact rows plus the strict comparison after optimization. |

## Acceptance verdict

| AC | Verdict | Basis |
|---|---|---|
| AC-01 | Pass | Clean-room JavaScript and Rust golden/object/bundle/reference results and shared scenario outcomes agree in source and packed runs across three OSes. |
| AC-02 | Pass | Run `32714126083` proves the exact implementation's ordered and disk-sorted libraries plus the installed public CLI on matching bounded million-entry bytes below 1 GiB. |
| AC-03 | Pass | The independent corpus executes all 58,520 systematic mutations and rejects or changes authenticated identity. |
| AC-04 | Pass | The installed adapter runs all five fixture profiles; native restore/import/proof/root/shelf/conflict cases execute through their public routes. |
| AC-05 | Pass | Inspection and verification require no private service, database schema, credential, or proprietary module; all first-party artifacts use MIT. |
| AC-06 | Pass | Root/parent/merge/closure cases and the typed abstract-cycle harness agree with frozen precedence. |
| AC-07 | Pass | Allocation, transition, restore, import, collision, concurrency, rollback, and same-authority recovery cases execute. |
| AC-08 | Pass | Malformed, truncation, hard-limit, configured-resource, callback, scratch-replacement, and combined-invalid cases fail deterministically without trusted partial state. |
| AC-09 | Pass | Empty/repeated/multi/corrupt/ceiling/profile/annotation cases agree; run `32714126083` retains the exact implementation's content-verified byte-identical logical-1-TiB result. |
| AC-10 | Pass | Bundle order, identity, transcript, accounting, closure, resource, and forbidden-claim boundaries agree. |
| AC-11 | Pass | Registry schema, immutability, lifecycle, family, unknown-feature, and lossless optional-extension behavior agree. |
| AC-12 | Pass | OS entropy, zero rejection, injected collisions, and exhaustion pass in both languages on Linux, macOS, and Windows. |

## Completion boundary

The public version-controlled package sources, source-bound retained archive
hashes, reproducible package contents, offline-installed consumers, three raw exact reports, machine-readable
completion record, and immutable exact/package source revisions are durable evidence.
No acceptance criterion or repository Definition of Done requires external
npm, crates.io, or GitHub Release publication. Actions archives are useful
mirrors but are not the sole retained proof.

ADRs 0008, 0009, and 0010 are `Accepted`. Format v1 may therefore be ratified as
the encoding and object-model contract. OGVCS-002 `*.test` profiles remain
conformance-only; ratification does not invent a production chunker or promote
profiles owned by later PRDs. No P0, P1, or P2 remains open.

## Recommendation

Move OGVCS-002 to `prd/done`, preserve the frozen byte/registry authority, and
ratify format v1. Keep exact scale outside pull requests and ordinary pushes;
repeat it manually on the agreed monthly or major-release cadence. Keep
conformance-only profiles and unavailable production chunk profiles disabled.
