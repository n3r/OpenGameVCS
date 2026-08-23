# OGVCS-002 critical review

- **Review date:** 2026-08-21
- **Boundary update:** 2026-08-23
- **Reviewer:** Independent Codex review agent (`ogvcs002_final_critical_review`)
- **Initial verdict:** Not acceptance-ready
- **Settled ordinary-candidate verdict:** No live P0 or P1 defect found
- **Lifecycle verdict:** Advance to `Validation`; do not move to `Done` before the two maintainer-deferred exact-scale proofs and durable final publication

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

The exact million-entry tree and logical-1-TiB workloads were excluded by the
maintainer's explicit decision. They remain authenticated inventory rows for
the final R0 campaign and are not replaced by reduced-scale claims.

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

Candidate commit `3aba34da7c75a1fc9120476873ee90e382aaab80` is the ordinary
hosted proof in
[run 32420451840](https://github.com/n3r/OpenGameVCS/actions/runs/32420451840).
Pinned Node 22 and Rust 1.82 jobs pass on Linux, macOS, and Windows; the Linux
job additionally creates and runs clean packed/offline fixture, JavaScript,
format, and Rust artifacts. The six deterministic platform reports compare
identically. The exact-scale job is skipped by design.

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
| Scale scheduling | Exact scale was opt-in, but its job depended on the complete ordinary three-OS matrix, needlessly repeating those billed jobs for each release-scale dispatch. | `.github/workflows/object-model-scale.yml` is release-only, has no PR, branch, schedule, or ordinary-matrix dependency, and is protected by `object-model-workflow-policy.test.mjs`. |
| Hosted portability | The first fresh Windows run overflowed its native stack on the bounded deep-tree route; later runs exposed five- and ten-minute test timeouts for two offline Cargo builds. | Rust semantic expansion now uses a resource-charged explicit DFS stack. Windows receives a finite fifteen-minute offline-test allowance beneath the 45-minute job ceiling; the replacement three-OS run passes. |
| Exact-scale oracle | A later diagnostic run reached the Rust million-entry tree and exposed a stale Rust-only expected payload digest even though Rust ordered/scratch output, Rust verification, and the completed JavaScript run all agreed on the emitted bytes. | Commit `7b4baa0` updates only the expected SHA-256 to the independently reproduced `2b13fa2c05a014ecc14a2d0e3db3adee5f828f9aa7e223c45357f3ac52d36681`. The incomplete diagnostic and maintainer-cancelled retry are not credited as scale acceptance. |

## Acceptance verdict

| AC | Verdict | Basis |
|---|---|---|
| AC-01 | Pass | Clean-room JavaScript and Rust golden/object/bundle/reference results and shared scenario outcomes agree in source and packed runs across three OSes. |
| AC-02 | **Deferred/incomplete** | Ordered and bounded-sort paths pass ordinary tests. A partial diagnostic proved matching million-entry tree bytes but did not complete the required retained two-language scale comparison. |
| AC-03 | Pass | The independent corpus executes all 58,520 systematic mutations and rejects or changes authenticated identity. |
| AC-04 | Pass | The installed adapter runs all five fixture profiles; native restore/import/proof/root/shelf/conflict cases execute through their public routes. |
| AC-05 | Pass | Inspection and verification require no private service, database schema, credential, or proprietary module; all first-party artifacts use MIT. |
| AC-06 | Pass | Root/parent/merge/closure cases and the typed abstract-cycle harness agree with frozen precedence. |
| AC-07 | Pass | Allocation, transition, restore, import, collision, concurrency, rollback, and same-authority recovery cases execute. |
| AC-08 | Pass | Malformed, truncation, hard-limit, configured-resource, callback, scratch-replacement, and combined-invalid cases fail deterministically without trusted partial state. |
| AC-09 | **Partially pass; exact scale deferred** | Empty/repeated/multi/corrupt/ceiling/profile/annotation cases agree. JavaScript completed one diagnostic 1-TiB stream, but Rust and the required retained cross-language comparison did not complete. |
| AC-10 | Pass | Bundle order, identity, transcript, accounting, closure, resource, and forbidden-claim boundaries agree. |
| AC-11 | Pass | Registry schema, immutability, lifecycle, family, unknown-feature, and lossless optional-extension behavior agree. |
| AC-12 | Pass | OS entropy, zero rejection, injected collisions, and exhaustion pass in both languages on Linux, macOS, and Windows. |

## Deferred Done gates

Runs `32441880044` and `32447152568` are diagnostic provenance only. The first
stopped before Rust 1-TiB execution and comparison; the second was cancelled at
maintainer request during the opt-in scale job after all ordinary jobs passed.
Neither changes the verdict below.

- Run and retain the exact `tree-million-entries` and `manifest-one-tib`
  reports during the final R0 campaign, including wall time, peak RSS, scratch
  high-water, processed counts/bytes, identities, and cross-language comparison.
- Publish the final versioned packages and evidence under durable release
  retention. The current GitHub artifacts are validation evidence, not final
  release publication.

ADRs 0008, 0009, and 0010 are already `Accepted`; their design status is not a
remaining blocker. Format v1 nevertheless remains an unratified validation
candidate until the two acceptance gaps and final publication close.

## Recommendation

Advance OGVCS-002 from `In development` to `Validation`. Preserve the frozen
authority and keep production writer ratification disabled. Do not move the PRD
to `prd/done` until the maintainer-authorized final R0 exact-scale campaign and
durable publication both pass.
