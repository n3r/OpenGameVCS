# OGVCS-002 critical review

- **Review date:** 2026-08-16
- **Reviewer:** Independent Codex subagent (`ogvcs002_final_critical_review`)
- **Initial verdict:** Not acceptance-ready
- **Settled implementation verdict:** No residual P0 codec or specification defect found
- **Freeze verdict:** No-freeze until deferred exact scale, hosted three-platform evidence, and a clean frozen revision are complete

## Scope and method

The reviewer independently examined the PRD, architecture, ADRs, normative prose,
CDDL, registries, JSON Schemas, vector generator and auditor, both codecs, public
CLI, fixture adapter, packages, offline distribution, scenario reporters, and CI.
Review used malformed and mixed-failure inputs, reduced resource limits, stalled
and mutable caller boundaries, replaced scratch files, and incomplete repository
graphs. JavaScript and Rust were compared only at public boundaries.

Inventory rows, duplicated expected values, detached limit helpers, and source-only
unit tests were not treated as cross-language proof. Rejections were evaluated as
the normative `(code, layer, stage)` triple. The exact million-entry and logical
1-TiB workloads were deliberately excluded from ordinary review and remain a
separately authorized hosted gate.

## Confirmed findings and remediation

| Area | Initial gap | Settled remediation |
|---|---|---|
| Diagnostic authority | Errors lacked a complete machine mapping to layers/stages, and public reports omitted stage. | `errors.json` freezes 81 codes, 94 legal sites, and 10 stages. Both APIs and scenario reports expose and compare the exact triple. |
| Scenario evidence | The inventory mislabeled layers and the report executed only a small JavaScript subset. | The corpus has 235 envelopes. JavaScript executes 233; Rust executes 228 and marks five adapter-only rows N/A; only two exact-scale rows remain inventory. All 230 shared rows compare identically. |
| Registries | Loaders incompletely bound files, shapes, immutable assignments, discovery, limits, and lifecycle. | Both loaders bind all 12 registries, enforce exact additive shapes and frozen assignments with bounded same-handle reads, expose every family, and share operation-aware lifecycle semantics. |
| Canonical encoding | Hostile nesting, map-key work, async caller mutation, and configured memory could escape typed bounds. | Depth/memory preflight, working-set charging, configured-budget propagation, and mutation/deadline regressions fail without trusted partial output. |
| Scratch integrity | Closed external-sort runs could be replaced before merge. | Both languages bind private workspaces, same-handle identity, and whole-run digests for name and FileID runs. |
| Graph and replay | Ancestor/shelf states and side-parent closure were trusted; decoded caches were mutable; replay retained unbounded states. | Every reachable snapshot/shelf revision is replayed, all edge families resolve, cache results cannot be mutated, and derived states are reserved and evicted. |
| Repository precedence | FileID, group, conflict, snapshot, tree, and manifest validators often returned traversal-order errors. | Bounded phase passes and same-stage collectors select the frozen catalogue winner; dual-fault regressions cover every repaired family. |
| Logical bundles | Sequence, identity, transcript, closure, declarations, lifecycle, and resources were ordered differently across entry points/languages. | Both verifiers use the same phase order, compare authenticated accounting before later layers, rank bundle-wide schema errors, and bound semantic indexes/state. |
| Fixture adapter | Consumed bytes, ledger collisions, target FileID state, callbacks, filesystem waits, paths, and retry publication were incompletely bound. | Exact ledger schemas, target-consumption checks, post-read digests, deadline-raced promise boundaries, path limits, hostile-key handling, and unchanged-state failure tests cover all five fixture profiles. |
| Offline boundary | Source reports did not prove packed implementations and the exact JS tarball was deleted. | The packed gate installs fixture/JS/format tarballs offline, packages Rust, compares shared outcomes, records SHA-256, and retains all four exact archives. |
| Licensing | Package metadata disagreed and first-party artifacts omitted a license. | The maintainer selected MIT; the workspace, fixture, JS, Rust, format, crate, npm tarballs, and offline distribution now ship and verify identical MIT text. |
| CI provenance | Actions used mutable tags and roadmap contract/checker paths did not trigger CI. | External actions are pinned to verified full SHAs; both trigger filters include all roadmap lifecycle sources. |

## Settled local proof

The ordinary root presubmit, JavaScript package, Rust tests under the declared
Rust 1.82 minimum, formatting, `clippy -D warnings`, packaging, offline
distribution, specification/vector checks, and source/packed comparison pass.
The selected MIT license is byte-identical across the repository and every
first-party packed/offline artifact, with package-contract assertions.
The independent audit reports 1,236 artifacts, 148 obligations, 235 scenarios,
58,520 mutations per language, 7,303 truncations per language, and 50 executable
max/max-plus-one cases across 25 hard-limit families.

The diagnostic packed run retains all four archives and produces shared
conformance SHA-256
`14b34af82edc216f2d406f66cb21fe877c6e9d1c0e33b62c807ff9fbe88a15a6`.
Because it used `--allow-dirty`, its `sourceRevision` names the preceding commit;
it is not release evidence and must be replaced by a clean frozen-commit run.

## Remaining blockers

| Severity | Blocker | Required closure |
|---|---|---|
| P1 | The million-entry and logical-1-TiB cases are the only inventory rows. | Per the maintainer's 2026-08-16 decision, defer them to the final R0 campaign; then run the gated release-scale workflow and retain time, peak RSS, scratch, counts, identities, and the JS/Rust comparison. |
| P1 | No hosted Linux/macOS/Windows result exists for the uncommitted candidate. | Commit/push the frozen candidate and retain all three reports plus their comparison. |
| P1 | The worktree is not a durable frozen revision. | Rerun packed conformance without `--allow-dirty` from the candidate commit. |
| P1 | Completion/changelog/status/ADR ratification cannot yet be honest. | Close all preceding gates, update this verdict, write final evidence/changelog, ratify ADR-0008/0009/0010, and only then move the PRD to `done`. |

## Acceptance verdict

| AC | Current verdict | Basis |
|---|---|---|
| AC-01 | Local technical pass; durable proof pending | Source and packed goldens agree; clean hosted proof is outstanding. |
| AC-02 | **Incomplete** | Exact one-million-entry and below-1-GiB evidence has not run. |
| AC-03 | Pass locally | Both implementations execute all 58,520 mutations. |
| AC-04 | Pass locally | The installed adapter runs five corpora; native semantic cases run separately. |
| AC-05 | Pass locally | No private service/import is required; every first-party package and offline artifact ships the selected MIT license. |
| AC-06 | Pass locally | All root/parent/merge/closure and abstract-cycle cases execute. |
| AC-07 | Pass locally | FileID allocation, transition, restore, import, and concurrency cases execute. |
| AC-08 | Pass locally | Malformed, truncation, hostile-resource, and boundary routes are typed and bounded. |
| AC-09 | **Incomplete** | Ordinary manifests pass; exact logical-1-TiB evidence has not run. |
| AC-10 | Pass locally | Bundle ordering, identity, transcript, accounting, closure, and claim boundaries agree. |
| AC-11 | Pass locally | Registry shape, immutability, lifecycle, and forward-preservation agree. |
| AC-12 | Pass locally; hosted proof pending | OS-entropy, zero, collision, and exhaustion cases pass in both languages. |

## Recommendation

Do not freeze or move OGVCS-002 to `prd/done` yet. After a clean MIT-licensed commit
passes the three-platform comparison and the final-R0 exact-scale campaign,
update this record with immutable commit/run/artifact links. Only then is an
Accepted/Done recommendation justified.
