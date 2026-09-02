# OGVCS-007 R1 completion audit

**Audit date:** 2026-09-01
**Code candidate:** `00ed027b798f0114c3817678685b4df7f63d8741`
**Bounded streaming addendum:** `a26d302b734f07872b0f3f6e1b0036eaf1643b86`
**Evidence-publication portability fix:** `b56e165eb3657288572ef16b0e5865a673877d4a`
**Hosted evidence revision:** `b56e165eb3657288572ef16b0e5865a673877d4a`
**Verdict:** not Done; bounded implementation is stageable, final-scale and
production-adoption gates remain open

This audit maps every OGVCS-007 requirement and acceptance criterion to the
current public source or retained evidence. It deliberately does not move the
PRD to `done`, accept ADR-0016, add the shared registry row, or authorize a
production writer.

## Trust boundary delivered by the candidate

The JavaScript package now exposes one high-level workspace reconstruction API
and one package-owned repository production transition:

- `reconstructManifestToWorkspace()` composes full ordered-content and Gear
  verification with the bounded OGVCS-046 atomic workspace writer.
- generation and verification issue private one-use receipts bound to verifier
  version, profile, manifest ObjectID and SHA-256, logical bytes, and whole-file
  SHA-256;
- `commitProductionManifest()` requires a complete, validated OGVCS-002
  `RegistrySnapshot` whose exact row is `family: chunking`, `owner: OGVCS-007`,
  `state: ratified`, and `productionWriteAllowed: true`; it consumes the exact
  receipt before calling `write` or `commit`;
- malformed, forged, reused, wrong-manifest, wrong-verifier, caller-shaped
  registry, and arbitrary-boundary inputs reach no publication callback;
- pre-commit callback/cancellation failures abort once, while a resolved durable
  commit remains successful if cancellation arrives afterward.

The shared registry intentionally lacks that row. The current package therefore
rejects the production transition with `CHUNK_PROFILE_UNSUPPORTED` before any
callback. The synthetic ratified registry used in tests is a complete validated
snapshot and is never shipped as production authority.

## Requirement matrix

| Requirement | Current result | Evidence and remaining work |
|---|---|---|
| FR-01 | Bounded pass; ratification pending | ADR-0016 and the generated profile freeze initialization, recurrence, masks, min/target/max, size classes, table provenance, and unchanged OGVCS-002 ChunkID preimage. JavaScript and Rust execute the independent vectors. The row is not yet ratified. |
| FR-02 | Bounded pass; lifecycle pending | Both implementations reproduce the exact OGVCS-002 manifest bytes, ObjectID, profile reference, logical length, whole digest, and ordered parts. The candidate registry is conformance-only; production emission remains fail closed. |
| FR-03 | Bounded pass | JavaScript generation, verification, comparison, and reconstruction are streaming. Scalar execution admits one worker/no completed-chunk queue, a fixed budget, bounded fragments, and a disk-backed bounded ledger. Rust now writes the canonical manifest through a bounded sink without retaining the manifest, part array, or boundary array; the legacy collecting API is a byte-identical compatibility wrapper. |
| FR-04 | Pass | Empty and 1..262,144-byte whole-file cases use the same canonical manifest and full verifier contract; malformed and corrupt small-file cases reject through the same error authority. |
| FR-05 | Pass at library/workspace boundary; server adoption pending | `reconstructManifestToWorkspace()` verifies every occurrence, length, ChunkID, Gear boundary, and final digest before atomic publication. The returned private receipt binds the exact workspace publication. OGVCS-008 adoption is still required before repository availability. |
| FR-06 | Pass | `compareManifest()` accepts a local known-chunk index and reports exact logical, unique, repeated, reused, newly required bytes and unique chunks without remote access; conflicting known lengths reject. |
| FR-07 | Pass in bounded suites | Generated 22-code authority, malformed vectors, overflow/count/resource admission, corrupt/short/long/missing delivery, conflicting metadata/index cases, repeated ordered references, callback/iterator failures, cancellation, scratch exhaustion, and hostile receipt/registry tests execute public APIs. |
| FR-08 | Pass in bounded scope | The [current authenticated packet](../evidence/OGVCS-007/README.md) retains source-like, structured, already-compressed, encrypted/random, insertion, replacement, and append results separately. |
| NFR-01 | Pass at retained revision | JavaScript/Rust reports match nine golden cases. Hosted run 33521316277 replayed bounded revision `b56e165` on Linux, macOS, and Windows, passed all six language/OS legs, and passed the aggregate six-report comparison. A later exact-scale source requires its own same-revision bounded pass. |
| NFR-02 | Pending final gate | Bounded runs prove bounded admission and record observed child-process peaks, but only the deferred 100-GiB campaign can satisfy the required file-length-independent measured peak. |
| NFR-03 | Pass | Report and independent verifier recompute `reused + newlyRequired = unique` and `unique + repeated = logical`; poor reuse is retained rather than hidden. |
| AC-01 | Pass at retained revision | Independent JavaScript and Rust implementations generated identical golden manifest bytes on the retained `b56e165` six-leg matrix and passed the aggregate comparison. |
| AC-02 | Pass | Every golden corpus reconstructs exactly after shuffled lookup order; first/middle/last corruption and short/truncated/long/missing delivery reject. |
| AC-03 | **Open final gate** | No 100-GiB campaign was run in this work. It must be the final acceptance run, not a per-PR job. |
| AC-04 | Pass in authenticated bounded evidence | Insertion and replacement retain bounded post-mutation resynchronization; compressed and encrypted/random rows report zero observed reuse for the retained inputs. |
| AC-05 | Bounded pass | Deterministic property fragmentation, independent recurrence differential checks, malformed vectors, resource/scratch bounds, iterator/callback hostility, digest mismatch, and process teardown tests complete without panic, out-of-bounds access, unbounded queueing, or accepted mismatch. |

## Current authenticated packet

The fresh packet is generated from the clean code candidate and includes:

- [standalone seven-workload report](../evidence/OGVCS-007/bounded-selection-report-2026-08-31.json);
- [authenticated OGVCS-005 bundle](../evidence/OGVCS-007/bounded-selection-bundle-2026-08-31/manifest.json);
- [independent product validation](../evidence/OGVCS-007/bounded-selection-bundle-validation-2026-08-31.json).

The base bundle verifier and OGVCS-007 verifier both pass. The retained
validation records bundle digest
`ef52b4384c4d483c62f78a4a8b2dd52629044a88624064df5f80d8bf1e174d36`,
seven samples, seven summaries, five threshold evaluations, report/result
status `passed`, and selection report SHA-256
`9c253b3230af89dadb90ba80f934651a067bd2bd14fe9ae0973f47a597064ac0`.
All seven captures succeed. Their observed process peaks range from
105,201,664 to 439,959,552 bytes and each equals the maximum of child `maxRSS`
and sampled child RSS. Every report and result says
`exactScaleExecuted: false`.

The evidence contains repository-relative paths only. It does not contain a
workspace root, temporary directory, user path, file contents, or protected
repository path.

## Bounded gates executed locally

- JavaScript syntax and package tests: 37/37 passed.
- Chunking contract generation/independent validation: 4/4 passed.
- Offline packed npm consumer, workspace publication, production-boundary
  disabled/ratified simulations, and temporary-root cleanup: passed.
- Generated authenticated-bundle test and current retained bundle replay:
  passed.
- Hosted bounded run 33521316277 at exact revision `b56e165`: JavaScript and
  Rust passed on Linux, macOS, and Windows; all six downloaded reports passed
  independent aggregate parity and matched the retained blobs byte-for-byte.
  The Windows directory-durability regression passed. The workflow contained
  zero scale jobs.
- No 100-GiB, 1-TiB, or other exact-scale campaign was run.

## Exact-scale harness disposition

A release-only harness is prepared in
`.github/workflows/chunking-manifest-scale.yml`, but it has not been dispatched
and is not acceptance evidence. It streams the same deterministic, exactly
100-GiB repeated-LCG source independently through JavaScript and Rust on Linux.
Each implementation must report exact byte accounting, manifest identity,
chunk-boundary transcript, whole-file digest, observed whole-process peak RSS,
wall time, bounded ledger use, and scratch cleanup. The comparison job rejects
different source revisions, runtime architectures, result projections, or
declared-bound violations and binds both input report hashes into its output.

The workflow is reachable only by an explicit boolean-confirmed dispatch that
also supplies the exact reviewed source revision, or by an
`ogvcs-007-scale-<same 40-character lowercase revision>` release tag. Its
preflight rejects a mismatched checkout and pins all three downstream checkouts
to the accepted commit. It has no pull-request, branch, or scheduled trigger,
and neither the ordinary package scripts nor the bounded workflow executes
either 100-GiB runner. Preparing and testing this harness does not close AC-03,
ratify the profile, or authorize production writes.

The pre-scale evidence-authority candidate now adds an OGVCS-007-owned
`chunking-exact-scale` corpus, `chunking-exact-scale-verify` task,
`chunking-exact-scale-release` profile, and release threshold. It also provides
separate JavaScript and Rust bundle publishers, an independent OGVCS-007
verifier, and a comparator that accepts only verifier-branded inputs. Tiny
synthetic hostile tests exercise those paths without invoking either 100-GiB
runner. The existing protected workflow's literal raw-report comparison flags
now publish and verify both bundles, emit self-contained flat publication and
validation JSON records covered by its existing artifact glob, and compare the
verified brands. This wiring is prepared but has not been dispatched, so it is
not completion evidence. The bundles provide
content-addressed, current-source verification, not producer-origin
authentication; their revision field is explicitly workflow-supplied and not
yet Git-bound.

The new contract pins the unchanged completed OGVCS-005 manifest and the
current chunking manifest. It deliberately does not change OGVCS-005-owned
schemas, tasks, profiles, thresholds, runtime, or completion evidence. The
existing 2026-08-31 bounded packet therefore remains byte-valid for its exact
predecessor but is not exact-scale evidence. No repository-metadata/identity
predecessor wave is created by this candidate. No checked-in evidence was
generated and no exact-scale runner was executed.

## Open gates and lifecycle disposition

Two acceptance facts keep the PRD and ADR open:

1. OGVCS-008 has not yet demonstrated that a `ContentManifestV1` can become
   repository-available only through the private receipt boundary.
2. OGVCS-007-AC-03 still requires the separately scheduled 100-GiB campaign.

Only after those gates pass may maintainers execute the still-unapplied exact
registry, profile, predecessor-pin, enablement, and rollback procedure in the
[production-profile lifecycle runbook](../runbooks/OGVCS-007-production-profile-lifecycle.md).
