# OGVCS-007 bounded seven-workload authenticated selection evidence

**Evidence date:** 2026-09-01
**Status:** Current-source bounded authenticated evidence retained; production adoption, profile ratification, and the final-scale gate remain blocked

This packet retains the bounded OGVCS-007 selection evidence used to close the
P0-2 authenticated-benchmark finding without attempting the separately deferred
100 GiB acceptance campaign. It retains two deterministic local bounded report
executions over the same seven workload classes: the standalone selection
report and the authenticated bundle run. The bundle validation binds the
bundle-embedded report and its same-run captures:

- source-like
- structured
- already-compressed
- encrypted/random
- insertion
- replacement
- append

The retained report is
[`bounded-selection-report-2026-08-31.json`](bounded-selection-report-2026-08-31.json).
It binds the chunking contract manifest SHA-256, workload-definition digest,
threshold file and digest, host/runtime identity, exact logical/unique/reused/
new byte accounting, per-workload chunk counts and manifest sizes, accounted
ledger memory, observed generation/compare/verify throughput, exact source
identity type/value, and bounded chunk-based resynchronization distance where a
post-mutation aligned reused chunk exists.

The authenticated OGVCS-005-compatible result bundle is retained under
[`bounded-selection-bundle-2026-08-31/`](bounded-selection-bundle-2026-08-31/)
and independently reverified by
[`bounded-selection-bundle-validation-2026-08-31.json`](bounded-selection-bundle-validation-2026-08-31.json).
The validation record is location-independent and stores a repository-relative
`bundleDirectory`, not an absolute host path.

This closes P0-2 in bounded scope: the seven-workload run now emits an
authenticated `ogvcs.benchmark/result-bundle/v1`, passes the public base and
product verifiers, retains all seven samples, and records same-run observed
child-process peak memory for each workload.

The packet is bound to the exact packaged source set introduced by code commit
`00ed027b798f0114c3817678685b4df7f63d8741`. The standalone report records
source-set SHA-256
`34fb64f36261f188ecce30378605f2b9960209c769b740239ebb5e8e63c56fcf`;
the authenticated bundle adds its producer and independent-verifier sources and
records
`28fcaf6ba5f5a15f8d4fdd3ab9e6240b20bda7517cd62e4c594a756b52d587ff`.
Both record the same 14-file packed implementation identity
`b2c779645ffd48a9c52b90dcc255224b393779160885821e5d4ebbac83d0d288`.

## Current bounded hosted implementation proof

[Workflow run 33476471118](https://github.com/n3r/OpenGameVCS/actions/runs/33476471118)
passed source revision
[`a26d302b734f07872b0f3f6e1b0036eaf1643b86`](https://github.com/n3r/OpenGameVCS/commit/a26d302b734f07872b0f3f6e1b0036eaf1643b86),
which contains the production-boundary code commit `00ed027`, this bounded
authenticated packet, and the bounded Rust manifest-streaming writer. JavaScript
and Rust each passed on Linux, macOS, and Windows; all six matrix jobs started
within one second, and the final job matched all nine bounded cases across all
six reports. The Rust legs also passed the streaming writer unit, closure,
golden-parity, exact-runner sink, formatting, strict Clippy, and offline package
gates. The exact run, job, timing, and artifact identities are retained in
[`github-actions-run-33476471118.json`](github-actions-run-33476471118.json).

The run record retains the archive and inner-report byte counts and SHA-256
digests for all six artifacts. All three JavaScript reports are byte-identical,
as are all three Rust reports. They are also byte-identical to the already
retained deterministic report blobs under
[`bounded-conformance-33328072458/`](bounded-conformance-33328072458/), so the
new record reuses those two checked-in blobs instead of duplicating them. The
hosted matrix was bounded, declares zero scale jobs, and did not run the
100-GiB campaign.

## What this evidence proves

- A bounded seven-workload corpus, retained local report, authenticated result
  bundle, and independent retained-validation record now exist in source
  control as OGVCS-007 bounded selection evidence.
- The report is executable from the public JavaScript implementation with:
  `node tools/chunking-selection-benchmark-report.mjs --output <report.json>`.
- The authenticated bundle is executable from the public publisher with:
  `node tools/chunking-selection-benchmark-bundle.mjs --output <bundle-dir>`.
- The public OGVCS-005 verifier and the independent OGVCS-007 product verifier
  both accept the retained bundle.
- The bounded threshold file is green for the retained report and the retained
  bundle.
- Every threshold failure forces `overallStatus: "failed"`.
- Compressed and encrypted/random inputs honestly report poor reuse.
- Source-like, structured, insertion, replacement, and append workloads record
  observed reuse rather than inferred savings.
- The report explicitly records `exactScaleExecuted: false`; it does not
  claim the deferred 100 GiB acceptance result.
- The retained captures record observed whole-process child peaks from fresh
  worker processes. The current retained range is 105,201,664 to
  439,959,552 bytes across the seven workloads, and every retained peak equals
  `max(child maxRSS, sampled child RSS)`.

## Ratification status

This packet does not ratify
`chunking.opengamevcs/gear-fastcdc-1m@1`, change the OGVCS-002 registry, or
flip production writes on. Since the original 2026-08-30 review, the bounded
implementation has closed the code-level portions of two blockers:

- P0-1 is closed at the package boundary: generation and full verification
  issue a private one-use receipt bound to the registered verifier version,
  profile, manifest identity, logical bytes, and whole-file digest.
  `commitProductionManifest` additionally requires a complete OGVCS-002
  registry snapshot that admits the exact OGVCS-007-owned ratified row before
  any caller publication callback can run. The bundled registry has no such
  row, so the transition currently fails closed.
- P0-3 is closed in source: `reconstructManifestToWorkspace` verifies the
  ordered content and Gear boundaries before streaming through OGVCS-046
  `atomicWriteStream`. Its one-slot rendezvous applies backpressure, and
  cancellation/deadline settlement cannot report failure after a durable
  commit.

The remaining open boundaries from the review are:

- P0-1 deployment boundary: OGVCS-008 must invoke the package-owned production
  boundary before a `ContentManifestV1` lifecycle record can become available;
  that integration proof is not part of this local evidence packet.
- Generated registry/production lifecycle: portable-encoder regeneration
  mechanically refreshed the chunking, benchmark, repository-metadata, and
  identity manifest/pin chain. The OGVCS-002 profile registry, production-write
  eligibility, ratification state, and downstream release lifecycle remain
  intentionally unchanged and open.
- Final-scale completion: the separate 100-GiB resource campaign is the final
  OGVCS-007 acceptance gate and must pass before profile ratification or writer
  enablement.

This packet does not ratify `chunking.opengamevcs/gear-fastcdc-1m@1`, change
the OGVCS-002 registry, or authorize production writes. It closes only the
bounded authenticated-evidence requirement that previously blocked P0-2.
