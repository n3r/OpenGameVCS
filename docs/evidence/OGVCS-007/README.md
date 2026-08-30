# OGVCS-007 bounded seven-workload authenticated selection evidence

**Evidence date:** 2026-08-30
**Status:** Bounded authenticated OGVCS-007 selection evidence retained; P0-2 closed, profile ratification still blocked

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
[`bounded-selection-report-2026-08-30.json`](bounded-selection-report-2026-08-30.json).
It binds the chunking contract manifest SHA-256, workload-definition digest,
threshold file and digest, host/runtime identity, exact logical/unique/reused/
new byte accounting, per-workload chunk counts and manifest sizes, accounted
ledger memory, observed generation/compare/verify throughput, exact source
identity type/value, and bounded chunk-based resynchronization distance where a
post-mutation aligned reused chunk exists.

The authenticated OGVCS-005-compatible result bundle is retained under
[`bounded-selection-bundle-2026-08-30/`](bounded-selection-bundle-2026-08-30/)
and independently reverified by
[`bounded-selection-bundle-validation-2026-08-30.json`](bounded-selection-bundle-validation-2026-08-30.json).
The validation record is location-independent and stores a repository-relative
`bundleDirectory`, not an absolute host path.

This closes P0-2 in bounded scope: the seven-workload run now emits an
authenticated `ogvcs.benchmark/result-bundle/v1`, passes the public base and
product verifiers, retains all seven samples, and records same-run observed
child-process peak memory for each workload.

## Bounded hosted implementation proof

[Workflow run 33328072458](https://github.com/n3r/OpenGameVCS/actions/runs/33328072458)
passed the receipt-enabled source revision
[`b098c3e2b8377fdf4cc2ec152e8a6b7b6f37f383`](https://github.com/n3r/OpenGameVCS/commit/b098c3e2b8377fdf4cc2ec152e8a6b7b6f37f383).
JavaScript and Rust each passed on Linux, macOS, and Windows; the final job
matched all nine bounded cases across all six reports. The exact run, job, and
artifact identities are retained in
[`github-actions-run-33328072458.json`](github-actions-run-33328072458.json).

The run record retains the inner byte count and SHA-256 for each of the six
platform artifacts. All three JavaScript inner hashes match, as do all three
Rust inner hashes. One deduplicated exact report blob per language is retained
under
[`bounded-conformance-33328072458/`](bounded-conformance-33328072458/) because
the downloadable artifacts expire on 2026-09-13. The hosted matrix was bounded
and did not run the 100-GiB campaign.

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
  worker processes. The current retained range is 104,742,912 to
  441,155,584 bytes across the seven workloads.

## Ratification status

This packet does not ratify
`chunking.opengamevcs/gear-fastcdc-1m@1`, change the OGVCS-002 registry, or
flip production writes on. Since the original 2026-08-30 review, the bounded
implementation has closed the code-level portions of two blockers:

- P0-1 is closed in source: full verification issues a private one-use receipt
  bound to the registered verifier version, profile, manifest identity, logical
  bytes, and whole-file digest. The workspace adapter consumes it before
  publication and rejects absent, reused, or mismatched receipts.
- P0-3 is closed in source: `reconstructManifestToWorkspace` verifies the
  ordered content and Gear boundaries before streaming through OGVCS-046
  `atomicWriteStream`. Its one-slot rendezvous applies backpressure, and
  cancellation/deadline settlement cannot report failure after a durable
  commit.

The remaining open boundaries from the review are:

- P0-1 deployment boundary: the private receipt is enforced by the package
  adapter, but no production server acceptor/emitter has adopted it yet.
- Generated registry/production lifecycle: portable-encoder regeneration
  mechanically refreshed the chunking, benchmark, repository-metadata, and
  identity manifest/pin chain. The OGVCS-002 profile registry, production-write
  eligibility, ratification state, and downstream release lifecycle remain
  intentionally unchanged and open.
- Final-scale completion: the separate 100-GiB resource campaign remains an
  OGVCS-007 completion/release gate after bounded profile ratification.

This packet does not ratify `chunking.opengamevcs/gear-fastcdc-1m@1`, change
the OGVCS-002 registry, or authorize production writes. It closes only the
bounded authenticated-evidence requirement that previously blocked P0-2.
