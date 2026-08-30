# OGVCS-007 bounded seven-workload benchmark evidence

**Evidence date:** 2026-08-30  
**Status:** Bounded benchmark evidence added; profile ratification still blocked

This packet closes the 2026-08-30 ratification review's missing benchmark
authority finding for OGVCS-007 FR-08 and AC-04 without attempting the deferred
100 GiB acceptance campaign. It records one authenticated, deterministic,
local bounded run of seven workload classes:

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

## What this evidence proves

- A closed seven-workload benchmark corpus now exists in source control.
- The report is executable from the public JavaScript implementation with:
  `node tools/chunking-selection-benchmark-report.mjs --output <report.json>`.
- The bounded threshold file is green for this retained report.
- Every threshold failure forces `overallStatus: "failed"`.
- Compressed and encrypted/random inputs honestly report poor reuse.
- Source-like, structured, insertion, replacement, and append workloads record
  observed reuse rather than inferred savings.
- The report explicitly records `exactScaleExecuted: false`; it does not
  claim the deferred 100 GiB acceptance result.

## Remaining ratification blockers

This packet does not ratify
`chunking.opengamevcs/gear-fastcdc-1m@1`, change the OGVCS-002 registry, or
flip production writes on. The remaining P0 blockers from the
2026-08-30 review are still:

- P0-1: no production-boundary OGVCS-007 verifier receipt rejects arbitrary
  boundaries before trusted publication.
- P0-3: no read-before-write reconstruction/publication path is deployed
  across the public trust boundary.

The review can therefore treat the benchmark/report gap as closed while keeping
the overall verdict blocked until those verifier and reconstruction boundaries
land and are re-reviewed.
