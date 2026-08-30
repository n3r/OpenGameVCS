# OGVCS-007 provisional bounded seven-workload selection evidence

**Evidence date:** 2026-08-30
**Status:** Provisional bounded OGVCS-007 selection evidence retained; P0-2 remains open

This packet retains a narrow, provisional OGVCS-007 selection-evidence record
for the 2026-08-30 ratification review without attempting the deferred
100 GiB acceptance campaign. It records one deterministic local bounded run of
seven workload classes:

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

It is not an authenticated OGVCS-005 result bundle, does not carry an
OGVCS-005 verifier receipt, and does not record observed whole-process peak
memory. It therefore cannot close the authenticated OGVCS-005 bundle finding
from P0-2 on its own.

## What this evidence proves

- A bounded seven-workload corpus and retained local report now exist in source
  control as provisional OGVCS-007 selection evidence.
- The report is executable from the public JavaScript implementation with:
  `node tools/chunking-selection-benchmark-report.mjs --output <report.json>`.
- The bounded threshold file is green for this retained local report.
- Every threshold failure forces `overallStatus: "failed"`.
- Compressed and encrypted/random inputs honestly report poor reuse.
- Source-like, structured, insertion, replacement, and append workloads record
  observed reuse rather than inferred savings.
- The report explicitly records `exactScaleExecuted: false`; it does not
  claim the deferred 100 GiB acceptance result.
- The report records per-operation ledger peaks only; it does not publish the
  observed process peak memory that P0-2 closure still requires.

## Ratification status

This packet does not ratify
`chunking.opengamevcs/gear-fastcdc-1m@1`, change the OGVCS-002 registry, or
flip production writes on. Since the original 2026-08-30 review, the bounded
implementation has closed two code-level blockers:

- P0-1 is closed in source: full verification issues a private one-use receipt
  bound to the registered verifier version, profile, manifest identity, logical
  bytes, and whole-file digest. The workspace adapter consumes it before
  publication and rejects absent, reused, or mismatched receipts.
- P0-3 is closed in source: `reconstructManifestToWorkspace` verifies the
  ordered content and Gear boundaries before streaming through OGVCS-046
  `atomicWriteStream`. Its one-slot rendezvous applies backpressure, and
  cancellation/deadline settlement cannot report failure after a durable
  commit.

The remaining P0 blocker from the review is:

- P0-2: no authenticated OGVCS-005 result bundle/verifier exists for the
  seven-class bounded run, and no observed process peak memory is retained for
  that run.

Actual P0-2 closure still requires an authenticated OGVCS-005-compatible result
bundle plus verifier outcome for the bounded seven-class run, along with
observed process peak memory. Until then, this packet remains narrow retained
selection evidence only. Ratification also remains gated by the current-source
hosted matrix, the generated registry/predecessor-pin lifecycle cut, and the
separately scheduled final 100-GiB resource campaign.
