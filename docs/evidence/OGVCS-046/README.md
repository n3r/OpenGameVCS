# OGVCS-046 validation evidence

**Status:** Pending hosted validation
**Package:** `@opengamevcs/path-filesystem` 1.1.0
**Contract:** `ogvcs.path/conformance-report/v1`, path contract 1.0.0

This directory is the retention point for OGVCS-046 validation. It intentionally contains no hosted run identifier, artifact digest, or completion claim until the exact source revision passes the Linux, macOS, and Windows workflow and the comparison job.

## Expected hosted evidence

Each operating-system artifact must contain an offline-packed installation report and conformance report with:

- 79 total rows, all passing;
- 63 pure cross-platform rows and 16 native filesystem rows;
- implementation `{ "name": "@opengamevcs/path-filesystem", "version": "1.1.0" }`;
- the native `native:bounded-staged-stream-publication` result;
- identical canonical results and package archive digests across Linux, macOS, and Windows.

The retained evidence set must include:

| Required record | Status |
|---|---|
| Exact source revision and workflow run | Pending |
| Linux packed package, report, and packed-evidence record | Pending |
| macOS packed package, report, and packed-evidence record | Pending |
| Windows packed package, report, and packed-evidence record | Pending |
| Three-platform comparison record | Pending |
| Linux unsafe-target syscall trace and audit | Pending |

## Local preflight

Before requesting hosted validation, run the package tests, report/tooling tests, packed-consumer conformance, workflow policy test, and roadmap policy gate. Local results establish development readiness only; they are not a substitute for retained three-platform evidence.

Local macOS development results on Node v24.9.0 for this tranche:

| Gate | Result |
|---|---|
| Path-filesystem syntax/contract sync | Passed |
| Path-filesystem package, streaming, recovery, and packed-consumer tests | 63/63 passed |
| Path contract generation/validation/package tests | 6/6 passed |
| Source conformance report | 79/79 passed; 63 pure and 16 native rows |
| Offline packed conformance report | 79/79 passed; runtime package 1.1.0 |
| Report, comparator, trace, workflow-policy, and independent-vector tests | 10/10 passed |
| Roadmap lifecycle policy | Pending serialized integration updates to the roadmap and OGVCS-004/OGVCS-007 inverse dependencies |

The root integration must also refresh `package-lock.json` and downstream exact runtime pins after merging the 1.1.0 package bump. Those shared changes are intentionally not represented as completed evidence here.

After a successful hosted run, replace the pending table with source-bound machine records and SHA-256/size bindings for every retained artifact. Keep the PRD In development until that evidence is reviewed and the remaining integration work is complete.
