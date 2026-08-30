# OGVCS-046 — Bounded staged workspace publication

**Status:** Completed
**Package:** `@opengamevcs/path-filesystem` 1.1.0
**Date:** 2026-08-30

## Added

- Added `atomicWriteStream(workspace, path, source, options)` as an additive package-root export. It accepts an `AsyncIterable` or Web `ReadableStream`, requires a branded workspace and closed preflight plan, and verifies the expected byte length and SHA-256 before publication.
- Added byte, scratch, chunk, time, operation, and cancellation bounds with stable `PathFilesystemError` failures.
- Added private same-filesystem staging, file and parent durability barriers, exact target and authority revalidation, and atomic replacement with an owner-bound rollback link for existing targets.
- Added the versioned `write-stream` transaction operation to crash inspection and recovery. Recovery rolls back an unpublished transaction or finalizes a durably committed publication.
- Added focused source, integrity, resource, race, fault, cancellation, cleanup, restart-recovery, and packed-consumer coverage.
- Added a native retained-conformance row that exercises successful streaming publication and pre-commit rollback while checking that no transaction remnants remain.
- Closed the final recovery windows: every created ancestor is synchronized, the rollback link and capability plan are revalidated after the final caller hook, ambiguous record-directory sync preserves restart authority, exact `.json.next` successors cover pre-record-rename crashes, and recovery is restart-idempotent.
- Kept the deadline timer referenced while it is the only authority able to reject a hung source; the Linux regression that exposed the prior unreferenced timer is retained.

## Compatibility and rollout

This release is API-additive. Existing OGVCS-004 path and workspace behavior remains at contract version 1.0.0. Deploy 1.1.0 readers and recovery tooling before enabling stream writers because older versions do not understand `write-stream` journal records.

Readers and recovery tooling must reach 1.1.0 before writers are enabled. The
[read-before-write and rollback runbook](../runbooks/OGVCS-046-read-before-write-rollback.md)
is the authoritative deployment sequence; downgrade is permitted only after all
`write-stream` remnants have been recovered or finalized.

## Hosted completion evidence

[Run 33322266963](https://github.com/n3r/OpenGameVCS/actions/runs/33322266963)
passed the normalized offline package on Linux, macOS, and Windows at source
[`a4e5951`](https://github.com/n3r/OpenGameVCS/commit/a4e59519ea25bf7d53785268024f2e261f4e0646).
Every host passed 79/79 rows, including the bounded staged-stream native row;
the strict comparator accepted identical decisions and package bytes. Raw
reports, packed identities, comparison, Linux syscall trace, machine run
metadata, and independent trace audit are retained in the
[implementation-evidence packet](../evidence/OGVCS-046/README.md). The trace is
an inherited `atomicWriteFile` confinement regression for the shared package
boundary, not direct `atomicWriteStream` syscall proof.

The final durability review added transaction-directory barriers after rollback
link and journal removal. It also made a durable `committed` record authoritative:
a cleanup or post-commit observer failure now returns the committed result and
leaves a recoverable remnant instead of falsely reporting publication failure.

Evidence-policy [run 33322803382](https://github.com/n3r/OpenGameVCS/actions/runs/33322803382)
passed the retained file identities, report/comparison reconstruction, Linux
trace replay, workflow routing, and then-pending lifecycle assertions at
evidence revision
[`8c24a16`](https://github.com/n3r/OpenGameVCS/commit/8c24a16c74266edcc4f63d2bfe8041b0b0982a51).
The PRD lifecycle is therefore complete.

No million-entry, 100-GiB, or 1-TiB campaign was run for this bounded API PRD.
The 100-GiB content campaign remains an OGVCS-007 final/major-release gate.
