# OGVCS-046 — Bounded staged workspace publication

**Status:** In development
**Package:** `@opengamevcs/path-filesystem` 1.1.0
**Date:** 2026-08-30

## Added

- Added `atomicWriteStream(workspace, path, source, options)` as an additive package-root export. It accepts an `AsyncIterable` or Web `ReadableStream`, requires a branded workspace and closed preflight plan, and verifies the expected byte length and SHA-256 before publication.
- Added byte, scratch, chunk, time, operation, and cancellation bounds with stable `PathFilesystemError` failures.
- Added private same-filesystem staging, file and parent durability barriers, exact target and authority revalidation, and atomic replacement with an owner-bound rollback link for existing targets.
- Added the versioned `write-stream` transaction operation to crash inspection and recovery. Recovery rolls back an unpublished transaction or finalizes a durably committed publication.
- Added focused source, integrity, resource, race, fault, cancellation, cleanup, restart-recovery, and packed-consumer coverage.
- Added a native retained-conformance row that exercises successful streaming publication and pre-commit rollback while checking that no transaction remnants remain.

## Compatibility and rollout

This release is API-additive. Existing OGVCS-004 path and workspace behavior remains at contract version 1.0.0. Deploy 1.1.0 readers and recovery tooling before enabling stream writers because older versions do not understand `write-stream` journal records.

Local validation is recorded in the OGVCS-046 evidence template. Hosted Linux, macOS, and Windows validation remains pending; this changelog does not claim three-platform completion.
