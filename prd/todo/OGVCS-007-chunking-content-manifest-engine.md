# OGVCS-007 — Chunking and content-manifest engine

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-002, OGVCS-004, OGVCS-005  
**Blocks:** OGVCS-008, OGVCS-013, OGVCS-014, OGVCS-017, OGVCS-020, OGVCS-028, OGVCS-029  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Clients can stream any supported file into deterministic content-defined chunks and a canonical manifest, reconstruct the exact bytes, and quantify actual reuse without holding the whole file in memory.

## Problem

Whole-object large-file storage re-uploads a giant file after a small edit. A chunker can reduce transfer and storage only if boundaries, hashing, packing inputs, limits, and failure behavior are deterministic and performant for real game formats.

## Scope

### In scope

- Versioned content-defined chunk algorithm and tunable size classes.
- Streaming whole-file digest, chunk digest, ordered manifest, and reconstruction.
- Whole-object/small-file fast path.
- Local missing/reuse analysis and shared-cache key contract.
- Per-format benchmark and safe resource limits.

### Out of scope

- Network negotiation, object persistence, authorization, pack storage, or garbage collection.

## Users and journeys

- **Client:** hashes a 100 GiB file with bounded memory and resumes transfer from its stable manifest.
- **Build agent:** reconstructs an exact file from cached and newly fetched chunks.
- **Studio evaluator:** sees measured reuse and cost by format instead of a promised universal dedup ratio.

## Requirements

### Functional

- **OGVCS-007-FR-01:** Version 1 SHALL define deterministic content-defined boundaries, hash preimages, minimum/target/maximum chunk sizes, and size-class selection.
- **OGVCS-007-FR-02:** A manifest SHALL include format version, logical length, whole-file SHA-256, ordered chunk IDs/lengths, and optional nonidentity hints.
- **OGVCS-007-FR-03:** Processing and reconstruction SHALL be streaming with a configurable bounded worker/memory budget.
- **OGVCS-007-FR-04:** Small files below a documented threshold MAY use one chunk but SHALL use the same manifest verification contract.
- **OGVCS-007-FR-05:** Reconstruction SHALL verify chunk ID/length and final file digest before atomic publication to a workspace.
- **OGVCS-007-FR-06:** The library SHALL calculate logical, unique, reused, and newly required bytes without contacting a remote service when given a known-chunk index.
- **OGVCS-007-FR-07:** Unsupported algorithm/version, malformed manifest, duplicate ambiguity, integer overflow, excessive chunk count, and resource exhaustion SHALL fail safely.
- **OGVCS-007-FR-08:** The benchmark SHALL report results separately for source-like, structured, already-compressed, encrypted/random, insertion, replacement, and append workloads.

### Quality attributes

- **OGVCS-007-NFR-01:** Identical bytes MUST produce identical manifests on all supported platforms and independent implementations.
- **OGVCS-007-NFR-02:** Peak memory SHALL be bounded independently of file length and measured under the 100 GiB fixture.
- **OGVCS-007-NFR-03:** The engine MUST never claim savings not observed in manifest/chunk comparison.

## Interfaces and data

Publish a stable library/API for `chunk(stream, policy) -> manifest + chunk stream`, `verify`, `reconstruct`, `compare`, and cache keys. Test vectors become part of OGVCS-002/005 conformance. Chunk/policy version is part of manifest identity.

## Development plan

1. Implement the versioned streaming chunker, canonical chunk/manifest encoding, hashing, and small fixed-boundary/golden reconstruction vectors.
2. Add content-defined chunking, large-file streaming ingest/reassembly, corruption/short-read handling, and bounded resource/error behavior.
3. Add policy selection, parameter/version compatibility, reuse/deduplication accounting, compression framing rules, and OGVCS-001 asset profiles.
4. Package client/server libraries, run cross-platform determinism/fuzz/performance suites, publish vectors and migration rules, and freeze the first interoperable chunker profile.

## Acceptance criteria

- **OGVCS-007-AC-01:** Two implementations generate identical manifests for every golden large-file vector.
- **OGVCS-007-AC-02:** All corpora reconstruct byte-identically after shuffled chunk delivery and reject a corrupted or truncated chunk.
- **OGVCS-007-AC-03:** The 100 GiB fixture completes within declared CPU/memory bounds without temporary whole-file duplication.
- **OGVCS-007-AC-04:** Insertion fixtures demonstrate boundary resynchronization; compressed/random fixtures transparently report poor reuse.
- **OGVCS-007-AC-05:** Fuzz/property tests find no panic, out-of-bounds access, unbounded allocation, or accepted digest mismatch.

## Verification plan

Cross-language vectors, streaming/property/fuzz tests, resource-limit tests, platform matrix, and OGVCS-005 per-format throughput/reuse benchmarks.

## Telemetry and operations

The library reports algorithm/version, bytes read, chunks, duration, peak queue/memory estimate, and reuse classification. It never logs file contents or protected paths.

## Rollout and rollback

Chunk algorithm is immutable per manifest version. New algorithms are read-before-write deployed; old readers reject unsupported required algorithms. Existing content is not rechunked automatically.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Fine chunks explode metadata | Size classes, manifest limits, and reconstruction benchmarks |
| Large chunks reduce reuse | Workload-driven parameter selection and published tradeoff |
| SIMD/platform optimization changes boundaries | Canonical reference algorithm and golden vectors |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
