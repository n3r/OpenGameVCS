# OGVCS-046 — Bounded staged workspace publication

**Status:** In development
**Release:** R1 — Developer Preview
**Priority:** P0
**Owner:** Codex and OpenGameVCS maintainers
**Depends on:** OGVCS-004
**Blocks:** OGVCS-007
**Source:** [OGVCS-007 integration requirement](OGVCS-007-chunking-content-manifest-engine.md)
**Last updated:** 2026-08-30

## Outcome

Streaming producers can publish a verified file into a workspace atomically and durably without retaining or duplicating the complete file in memory.

## Problem

OGVCS-004 provides safe atomic publication for caller-owned in-memory bytes, while large-file reconstruction needs a bounded streaming sink. Reimplementing staging in each consumer would bypass the branded workspace, closed preflight plan, no-follow checks, durability barriers, stable failures, and recovery protocol.

## Scope

### In scope

- Additive `AsyncIterable` and Web `ReadableStream` workspace publication API in `@opengamevcs/path-filesystem`.
- Required final byte-length and SHA-256 verification before publication.
- Configurable byte, scratch, chunk, operation, time, and cancellation limits.
- Private same-filesystem staging, atomic replacement, file and directory durability barriers.
- Versioned crash journal, rollback link, eager ordinary-failure cleanup, restart inspection and recovery.
- Package-root export, example, packed-consumer proof, and hostile/race/fault/resource tests.

### Out of scope

- Content-defined chunking algorithms, manifests, profiles, or OGVCS-007 identity decisions.
- Root package/workspace changes, roadmap integration, or amendments to completed OGVCS-004 requirements.
- A stronger native directory-handle adapter for continuously hostile same-authority namespace mutation.

## Users and journeys

- **Chunk reconstruction client:** streams a verified large file into its workspace without retaining a second complete in-memory copy.
- **Workspace library consumer:** receives the same branded-plan, path-confinement, durability, and crash-recovery guarantees for bounded streams as for buffered writes.
- **Administrator:** inspects and safely resolves an interrupted stream-publication transaction without guessing whether old or new bytes became durable.
- **Security engineer:** proves source, capability, namespace-race, and filesystem faults cannot redirect publication outside the bound workspace target.

## Requirements

### Functional

- **OGVCS-046-FR-01:** Publication SHALL require the existing module-branded workspace and an owner-bound closed materialization preflight plan covering the exact path and entry kind.
- **OGVCS-046-FR-02:** The API SHALL consume an async byte source one bounded chunk at a time and SHALL NOT retain the complete file.
- **OGVCS-046-FR-03:** The API SHALL reject a byte-length or SHA-256 mismatch before replacing the target.
- **OGVCS-046-FR-04:** Capability authority SHALL be revalidated before the first destructive boundary and again immediately before publication.
- **OGVCS-046-FR-05:** The staged file SHALL be private, no-follow, same-filesystem, synced before publication, and atomically renamed only after exact stage, target, ancestor, and rollback state verification.
- **OGVCS-046-FR-06:** Replacing an existing file SHALL retain an exact owner-bound rollback link until publication is durable; an unavailable hardlink capability SHALL fail closed before replacement.
- **OGVCS-046-FR-07:** Source, integrity, limit, cancellation, disk, sync, rename, and callback failures SHALL preserve or restore the prior target and eagerly remove owned staging when safe.
- **OGVCS-046-FR-08:** Every crash boundary SHALL leave either the prior target or a versioned `write-stream` transaction record that inspection and recovery can validate without following links.

### Quality attributes

- **OGVCS-046-NFR-01:** Peak retained source memory SHALL be bounded by the configured chunk ceiling independently of file length.
- **OGVCS-046-NFR-02:** All public failures SHALL be stable `PathFilesystemError` values with privacy-safe details.
- **OGVCS-046-NFR-03:** Filesystem operations SHALL settle before cleanup; deadlines may cooperatively cancel sources and callbacks but SHALL NOT allow a timed-out filesystem promise to mutate after rollback.

## Interfaces and data

Publish `atomicWriteStream(workspace, repositoryPath, source, options)`. Required options are `plan`, `expectedBytes`, and lowercase `expectedSha256`. Resource options include `maxBytes`, `maxScratchBytes`, `maxChunkBytes`, `maxTimeMs`, `maxOperations`, and `signal`. The result uses the existing frozen `{path, bytes, sha256, transaction}` shape. The existing transaction-record version gains an additive `write-stream` operation with planned, staged, published, and committed states.

## Development plan

1. Implement bounded source adaptation, expected-identity checking, and no-follow staged writes.
2. Bind capability revalidation and rollback-link creation to the existing preflight authority.
3. Extend transaction inspection/recovery across every stream publication state.
4. Publish examples, package coverage, fault/race/resource/restart tests, and platform evidence.

## Acceptance criteria

- **OGVCS-046-AC-01:** A multi-chunk source publishes exact bytes while measured live source retention remains bounded by one configured chunk.
- **OGVCS-046-AC-02:** Source failure, cancellation, every configured resource ceiling, integrity mismatch, stage mutation, ancestor/target race, sync fault, and rename fault never replace the prior target without an honestly recoverable journal.
- **OGVCS-046-AC-03:** Restart tests at partial-stream, rollback-link, staged-record, post-rename, published-record, and committed-record boundaries restore or finalize the documented state and leave no transaction artifacts after recovery.
- **OGVCS-046-AC-04:** The packed npm consumer imports and executes the public API offline.
- **OGVCS-046-AC-05:** Linux, macOS, and Windows jobs pass the same behavioral suite, with unsupported rollback-link capability rejected before replacement.

## Verification plan

Run focused streaming publication tests, the complete path-filesystem package suite and syntax checks, packed offline consumer installation, and the existing three-platform path-filesystem workflow.

## Telemetry and operations

Use existing privacy-safe filesystem telemetry. Transaction inspection reports only stable operation, state, canonical repository path already present in owner-bound records, and artifact-presence fields; it does not report content or protected temporary paths.

## Rollout and rollback

The API and journal operation are additive. OGVCS-007 consumes the package-root export only after OGVCS-046 is complete. Rollback removes the export and implementation only after all `write-stream` remnants have been recovered or finalized.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Crash leaves a linked prior inode or partial stage | Durable state before every destructive transition and restart recovery tests |
| Timeout races a still-running filesystem promise | Await filesystem operations; race only cooperative source/callback work |
| Source mutates a yielded view | Copy each bounded chunk before hashing and writing |
| Native reparse behavior exceeds portable Node visibility | Preserve OGVCS-004 private-root requirement and fail closed on detected identity changes |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
