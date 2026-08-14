# OGVCS-045 — Untrusted parser sandbox and credential broker

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-003, OGVCS-004, OGVCS-009  
**Blocks:** OGVCS-020, OGVCS-026, OGVCS-029, OGVCS-031  
**Source:** [OpenGameVCS architecture](../../architecture.md)  
**Last updated:** 2026-08-14

## Outcome

Importers and later converter/merge tools can process hostile repository data through a reusable credential-free, no-network, resource-bounded sandbox while a separate minimal broker performs authorized acquisition and validates declared outputs.

## Problem

Read-only credentials do not make complex Git, Perforce, archive, image, or engine parsers safe. Running parsing in the same process that holds source or destination credentials converts malformed input into a credential-exfiltration and control-plane compromise path. Each consumer needs one proven isolation and broker contract.

## Scope

### In scope

- Signed tool/runtime manifests, immutable declared inputs, credentialed acquisition broker, isolated job runner, scratch/output contracts, validation, provenance, cancellation, cleanup, and safe errors.
- No-network/no-credential default, process/user/filesystem/capability/syscall isolation where supported, and strict CPU/memory/time/disk/output/fanout limits.
- Reference Linux worker backend for R1 plus portable adapter/conformance interface for later supported worker/client platforms.
- Adversarial corpus, network/credential canaries, parser harness, seeded escape/resource failures, and reusable conformance runner.

### Out of scope

- Git, Perforce, asset-preview, or semantic-merge domain parsing and output semantics.
- Executing arbitrary repository hooks, trusting tool output as source, or promising a universal kernel-level sandbox on an unsupported platform.
- Long-lived general compute jobs or public converter marketplace.

## Users and journeys

- **Importer:** asks a broker to acquire an immutable bounded source batch, parses it without credentials/network, and receives validated outputs plus provenance.
- **Security engineer:** plants network, filesystem, credential, fork, bomb, and exfiltration canaries and obtains deterministic denied evidence.
- **Operator:** revokes one vulnerable tool/runtime digest, stops new jobs, quarantines outputs, and preserves an audit trail.

## Requirements

### Functional

- **OGVCS-045-FR-01:** The acquisition broker SHALL use narrowly scoped read-only credentials, enforce source allowlists/quotas, write immutable staged inputs, and pass only handles plus declared metadata to the parser runner.
- **OGVCS-045-FR-02:** Parser workers SHALL receive no source, destination, user, repository, metadata-service, or object-store credential and SHALL have network disabled by default.
- **OGVCS-045-FR-03:** Each job SHALL bind signed tool/runtime digests, exact input digests, options, resource class, output schema, actor/purpose, and idempotency key.
- **OGVCS-045-FR-04:** The reference sandbox SHALL isolate process/user/filesystem/capabilities and supported syscall surface, use read-only runtime/input mounts, bounded scratch, and wall/CPU/memory/process/disk/output limits.
- **OGVCS-045-FR-05:** Outputs SHALL be count/size/type/schema/path validated and copied through a broker; workers SHALL not publish repository objects or mutate authoritative state directly.
- **OGVCS-045-FR-06:** Jobs SHALL be queued, cancellable, retry-bounded, restart-safe, and resistant to archive traversal, symlink/device tricks, decompression bombs, recursive structures, hangs, fork storms, and output floods.
- **OGVCS-045-FR-07:** Logs/errors SHALL use allowlisted safe codes; raw stderr, source paths/content, credentials, environment, and hidden metadata SHALL remain in restricted evidence or be discarded.
- **OGVCS-045-FR-08:** Tool/runtime revocation SHALL block new execution and output reuse for that generation and SHALL identify affected completed jobs without exposing their inputs broadly.
- **OGVCS-045-FR-09:** Provenance SHALL record job, input/tool/runtime/output digests, resource policy, broker/sandbox version, validation result, timestamps, and security events.
- **OGVCS-045-FR-10:** A portable adapter contract and conformance runner SHALL distinguish required isolation from platform-specific controls and fail closed when a required control is unavailable.

### Quality attributes

- **OGVCS-045-NFR-01:** Escape, credential, network, host-file, sibling-job, undeclared-input, and control-plane access attempts MUST fail under the reference R1 worker profile.
- **OGVCS-045-NFR-02:** Every bomb/hang/crash/fork/output-flood case MUST terminate within the declared resource envelope and leave subsequent jobs healthy.
- **OGVCS-045-NFR-03:** Broker/sandbox failure MUST NOT publish a partial authoritative mutation or make unvalidated output available to a consumer.

## Interfaces and data

Deliver tool/runtime manifest, acquisition request/grant, immutable staged-input descriptor, job/resource/output policy, runner adapter, safe result/error, validation report, provenance, revocation record, cleanup receipt, adversarial corpus, and conformance report.

## Development plan

1. Implement signed manifests, acquisition broker, immutable staging, job state/idempotency, credential separation, provenance, and safe result schemas.
2. Implement the reference no-network/credential-free Linux sandbox with namespace/capability/syscall/filesystem and resource limits plus cleanup/restart handling.
3. Implement output broker/validation, revocation, portable adapter/conformance runner, canaries, traversal/bomb/fork/output defenses, and consumer test harness.
4. Complete independent sandbox review and seeded escape/exfiltration/resource tests; publish packages and require consumer PRDs to pass the conformance profile.

## Acceptance criteria

- **OGVCS-045-AC-01:** Network, credential, host-file, sibling-job, undeclared-input, device/symlink, and control-plane canaries are inaccessible from the reference worker.
- **OGVCS-045-AC-02:** Traversal, bomb, recursion, hang, crash, fork, memory, disk and output attacks terminate within bounds and do not degrade the next clean job.
- **OGVCS-045-AC-03:** Killing broker/runner/output validation at every boundary leaves no authoritative mutation and resumes or safely restarts with one explainable job result.
- **OGVCS-045-AC-04:** Revoked/unsigned tools or unavailable required controls cannot execute or serve prior outputs as valid for the revoked generation.
- **OGVCS-045-AC-05:** A dummy importer and converter adapter pass the public conformance runner without receiving credentials or direct publication capability.

## Verification plan

Sandbox red-team corpus, network/credential canaries, namespace/filesystem/syscall tests, decoder/parser fuzzing, resource-exhaustion matrix, broker/runner crash injection, output validation, revocation races, provenance checks, and independent isolation review.

## Telemetry and operations

Expose queue age, job/result class, resource kills, tool/runtime/sandbox version, revocation, cleanup, and safe security violations. Credentials, paths, input/output content, environment, and user identity are excluded from shared telemetry.

## Rollout and rollback

Enable only the dummy conformance tool, then one importer parser profile. Consumer tools remain disabled if conformance or required isolation is unavailable. Emergency rollback revokes digests and stops workers without deleting staged evidence needed for investigation.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Platform sandbox offers weaker controls | Named profiles, conformance requirements, and fail-closed unsupported state |
| Broker becomes a confused deputy | Narrow source allowlists, immutable inputs, actor/purpose binding, no parser-selected credentials |
| Validated output still contains active content | Consumer-specific validation remains mandatory after generic bounds/schema checks |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
