# OGVCS-045 — Untrusted parser sandbox and credential broker

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-003, OGVCS-004, OGVCS-009  
**Blocks:** OGVCS-020, OGVCS-026, OGVCS-029, OGVCS-031  
**Source:** [OpenGameVCS architecture](../../architecture.md)  
**Last updated:** 2026-09-02

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

- Implementation changes: exact source
  [`8e863b503bf2c0ebc66d1f80cf7935e1575575d0`](https://github.com/n3r/OpenGameVCS/commit/8e863b503bf2c0ebc66d1f80cf7935e1575575d0)
  provides a private candidate-named Linux reference worker and portable
  credential-free protocol boundary; it is not a production or public
  constructor. The later local-only restart tranche at
  [`3049f81880712cb1aead1e7634001f82b08ae76d`](https://github.com/n3r/OpenGameVCS/commit/3049f81880712cb1aead1e7634001f82b08ae76d)
  adds state-root-scoped daemon authority, authenticated current-authority
  resource discovery and inspection, closed hashed quarantine evidence, and
  restart ordering that refuses local job denial until daemon absence is
  proved. It deliberately performs no orphan deletion.
- Source-only conformance boundary: local revision
  `f857d91164730c79dd9c32273050d9f3ec7a6f94`, replayed onto integration
  `e32f0e26eef7a168994d31d9b89c434b11501a99` from the original
  `4b25ff447b81d0d8d7728b1b782a5c83852b2535` base, adds exact checked-out
  source binding, private importer/converter models, a closed Linux v2 schema,
  and 13 test-only hard-kill hooks. Its [non-hosted model
  packet](../../docs/evidence/OGVCS-045/source-only-v2/README.md) and
  [boundary review](../../docs/reviews/OGVCS-045-conformance-closure-boundary-review.md)
  make no live-Docker, complete controller-observation, exact OCI binary,
  Linux restart-execution, hosted retention, public admission, cleanup, or
  rollout claim. The historical v1 upload remains unchanged.
- Test and benchmark results: exact-source [hosted run
  33636956770](../../docs/evidence/OGVCS-045/github-actions-run-33636956770.json)
  passed the private Linux Docker/cgroup/seccomp lane and portable Node 24
  lanes on Ubuntu, macOS, and Windows at integration revision
  `3563167763a54b97eb8166ded1db895aa3a5b7cd`. Its retained 43-case [Linux
  report](../../docs/evidence/OGVCS-045/linux-reference-conformance-2026-09-02-run-33636956770.json)
  is 3,621 bytes with SHA-256
  `b3e292a64173ac76857c04545e3c41fb2a6b0a7c76e63b0271c380b050e7c472`.
  It records bounded private candidate behavior relevant to AC-01 and AC-02;
  the same hosted candidate lane exercised signed-manifest and required-control
  admission, prior/new-job revocation, restart detection, and closed-diagnostic
  checks relevant to AC-04. The historical initial candidate run remains
  retained in the evidence packet.
  Separately, a 2026-09-02 macOS/Node 24.9.0 local run of
  `npm run test:sandbox` passed five contract/package cases, 54 of 61 runtime
  cases with seven Linux-only cases skipped, and four retained/workflow policy
  cases. That local run covers restart detection and quarantine models but is
  neither retained Linux Docker evidence nor hosted settlement proof.
  For the source-only tranche, macOS/Node 24.9.0 additionally observed all 13
  test children self-`SIGKILL` before the parent watchdog with the expected
  durable pre-restart state. The Linux-only restart-disposition test was
  skipped, no hosted job was dispatched, and the committed kill document is
  explicitly a non-executed model.
- Security/reliability review: the retained
  [evidence packet](../../docs/evidence/OGVCS-045/README.md) is explicitly
  non-completion evidence. The narrow
  [restart-reconciliation boundary review](../../docs/reviews/OGVCS-045-restart-reconciliation-boundary-review.md)
  accepts only current-authority detection and quarantine. AC-03 and AC-05
  remain open, as do exact deployed runtime attestation, approved and hosted
  daemon-orphan settlement, the complete broker/runner/output-validator kill
  matrix, independent full isolation review, public conformance admission, and
  production broker/runner integration.
- Documentation/runbooks: the evidence packet and
  [`docs/changelog/OGVCS-045.md`](../../docs/changelog/OGVCS-045.md) document
  the private boundary and its fail-closed nonclaims; no production operations
  or cleanup runbook is claimed.
- Rollout result: none. OGVCS-045 remains Todo and all five acceptance criteria
  remain open. Consumer rollout, authoritative container/tmpfs cleanup,
  foreign, legacy, or ambiguous-resource operations, and production restart
  behavior remain open; neither the retained run nor the local detection
  tranche closes a criterion.
