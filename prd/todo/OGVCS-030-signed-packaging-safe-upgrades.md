# OGVCS-030 — Signed packaging and safe upgrades

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-021, OGVCS-022, OGVCS-023, OGVCS-028, OGVCS-041, OGVCS-043, OGVCS-044  
**Blocks:** OGVCS-032, OGVCS-036, OGVCS-037, OGVCS-038  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Operators and users can verify the origin and contents of every distributed component, upgrade through a compatibility-checked procedure, recover from interruption, and return to a supported state without trusting an online installer.

## Problem

A VCS is a supply-chain root for valuable source assets. Unsigned plugins, mutable downloads, unclear version skew, and in-place schema changes create compromise and outage risk. Early installation mechanics must mature into a signed release train with preflight, evidence, and explicit rollback limits.

## Scope

### In scope

- Reproducible or traceable builds, immutable release manifest, checksums, signatures, provenance, SBOM, license inventory, vulnerability policy, trust-root rotation, and offline bundles.
- Coordinated server/CLI/desktop/Unreal-plugin and desktop-review compatibility matrix, upgrade preflight, maintenance/drain, migration, verification, rollback/roll-forward, and release evidence.
- Supported single-site upgrade paths from designated prior releases.

### Out of scope

- HA rolling upgrades, app-store policy, unattended forced updates, managed-service rollout orchestration, or indefinite compatibility with every prerelease.

## Users and journeys

- **Administrator:** verifies an offline bundle, previews compatibility/disk/schema impact, backs up, upgrades, validates service/data, and records the result.
- **End user:** installs a signed CLI/desktop/plugin whose version is known compatible and can verify its build identity locally.
- **Security responder:** revokes a compromised signing key/artifact and publishes a signed replacement/recovery advisory through another trusted channel.

## Requirements

### Functional

- **OGVCS-030-FR-01:** Every release SHALL have an immutable canonical manifest listing component name/version/platform, digest/size, build provenance, source revision, protocol/schema/format ranges, dependencies, and release channel.
- **OGVCS-030-FR-02:** Artifacts and manifest SHALL be signed with an offline-root/rotatable-delegated trust design; installers/updaters SHALL verify signature, digest, expiry/revocation policy, and target platform before execution.
- **OGVCS-030-FR-03:** Each release SHALL publish a machine-readable SBOM, bundled-license inventory, vulnerability assessment/exceptions, and reproducibility or documented build-environment attestation.
- **OGVCS-030-FR-04:** A complete offline bundle SHALL contain all required artifacts, migrations, compatibility metadata, verification tooling, and docs; installation/upgrade SHALL require no vendor network access.
- **OGVCS-030-FR-05:** Upgrade preflight SHALL validate current/supported path, package authenticity, backup/restore freshness, storage/database health, disk headroom, configuration, schema, active jobs/submits, client skew, and rollback feasibility before mutation.
- **OGVCS-030-FR-06:** Upgrade SHALL use a durable staged state machine with maintenance/drain semantics, idempotent steps, progress, safe retry, and a recorded point after which restore/roll-forward replaces binary rollback.
- **OGVCS-030-FR-07:** Post-upgrade validation SHALL cover service readiness, protocol negotiation, repository invariants, sample content read/write, verifier state, events, locks, backup compatibility, and client/plugin smoke tests before reopening mutations.
- **OGVCS-030-FR-08:** The initial compatibility matrix SHALL be generated from the OGVCS-041 protocol/profile registry and define server-client/plugin/API/event/format skew and degraded behavior; incompatible mutations SHALL fail before they start. OGVCS-036 may extend public profiles/LTS coverage but SHALL not be required to define this R2 matrix.
- **OGVCS-030-FR-09:** Rollback SHALL be automated where formats remain compatible; otherwise the tool SHALL require a verified pre-upgrade recovery point and execute/document restore or forward recovery explicitly.
- **OGVCS-030-FR-10:** Trust-root rotation and emergency revocation SHALL be signed, threshold/dual-controlled, time-aware, testable offline, and resistant to rollback/freeze attacks.
- **OGVCS-030-FR-11:** Release notes SHALL call out migrations, compatibility removals, security fixes, operator actions, known risks, rollback boundary, and support window.
- **OGVCS-030-FR-12:** Signed/offline bundles and postflight SHALL include the OGVCS-043 integrated CLI, OGVCS-023 Unreal plugin, desktop client, and OGVCS-044 review workflow with exact supported combinations and smoke evidence.

### Quality attributes

- **OGVCS-030-NFR-01:** Tampered, truncated, substituted, wrong-platform, revoked, expired-policy, or downgrade artifacts MUST be rejected before executable/schema mutation.
- **OGVCS-030-NFR-02:** Crash/power-loss at every upgrade stage MUST resume or stop in a documented recoverable state without silent mixed-version service.
- **OGVCS-030-NFR-03:** The supported upgrade matrix MUST be exercised automatically for every release candidate using representative repositories and clients.

## Interfaces and data

Define release/artifact manifest, signature/trust metadata, SBOM/provenance links, OGVCS-041-derived compatibility matrix, integrated-client/plugin inventory, upgrade plan/state ledger, preflight and postflight reports, rollback boundary, revocation record, and operator evidence bundle.

## Development plan

1. Implement reproducible/attested build outputs, canonical release manifests, SBOM/license/vulnerability gates, artifact signing and complete offline bundle assembly.
2. Implement trust bootstrap/delegation/rotation/revocation and local artifact/bundle verifier with tamper, target-platform and downgrade protection.
3. Implement upgrade preflight plus durable drain/migrate/restart/postflight/rollback-or-restore state machine and the OGVCS-041-derived component compatibility matrix covering OGVCS-043/023/044 artifacts.
4. Complete supported-version, power-loss, capacity, key and offline operator drills, then promote identical digests through internal → partner → candidate → supported channels.

## Acceptance criteria

- **OGVCS-030-AC-01:** Independent offline verification authenticates every artifact and rejects the full tamper/substitution/downgrade/revocation corpus.
- **OGVCS-030-AC-02:** Every supported source→target version path upgrades a representative deployment and passes full postflight plus client/plugin compatibility tests.
- **OGVCS-030-AC-03:** Fault injection at each download/stage/drain/migration/restart/postflight point reaches only a safe retry, proven rollback, or documented restore/roll-forward state.
- **OGVCS-030-AC-04:** A release-blocking trust-root rotation/revocation drill succeeds using an offline bundle and separate trusted communication path.
- **OGVCS-030-AC-05:** An administrator unfamiliar with the build pipeline completes upgrade and recovery from published runbooks within the declared maintenance/RTO envelope.
- **OGVCS-030-AC-06:** Every supported bundle installs and smoke-tests the integrated CLI, desktop review workflow, and Unreal plugin; omitting or mismatching any declared component fails preflight before mutation.

## Verification plan

Artifact/signature negative suite, reproducibility/provenance checks, SBOM/vulnerability gates, full supported-version matrix, power-loss/fault harness, disk/capacity failures, key rotation/revocation exercise, offline installation, and timed operator upgrade/restore game.

## Telemetry and operations

Record local release/build identity, compatibility negotiation, preflight gates, stage/duration/result, migration ledger, postflight, and rollback/restore outcome. No updater analytics are required; any exported evidence is operator-controlled and scrubbed.

## Rollout and rollback

Promote immutable builds through internal, design-partner, candidate, and supported channels using the same digests. Upgrade is operator-initiated. Rollback follows the manifest's exact boundary; emergency revocation can prevent new installs without deleting working deployments automatically.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Signing key compromise | Offline root, delegated short-lived keys, dual control, revocation drills |
| Schema migration makes rollback impossible | Explicit boundary, verified backup gate, roll-forward/restore test |
| Client/server skew breaks production | Machine-readable matrix and mutation-time negotiation |
| Online service becomes a hidden dependency | Complete verifiable offline bundles |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
