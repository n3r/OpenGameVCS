# OGVCS-021 — Starter deployment and administrator bootstrap

**Status:** Todo  
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-006, OGVCS-008, OGVCS-009, OGVCS-017, OGVCS-018  
**Blocks:** OGVCS-028, OGVCS-030, OGVCS-032, OGVCS-043  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-09-02

## Outcome

An administrator can install a supported single-site OpenGameVCS deployment from documented artifacts, bootstrap identity/storage safely, diagnose health, back it up, restore it, and remove it without hidden vendor services.

## Problem

Correct components do not make an operable product. Early deployments fail when configuration is implicit, secrets are copied into files, readiness means only “process is alive,” or no one has rehearsed recovery. The developer preview needs one narrow, repeatable reference topology before promising high availability.

## Scope

### In scope

- Supported single-node/single-site service topology, packages or container composition, metadata database, filesystem/S3-compatible content backends, TLS, identity bootstrap, and first repository.
- Configuration validation, migrations, health/readiness, backup/restore hooks, logs/metrics endpoints, diagnostics bundle, and install/upgrade/uninstall runbooks.
- Air-gapped-capable runtime after artifacts and dependencies are staged.

### Out of scope

- High availability, cross-region failover, rolling upgrades, managed hosting, auto-scaling, and broad Kubernetes/operator support.

## Users and journeys

- **Administrator:** validates prerequisites, installs, bootstraps the first admin through a one-time path, connects object storage and identity, and creates a repository.
- **Operator:** distinguishes dependency degradation from process death, collects redacted diagnostics, backs up, and restores to a clean host.
- **Security reviewer:** confirms trust roots, secrets, ports, principals, filesystem ownership, and outbound network requirements.

## Requirements

### Functional

- **OGVCS-021-FR-01:** The reference topology SHALL declare supported OS/runtime/database/object-store versions, CPU/RAM/disk/network sizing, ports, service accounts, and filesystem permissions.
- **OGVCS-021-FR-02:** Installation SHALL be non-interactive after explicit configuration and SHALL validate all inputs/dependencies before mutating durable schema or repository state.
- **OGVCS-021-FR-03:** First-admin bootstrap SHALL use a time-bounded single-use secret over TLS and SHALL be disabled permanently after successful identity-provider/admin configuration unless an audited recovery procedure is invoked.
- **OGVCS-021-FR-04:** Secrets SHALL be accepted through supported secret providers/files with restrictive permissions, never embedded in generated public configuration, images, command history guidance, or diagnostics.
- **OGVCS-021-FR-05:** Configuration SHALL have a versioned schema, validation command, documented defaults, safe reload/restart classification, and rejection of unknown/invalid security-critical keys.
- **OGVCS-021-FR-06:** Liveness and readiness SHALL separately report metadata, storage, identity, verifier, backup, capacity, and schema compatibility with actionable but non-secret reason codes.
- **OGVCS-021-FR-07:** Schema changes SHALL be versioned, preflighted, resumable where possible, backup-gated when irreversible, and refuse unsupported downgrade.
- **OGVCS-021-FR-08:** The bundle SHALL invoke OGVCS-018 backup/restore and OGVCS-017 verification without undocumented manual database/object-store edits.
- **OGVCS-021-FR-09:** Runtime operation SHALL not require a vendor license/check-in service; all outbound destinations and telemetry defaults SHALL be explicit and disableable.
- **OGVCS-021-FR-10:** Uninstall SHALL preserve durable data by default and require an explicit separate confirmation to remove named deployment data.

### Quality attributes

- **OGVCS-021-NFR-01:** A trained administrator MUST complete clean install, identity/storage bootstrap, first repository creation, backup, clean restore and verification using only published runbooks within two hours on the reference environment.
- **OGVCS-021-NFR-02:** Repeating install, config validation, restart, and restore commands MUST be idempotent or fail with an actionable safe state.
- **OGVCS-021-NFR-03:** Default exposure MUST be least privilege: TLS required outside loopback, no default passwords, no anonymous repository access, and minimal service-account permissions.

## Interfaces and data

Deliver the reference topology manifest, versioned configuration schema, prerequisite/preflight report, bootstrap token record, migration ledger, health/readiness schema, diagnostic-bundle manifest, and install/recovery runbooks.

## Development plan

1. Implement the reference topology/package composition, prerequisite checker, versioned configuration schema/validator, service users, ports, TLS, and filesystem/object-store setup.
2. Implement one-time first-admin/identity/storage/repository bootstrap, secret-provider integration, secure defaults, liveness/readiness, and idempotent install/restart.
3. Integrate schema migration ledger, backup/restore/verifier commands, capacity checks, diagnostic bundles, and preserve-by-default uninstall/reinstall.
4. Complete clean-host/offline/negative/dependency-fault/security and timed-operator tests, publish immutable artifacts/runbooks, and support exactly one topology initially.

## Acceptance criteria

- **OGVCS-021-AC-01:** Fresh supported hosts complete automated install, identity/storage bootstrap, repository creation, backup, clean restore, and full metadata/content/configuration verification without undocumented access.
- **OGVCS-021-AC-02:** Invalid TLS, credentials, permissions, schema, database, object store, capacity, and clock configurations fail preflight with no partial durable mutation.
- **OGVCS-021-AC-03:** Dependency failure matrix produces correct liveness/readiness and prevents mutation readiness whenever metadata, object storage, identity, schema, capacity, verifier, or backup prerequisites are unsafe.
- **OGVCS-021-AC-04:** Security review finds no shipped default credential, world-readable secret, undeclared listener, mandatory vendor egress, or unredacted diagnostic secret.
- **OGVCS-021-AC-05:** Uninstall/reinstall preserves named data by default and the recovery runbook restores service without private engineering intervention.

## Verification plan

Clean-host CI across supported platforms/topologies, configuration fuzz/negative tests, dependency failure injection, secret and listener scanning, backup/restore drill, upgrade interruption tests, offline runtime test, and timed operator usability exercise.

## Telemetry and operations

Expose component version/build, safe config fingerprint, dependency readiness, capacity thresholds, backup/verifier age, migration state, and request correlation. Diagnostic bundles are allowlisted, previewable, and redacted by construction.

## Rollout and rollback

Publish immutable prerelease artifacts and one reference topology. Every schema-changing update requires backup and a rehearsed recovery path. Rollback restores the last compatible package/config or documented backup; unsupported database downgrade is blocked explicitly.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| “Easy install” hides unsafe defaults | Secure schema defaults and automated exposure/secret checks |
| Environment matrix grows before core is stable | One supported topology with explicit compatibility table |
| Upgrade leaves mixed schema/binaries | Preflight, migration ledger, compatibility fence, backup gate |
| Diagnostics leak studio data | Allowlist collection, local preview, redaction tests |

## Completion evidence

- Implementation changes: Bounded candidate relevance only. The unpublished,
  unwired Rust 1.82 rc.3 crate under `core/deployment-preflight/rust` evaluates
  one fixed caller-supplied topology and one fixed generation-bound set of
  metadata, object-storage, identity, verifier, backup, capacity, and schema
  observations. It rejects unsafe supplied listener/default/secret-reference/
  service-principal shapes, separates liveness from readiness with closed safe
  reasons, rejects schema downgrade, applies a supplied maximum-300-second
  observation-age fence, and requires opaque irreversible-migration evidence
  bound to the deployment, exact artifact set, compatibility and configuration
  generation, source and target schema, and current metadata, object-storage,
  verifier, backup, and schema observation generations. It also binds the
  verified manifest subject, distinct source/target claims, and retention
  beyond evaluation. A pure addition compares two independently validated,
  supplied configurations: exact equality reports no observed change; every
  same-deployment difference requires a distinct opaque generation and at
  least a full restart; artifact or compatibility changes require an external
  deployment procedure. It offers no reload-safe or operational-permission
  result. It performs no discovery, installation, bootstrap, migration,
  backup, restore, reload, restart, upgrade, service operation, or durable
  mutation.
- Test and benchmark results: Local deterministic unit cases cover the healthy
  configuration/observation/report known answers and exhaustive projection
  binding; listener exposure/port negatives; distinct secret-reference and
  service-principal shapes; generation, compatibility, observation order and
  temporal edges; all seven dependency classes and 28 unhealthy states;
  irreversible migration scope/source/manifest/retention gating; stable error
  precedence; exact/max+1 fixed-shape, logical-work and conservative retained-
  charge limits; cancellation; redacted debug; and report-local structural
  checks. Transition cases cover the deterministic checksum and direction;
  configuration-generation reuse; deployment, artifact, compatibility,
  listener, secret, and principal substitution; invalid prior/replacement
  shapes; exact and max+1 work/retained bounds; checked overflow; every
  cancellation checkpoint; report tampering; and redacted debug. Rust 1.82
  debug/release, warning-denied Clippy, bounded and extracted package,
  source-policy, and roadmap gates are the candidate's local evidence. Exact
  revision `fa61786b272a019b82f4e96eaaa47dbef60c5b6c` also passed this
  source/package boundary on hosted Linux, macOS, and Windows in
  [run 33664922198](https://github.com/n3r/OpenGameVCS/actions/runs/33664922198).
  That is source portability only; no clean-host, deployed dependency-fault,
  offline-runtime, timed-operator, scale, latency, or SLO campaign has run.
- Security/reliability review: See
  `docs/reviews/OGVCS-021-deployment-preflight-boundary-review.md`. Secret and
  principal values are opaque commitments and every access/permission/health/
  time field remains a supplied fact. The report checksum is not
  authentication, authorization, freshness, or audit evidence. Exact input
  cardinalities, pre-traversal 18/19-unit logical-work admission, allocation-
  free validation, fixed-buffer reason staging, pre-result-allocation 512–640
  byte conservative retained charging, and cooperative cancellation provide
  only a bounded pure-evaluator boundary. Transition comparison adds a fixed
  21-unit logical charge and conservative 192-byte fixed-result charge. Its
  directional checksum is likewise unauthenticated, it does not establish
  installed state or generation order, and neither candidate result has a
  mutation-authorization or `mutation_ready` field.
- Documentation/runbooks: The private crate README documents the supplied-fact
  topology, readiness, migration, and conservative transition boundaries,
  resource behavior, and nonclaims. There is no install, bootstrap, restart,
  upgrade, recovery, backup/restore, diagnostics, or uninstall operator runbook
  because none of those workflows exists yet.
- Rollout result: Not rolled out. OGVCS-021 remains Todo and all five
  acceptance criteria remain open. Supported artifacts and versions,
  prerequisite discovery, installer/composition, real secret/TLS/identity/
  storage integration, first-admin bootstrap, public configuration/parser and
  health interfaces, installed-generation discovery/provenance, reload-safe
  classification, actual restart/upgrade behavior, migration ledger/execution,
  OGVCS-017/018 invocation, diagnostics, repository creation,
  uninstall/reinstall, clean recovery, and operations evidence remain
  unimplemented.
