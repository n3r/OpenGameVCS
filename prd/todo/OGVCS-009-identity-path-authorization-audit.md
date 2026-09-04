# OGVCS-009 — Identity, path authorization, and audit

**Status:** In development
**Release:** R1 — Developer Preview  
**Priority:** P0  
**Owner:** Codex and OpenGameVCS maintainers
**Depends on:** OGVCS-003, OGVCS-006, OGVCS-041  
**Blocks:** OGVCS-010, OGVCS-011, OGVCS-013, OGVCS-016, OGVCS-018, OGVCS-019, OGVCS-021, OGVCS-025, OGVCS-026, OGVCS-027, OGVCS-028, OGVCS-032, OGVCS-033, OGVCS-035, OGVCS-036, OGVCS-042, OGVCS-045  
**Source:** [Architecture ADR-0004](../../adr/0004-dr-authority-security-epochs.md)  
**Last updated:** 2026-09-05

## Outcome

Human and service identities authenticate through supported flows; every metadata/content operation receives one consistent path-aware authorization decision; privileged activity is captured in tamper-evident, access-controlled audit records.

## Problem

Repository-wide permissions are insufficient for outsourcing and sensitive game IP. Inconsistent filters across tree, history, lock, search, review, event, and object APIs can reveal hidden content even when direct download is denied.

## Scope

### In scope

- Local bootstrap identity, OIDC device/browser login, service identities, scoped tokens, sessions, and revocation.
- Versioned roles/groups/path policies and deterministic policy evaluation.
- Authorization middleware and filtered metadata views.
- Transfer-grant issuance for OGVCS-008.
- Append-only audit ingestion, integrity chain, query permission, retention hooks, and export.

### Out of scope

- Built-in enterprise identity provider, full SAML server, SIEM product, or compliance certification.

## Users and journeys

- **Artist:** signs in through studio OIDC and sees only authorized repository paths.
- **Build service:** uses a short-lived path/read-scoped identity without a human seat assumption.
- **Administrator:** grants an outsourcer access to one subtree and confirms enumeration tests deny everything else.
- **Auditor:** retrieves privileged action history without receiving unrelated protected content.

## Requirements

### Functional

- **OGVCS-009-FR-01:** The starter deployment SHALL support a recoverable local bootstrap administrator and OIDC Authorization Code with PKCE/device flow; production SHALL permit disabling local login after recovery configuration.
- **OGVCS-009-FR-02:** Service credentials SHALL be nonhuman, scoped, expiring, rotatable, and distinguishable in audit; stored secrets SHALL never be retrievable after creation.
- **OGVCS-009-FR-03:** Policies SHALL express tenant/repository/branch/path scopes, group/identity subjects, OGVCS-003 verbs, explicit deny, and inherited rules with versioned evaluation semantics.
- **OGVCS-009-FR-04:** All server APIs SHALL use the same decision library/service and pass canonical resource context; missing context or evaluator failure SHALL deny.
- **OGVCS-009-FR-05:** Tree, history, snapshot, lock, event, review, and list responses SHALL return authorization-filtered views that satisfy OGVCS-003 non-disclosure rules.
- **OGVCS-009-FR-06:** Transfer grants SHALL be short-lived, audience-bound, operation-specific, authority/security-epoch-bound, and revocable within the documented maximum window.
- **OGVCS-009-FR-07:** Policy changes SHALL be validated, versioned, previewable against example requests, atomic, and audited with actor/reason/diff reference.
- **OGVCS-009-FR-08:** Audit records SHALL be append-only, ordered per tenant, integrity-linked, redacted by event class, and readable/exportable only with separate permission.
- **OGVCS-009-FR-09:** Authentication/token/policy/audit endpoints SHALL have brute-force, enumeration, and rate controls.
- **OGVCS-009-FR-10:** Sessions, service tokens, grants, signing-key generations, and security-sensitive caches SHALL bind a monotonic authority/security epoch and fail closed after promotion to a newer epoch.
- **OGVCS-009-FR-11:** Epoch transition SHALL rotate or fence issuing authority, invalidate reusable old-epoch credentials/proofs, append an immutable audit event, and expose only a non-sensitive reauthentication/reconciliation reason.

### Quality attributes

- **OGVCS-009-NFR-01:** Authorization adds a measured p95 latency budget that does not violate same-region lock and metadata SLOs.
- **OGVCS-009-NFR-02:** Revoked human sessions/service tokens SHALL stop authorizing new operations within the declared bound; already issued object grants obey their shorter maximum TTL.
- **OGVCS-009-NFR-03:** Audit integrity verification MUST identify removal, insertion, reordering, or mutation of covered records.
- **OGVCS-009-NFR-04:** After a new authority epoch opens for writes, no old-epoch session, service token, transfer grant, lock proof, or cached allow decision may authorize a new protected operation.

## Interfaces and data

Publish identity/session/token, authority/security epoch and key generation, group/role/policy, authorize, batch-authorize, decision-reason, transfer-grant, audit append/query/export, and revocation contracts. Policy and audit schemas implement OGVCS-003 exactly. Clients receive actionable non-sensitive denial codes.

## Development plan

1. Implement identity/session/service-principal models and the first supported interactive and non-interactive authentication adapters with secure token lifecycle.
2. Implement versioned repository/path policy storage, canonical decision evaluation, authorized enumeration/query wrappers, and OGVCS-003 vector compatibility.
3. Implement scoped transfer-grant issuance plus the append-only tamper-evident audit ledger, privileged-action reasons, checkpoints, export, and sink cursors.
4. Complete revocation/non-disclosure/concurrency/load/failure tests, publish admin/client APIs and runbooks, then roll out deny-only observation before enforcement.

## Acceptance criteria

- **OGVCS-009-AC-01:** Internal-team and restricted-outsourcer golden policies pass every OGVCS-003 vector across all implemented APIs.
- **OGVCS-009-AC-02:** A known protected path/hash cannot be discovered through metadata, transfer, audit, timing batch shape, or error differences within the threat-model tolerance.
- **OGVCS-009-AC-03:** Session, service-token, and transfer-grant revocation meet documented bounds under cache and network faults.
- **OGVCS-009-AC-04:** Audit tamper tests identify every seeded modification and audit readers cannot access unauthorized event details.
- **OGVCS-009-AC-05:** OIDC outage preserves existing valid sessions as configured but never falls back to an unintended authentication path.
- **OGVCS-009-AC-06:** A simulated promotion rejects every seeded old-epoch session/token/grant/cache decision, accepts newly issued scoped credentials, and records one verifiable transition without protected-state leakage.

## Verification plan

Authorization conformance/negative enumeration, identity-flow integration, token lifecycle, fuzz/rate tests, policy property tests, audit tamper tests, and latency benchmarks.

## Telemetry and operations

Metrics cover auth success/failure class, policy latency/cache, denials, revocation lag, grant issuance, privileged actions, audit queue/verification, and rate limiting. High-cardinality identities/paths are confined to protected audit.

## Rollout and rollback

Policies deploy in monitor/dry-run mode against captured authorized test requests, then enforce deny. Evaluator versions dual-run before cutover. Rollback may revert policy version but cannot remove audit history or re-enable revoked credentials.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Fine-grained checks harm performance | Batch decisions, safe caches keyed by policy version, benchmark gates |
| Filtered history becomes misleading | Explicit partial-view markers without leaking hidden counts/details |
| Bootstrap account becomes permanent backdoor | Recovery ceremony, disable control, alerts, hardware/secret-store guidance |

## Completion evidence

- Implementation changes: candidate 0.2 OIDC/bootstrap, policy/security
  mutation, trusted checkpoint/rate-source, streamed aggregate authorization,
  and a private repository-metadata lifecycle bridge are implemented. The
  bridge consumes the opaque current receipt and commits identity consumption
  plus lifecycle evidence in one caller-owned serializable transaction. A
  sealed adapter-internal metadata read dispatcher additionally covers exactly
  `repository.get-settings` and `reference.read`: it reverifies negotiation at
  the database clock, authorizes the exact resource before existence lookup,
  and retains the decision through same-transaction commitment and commit. A
  separate source-only transaction-authorized page prerequisite now filters an
  ordered, server-derived candidate set after one sealed-view currentness
  reconstruction and exposes checked candidate references only after an exact
  live-transaction/query/candidate HMAC verification. The verified witness and
  its borrowed items cannot outlive the mutable transaction borrow. Its future
  separate `PostgresMetadataPageDispatcher` integration is constrained to
  exactly `tree.page`, `reference.list`, `history.ancestry-page`,
  `history.file-id-page`, `history.path-page`, and `file-id.history`;
  project-scoped `repository.list` is excluded. It is not wired by this
  contract tranche. The 0-through-10,000 public `pageSize` contract is retained:
  zero privately finds at most the first authorized sentinel, returns no items,
  returns `more` with a fresh cursor bound to the same decoded `after` position
  or internal empty-byte start sentinel when a sentinel exists, and otherwise
  returns `complete` with no cursor. A later positive page skips nothing and no
  denied-candidate status is exposed.
- Test and benchmark results: 30 bounded contract vectors, 60 JavaScript
  runtime tests, independent mutation/package gates, and bounded hosted
  three-OS evidence are present. Local PostgreSQL 16 evidence covers exact
  100,000-resource identity authorization and the reconciled hostile lifecycle
  bridge. A fresh PostgreSQL dispatcher test covers valid cross-subject token
  substitution, hidden/missing/cross-tenant/stale authority equivalence,
  attacker-key negotiation forgery, and post-decision commit rollback; the
  final combined hosted scale/latency campaign remains open. Bounded Rust unit
  and external contract tests cover the page primitive's complete-scan,
  duplicate, exact 100,000/100,001 candidate, 1,000-result, ordering, context,
  transaction, and HMAC boundaries without claiming a PostgreSQL live page
  run. Compile-fail probes additionally reject witness or borrowed-item reuse
  after the transaction boundary.
- Security/reliability review: caller-selected checkpoints, rate identities,
  transaction identities, policy preview, device-flow outage retry, and
  ambiguous decision commits fail closed.
- Documentation/runbooks: package/contract READMEs and the identity/policy
  operations runbook describe adapter ownership and recovery procedures.
- Rollout result: not yet rolled out. Studio OIDC/KMS providers, external audit
  checkpoint/root authority, public route binding, production SLO/fault proof,
  participant-derived session authority, HTTP/authentication/native-CLI
  carriers, the remaining metadata operations, and an end-to-end rollout
  remain completion gates. The dispatcher-private tenant/reference projections
  are not OGVCS-041 protocol mappings; every public metadata route remains
  unregistered. The page semantic-query digest is metadata-owner supplied and
  is not independently reconstructed here; negotiation `sessionId` is still
  not linked to credential presentation. This contract tranche adds no cursor
  or page dispatcher.
  Timing and non-disclosure acceptance remains open; every other acceptance
  criterion remains open as well.

This PRD remains in `prd/todo`, and all six OGVCS-009 acceptance criteria remain
open.
