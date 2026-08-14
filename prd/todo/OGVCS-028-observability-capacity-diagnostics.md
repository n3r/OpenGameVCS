# OGVCS-028 — Observability, capacity, and diagnostics

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P0  
**Owner:** Unassigned  
**Depends on:** OGVCS-005, OGVCS-006, OGVCS-007, OGVCS-008, OGVCS-009, OGVCS-010, OGVCS-016, OGVCS-017, OGVCS-018, OGVCS-019, OGVCS-021, OGVCS-025, OGVCS-027  
**Blocks:** OGVCS-030, OGVCS-032, OGVCS-035  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Operators can determine whether OpenGameVCS is correct, available, fast, recoverable, and sufficiently provisioned from supported signals and runbooks—without inspecting customer content or asking engineers to query internal databases.

## Problem

Generic CPU dashboards cannot explain a stuck submit, stale verifier, authorization denial spike, lock hotspot, or approaching metadata/object limit. Reliability requires product-level service indicators, end-to-end correlation, privacy-safe diagnostics, capacity models, and alerts proven against injected failures.

## Scope

### In scope

- Service catalog, structured logs, metrics, traces, audit correlation, dashboards, SLO/error-budget definitions, alert rules, capacity forecasts, health views, diagnostics bundles, and incident runbooks.
- Coverage for every R1 critical user and operator journey plus R2 lock/cache/review signals as those components integrate.
- Collection/export configuration using open telemetry formats where practical.

### Out of scope

- A hosted monitoring vendor, security-information/event-management replacement, end-user product analytics, or automatic capacity procurement.

## Users and journeys

- **On-call operator:** moves from a user correlation ID to the failing stage/dependency, applies a tested runbook, and confirms recovery through an SLI.
- **Capacity planner:** forecasts metadata, unique object, egress, cache, verification, backup, and transaction headroom by repository/tenant without reading content.
- **Security/privacy reviewer:** knows every collected field, retention destination, redaction rule, and high-cardinality boundary.

## Requirements

### Functional

- **OGVCS-028-FR-01:** Publish a versioned service catalog mapping user journeys to components, dependencies, owners, SLIs, SLO targets, alert severity, and runbooks.
- **OGVCS-028-FR-02:** All request, background job, transaction, event, transfer, lock, verifier, backup, and cache paths SHALL carry safe correlation identifiers across service boundaries.
- **OGVCS-028-FR-03:** Structured signals SHALL use a reviewed schema with units, bounded labels, monotonic/counter semantics, sampling policy, version, and explicit prohibited sensitive fields.
- **OGVCS-028-FR-04:** Product SLIs SHALL cover submit correctness/latency, metadata reads, content transfer/integrity, authorization, lock acquisition/renewal, event lag, verifier freshness, backup/restore readiness, capacity, and client compatibility.
- **OGVCS-028-FR-05:** Correctness signals—missing referenced content, unauthorized success, split lock ownership, failed restore verification—SHALL be distinct from availability and latency and SHALL not be averaged away.
- **OGVCS-028-FR-06:** Alerts SHALL link a tested runbook, required permissions, safe diagnostic commands, escalation/communication criteria, and an objective recovery confirmation.
- **OGVCS-028-FR-07:** Capacity views SHALL distinguish logical/unique/replicated/cached/backup bytes, metadata growth, object/request rates, transfer egress, queue depth, and configurable headroom/exhaustion dates.
- **OGVCS-028-FR-08:** A diagnostics bundle SHALL be allowlist-built, locally previewable, redacted, time-bounded, size-bounded, encryptable, and omit content/path/message/token/secret data by default.
- **OGVCS-028-FR-09:** Audit records SHALL be linkable by approved operators without copying privileged event bodies into general logs or metrics.
- **OGVCS-028-FR-10:** Signal pipeline failure, lag, sampling, and dropped-cardinality data SHALL itself be visible; “no data” SHALL not display as healthy.
- **OGVCS-028-FR-11:** Default retention and export endpoints SHALL be documented/configurable and runtime operation SHALL not require a vendor observability service.
- **OGVCS-028-FR-12:** OGVCS-025 review/shelf publish, approval/check staleness, promotion and retention plus OGVCS-027 cache authorization, fill, corruption, eviction and origin-fallback paths SHALL have correlated safe SLIs, capacity signals, alerts and runbooks.

### Quality attributes

- **OGVCS-028-NFR-01:** Instrumentation overhead at reference load MUST remain within approved CPU, memory, storage, and p95 latency budgets.
- **OGVCS-028-NFR-02:** Every P0 fault-harness scenario MUST yield the expected SLI change and alert or an explicitly documented non-page event within a measured detection bound.
- **OGVCS-028-NFR-03:** Automated scanning and review MUST find no secret, credential, raw content, commit message, or protected full path in default exported signals/bundles.

## Interfaces and data

Deliver the telemetry schema/registry, service and journey catalog, SLI/SLO/error-budget definitions, dashboard/alert-as-code, capacity model/input schema, diagnostic-bundle manifest, safe correlation format, and runbook template/catalog.

## Development plan

1. Implement the telemetry schema registry, correlation propagation, service/journey catalog and baseline structured instrumentation for every R1 critical path plus OGVCS-025 review and OGVCS-027 cache contracts.
2. Implement SLI/SLO/error-budget definitions, dashboards, alerts-as-code, signal freshness/cardinality controls and open exporter configuration.
3. Implement capacity accounting/forecast models and allowlisted previewable diagnostics bundles with privacy canaries and audit correlation.
4. Run instrumentation-overhead/cardinality and full fault-to-alert incident games, publish runbooks, and promote signals from observe → ticket → page only after proof.

## Acceptance criteria

- **OGVCS-028-AC-01:** Operators diagnose and mitigate each representative commit, storage, auth, lock, verifier, backup, event, and dependency fault from supported signals/runbooks without internal database queries.
- **OGVCS-028-AC-02:** Fault-injection exercises verify alert threshold, detection time, routing, deduplication, runbook action, and recovery confirmation with no critical false-green state.
- **OGVCS-028-AC-03:** Reference-load comparison shows instrumentation within the approved overhead budget and cardinality/storage remain bounded.
- **OGVCS-028-AC-04:** Capacity forecasts correctly warn before synthetic disk/object/database/queue limits and reconcile logical, unique, replicated, cache, and backup byte accounting.
- **OGVCS-028-AC-05:** Privacy/security audit plus automated canaries find no prohibited data in default metrics, traces, logs, alerts, or diagnostics.
- **OGVCS-028-AC-06:** Review publish/promotion/staleness/retention and cache auth/fill/corruption/loss fault games produce the expected safe signals and recovery runbooks without leaking paths, review data, object IDs, or identities.

## Verification plan

Telemetry schema lint, canary secret/path tests, OGVCS-005 fault-to-alert matrix, load/overhead benchmark, cardinality attacks, collector outage/lag tests, dashboard snapshot checks, timed incident games, and capacity model backtesting.

## Telemetry and operations

This PRD owns the telemetry governance itself: schema changes are reviewed, dashboards/alerts are version controlled, SLOs are release-gated, and signal retention/export is operator-configured. A monthly design-partner review retires unactionable signals and adds missing runbook evidence.

## Rollout and rollback

Instrument in non-alerting mode, validate field safety/cardinality, publish dashboards, then enable ticket alerts and finally pages after fault-game proof. Individual signal/alert rules can roll back independently; correctness invariants retain a minimal emergency signal set.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| High-cardinality labels overload monitoring | Schema registry, bounded IDs, lint/load tests |
| Dashboards are green while telemetry is absent | Freshness/completeness meta-monitoring and explicit unknown state |
| Diagnostics leak studio IP | Allowlist construction, preview, redaction canaries, encryption |
| Alerts exist but are not actionable | Fault-game acceptance and runbook recovery confirmation |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
