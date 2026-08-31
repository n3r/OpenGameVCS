# OGVCS-008 — Object storage and transfer service

**Status:** In development

**Internal prerequisite:** repository metadata schema v9

**Date:** 2026-09-01

## Repository-backed lifecycle persistence tranche

- Reserved additive expand/migrate/contract migration v9 without deriving
  durability, health, lifecycle generations, or publication reachability from
  legacy metadata rows.
- Added normalized authoritative object lifecycle state, exact immutable
  backend/verification/deletion/reopen/health receipt facts, one-use receipt
  consumptions, publication reachability, deletion fences, direct transaction
  facts, application receipts, and an internal protected outbox.
- Corrected the health axis: `not-applicable` has no health generation or
  observation, while `healthy` and `unhealthy` require both. Newly available or
  quarantined objects may remain unobserved until their first health receipt.
- Added private direct publication persistence for a sorted/unique maximum of
  1,024 objects. The current metadata transaction hook is submit-only and
  revalidates its exact `Publish` view; GC and transfer capabilities remain
  closed pending their own authority participants.
- Added structurally sealed aggregate-plan persistence up to 100,000 declared
  objects with deterministic chunks of at most 1,000 items and 1 MiB. Items are
  inserted set-wise per chunk, payload and plan digests are recomputed, and
  global opaque-key order and object uniqueness are checked without loading a
  100,000-element Rust vector.
- Pinned the existing OGVCS-008 object-transfer rc.5 manifest and artifact-set
  digests without changing any ratified assignments.

## Deliberate remaining work

OGVCS-008 and OGVCS-010 remain Todo. This tranche does not implement backend,
KMS, filesystem, S3, network, transfer-session, or public protocol routes. The
aggregate plan commitment is structural, not an authority MAC; aggregate
application stays dormant until OGVCS-009 aggregate-v3 supplies and revalidates
its actual key-ring-authenticated receipt. The internal lifecycle application
receipt is not an authenticated or disaster-recovery OGVCS-010 commit receipt,
and audit correlation identifiers are not audit appends. GC current-root proof,
retention authority, transfer authority, hosted deployment, and exact-scale
campaigns remain future work.

## Bounded evidence

Rust 1.82 unit and PostgreSQL integration coverage exercises migration
checksum/replay/upgrade/future-version fences, lifecycle constraints, exact
receipt binding, direct 0/1/1,024/1,025 limits, declared aggregate
99,999/100,000/100,001 limits, 1,000+1 set-based chunk insertion, cross-chunk
order, duplicate/substitution/tamper rejection, submit-only poisoning, and
atomic application/fact/reachability/outbox persistence. These reduced fixtures
are intentionally not an exact 100,000-object performance campaign.

The integrated revision `a96f410a26e30a02116c2ecdf410ab040168b912`
also passed the bounded hosted workflow on Ubuntu with PostgreSQL 15, macOS,
and Windows ([run 33450207801](https://github.com/n3r/OpenGameVCS/actions/runs/33450207801)).
The retained 15-row report and machine record are in the
[OGVCS-006 bounded evidence packet](../evidence/OGVCS-006/README.md); they do
not claim hosted production deployment or exact-scale completion.
