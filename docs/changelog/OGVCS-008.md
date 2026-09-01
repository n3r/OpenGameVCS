# OGVCS-008 — Object storage and transfer service

**Candidate date:** 2026-09-01

**Contract:** `0.1.0-rc.6`

**Status:** In development; acceptance gates remain open

**Internal prerequisite:** repository metadata schema v9

**License:** MIT

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
- Pinned the OGVCS-008 object-transfer rc.6 manifest and artifact-set
  digests without changing any ratified assignments.

## Object storage and resumable transfer candidate

This lane adds a narrow branded backend capability port and S3-compatible
adapter while preserving the filesystem backend. The S3 path uses SigV4,
HTTPS-by-default transport, conditional immutable creation, exact metadata and
whole-body read-back, bounded retries/deadlines/listing, and generation-fenced
deletion. A common suite exercises both adapters, with an offline deterministic
fake and a pinned live-MinIO hosted job.

Logical 100-GiB content is represented as many immutable objects without
lifting the 64-MiB canonical object bound. Durable paged plans and verified
ledgers support resume and bounded-memory reconstruction/whole hashing. Sealed
batch plans bind grant/object set/request root/generation/receipt/pack offsets
and authorize the complete set before existence checks. Durable unique-byte
quota, internal availability/integrity events, and bounded privacy-safe
telemetry are also included.

The `0.1.0-rc.6` contract extends the filesystem anchor additively with S3 and
content-transfer profiles, seven schemas, and five vector sets. Existing error
codes, transition assignments, and public/wire route ownership are unchanged.

## Additive content-manifest production acceptor candidate

- Added an opaque package-branded repository-metadata candidate port without
  changing the frozen rc.6 semantic vectors or its existing same-process
  one-use receipt participant.
- The service now has an opt-in path that reads the durable stored manifest,
  reads every exact chunk from the same mapped tenant/repository authority,
  checks lifecycle and backend identities around every bounded read, calls the
  package-owned `verifyManifest()`, and crosses `commitProductionManifest()`
  before the adapter may atomically record kind-2 availability.
- Immediate commit and response-loss replay proofs bind the exact manifest,
  opaque key, authority/subject/tenant scope, backend receipt, generation,
  immutable production statement, verification digest, and original finalize
  semantic fingerprint. An `available` row alone is never accepted.
- Dependency reads are limited to the exact signed explicit grant set: at most
  4,096 unique objects including the manifest. The candidate advertises
  `requestRootDependencyClosure=false`; it streams the sorted dependency
  generation-set digest and requires the owning adapter to lock or revalidate
  every exact dependency generation through the same commit.
- Adapter functions and registries are captured; passive records are cloned and
  frozen; proxy/prototype/cross-instance handles fail closed. Adapter errors,
  including hostile getters/proxies/non-Error values, map to fixed
  non-secret-bearing transfer errors.

This is not a contract ratification or deployment claim. No real OGVCS-003,
OGVCS-006, or OGVCS-009 adapter and no public route currently implements the
candidate port. Its explicit 4,096-object ceiling cannot support the OGVCS-007
100-GiB request-root profile, so it must not be used to ratify that profile.

## Deliberate remaining work and open gates

OGVCS-008 and OGVCS-010 remain Todo. The pinned live-MinIO workflow now has
retained bounded hosted evidence, but the separately confirmed exact 100-GiB
interrupted transfer/reconstruction workflow has not run. Exact reference
throughput and memory acceptance therefore remain open. Public protocol routes,
reachability/GC, authenticated publication, retention and transfer authority,
KMS integration, and hosted production deployment remain owned by their
separate lanes.

The aggregate lifecycle plan commitment is structural, not an authority MAC;
aggregate application stays dormant until the OGVCS-009 aggregate-v3 receipt
is consumed and revalidated in the same transaction. The internal lifecycle
application receipt is not an authenticated or disaster-recovery OGVCS-010
commit receipt, and audit correlation identifiers are not audit appends.

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

The object-transfer candidate passed its local contract, runtime, workflow
policy, roadmap, hostile-case, syntax, and package dry-run gates. Hosted run
[33452796108](https://github.com/n3r/OpenGameVCS/actions/runs/33452796108)
passed Linux, macOS, Windows, and the pinned MinIO shared-backend job after an
earlier run exposed and commit `a36de6d` fixed an exact Windows lock-cleanup
race. The retained machine record is in the
[OGVCS-008 bounded evidence packet](../evidence/OGVCS-008/README.md). The
release-only exact 100-GiB job remains explicitly unexecuted.
