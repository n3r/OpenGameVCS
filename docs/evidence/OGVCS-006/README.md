# OGVCS-006 bounded candidate evidence

This packet preserves bounded hosted evidence for the internal PostgreSQL
metadata adapter. It is not completion evidence for OGVCS-006 and does not
change the PRD's **In development** status.

## Root-scoped publication-candidate acquisition hosted update

- Source: [`2a56e3a7ee6c15cebf535c84b025a289abb079a9`](https://github.com/n3r/OpenGameVCS/commit/2a56e3a7ee6c15cebf535c84b025a289abb079a9)
- Workflow: [run 33516919674](https://github.com/n3r/OpenGameVCS/actions/runs/33516919674), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33516919674.json`](github-actions-run-33516919674.json)

The exact hosted source passed all four locked jobs: PostgreSQL 15 on Linux,
the separate thirteen-boundary PostgreSQL 15 hard-restart proof, macOS, and
Windows. The live PostgreSQL harness proves that publication-candidate reads
start from the exact Snapshot root and exclude unreachable corrupt or
foreign-contract metadata plus 1,001 unrelated FileID/import rows. Reachable
contract, identity, positional-substitution, and missing-row faults still
reject and roll back without partial reference, sequence, idempotency, or
outbox state. The portable Rust suite proves the exact 1,000-item batch plus
one-item remainder and its hostile header/payload boundaries on all three
host operating systems.

GitHub reports two non-expired archives for the run:

- `repository-metadata-postgres-Linux` (artifact `9804105079`): 586 archive
  bytes, digest
  `sha256:95b1a6460d397e7ac315c3c3f445092ede24fd37c66cb14425e59aa6e61bc34e`;
- `repository-metadata-atomic-submit-restart-PG15` (artifact `9804046666`):
  1,457 archive bytes, digest
  `sha256:2607afffc049b54c6a9b3de6905f14c81516955e95232c750ea63f46a36820bc`.

Those archive sizes and SHA-256 values are bound from the public GitHub Actions
artifact metadata. On 2026-09-01, authenticated `gh run download` acquisition
successfully extracted both artifacts. The CLI did not retain the downloaded
ZIP bytes, so the GitHub-reported archive digests were not independently
rehashed. The extracted thirteen-case-plus-summary hard-restart JSONL is 10,094
bytes with SHA-256
`0121ae6b7b106f360cfae39fa51bf199b4ee9b03b74be8f96fee413f33c0370e`;
all fourteen lines parse as JSON, the thirteen cases report `passed`, and the
summary reports `caseCount: 13`. The extracted hosted service report is 1,001
bytes with SHA-256
`e8dae7794e0c71205c94f610fb7a99a8c6a1c8caea2ae57cf0f8a787f9747f40`.
It is byte-identical to the exact source's unchanged deterministic 15-row
report retained as
[`repository-metadata-service-report-2026-09-01.jsonl`](repository-metadata-service-report-2026-09-01.jsonl)
(the same size and SHA-256). This proves direct hosted-report content equality;
it does not independently authenticate the transient ZIP representation.

This is bounded private-adapter evidence, not an exact-scale campaign. The
million-entry pagination case required by OGVCS-006-AC-04 and the exact
100,000-object publication-candidate campaign were not run;
`exactScaleExecuted` remains `false`. No public route, request-root authority,
production mapping writer, or object-store composition is claimed. OGVCS-006
remains **In development**.

## V13 aggregate identity-to-lifecycle mapping update

- Integrated and hosted source: [`aa13161cca228d5f92154928508f9f866225d9f5`](https://github.com/n3r/OpenGameVCS/commit/aa13161cca228d5f92154928508f9f866225d9f5)
- Workflow: [run 33506824950](https://github.com/n3r/OpenGameVCS/actions/runs/33506824950), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33506824950.json`](github-actions-run-33506824950.json)

The exact hosted source passed locked Node 24 and Rust 1.82 checks on Windows,
macOS, and Ubuntu. PostgreSQL 15 passed both Clippy profiles, the full bounded
aggregate bridge matrix, the content-manifest availability matrix, and the
live metadata report. The v13 cases require an immutable one-to-one mapping
seal between each lifecycle plan and OGVCS-009 identity plan, verify the exact
per-item relation even when lifecycle opaque-key order reverses identity order,
reject missing or hostile relations before receipt consumption, and roll back
mapping/evidence failures with the caller-owned SERIALIZABLE transaction.

The separate hard-restart job also passed all thirteen process-kill boundaries
with changed Docker and PostgreSQL process identities. The retained service
report is byte-identical to the existing 2026-09-01 packet; the new restart
artifact is content-bound by the machine record.

This remains bounded private-bridge evidence. The exact 100,000-item cases were
not enabled, no production mapping writer or JavaScript-to-Rust subject/scope
mapper exists, and no public submit route, request-root authority, or production
object-store composition is claimed. OGVCS-006 remains **In development**.

## Private content-manifest availability update

- Integrated implementation: [`31aa82eb4877b7b1bf62870202f4b76d2dcca10c`](https://github.com/n3r/OpenGameVCS/commit/31aa82eb4877b7b1bf62870202f4b76d2dcca10c)
- Hosted source: [`3827586d9d2f0cec489149b84b20eedf9c0bc03f`](https://github.com/n3r/OpenGameVCS/commit/3827586d9d2f0cec489149b84b20eedf9c0bc03f)
- Workflow: [run 33500174865](https://github.com/n3r/OpenGameVCS/actions/runs/33500174865), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33500174865.json`](github-actions-run-33500174865.json)

The exact hosted source passed Node 24 and Rust 1.82 locked checks on Windows,
macOS, and Ubuntu. The PostgreSQL 15 job passed both Clippy profiles, the
identity-bound and same-transaction aggregate regressions, and the new
route-less content-manifest availability matrix against fresh databases. The
matrix proves full explicit-set authorization before protected lookup,
one-use production-verification receipt consumption, staged-to-available CAS,
immutable typed proof and authorization-page commitments, lost-response
reconciliation, current lifecycle-contract pinning, tenant-scope equality,
fact/outbox identity, and current length/scope replay joins.

The first hosted attempt, run `33499729455`, exposed one stale v7-to-current
migration-count assertion after schema v12 added three phases. Commit
`3827586` changed the expected remaining count from twelve to fifteen; the
formerly failing identity-bound PostgreSQL test and the complete rerun then
passed. The retained service report remains byte-identical to
[`repository-metadata-service-report-2026-09-01.jsonl`](repository-metadata-service-report-2026-09-01.jsonl)
and is deduplicated.

This is bounded private-participant evidence. It adds no public route,
transport, JavaScript-to-Rust subject/scope mapper, request-root authority,
production S3/MinIO composition, health/GC/delete authority, or 100-GiB result.
PostgreSQL independently recomputes the lifecycle verification receipt, but
the Rust adapter remains authoritative for production-statement,
committed-proof, dependency-generation-set, and authorization-closure digests.
OGVCS-006 remains **In development**.

## Private atomic-submit hard-restart update

- Source: [`16afa896d589efec8e8c10e694efbefed44018ba`](https://github.com/n3r/OpenGameVCS/commit/16afa896d589efec8e8c10e694efbefed44018ba)
- Workflow: [run 33479805287](https://github.com/n3r/OpenGameVCS/actions/runs/33479805287), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33479805287.json`](github-actions-run-33479805287.json)
- Retained restart report: [`atomic-submit-hard-restart-report-2026-09-01.jsonl`](atomic-submit-hard-restart-report-2026-09-01.jsonl), 10,094 bytes, SHA-256 `85b36ec4c7f30c9864d5b3ffc7d25594a891ad038a3850cc339b872703df32ca`

Node 24 and Rust 1.82 locked checks passed on Windows, macOS, and Ubuntu.
Ubuntu also passed the ordinary PostgreSQL 15 suite. A separate PostgreSQL 15
job ran the feature-gated private atomic-submit harness through thirteen exact
crash boundaries, killed the PostgreSQL postmaster with `SIGKILL`, observed
exit 137, and required a changed Docker PID and postmaster start time after
every restart.

The eleven boundaries from `before-bridge` through `before-commit` recovered
the complete old state. The `commit-io` boundary also recovered the old state
in this run; either complete old or complete new is the accepted atomic
outcome at that boundary. `after-commit-before-response` recovered the complete
new state. Every recovery contained exactly one FileID consumption, identity
consumption, lifecycle application, and final outcome. The retained report
contains no connection URL, database name, loopback address, raw container or
backend identifier, or SQL/COMMIT query text.

The restart artifact is
`repository-metadata-atomic-submit-restart-PG15` (artifact `9789526442`, GitHub
digest `sha256:96641ace75d52c175440c678536baeaa5084263813b66aff89b7507dcd0477eb`).
The ordinary report artifact is `repository-metadata-postgres-Linux` (artifact
`9789561501`, GitHub digest
`sha256:9e2fba9a10a9fdd7a67a000fc6184fcd3cb6941373cf1d378f20fce3f9cebed8`);
its report is byte-identical to the already retained 2026-09-01 report and is
therefore deduplicated.

This is bounded private-adapter evidence. It does not prove a public or
production request path, production OGVCS-009 authorization, authenticated
server-host restart behavior, production orchestration, or the million-entry
acceptance campaign. `exactScaleExecuted` remains `false`, and OGVCS-006 stays
**In development**.

## Sealed metadata dispatcher update

- Source: [`883e34e225a7108a6251fe6c3dd75bb080987102`](https://github.com/n3r/OpenGameVCS/commit/883e34e225a7108a6251fe6c3dd75bb080987102)
- Workflow: [run 33470484624](https://github.com/n3r/OpenGameVCS/actions/runs/33470484624), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33470484624.json`](github-actions-run-33470484624.json)
- Retained live report: [`repository-metadata-service-report-2026-09-01.jsonl`](repository-metadata-service-report-2026-09-01.jsonl), 1,001 bytes, SHA-256 `e8dae7794e0c71205c94f610fb7a99a8c6a1c8caea2ae57cf0f8a787f9747f40`

Node 24 and Rust 1.82 locked checks passed on Windows, macOS, and Ubuntu.
Ubuntu additionally ran both Clippy profiles, the existing bounded PostgreSQL
suite, and the sealed metadata dispatcher regression against a separately
created fresh PostgreSQL 15 database. That regression proves successful
`repository.get-settings` and `reference.read`, subject-bound consistency
tokens, uniform hidden/missing/cross-tenant/stale/forged denials, retained
negotiation-key verification, and rollback on a deferred commit fault.

This remains bounded adapter evidence. The dispatcher is private, all public
metadata routes remain unregistered, the other twenty operations are absent,
and no authenticated server host, durable session authority, or native CLI
network carrier exists. The report artifact is byte-identical to the retained
lifecycle-v9 report and is therefore deduplicated.

## Public service-contract boundary update

- Source: [`e3c325c7f2b69a8ffb57a4723b814f2286569ba5`](https://github.com/n3r/OpenGameVCS/commit/e3c325c7f2b69a8ffb57a4723b814f2286569ba5)
- Workflow: [run 33454673693](https://github.com/n3r/OpenGameVCS/actions/runs/33454673693), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33454673693.json`](github-actions-run-33454673693.json)
- Retained live report: [`repository-metadata-service-report-2026-09-01.jsonl`](repository-metadata-service-report-2026-09-01.jsonl), 1,001 bytes, SHA-256 `e8dae7794e0c71205c94f610fb7a99a8c6a1c8caea2ae57cf0f8a787f9747f40`

Node 24 and Rust 1.82 locked checks passed on macOS, Windows, and Ubuntu;
Ubuntu also ran both Clippy profiles and the live PostgreSQL 15 harness. This
run covers the framework-neutral 22-operation contract adapter, bounded closed
request parsing, the 10,000-item public page limit, semantic idempotency, and
bounded response/error carriers. Protocol timestamps are validated as portable
Unix-millisecond integers before conversion to a platform `SystemTime`, so the
exact protocol maximum remains parseable and unreachable future reservations
are rejected consistently on Windows as well as Unix hosts.

The live report is byte-identical to the retained lifecycle-v9 report and is
therefore deduplicated. This is bounded service-contract evidence, not evidence
for a production transport/dispatcher, same-transaction aggregate lifecycle
coordination, or the million-entry acceptance campaign.

## Identity-v3 compatibility update

- Source: [`664bc0af1c53ded3bd85a4b262e246e187948c5f`](https://github.com/n3r/OpenGameVCS/commit/664bc0af1c53ded3bd85a4b262e246e187948c5f)
- Workflow: [run 33452564678](https://github.com/n3r/OpenGameVCS/actions/runs/33452564678), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33452564678.json`](github-actions-run-33452564678.json)
- Retained live report: [`repository-metadata-service-report-2026-09-01.jsonl`](repository-metadata-service-report-2026-09-01.jsonl), 1,001 bytes, SHA-256 `e8dae7794e0c71205c94f610fb7a99a8c6a1c8caea2ae57cf0f8a787f9747f40`

This rerun proves lifecycle-v9 together with identity migration v3 on macOS,
Windows, and Ubuntu/PostgreSQL 15. The integration regression found locally was
fixed without relaxing v3 credential immutability: authority promotion leaves
the epoch-1 credential unchanged and issues a new generation-2 credential with
a new presentation. The live test proves the old presentation is stale before
using the new credential. The hosted report is byte-identical to the retained
lifecycle-v9 report, so it is deduplicated rather than checked in twice.

This remains bounded evidence. It does not claim the public service,
same-transaction aggregate lifecycle application, or exact million-entry gate.

## Lifecycle-v9 update

- Source: [`a96f410a26e30a02116c2ecdf410ab040168b912`](https://github.com/n3r/OpenGameVCS/commit/a96f410a26e30a02116c2ecdf410ab040168b912)
- Workflow: [run 33450207801](https://github.com/n3r/OpenGameVCS/actions/runs/33450207801), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33450207801.json`](github-actions-run-33450207801.json)
- Retained live report: [`repository-metadata-service-report-2026-09-01.jsonl`](repository-metadata-service-report-2026-09-01.jsonl), 1,001 bytes, SHA-256 `e8dae7794e0c71205c94f610fb7a99a8c6a1c8caea2ae57cf0f8a787f9747f40`

Rust 1.82 locked tests passed on Ubuntu, macOS, and Windows. Ubuntu also ran
formatting, both default and feature-gated Clippy with warnings denied, the
identity-bound regressions, and the live harness against a disposable
PostgreSQL 15 service. All 15 bounded report rows passed, including immutable
settings, outbox leasing, project cursors, bounded history, and the new
`lifecycle-v9-atomic-publication` row. The Linux artifact is
`repository-metadata-postgres-Linux` (artifact `9779510931`) and expires on
2026-09-14; the report is retained here independently of that expiry.

This update remains bounded: `exactScaleExecuted` is `false`, aggregate
lifecycle application remains closed until the one-use OGVCS-009 receipt is
consumed in the same PostgreSQL transaction, and the public service and
million-entry gates remain open.

## Tested boundary

- Source: [`dd5a5f07a04913d15f8a52060bec6ca6f49099fc`](https://github.com/n3r/OpenGameVCS/commit/dd5a5f07a04913d15f8a52060bec6ca6f49099fc)
- Workflow: [run 33326767715](https://github.com/n3r/OpenGameVCS/actions/runs/33326767715), completed successfully on 2026-08-30
- Machine record: [`github-actions-run-33326767715.json`](github-actions-run-33326767715.json)
- Retained live report: [`repository-metadata-service-report-2026-08-30.jsonl`](repository-metadata-service-report-2026-08-30.jsonl), 711 bytes, SHA-256 `f54d4e449fa0962beefb492276ae709e4fc2b79d1b9e798fa6da3b90a7853491`

Rust 1.82 locked tests passed on Ubuntu, macOS, and Windows. Ubuntu additionally
ran formatting, Clippy with warnings denied, and the live harness against a
disposable PostgreSQL 15.19 service. The downloadable Linux artifact is
`repository-metadata-postgres-Linux` (artifact `9736467198`, archive SHA-256
`eccef87709a796debe16f799490f869832780418622a35e5ab077fa7f2d6f1ff`).
The raw report is checked in because the hosted artifact expires on
2026-09-13.

## Bounded result

All ten live rows passed:

1. v1-to-v2 migration preserves unpublished history;
2. canonical file graph;
3. authorization binding and transaction poisoning;
4. authorized-view item projections;
5. publication index and FileID lifetime binding;
6. 100 concurrent CAS racers;
7. FileID race and tombstone behavior;
8. rollback, outbox, and idempotency behavior;
9. repeat/checksum/downgrade migration behavior; and
10. primary and lagging consistency-token behavior.

## Deliberately unclaimed

`exactScaleExecuted` is `false`. This run did not execute the million-entry
pagination campaign and does not satisfy OGVCS-006-AC-04. Per the repository's
scale policy, that campaign remains deferred to the final release-scale run.

This evidence also does not claim the complete public 22-operation API,
production OGVCS-009/OIDC authorization, HTTP bindings, or production external
path-profile and chunk-store adapters. Those remain required before OGVCS-006
can leave **In development**.
