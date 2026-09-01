# OGVCS-006 bounded candidate evidence

This packet preserves bounded hosted evidence for the internal PostgreSQL
metadata adapter. It is not completion evidence for OGVCS-006 and does not
change the PRD's **In development** status.

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
