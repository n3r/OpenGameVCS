# OGVCS-010 bounded private-candidate evidence

This packet preserves hosted evidence for the restricted, route-less
`PreallocatedCreationSubmit` candidate. It is not completion evidence for
OGVCS-010 and does not change the PRD's **Todo** status.

## Exact aggregate-plan binding and lock-order hardening

- Integrated source: [`3d793383c0289ddf0b3acc5887a79bc006b93e55`](https://github.com/n3r/OpenGameVCS/commit/3d793383c0289ddf0b3acc5887a79bc006b93e55)
- Workflow: [run 33579298064](https://github.com/n3r/OpenGameVCS/actions/runs/33579298064), completed successfully on 2026-09-02
- Machine record: [`github-actions-run-33579298064.json`](github-actions-run-33579298064.json)
- Retained restart report: [`atomic-submit-hard-restart-report-2026-09-02.jsonl`](atomic-submit-hard-restart-report-2026-09-02.jsonl), 10,094 bytes, SHA-256 `ac29199527a8c0d2c44f03b8d57e0a6cc400f652dd0dbfea8421cc0d1e8a74e1`

The exact source passed all four hosted jobs. The portable lanes used Node
24.18.0 on macOS and Node 24.19.0 on Ubuntu and Windows, with Rust 1.82.0.
PostgreSQL 15.19 passed the full bounded aggregate bridge and v13 mapping
matrix, both Clippy profiles, content-manifest availability, and the live
metadata report. The added cases prove that intent creation and preflight do
not wait behind mutable publication-row locks, and that fresh work is bound to
the exact aggregate plan ID, decision digest, and resource-projection digest.
Receipt substitution, changed-request reuse, pending unmapped work, and wrong
consumption fail closed without state mutation; historical committed replay
continues through its immutable stored plan and consumption evidence.

The separate hard-restart job passed all thirteen process-kill boundaries.
The retained JSONL contains thirteen distinct `passed` cases plus one `passed`
summary and reports changed Docker and PostgreSQL process identities after
every `SIGKILL`. The hosted service report was independently downloaded and is
byte-identical to the existing 1,001-byte report, SHA-256
`e8dae7794e0c71205c94f610fb7a99a8c6a1c8caea2ae57cf0f8a787f9747f40`;
it remains deduplicated under the OGVCS-006 evidence packet.

The first exact attempt, [run 33557680481](https://github.com/n3r/OpenGameVCS/actions/runs/33557680481), exposed a PostgreSQL-15-only defect in the new historical-migration
test helper: it tried to re-enable table triggers while deferred delete-trigger
events were pending. The production checks, macOS, Windows, and thirteen-case
restart job passed in that attempt. Source `3d79338` changed only the fixture to
use a connection-local replica role and restore it before disconnect; the
complete rerun then passed. The failed attempt is not counted as success
evidence.

This remains bounded private-adapter evidence. There is no public
`spec/atomic-submit` contract or route, request-root authorization, general
operation-set planner, production subject/scope mapper, lock/review/check
authority, public recovery receipt, 100-finalizer campaign, or exact-scale
execution. OGVCS-010 remains **Todo**.
