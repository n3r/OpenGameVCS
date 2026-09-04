# OGVCS-045 conformance-closure boundary review

**Decision:** SHIP the source-only implementation and non-hosted models. HOLD
every live-v2, retained kill-matrix, public-admission, cleanup, production, and
acceptance-criterion claim.

**Reviewed source:**
`123bddf53e4ff647eba872ea96bb3cf7568509a5`, based exactly on
`4b25ff447b81d0d8d7728b1b782a5c83852b2535`.

## Accepted source boundary

The private portable runner executes exactly one dummy importer and one dummy
converter through the existing candidate broker/supervisor. Both must return
`VALIDATED`; the launch record must contain exactly `arguments`, `environment`,
`job`, `limits`, and `stdin`; the broker credential canary must be absent; and
no publication callback or repository authority may enter the launch record.
The runner remains repo-private and every report denies host-isolation,
production-broker, public-admission, and repository-publication claims.

Each report binds a 40-hex checked-out revision and a sorted, bounded inventory
of exact path, byte-count, and SHA-256 records. Generation first requires the
supplied revision to equal `git rev-parse --verify HEAD`, then requires every
inventory path to match that revision. Binary `git show` output is hashed as
bytes. The three-platform comparator snapshots every closed record and array,
requires Node 24 and exactly importer/converter, and rejects forged empty or
merely self-consistent reports.

The Linux v2 builder closes operating system, architecture, cgroup v2,
complete recognized controller inventory, seccomp, cgroup namespace,
rootless state, runtime name/path kind, sanitized runtime version/commit, and
`runtimeBinaryBinding: "unproven"`. The existing live workflow and v1 builder
remain the only retained channel and keep their prior payload. The committed v2
document is deliberately a synthetic schema fixture: no exact runc
version/commit or complete controller set for historical run 33636956770 was
available, so none was inferred.

## Hard-kill boundary

The exact frozen test-only hook sequence is:

1. `after-admission`
2. `after-acquisition-state`
3. `after-input-stage`
4. `after-stage`
5. `after-running-state`
6. `after-worker`
7. `after-validating-state`
8. `after-output-collection`
9. `after-validation`
10. `after-committing-state`
11. `before-output-commit`
12. `after-output-commit`
13. `after-result-commit`

The hook capability is available only from the package testing export, validates
the boundary at construction, fires once, durably writes its marker, and then
self-sends `SIGKILL`. The parent separately records whether its 15-second
watchdog fired; watchdog termination cannot satisfy a child self-kill case.

Expected restart dispositions are closed as follows:

- admission through `after-running-state` recover to one denied result;
- `after-worker` and `after-validating-state` remain nonterminal and quarantine
  when a daemon resource is represented;
- output collection through `before-output-commit` recover denied with no
  available output;
- `after-output-commit` removes the uncommitted local bundle and recovers
  denied; and
- `after-result-commit` replays the exact validated result and bundle.

The existing 16 Docker crash topologies remain a separate test inventory. An
empty topology permits local recovery; every represented container or volume
requires quarantine and asserts zero destructive Docker calls. No automatic
daemon cleanup was added.

Restart execution is Linux-only. Production stale-lease recovery authenticates
boot ID, PID, and `/proc` start ticks; macOS intentionally treats a killed owner
as unprovable, and Windows has no POSIX `SIGKILL`. On macOS with Node 24.9.0,
all 13 children did self-`SIGKILL` before the watchdog and left the expected
durable pre-restart state, but the Linux restart-disposition matrix was skipped.
The workflow can execute that matrix in Linux runner-temporary storage, but no
such run was dispatched or retained in this tranche.

## Retention and claim boundary

Workflow policy pins exactly one upload action and the exact historical v1
upload step. It fails if a second upload appears or portable, kill, source-v2,
control-fact, or runtime-binding metadata enters that retained slice. New
portable and kill commands write only under runner temporary storage and print
bounded summaries.

No Docker command, hosted dispatch, push, daemon mutation, orphan deletion,
public admission, or production rollout was performed for this review. The
source-only packet is labeled non-hosted; its Linux v2 controller/runtime facts
and kill dispositions are synthetic or non-executed models, not observations.

## Open blockers

A new authorized hosted run must retain genuine reports from Linux, macOS, and
Windows, a Linux live-Docker v2 report with exact observations, and the Linux
13-boundary restart report before those evidence claims exist. Exact daemon
runtime-binary identity remains unproved even when the daemon reports the
relative `runc` runtime name. Public conformance admission, a production broker,
consumer integration, independent isolation review, approved authenticated
daemon settlement, operations/runbooks, and rollout also remain open.

OGVCS-045 stays Todo and AC-01 through AC-05 remain open.
