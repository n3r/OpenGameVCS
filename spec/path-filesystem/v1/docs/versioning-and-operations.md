# Versioning, operations, and rollback

Repository case mode, fold version, and platform-profile reference are immutable
repository settings. A behavior change receives a new profile major. Migration
must compute both old and new keys over the complete tree, report every
collision before mutation, preserve FileIDs, create normal OGVCS-002 rename
operations, and publish only after the new tree validates.

Version 1 has explicit outcomes for case-only rename, rename cycle,
directory/file replacement, delete/modify, junction/reparse point, sparse file,
locked-open file, antivirus interference, symlink materialization, and
executable intent in `registries/operation-outcomes.json`.

The reference API exposes a module-branded in-process telemetry collector with
profile IDs, stable preflight-failure classes, unsafe-target denials, watcher
gap/reconciliation counts and total duration, busy retries, and atomic fallback
refusals. Snapshots are frozen counters: they contain no protected full path,
symlink target, content digest, or temporary name and never invoke caller code.

Rollout starts in preflight/audit mode, then enables writes only after a
complete-set, workspace-bound plan has captured host capabilities and vector
conformance passes. Every materializing mutation revalidates that capability
snapshot. Rollback disables mutation and watcher
acceleration and forces reconciliation. It never changes collision keys,
relabels an existing repository, follows a link, publishes an incomplete
transaction, or marks an unreconciled workspace clean.
