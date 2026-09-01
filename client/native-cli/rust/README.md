# OpenGameVCS verified local CLI foundation — Rust

`ogvcs-local-cli` implements contract `0.2.0-rc.2`, a fail-closed OGVCS-011
local foundation candidate. It is a production-oriented local tranche, not an
OGVCS-011 completion or remote E2E claim.

The crate also contains a private OGVCS-012 workspace-index candidate. It does
not add a public `status` command or change the first-party route adapter.

Implemented surface:

- fieldwise configuration precedence `flag > environment > workspace > user
  profile > system default`, with nonsecret source reporting;
- stable human/JSON results and exit classes;
- explicit headless and OS credential-provider interfaces whose secret bytes
  cannot be cloned, debugged, serialized, or retained after authentication;
- typed, versioned authentication/discovery/capability/binding/FileID ports,
  including a receipt-bearing handoff for an already reconciled allocation;
- atomic verified workspace create/open/list/configure/recover/remove with
  digest-bound journals and deterministic crash reconciliation;
- OGVCS-004 canonical-path and collision-key preflight plus bounded local
  add/move/delete/revert intent that never uploads or submits;
- progress, resume tokens, cooperative cancellation, Unix signals, Windows
  console cancellation, and explicit redacted diagnostics;
- owner/mode/ACL/link/reparse checks on Unix, macOS, and Windows; atomic
  no-replace handle-relative mutation on Linux/macOS and a Windows
  `NtSetInformationFile(FileRenameInformation)` adapter.

The private workspace-index candidate adds:

- bounded canonical baseline streaming (at most 1,000 entries and 1 MiB per
  chunk) with a complete current-binding receipt, rather than a caller-owned
  million-entry vector;
- create-new, sealed generations whose artifacts and owning directory are
  synced before an atomic active-pointer promotion; status fails closed while
  a transition is active and revalidates active/watcher state before return;
- a fixed-width digest lookup that always revalidates the complete canonical
  path, repository key, and platform key after a digest hit;
- a strict `+1`, hash-chained watcher journal with exact 100,000-event and
  bounded-chunk limits, atomic cursor state, gap/overflow degradation, and
  content hashing for every event-touched regular file;
- deterministic status classification, repository/local ignore precedence,
  and owner-keyed HMAC paging cursors bound to the generation, repository
  settings, path profile/case mode, both ignore digests, filter, and full last
  path key;
- per-call authenticated reader leases created, synced, and kernel-locked
  before the mutation lock is released, so compaction cannot remove the
  generation used to construct that page;
- a private, bounded physical compactor that advances a durable logical epoch,
  reclaims only authenticated abandoned leases, removes at most eight sealed
  generations per call, and always retains the current generation plus its
  authenticated numeric predecessor; and
- authenticated rebuild/repair that publishes a new generation without
  modifying local work files.

No production-callable adapter can currently mint a native watcher continuity
proof: the only public checkpoint constructor is degraded. The first-party
binary also has no authenticated workspace-baseline route, so authoritative
clean status is not publicly available. Compaction likewise has no public CLI
route. A lease covers only one status call/page: after that call returns, its
cursor remains authenticated but a later page may fail stale if its generation
has been reclaimed. The active generation remains byte-compatible with the
`0.1.0-rc.1` generation format; the additive `0.1.0-rc.2` retention controls
are private local metadata. Mixed old/new processes are unsupported during
compaction: restart cooperating clients before enabling it, and rebuild the
private index before downgrading. Owner-HMACs and kernel locks fail closed for
cross-workspace/repository records, but they do not solve the documented
same-authority lock-namespace replacement or Unix unlink-by-handle residual.
Exact one-million-path p95, telemetry, the full fault matrix, and three-OS
native watcher evidence are also absent. OGVCS-012 therefore remains Todo.

The first-party binary installs `UnavailablePublicRoutes`, so commands that
need OGVCS-006/008/009 fail with `PUBLIC_ROUTE_UNAVAILABLE` before local
mutation. Tests use typed fakes. Capability selections are bound to exact
predecessor registry hashes, but this crate does not itself MAC-verify complete
OGVCS-041 negotiation receipt claims; that remains a public-adapter blocker.

`stage_add` does not own or invoke OGVCS-006 `file-id.allocate`. It accepts only
a predecessor-presented allocation that was already completed and reconciled,
then retains the opaque `far1` receipt plus idempotency-key digest in the
private staging journal. Public reports contain digests only. Publishing the
allocation/status adapter and proving its lost-response recovery remain
explicit residuals.

The local mutation lock serializes cooperating CLI processes. It is not a
security boundary against a malicious same-authority process that replaces the
lock namespace entry between commands or detaches the locked inode on Unix.
Windows lock handles deny delete sharing while held. Windows files receive
their owner and protected DACL atomically at `CREATE_NEW`; directories receive
the same descriptor at `CreateDirectoryW`, followed by a no-follow validation
open. The same-authority namespace interval between directory creation and that
open remains an explicit residual. If that reopen cannot prove the created
identity, the command fails closed and deliberately leaves uncertain cleanup
to recovery instead of deleting a possibly substituted directory. Hosted
Windows runtime evidence is tracked separately.

Windows file and directory flush handles are opened synchronously (without
`FILE_FLAG_OVERLAPPED`) with `GENERIC_WRITE`; file contents and both pinned
mutation parents are passed through `FlushFileBuffers`. Confined rename uses
the source handle plus a pinned destination-directory `RootDirectory` handle,
an explicitly NUL-backed `FILE_RENAME_INFORMATION` buffer, and
`ReplaceIfExists=false`. The native rename call is documented from Windows
2000, while this crate's handle-bound cleanup also uses
`SetFileInformationByHandle`, documented from Windows Vista. The product PRD
still defines the supported floor as current supported Windows rather than a
specific legacy release; this candidate does not broaden that policy.

The authenticated companion schemas/vectors live in
[`spec/cli-workspace/v1`](../../../spec/cli-workspace/v1). The original v1
unverified local-declaration library surface remains for compatibility; the
binary uses the verified v2 path.

The private workspace-index format, limits, crash ordering, cursor bindings,
and nonclaims are authenticated separately in
[`contracts/workspace-index/v1`](contracts/workspace-index/v1). This contract
is local implementation evidence, not a public protocol assignment.

Rust 1.82 bounded gates:

```sh
node ../../../spec/cli-workspace/v1/scripts/generate.mjs --check
node ../../../spec/cli-workspace/v1/validate-spec.mjs
node scripts/sync-contract.mjs --check
node contracts/workspace-index/v1/scripts/generate.mjs --check
node contracts/workspace-index/v1/validate.mjs
cargo fmt --all -- --check
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
./scripts/test-packed.sh
```

`test-packed.sh` packages and tests the CLI together with the unpublished
OGVCS-002 and OGVCS-004 Rust crates as one offline artifact set.

The exact watcher/status limit proofs are opt-in bounded release tests:

```sh
cargo test --locked --offline \
  production::workspace_index::tests::exact_100000_watch_events_plus_one_and_new_generation_are_bounded \
  -- --ignored --exact --nocapture
cargo test --locked --offline \
  production::workspace_index::tests::exact_1000_changed_files_status_is_bounded \
  -- --ignored --exact --nocapture
```
