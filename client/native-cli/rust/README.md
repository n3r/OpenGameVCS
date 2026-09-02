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
- an enforced subscribe → complete baseline/ignore/full-scan → final watcher
  barrier order for rebuild and repair, with repair retaining one mutation lock
  across verification of and reseal from the exact same active generation;
- a fixed-width digest lookup that always revalidates the complete canonical
  path, repository key, and platform key after a digest hit;
- a strict `+1`, hash-chained watcher journal with exact 100,000-event and
  bounded-chunk limits, atomic cursor state, gap/overflow degradation, and
  content hashing for every event-touched regular file;
- opening and final private status-time watcher barriers under the mutation
  lock that journal exact session/cursor-linked batches and reject a page when
  the final event transcript differs from the one classified; an idle
  cursor-only advance is bound into the returned page and an authenticated
  prior page can continue when the exact authority and event transcript remain
  unchanged, while unavailable, failed, gapped, or substituted authority
  closes/degrades and the public wrapper installs only the unavailable fence;
- persisted watcher liveness with only two accepted shapes: authoritative is
  continuous, resumable, open, and not reconciliation-required; degraded is
  non-continuous, closed, and reconciliation-required;
- deterministic status classification, repository/local ignore precedence,
  structurally validated Applied staging candidates whose persisted path keys
  are re-derived and whose intent IDs and repository/platform path identities
  are checked for load-time and candidate-admission uniqueness, whose unordered
  watcher identity-reset or incompatible incoming/outgoing-lineage
  intersections fail closed without a FileID/prior, and whose locally
  immutable source FileID and current
  source absence are checked before a Move/Delete identity is lent; and
  owner-keyed HMAC v2 paging
  cursors retaining the exact watcher payload/cursor as authenticated
  predecessor audit bindings and binding the watcher authority plus event
  transcript, generation, staging generation/digest, repository settings, path
  profile/case mode, both ignore digests, filter, and full last path key;
- per-call authenticated reader leases created, synced, and kernel-locked
  before the mutation lock is released, so compaction cannot remove the
  generation used to construct that page;
- a private, bounded physical compactor that advances a durable logical epoch,
  reclaims only authenticated abandoned leases, removes at most eight sealed
  generations per call, and always retains the current generation plus its
  authenticated numeric predecessor; and
- authenticated rebuild/repair that publishes a new generation without
  modifying local work files; a test-only full-scan oracle independently reads
  the immutable baseline and filesystem, then compares every bounded status
  page after healthy repair and after reconstructible watcher-state/event-chain
  corruption. Active, seal, entry, lookup, finding, ignore, retention, key,
  lease, and pending-control corruption remains fail-closed before another
  generation is published. Rebuild preflight authenticates existing reader
  leases without deleting them, and status rejects the first distinct
  over-limit candidate before inserting it into the in-memory map.

No production-callable adapter can currently mint a native watcher continuity
proof: the only public checkpoint constructor is degraded. The first-party
binary also has no authenticated workspace-baseline route, so authoritative
clean status is not publicly available. The library now exposes typed
`workspace_status_page_authorized` and `repair_workspace_index_authorized`
adapter facades: both authenticate the current subject and authority/security
epochs and validate the public binding. Status rechecks the exact verified
workspace metadata under its mutation lock before each watcher fence and index
write. Repair checks it before watcher subscription and again under the lock
before generation publication; a race after subscription still fails before
index mutation. The first-party binary still installs the unavailable route,
and corrupt sealed authority still has no discard/reseed operation. Direct
watcher-batch append is no longer a public crate surface; test fixtures retain
it only to exercise the durable journal, while production adapters can deliver
a batch solely through the exact session/cursor-bound status-fence sink.
Compaction likewise has no public CLI route. A lease covers only one status
call/page: after that call returns, its cursor remains authenticated but a later
page fails stale if its generation, watcher authority/event transcript, or
staging snapshot changed. Only the old payload digest/cursor may drift under an
exact stable authority and transcript; they remain authenticated predecessor
audit bindings. Cursor-only idle advances are rebound on the next returned page
and do not force an unbounded restart. The active generation remains
byte-compatible with the `0.1.0-rc.1` generation format; the additive rc.2
retention controls, rc.3 reconciliation/cursor semantics, and rc.4 bounded
state-matrix/staging validation are private local metadata. The stable
`cursor-hmac-key-v1.bin` name versions key storage; rc.4 retains
`status-cursor/v2` plus its v2 domain and rejects v1 cursors. Mixed old/new processes are unsupported during
compaction: restart cooperating clients before enabling it, and rebuild the
private index before downgrading. Owner-HMACs and kernel locks fail closed for
cross-workspace/repository records, but they do not solve the documented
same-authority lock-namespace replacement or Unix unlink-by-handle residual.
Exact one-million-path p95, telemetry, the full fault matrix, and three-OS
native watcher evidence are also absent. The independent repair oracle is a
bounded test authority, not a public discard/reseed operation for corruption
of sealed baseline authority. OGVCS-012 therefore remains Todo.

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
node scripts/test-hermetic.mjs
```

`test-packed.sh` packages and tests the CLI together with the unpublished
OGVCS-002 and OGVCS-004 Rust crates as one offline artifact set.

`test-hermetic.mjs` is a test-only installed-artifact and process-recovery
gate. It packages those same three crates, unpacks them away from the checkout,
and builds the ordinary release `ogvcs` binary with no test feature or
test-specific environment adapter. It then copies only that binary and the
authenticated CLI contract into an initially empty runtime root. Package
archives, unpacked sources, and the build tree are removed before the copied
binary is exercised under fresh home, profile, configuration, and temporary
directories. The build may use Cargo's already provisioned offline dependency
cache; this is not a clean-host dependency-fetch or signed-distribution proof.

The separately built `ogvcs-hermetic-fixture` Cargo example is a controller,
not an installed product binary. It remains outside the runtime root and uses
the existing typed repository-route adapter boundary to prepare deterministic
local state and stop the controller process immediately after durable journal
and removal boundaries. Recovery, listing, and removal are then executed only
through the copied release binary. The installed binary has no fixture path,
feature, environment override, or route implementation. Cargo examples are not
installed, and workflow policy mechanically checks the separate target and
runtime inventories. On Windows, the controller compiles the packaged native
security module directly to create roots with the same atomic protected DACL
that the product validates; a separate root with an explicit Everyone allow
ACE proves that the installed binary rejects the hostile DACL before mutation.
An isolated `auth invoke` case proves credential environment delivery and the
unavailable public route independently of workspace-root validation.

The gate delivers real SIGINT and SIGTERM to the synchronized controller on
Linux and macOS. On Windows it creates a dedicated console process group and
requires `CTRL_BREAK_EVENT` delivery to that exact group; an unsupported or
failed delivery fails the gate, and the cleanup kill is never accepted as
signal evidence. Local macOS execution is proven by the source gate. Linux and
Windows execution for an exact candidate requires the pinned three-OS workflow
registered on `main` and `r1-foundation-integration` to complete for that exact
commit; this source tree does not substitute a prior run as candidate evidence.
This gate does not add a public route or authentication carrier, selective-sync
semantics, signing, installation packaging, or an OGVCS-011 completion claim.

## Plain-log and accessibility boundary

After cancellation signal-handler installation, ordinary command output is
deliberately terminal-agnostic text. A successful human command writes one
labeled `ok[CODE]: message` line to stdout. A failed human command writes one
labeled `error[CODE]: message` line followed by one `Next step: action` line to
stderr, in that order; stdout remains empty. This ordinary result path emits no
ANSI escape, cursor-control, hyperlink, spinner, or color sequence and does not
branch on `TERM`, `NO_COLOR`, `COLORTERM`, `CLICOLOR`, or force-color hints.
The current implementation ceiling is 384 UTF-8 bytes per human line, derived
from the authenticated result-field bounds and labels, and the process tests
exercise output through pipes with no interactive input.

For ordinary outcomes after signal installation, JSON output remains one
newline-terminated result object on stdout with empty stderr for both success
and failure. Hostile terminal environments must produce byte-identical JSON
and plain output. The exercised public-route failure keeps canary paths,
repository locators, and credential values out of both human and machine
failures, while credential values remain absent from every exercised result.
Nonsecret endpoints and digest identities intentionally present in ordinary
machine successes are not claimed as redacted. The Rust integration and
installed-artifact gates enforce these properties without a color or
terminal-detection dependency.

Signal-handler installation failure is a separate startup-fatal path before
format resolution. It emits a fixed, bounded, color-free two-line error and
next step on stderr, exits unavailable, and does not produce the machine JSON
envelope even when JSON was requested. This tranche does not relabel that path
as an ordinary command outcome or claim machine-stream uniformity for it.

This is bounded source and process evidence for OGVCS-011-AC-05. It is not a
screen-reader user study, a signed-binary usability certification, or hosted
three-OS evidence for this exact candidate; those remain release evidence
requirements while OGVCS-011 stays Todo.

The exact watcher/status limit proofs are opt-in bounded release tests:

```sh
cargo test --locked --offline \
  production::workspace_index::tests::exact_100000_watch_events_plus_one_and_new_generation_are_bounded \
  -- --ignored --exact --nocapture
cargo test --locked --offline \
  production::workspace_index::tests::exact_1000_changed_files_status_is_bounded \
  -- --ignored --exact --nocapture
```
