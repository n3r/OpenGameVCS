# OpenGameVCS verified local CLI foundation — Rust

`ogvcs-local-cli` implements contract `0.2.0-rc.2`, a fail-closed OGVCS-011
local foundation candidate. It is a production-oriented local tranche, not an
OGVCS-011 completion or remote E2E claim.

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
  `SetFileInformationByHandle` adapter.

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

The authenticated companion schemas/vectors live in
[`spec/cli-workspace/v1`](../../../spec/cli-workspace/v1). The original v1
unverified local-declaration library surface remains for compatibility; the
binary uses the verified v2 path.

Rust 1.82 bounded gates:

```sh
node ../../../spec/cli-workspace/v1/scripts/generate.mjs --check
node ../../../spec/cli-workspace/v1/validate-spec.mjs
node scripts/sync-contract.mjs --check
cargo fmt --all -- --check
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
./scripts/test-packed.sh
```

`test-packed.sh` packages and tests the CLI together with the unpublished
OGVCS-002 and OGVCS-004 Rust crates as one offline artifact set.
