# OpenGameVCS local CLI candidate — Rust

`ogvcs-local-cli` is a deliberately small, local-only candidate for the
OGVCS-011 native CLI foundation. It fixes the public shape of selected local
operations without asserting that the larger OGVCS-011 journey is complete.

## Included candidate surface

- configuration resolution with the frozen precedence `flag > environment >
  workspace > user profile > system default`, including a source report for
  nonsecret values;
- versioned result envelopes and stable exit classes;
- atomic private `.ogvcs` metadata creation, inspection, and journal recovery
  after an interrupted publication;
- a cooperative cancellation/fault-injection seam for bounded library tests;
- a noninteractive credential-provider seam that never obtains a credential;
- explicit, redacted diagnostic preview and creation.

The machine result envelope is `ogvcs.cli-workspace/result/v1`, and this crate
implements contract version `0.1.0-rc.1`. Every envelope carries the SHA-256 of
the generated companion manifest. Contract constants, exit codes, schema IDs,
and executable vectors are generated from
[`spec/cli-workspace/v1`](../../../spec/cli-workspace/v1); the sync check fails
if the crate and that authenticated artifact set drift.

## Deliberate boundaries

This candidate performs **no** server call, credential retrieval, repository
discovery, capability negotiation, sync, submit, status, locking, or working
tree mutation. It accepts only opaque, lower-case 32-byte declaration digests
for repository/branch/baseline/spec and retains those values with
`unverified-local-declaration`; they are not proof of an
OGVCS-006 repository, OGVCS-008 lifecycle state, OGVCS-009 identity session,
or OGVCS-041 negotiated protocol. A future owner must replace that seam only
after those public bindings exist.

Metadata commands fail closed when private ownership/permission checks cannot
be made. On macOS, any extended ACL entry is rejected in addition to the owner
and mode checks. The first candidate reports `WORKSPACE_SAFETY_UNSUPPORTED` on
Windows instead of making an unsupported ACL-security claim.

The binary does not yet expose signal handling, progress, or a user-facing
cancellation control; the cancellation probe is a library/test seam only.
Crash recovery covers a control directory that reached atomic publication.
The root and its namespace ancestors must not be concurrently replaced by code
running with the same operating-system authority; this candidate rejects
observed final symlinks and reparse points but does not claim a handle-relative
defense against a continuously hostile same-authority process.

## Local validation

Rust 1.82 is required. The normal bounded checks are:

```sh
node ../../../spec/cli-workspace/v1/scripts/generate.mjs --check
node scripts/sync-contract.mjs --check
cargo fmt --all -- --check
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo package --locked --offline
./scripts/test-packed.sh
```

These checks are local and bounded; no exact-scale campaign or network access
is part of this candidate.
