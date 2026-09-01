# OGVCS CLI/workspace contract v1 — verified local foundation candidate

**Contract version:** `0.2.0-rc.2`
**Status:** candidate; not a completion claim for OGVCS-011 and not remote E2E evidence.

This artifact set freezes the local OGVCS-011 tranche implemented by
`client/native-cli/rust`: exact nonsecret configuration precedence, stable
result/exit shapes, secret-safe credential-provider invocation, typed public
service ports, verified workspace metadata and recovery, bounded local staged
intent, progress/cancellation seams, signal handling, and redacted diagnostics.

The first-party binary deliberately installs `UnavailablePublicRoutes`.
OGVCS-006 repository discovery, OGVCS-008 lifecycle/FileID authority, and
OGVCS-009 authentication do not yet publish the owning routes needed by this
client, so real create/configure/staging commands fail with
`PUBLIC_ROUTE_UNAVAILABLE` before local mutation. Executable contract tests use
typed fakes that return existing predecessor facts; they are not a private
database adapter or a remote-journey claim.

## Stable command results and configuration

Every JSON result uses `ogvcs.cli-workspace/result/v1`, carries this contract
version and the exact companion-manifest SHA-256, and returns one registered
exit class, a stable code, an object-valued `data` member, safe text, and one
actionable next step. Machine failures use stdout only; human failures use
stderr and do not depend on color.

Each nonsecret configuration field resolves independently in this order:

`flag > environment > workspace > user profile > system default`

The bounded fields are `endpoint`, `profile`, and `output`. Secret-like config
keys are rejected. Secrets are accepted only from an explicit headless
environment provider or an OS credential-store interface, are borrowed only
during synchronous authentication, are never `Clone`, `Debug`, or serializable,
and are overwritten on drop. Noninteractive commands never prompt.

## Verified workspace and capability boundary

The v2 workspace format stores a public-service binding only after the typed
route supplies authentication, discovery, capability selection, binding
validation, and later side-effect-free FileID fact presentation. It pins the exact OGVCS-003 authorization,
OGVCS-004 path, OGVCS-002 repository, and OGVCS-041 protocol registry digests,
the portable path profile, repository identity, snapshot baseline, subject
digest, and authority/security epochs. Raw caller declarations cannot create a
verified workspace. The stored 32-hex repository identity is the exact 16-byte
form of the OGVCS-006 RFC 4122 UUID, not an independently invented identifier.

This client validates the selected facts and a receipt digest, then requires
the route adapter to validate the binding. It does **not** possess a session
key or locally MAC-verify the complete OGVCS-041 `NegotiationReceipt` claims in
fixed MAC-first order. A future public adapter must provide a branded verified
receipt or the complete claims/MAC verifier before the binding is production
trusted. Until then, `public-service-verified` describes the typed adapter
contract exercised by fakes, not independent remote proof.

Creation and configuration use pending metadata plus a digest-bound journal.
Every mutator requires a complete journal whose desired digest equals current
metadata. Recovery commits a valid prepared transition or removes a validated
stale pending file. Removal publishes a deterministic, root-bound record and
tombstone; a crash before detach restores the ready command path, while a crash
after detach is safely completed by retry/recovery. Hostile links/reparse
points or mismatched records fail closed.

The original v1 unverified declaration schemas remain authenticated for
compatibility with the earlier library vectors, but the first-party binary no
longer creates them.

## Workspace-confined staging

Add/move/delete/revert validate OGVCS-004 canonical paths and collision keys,
preserve server-issued FileIDs, write a bounded local intent journal, and
report `uploadsStarted: false`, `submitStarted: false`, and remote durable state
`unchanged`. They never upload or submit. Add is deliberately narrower than a
FileID allocation journey: its port may only present a previously completed,
idempotency-reconciled OGVCS-006 allocation. It must not invoke
`file-id.allocate`. The typed handoff binds repository/path facts and carries
the FileID, expiry, opaque `far1` receipt, and allocation idempotency-key digest.
The private owner-checked journal retains the receipt for first registration;
list/progress/result/diagnostic surfaces expose at most its digest. A lost
handoff response publishes no local intent, while allocation ambiguity remains
the predecessor adapter's responsibility.

Linux uses pinned directory FDs plus `renameat2(RENAME_NOREPLACE)`; macOS uses
pinned directory FDs plus `renameatx_np(RENAME_EXCL)`. Both sync source and
destination parents. Windows uses a source handle opened with delete access,
reparse-checked pinned ancestor/destination-parent handles, and
`SetFileInformationByHandle` with replacement disabled. Windows compilation is
checked locally; hosted Windows runtime evidence remains pending until an
existing default-branch workflow can dispatch this branch.

Workspace metadata requires owner-only Unix modes with macOS extended ACLs
rejected. Windows requires the current owner, permits granting ACEs only for
the owner, LocalSystem, and Administrators, rejects reparse/multi-link metadata
objects, and requires a protected DACL so future inheritance cannot broaden
access.

The exclusive mutation file lock prevents races among cooperating CLI
processes. A malicious process running as the same OS authority can still
unlink/replace a lock namespace entry on Unix or exploit Windows delete-sharing
semantics; this candidate does not claim a security boundary against that
same-authority attacker.

## Cancellation, diagnostics, and remaining scope

Progress events report phase/items/bytes and optional resume tokens. SIGINT and
SIGTERM on Unix and console cancellation on Windows set a process cancellation
source. Cancellation before publication cleans temporary state; cancellation
after a durable journal returns a recovery token. The irreversible part of
removal ignores cooperative cancellation and uses the deterministic removal
record for process/host-crash reconciliation.

Diagnostics are preview-only until explicitly created. Verified diagnostic
artifacts contain only digests, pinned public registry hashes, provider kind
and availability, endpoint scheme, and counts—never local paths, locators,
endpoints, subjects, profiles, or secret bytes.

This tranche does not implement FileID allocation/reconciliation, sync, submit,
status/index reconciliation, locks/edit intent, materialization, or any remote
network route. OGVCS-011 remains Todo until the public predecessor routes,
receipt verification, and hosted three-OS journey evidence are integrated.

## Validation

`manifest.json` authenticates every shipped contract artifact. The Rust
binding and executable vectors are generated from it. The bounded gates are:

```sh
node scripts/generate.mjs --check
node validate-spec.mjs
node --test test/*.test.mjs
node ../../../client/native-cli/rust/scripts/sync-contract.mjs --check
cargo fmt --manifest-path ../../../client/native-cli/rust/Cargo.toml -- --check
cargo test --manifest-path ../../../client/native-cli/rust/Cargo.toml --locked --offline
cargo clippy --manifest-path ../../../client/native-cli/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
../../../client/native-cli/rust/scripts/test-packed.sh
```
