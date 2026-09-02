# OpenGameVCS R1 CLI evidence transcript validator — private Rust candidate

`ogvcs-cli-evidence-validator` is an unpublished Rust 1.82 library that
validates the bounded shape of caller-supplied OGVCS-043 compatibility and
vertical-slice evidence. It is intentionally unwired. It does not run the
native CLI, install an artifact, contact a service, read a workspace, or
perform any product operation.

## Fixed evidence vocabulary

The compatibility inventory has exactly eight records in this order:

1. native CLI;
2. starter deployment;
3. public protocol baseline;
4. workspace lifecycle;
5. workspace status;
6. selective sync;
7. hard lock; and
8. atomic submit.

Every record carries caller-supplied fixed-width commitments and structured
versions for its artifact, component, protocol, format, and capability set.
The protocol and format commitment/version pairs must agree across the whole
inventory. Every record must declare checksum/build-provenance verification,
compatibility, and a public versioned route. These are transcript facts, not
independent artifact inspection by this crate.

The scenario has exactly sixteen ordered phases:

1. artifact verification;
2. compatibility preflight;
3. clean-host install;
4. primary authentication;
5. repository bootstrap;
6. primary workspace creation;
7. primary selective sync;
8. primary status;
9. primary hard-lock edit;
10. atomic submit;
11. submit-result recovery;
12. secondary authentication;
13. secondary workspace creation;
14. secondary selective fetch;
15. Snapshot byte verification; and
16. redacted evidence finalization.

Each phase supplies request/result commitments, monotonic start/finish ticks, a
typed safe result and recovery class, a public-route fact, a capability fact,
and a phase-specific Snapshot fact where applicable. Mutating phases require a
declared capability check before mutation. Fail-closed or cancelled phases
force every later phase to be `NotRunAfterSafeStop`; skipped records must use
canonical zero request/result commitments and zero ticks, and they do not
extend the executed timing summary. They produce a safe incomplete
disposition rather than a successful one.

### Recovery phase matrix

Result/recovery pairing is checked before phase compatibility. Every non-`None`
recovery then uses this closed matrix:

| Recovery | Allowed canonical phases |
|---|---|
| `RetrySameRequest` | all 16 phases; this means the exact committed request, including its owning idempotency semantics |
| `ResolveOriginalSubmit` | 10 atomic submit; 11 submit-result recovery |
| `Reauthenticate` | 4 primary authentication through 14 secondary selective fetch |
| `RefreshBranchAndRestage` | 10 atomic submit; 11 submit-result recovery |
| `ReacquireLock` | 9 primary hard-lock edit; 10 atomic submit |
| `RefetchVerifiedContent` | 7 primary selective sync; 14 secondary selective fetch; 15 Snapshot byte verification |
| `FreeDiskAndResume` | 3 clean-host install; 6 primary workspace creation; 7 primary selective sync; 9 primary hard-lock edit; 10 atomic submit; 13 secondary workspace creation; 14 secondary selective fetch; 16 redacted evidence finalization |
| `ResumeAfterCancellation` | all 16 phases, and only with `CancelledLocalWorkPreserved` |

Universal retry/resume entries are structural caller claims, not permission to
retry or proof that an owning component's idempotency/cancellation contract was
satisfied. All other phase/recovery pairs fail with
`RecoveryPhaseMismatch`.

The context contains two opaque workspace bindings and two opaque identity
bindings whose four byte values may not alias. Its primary selection,
secondary selection, selected-root, and exact-byte-verification commitments
must also be pairwise distinct. It carries bounded selected item/byte counts
and only the count of excluded items declared unmaterialized. There is no
field for a credential, identity value, raw path, file content, message, or
diagnostic text. Redaction must be declared allowlist-verified. `Debug`
rendering redacts all generic commitments and participant bindings; that is a
logging guardrail, not a secrecy claim about caller-held or digest-bound
values.

Submit, result-resolution, fetch, and byte-verification facts compose the
OGVCS-002 `ObjectRef` type. The validator requires `ObjectKind::Snapshot` and
one identical reference across completed phases. It does not fetch, decode,
authorize, prove availability of, or otherwise validate the referenced
Snapshot object.

## Digest and bounds

Successful validation returns a deterministic SHA-256 digest under
`OpenGameVCS R1 CLI evidence report\0v1\0`. The transcript uses fixed tags and
big-endian integers. The digest binds every accepted context, component, and
step field plus the derived disposition, Snapshot identity, executed timing
summary, fixed record counts, executed-step count, work units, and
retained-memory reservation. `component_records` and `step_records` describe
the fixed supplied arrays; `executed_steps` excludes canonical skipped
records. The digest is unkeyed and is not a signature, provenance authority,
authorization token, or public evidence schema.

Operational acceptance limits are deliberately outside the digest: changing
a limit without changing accepted evidence does not change the report. All
limits have literal hard maxima. Validation requires exactly 8 components and
16 steps, charges exactly 320 work units for a complete traversal, retains no
input record or heap collection, and reserves a fixed cross-platform 768 bytes
for the source-modeled hash/cross-check state. A compile-time assertion keeps
that model within the reservation. Component/step inputs are borrowed slices;
caller storage and capacity are outside the validator and are never cloned or
retained. Cancellation is checked before input processing, before each fixed
record, before final summary hashing, and again after digest finalization
immediately before report release. Any error or cancellation returns no
digest or summary.

## Explicit nonclaims

This crate performs no installation, process execution, filesystem/network or
other I/O, authentication, authorization, repository/workspace creation,
sync, status, lock, submit, idempotency lookup, fetch, content verification,
clean-host provisioning, private adapter access, persistence, diagnostics
collection, signing, packaging, OS coverage, fault injection, or hosted
scenario execution. Caller commitments are opaque assertions; possession of a
valid transcript does not prove their truth. In a safe incomplete result,
context and compatibility commitments remain predeclared caller inputs and
must not be read as observations of phases marked not run.

The returned `AllStepsSucceededOrRecovered` label means only that all sixteen
supplied records passed this private structural validator. It is not an
OGVCS-043 acceptance result. OGVCS-043 remains Todo and AC-01 through AC-05
remain open.

## Local verification

From the repository root, with Rust 1.82 and the offline dependency cache:

```sh
cargo +1.82.0 fmt --manifest-path client/cli-evidence/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path client/cli-evidence/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path client/cli-evidence/rust/Cargo.toml --locked --offline --release
cargo +1.82.0 clippy --manifest-path client/cli-evidence/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
client/cli-evidence/rust/scripts/test-packed.sh
npm run test:cli-evidence
npm run test:roadmap
```
