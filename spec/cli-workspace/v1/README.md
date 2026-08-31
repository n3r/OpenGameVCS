# OGVCS CLI/workspace contract v1 — local-only candidate

**Contract version:** `0.1.0-rc.1`
**Status:** candidate; not a completion claim for OGVCS-011.

This contract freezes only the local foundation tranche implemented by
`client/native-cli/rust`. It defines configuration precedence and source
reporting, result envelopes/exit classes, private workspace metadata,
recovery, noninteractive credential availability, and redacted diagnostics.

It has no OGVCS-006 route or capability binding, no OGVCS-008 lifecycle
binding, no OGVCS-009 identity-session binding, and no OGVCS-041 negotiated
message binding. Thus it **must not** be used as a network, repository
discovery, sync, submit, status, lock, or working-tree-mutation contract.

## Stable result shape

Every JSON result uses schema `ogvcs.cli-workspace/result/v1`, includes this
contract version, a boolean `ok`, one of the exit classes in
[`registries/exit-classes.json`](registries/exit-classes.json), a stable code,
and an object-valued `data` member. Failures also carry a safe human message
and one actionable `nextStep`. Implementations must not expose underlying path,
credential, identity, or server error text in either field.

## Configuration

Each nonsecret field is resolved independently in this exact order:

`flag > environment > workspace > user profile > system default`

The candidate fields are `endpoint`, `profile`, and `output`. `endpoint` is a
safe HTTP(S) endpoint without userinfo, query, or fragment; `profile` is a
bounded label; and `output` is `human` or `json`. Configurations containing
secret-like keys are rejected before a source report is produced. The report
schema is [`schemas/ConfigResolution.schema.json`](schemas/ConfigResolution.schema.json).

## Workspace declaration and recovery

`workspace create` stores a schema-versioned `.ogvcs/workspace.json` only in a
private owned root. It stages then atomically publishes the control directory;
an interruption after publish leaves an initializing journal record, and
`workspace open` returns `WORKSPACE_RECOVERY_REQUIRED` until `workspace
recover` checks the matching record and marks it complete. The completed record
is retained as part of the local atomicity proof. No operation makes a network
request. The corresponding schemas are
[`WorkspaceMetadata.schema.json`](schemas/WorkspaceMetadata.schema.json) and
[`InitializationRecord.schema.json`](schemas/InitializationRecord.schema.json).

Repository/branch/baseline/spec inputs must already be opaque lower-case
32-byte digests; the candidate does not accept raw declarations. They are
stored with `verification: "unverified-local-declaration"`, not as claims that
the declarations identify an OGVCS server object or protocol.

## Credential and diagnostic boundaries

The provider seam exposes only `available`, `unavailable`, or
`headless-required`; it intentionally has no credential-value retrieval API.
`--non-interactive` never prompts and returns `AUTHENTICATION_REQUIRED` if
availability is not already supplied. Diagnostics are previewed before any
write, require explicit creation, and contain only redacted digests and source
classes—not paths, identities, endpoints, declaration inputs, or secrets.

## Contract validation

Run `node validate-spec.mjs` (or `npm test`) from this directory. Runtime
execution and hostile recovery coverage live in the Rust crate's bounded test
suite; this spec validator deliberately does not contact a server or run a
scale workload.
