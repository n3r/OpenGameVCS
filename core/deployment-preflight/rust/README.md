# OGVCS-021 private deployment-preflight rc.2

This unpublished Rust 1.82 crate is a bounded, deliberately unwired evaluator
for a narrow part of OGVCS-021. It validates caller-supplied static deployment
facts and caller-supplied health observations, then produces a deterministic
liveness/readiness report. It performs no environment discovery, installation,
bootstrap, migration, backup, restore, or service operation.

The rc.2/V2 private contract adds exact artifact-set and target-schema binding
to irreversible-migration evidence. V1 evidence and report digests are not
accepted as V2; there is no compatibility adapter because neither revision was
published or wired.

## Supplied configuration boundary

The candidate accepts exactly one private topology shape:

- API, administration, and metrics listener records in canonical order, with
  distinct nonzero ports;
- TLS for every non-loopback listener and loopback-only administration and
  metrics exposure;
- four distinct opaque secret-reference commitments for metadata, object
  storage, identity signing, and backup encryption, each accompanied by
  supplied facts saying access is restricted and the reference is absent from
  public config and diagnostics;
- three distinct opaque service-principal commitments for control plane,
  worker, and administration, each accompanied by supplied non-root and
  non-interactive facts; and
- disabled-by-default telemetry, no mandatory vendor check-in, and durable-data
  preservation as the only accepted default policy.

These are inert records. A nonzero commitment does not prove that a file,
secret provider, certificate, principal, permission, process, port, or network
policy exists or is safe. The crate never accepts secret bytes and has no
filesystem, environment, socket, keyring, provider, container, or process API.
It therefore cannot establish restrictive permissions, absence from command
history or images, listener ownership, TLS validity, least privilege, or
air-gapped operation.

## Observation and readiness boundary

One observation contains exactly one supplied generation-bound state for each
of metadata, object storage, identity, verifier, backup, capacity, and schema.
Liveness depends only on the supplied `process_alive` fact. Readiness requires
liveness plus `Healthy` for every dependency. Failures are returned as a
closed, sorted list of non-secret reason codes; no backend message or caller
string is copied into the report. A compatibility-set or configuration-
generation mismatch fails without a report.

Evaluation also receives a caller-supplied evaluation time and maximum
observation age. The age must be in `1..=300` seconds, the observation cannot
postdate evaluation, and its inclusive age cannot exceed the supplied bound.
The report binds the capture time, evaluation time, and age policy. The crate
has no clock authority: those values can still be false, and a structurally
valid report does not remain fresh after its declared evaluation. An adapter
must obtain trusted time and rerun preflight immediately before any external
action.

Schema intent rejects zero versions, downgrades, class/version inconsistency,
and backup-gate evidence attached to a non-irreversible intent. An irreversible
upgrade requires nonzero evidence bound to the deployment, exact artifact set,
compatibility and configuration generation, source and target schema, and
current metadata, object-storage, verifier, backup, and schema observation
generations. It also binds a backup
manifest, the manifest named as the verification subject, verifier report,
distinct source/target storage and credential-scope commitments, retention and
encryption policy commitments, capture time, and retention strictly beyond the
supplied evaluation time. Equality of the manifest and verified-subject fields
only checks the caller's supplied claim; inequality of source/target fields
only rejects an obvious alias.

Those values are supplied evidence only. OGVCS-017 and OGVCS-018, plus a future
trusted adapter, must authenticate the verifier result, backup completeness,
source-state coverage, target/credential separation, time, retention, and the
transactional relationship to the migration. This crate neither runs nor
authorizes a migration and never mutates durable state. The report deliberately
has no `mutation_ready` or authorization field. Its
`backup_gate_evidence_present` bit records only whether the validated supplied
record was included and makes the logical work charge structurally
reconstructible.

Configuration, observation, and report fields are domain-separated SHA-256
commitments. `has_valid_binding` checks only report-local structure and its
recomputable checksum; it is not a signature, MAC, authentication result,
authorization decision, freshness proof, or durable audit record.

## Resource behavior

Input cardinalities are checked before semantic traversal. The deterministic
logical work charge is exactly 18 units without backup evidence or 19 with it,
and is admitted before value validation. Validation uses fixed slices and
stack buffers rather than a set allocation. Cancellation is checked before
input access, between bounded stages and dependency observations, and again
after hashing before the only result-vector allocation. Failure returns no
partial report.

Reason codes are staged in a fixed stack buffer. A conservative retained-memory
charge of 512 base bytes plus 16 bytes per reason is admitted before the result
vector is allocated; it reaches 640 bytes for process failure plus all seven
dependency reasons. This charge is deterministic accounting, not an exact
allocator measurement. Callers retain ownership of all input vectors and any
capacity they allocated before invocation remains outside the charge. The
accepted topology itself has fixed cardinality.

This is deterministic accounting for the private evaluator, not an allocator,
CPU, latency, capacity, or reference-scale measurement.

Error precedence is fixed: invalid configured limits, initial cancellation,
exact input shapes, work admission, configuration, observation generation and
compatibility, observation time, migration shape, backup gate, dependency
reasons, retained charge, then final cancellation. Later semantic defects are
not inspected after an earlier failure class.

Default `Debug` output redacts listener details, secret-reference, principal,
generation, backup, configuration, observation, and report commitments. Safe
reason codes remain visible. Public fields remain explicitly accessible, so
redacted debug output is a logging guardrail rather than secrecy or
authorization.

## Hard bounds

| Resource | Candidate maximum |
|---|---:|
| Listeners / secret references / service accounts | 3 / 4 / 3 exactly |
| Dependency observations | 7 exactly |
| Observation age policy | 300 seconds |
| Logical work charge | 19 units |
| Retained-memory charge | 640 bytes |

## Explicit nonclaims

There is no topology manifest, supported-version matrix, prerequisite probe,
installer, package or container composition, database/object-store adapter,
TLS termination, identity or first-admin bootstrap, one-time secret, public
configuration schema, reload/restart classifier, migration ledger, resumable
migration, backup/restore invocation, diagnostics bundle, logs/metrics server,
public health endpoint, CLI, service, authentication, authorization, repository
creation, uninstall/reinstall workflow, operator runbook, clean-host/offline
exercise, hosted cross-OS evidence, timed usability run, scale/SLO campaign, or
rollout. No OGVCS-021 acceptance criterion is satisfied. OGVCS-021 remains
Todo.

Local gates:

```text
cargo +1.82.0 fmt --manifest-path core/deployment-preflight/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/deployment-preflight/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path core/deployment-preflight/rust/Cargo.toml --locked --offline --release
cargo +1.82.0 clippy --manifest-path core/deployment-preflight/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo +1.82.0 package --manifest-path core/deployment-preflight/rust/Cargo.toml --locked --offline --allow-dirty
node --test tools/deployment-preflight-source-policy.test.mjs
npm run test:roadmap
```

The package command proves only that this private crate's bounded archive
recompiles from packed source;
it is not hosted install or deployment evidence. The path-scoped hosted
workflow repeats these source-only gates on Linux, macOS, and Windows; a green
run establishes source portability for its exact revision only, not a clean-host
install, dependency probe, upgrade, rollback, or operator exercise.
