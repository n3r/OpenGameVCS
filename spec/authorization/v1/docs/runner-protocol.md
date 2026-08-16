# Authorization threat runner protocol v1

## Purpose

The public runner applies the language-neutral abuse catalog to either the
packaged reference fixture or an independently implemented adapter. The
reference fixture demonstrates deterministic contract semantics; it is not a
production policy evaluator. A server, client, cache, or sandbox implementation
claims conformance only for vectors it executes through its real public boundary.

## Invocation and exit status

The JavaScript package installs `ogvcs-authz`:

```text
ogvcs-authz run [--adapter <command>] [--output <report.json>]
ogvcs-authz inspect
ogvcs-authz verify-grants
```

With no adapter, `run` uses the packaged synthetic reference fixture. With an
adapter, the runner spawns the exact executable and arguments supplied after
`--adapter`; it does not invoke a shell. Exit 0 means every selected vector
passed and a complete report was written. Exit 1 means a valid completed report
contains one or more failed vectors. Exit 2 means command usage is invalid.
Exit 3 means package/vector validation failed. Exit 4 means the adapter protocol,
resource ceiling, timeout, or process boundary failed. Reports are never marked
successful after a partial or malformed exchange.

## NDJSON adapter exchange

Standard input starts with exactly one canonical JSON line:

```json
{"contractVersion":"1.0.0","manifestSha256":"<64 lowercase hex>","registrySetSha256":"<64 lowercase hex>","schemaVersion":"ogvcs.authorization/runner-hello/v1","vectors":30}
```

It is followed by one canonical JSON line per abuse vector, in ascending vector
ID order:

```json
{"schemaVersion":"ogvcs.authorization/runner-vector/v1","vector":{...}}
```

The runner closes standard input after the last vector. The adapter writes one
canonical JSON result line per input vector, in the same order:

```json
{"code":"DENY_NOT_AUTHORIZED","id":"vector-path-enumeration","result":"deny","schemaVersion":"ogvcs.authorization/runner-result/v1"}
```

Every object is closed. Unknown/missing/duplicate IDs, extra lines, reordered
rows, non-canonical JSON, a code not in the decision registry, mismatched
allow/deny polarity, protected response fields, or output after the expected
row count fails the run. Diagnostics go to bounded stderr and must not contain
protected vector input values.

For a production conformance claim, the adapter MUST execute each vector's
assertions through the implementation's real public boundary. It MUST inspect
the real response, status, aggregates, cursors, logs or sandbox result relevant
to `abuseCase` and `forbiddenResponseFields`, and emit a passing result only
after those checks succeed. The runner proves the adapter protocol, inventory,
bounds, and reported result equality; it cannot prove that an opaque adapter
actually exercised a server. The packaged example adapter is therefore a
protocol/reference fixture, not production-server evidence.

## Bounds and cancellation

Defaults are 10,000 vectors, 4 MiB per input/output line, 64 MiB total adapter
stdout, 8 MiB stderr, 120 seconds elapsed, and one child process. The runner
kills the process tree on timeout, output overflow, protocol failure, abort, or
caller cancellation and waits for termination before returning. Callers may
select lower ceilings but not values above packaged hard maxima.

The adapter receives a minimal environment allowlist (`PATH`, platform process
requirements, and explicit caller-provided variables), no secrets injected by
the runner, no shell interpolation, and inherited filesystem/network policy only
from the caller's sandbox. Production server conformance SHOULD run the adapter
inside the sandbox profile appropriate to the implementation.

## Result comparison and report

The runner compares the exact result/code pair and verifies that no name in
`forbiddenResponseFields` occurs anywhere in the closed adapter result. The
adapter remains responsible for applying that list to the real boundary under
test before emitting its result. The runner creates one
row per vector, sorts rows by ID, hashes canonical row JSON, and emits
`RunnerReport.schema.json` with package version, exact manifest and registry-set
digests, adapter identity, counts, digest, and pass/fail rows. The report contains no vector input,
protected resource field, policy, claim, signature, stdout, or stderr.

An external adapter failure is a runner failure, not an authorization allow. A
timeout, crash, malformed response, or unavailable policy must never cause the
runner to synthesize a passing denial row.
