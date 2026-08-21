# Benchmark/fault driver protocol v1

The driver writes one canonical `DriverHello` JSON line immediately after
startup. The hello binds the exact benchmark contract manifest, the registered
OGVCS-041 control profile, the OGVCS-005 test profile, supported versions,
capabilities, and the fact that fault hooks are disabled.

The harness validates the hello and chooses version 1 before sending any
command. No common version, missing required capability, wrong authority,
oversized input, noncanonical JSON, unexpected stderr, timeout, or malformed
result is a typed pre-mutation rejection. Only a successful `negotiate`
command can enable the authenticated test session. A production process must
never expose this profile.

Commands carry deterministic IDs and idempotency keys. Results carry a closed
code, retryability, exact mutation count, pre-mutation witness, sanitized
output, and an ordered bounded trace. Retrying the same key and canonical
command returns the same result without duplicating mutation; reuse with a
different command is rejected.

Messages are at most 1 MiB, a process exchange is at most 64 MiB, traces are at
most 4,096 events, and the operation deadline is at most 120 seconds. Limits
are checked before allocation or mutation. The harness terminates a process
that violates a bound and never interprets EOF as successful completion.
