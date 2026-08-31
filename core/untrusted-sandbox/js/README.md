# OGVCS-045 candidate supervisor

This package is a **candidate-only test boundary**, not a production sandbox or
credential authority. Its public API names (`CandidateSandboxSupervisor` and
`CandidateCredentialBroker`) deliberately make that limitation visible. Only a
branded test launcher can construct the supervisor, and that constructor is
available solely from the `./testing` export. A real OS-enforcing launcher is
intentionally not shipped here.

The candidate broker retains a test acquisition credential privately; parser
launch receives an empty environment, no arguments, sorted-key canonical stdin,
and an opaque immutable input handle only. Every external record is copied from
inert own data properties before use; accessors, proxies, and generic thenables
are rejected without coercion. Launcher capability and resource limits remain
in private immutable state.

Acquire, launch, process-handle validation, reads, shutdown calls, and process
settlement are deadline-bounded. Cleanup attempts TERM, then process-group KILL,
and returns a job result only after the launcher's exit promise settles. Missing
post-KILL settlement rejects with `SANDBOX_SETTLEMENT_UNCONFIRMED` and poisons
that supervisor so a caller cannot mistake a potentially live worker for a
completed job. A branded launcher must also guarantee that an aborted or failed
start leaves no live process before its launch promise rejects. Launcher code is
trusted test infrastructure and must never block the JavaScript event loop.

Parser output must be zero-exit, stderr-free, duplicate-free sorted-key canonical
JSON conforming to the closed output schema and OGVCS-004 portable paths.
