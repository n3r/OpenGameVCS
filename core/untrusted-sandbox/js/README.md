# OGVCS-045 candidate supervisor

This package is a **candidate-only test boundary**, not a production sandbox or
credential authority. Its public API names (`CandidateSandboxSupervisor` and
`CandidateCredentialBroker`) deliberately make that limitation visible. Only a
branded test launcher can construct the supervisor, and that constructor is
available solely from the `./testing` export. A real OS-enforcing launcher is
intentionally not shipped here.

The candidate broker retains a test acquisition credential privately; parser
launch receives an empty environment, no arguments, canonical stdin, and an
opaque immutable input handle only. Every external record is copied from inert
own data properties before use. Start, acquire, output, shutdown, and process
settlement are deadline-bounded; timeout cleanup attempts TERM, process-group
KILL, then bounded settlement. Parser output must be zero-exit, stderr-free,
canonical JSON with OGVCS-004 portable paths.
