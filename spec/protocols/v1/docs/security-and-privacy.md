# Security and privacy

Untrusted forwarding headers cannot establish identity, origin, tenant,
repository, or authorization. Negotiation receipts prove the selected tuple,
not permission. Transfer grants remain OGVCS-003 artifacts and never appear in
URLs. Control and transfer compression are disabled, and mutation redirects
are refused so credentials and idempotency scope cannot cross origins.

The processing order is bounded framing, canonical JSON safety, closed schema,
authenticated negotiation/session binding, authorization, idempotency
reservation, then mutation. Every earlier failure has mutationCount zero.
Output remains staged and untrusted until the complete operation, digest, and
terminal checks succeed. Promise-based sources, sinks, adapters, and hooks race
a shared deadline and receive cancellation where supported; late caller-owned
side effects remain caller responsibility. Synchronous host calls are bounded
and checkpointed before and after because they cannot be preempted safely.

Errors, logs, telemetry, and retained reports contain only stable codes, safe
classes, correlation IDs, selected public versions, resource summaries, and
sanitized digests. They exclude payloads, credentials, grants, receipt MACs,
cursor tokens, subject/tenant raw values, protected paths/objects, policy text,
stack traces, and hidden cardinalities. Security vectors assert these absences.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
