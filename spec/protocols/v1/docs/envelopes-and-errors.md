# Envelopes and safe errors

## Closed envelopes

Request and response roots are closed. An application operation and body are
carried without defining domain routes in this contract. Unknown members are
permitted only as values of the namespaced extensions map, which is limited to
maxExtensionEntries. A successful ResponseEnvelope carries body and no problem;
a failed envelope carries problem and no body. Correlation and deadline fields
are operational metadata, not authorization or semantic-idempotency input.

## RFC 9457-safe subset

ProblemDetails is a closed authorization-safe subset of RFC 9457. The error
registry fixes code, type URI, title class, HTTP/body status, retryability, and
the only permitted parameter names. The body omits `detail` and `instance`.
Stack data, credentials, grants, policy text, protected paths/objects, hidden
counts, arbitrary parameters, and implementation messages are forbidden.
Parameters are bounded strings and must be permitted by the selected error
entry; names are unique. HTTP status, body status, title, type, code,
retryability, and retry headers must describe the same entry.

When and only when a safe `retryAfterMs` parameter is present, HTTP carries
exactly one RFC 9110 `Retry-After` delta-seconds field. Field-name comparison is
ASCII-case-insensitive and duplicate detection occurs after lowercase
normalization; canonical emission spells `retry-after`. The value is the
canonical nonnegative decimal `ceil(retryAfterMs / 1000)`, capped at 86400.
HTTP-date form, signs, leading zeroes, mismatches, missing fields, unexpected
fields, and case-folded duplicates are PROTOCOL_MALFORMED in v1.

Parsing, configured-resource, compatibility, receipt, authorization, cursor,
and idempotency failures are pre-mutation. An implementation maps unexpected
internal failures to INTERNAL_ERROR without copying exception text into the
wire body or retained conformance report.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
