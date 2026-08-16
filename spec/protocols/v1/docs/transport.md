# Transport and framing

## Production profile

The baseline control profile is TLS 1.3 over HTTP/1.1. A production client
validates the peer certificate and hostname, refuses cleartext and older TLS,
and never silently substitutes HTTP/2, HTTP/3, gRPC, protobuf, or another
framing profile. Negotiation and every mutation-capable operation require HTTPS
over TLS 1.3. The loopbackConformance flag never authorizes cleartext
negotiation: HTTP fails before selection or receipt issuance. Any cleartext
loopback allowance is confined to the non-production EnvelopeCaseInput harness
and cannot produce negotiation or release evidence. Proxies use an explicit
CONNECT configuration; forwarding headers never establish origin, subject,
tenant, repository, or authorization.

Control bodies are duplicate-free bounded I-JSON. A receiver limits declared
and actual bytes before allocation, validates UTF-8 and duplicate members,
checks depth/nodes/collections while parsing, validates the closed schema, and
only then performs semantics. Producers emit RFC 8785 bytes. Receivers may
accept a noncanonical member order, but never hash the received bytes as the
semantic request. Content coding is identity; compressed control input is
rejected rather than decompressed.

## Redirects and streams

Mutations, grant-bearing requests, and requests with idempotency keys never
follow redirects. Read-only redirects require an explicit same-origin policy.
Each JSONL line is one bounded RFC 8785 StreamFrame followed by LF. Sequence
starts at zero and increases by one. Exactly one terminal, gap, cancelled, or
error frame ends the stream; data after it is invalid. EOF, timeout, proxy
closure, and an empty final read without such a frame are incomplete, never
success.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
