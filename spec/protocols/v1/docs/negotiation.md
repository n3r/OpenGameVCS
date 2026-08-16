# Negotiation and receipts

## Independent selection

The server authenticates subject, tenant, authority epoch, and session before
repository-specific selection. It then intersects protocol, message schema,
repository format, authorization contract, path contract, path profile, event,
transfer, and extension axes independently. Offer ordering is not preference.
For each mandatory axis the selected entry is the permitted common registry
entry with the lowest immutable numeric code. Required unknown capabilities,
forbidden lifecycle states, an empty axis, or removal of a client minimum fail
before mutation. Only candidate or ratified compatibility tuples are selectable
for new sessions. Deprecated tuples and reserved lifecycle entries are rejection
witnesses, not a read-compatibility path. Every identifier carried in the optional `extensions` list is
intrinsically optional; an unknown entry there is ignored. Required behavior
appears only in `requiredCapabilities` and must be registered and negotiated.
A registered required extension must also appear on the offered extension axis;
otherwise no compatibility tuple is common. Selected extensions follow the
authenticated compatibility-row order, independent of client offer order.

The selection carries separate authorization, path, repository, and protocol
registry digests. The negotiation digest is computed over every registry except
the compatibility registry, allowing the latter to bind that digest without a
circular hash. The contract manifest separately authenticates the complete
registry set, including compatibility.

Negotiation requires HTTPS over TLS 1.3 before selection or receipt issuance.
loopbackConformance is only an adversarial conformance input here and cannot
widen that rule; cleartext loopback testing belongs to the separate envelope
harness and is never bound as a negotiation receipt mode.

## Authenticated receipt

Receipt claims bind the complete selection, subject and tenant digests,
authority epoch, session, client/server nonces, issue time, and expiry. The
receipt MAC is HMAC-SHA-256 over `ASCII("OGVCS-PROTOCOL-NEGOTIATION-RECEIPT-V1\0")
|| ASCII(keyId) || 0x00 || JCS(claims)` using the registered key.
The server nonce is canonical unpadded base64url whose decoded value is 16..64
bytes, inclusive; 65 decoded bytes are malformed. A spelling with nonzero
unused tail bits is malformed even when a
permissive decoder would produce the same bytes.
Receipt lifetime is strictly positive and cannot exceed maxReceiptLifetimeMs.
Every mutation verifies
the MAC before checking expiry, principal/session bindings, or selected
digests, then completes those checks before domain authorization or state
access. A receipt with both a corrupt MAC and expired claims returns
NEGOTIATION_RECEIPT_INVALID without exposing the expiry distinction. A receipt
is downgrade/tamper evidence; it is never an authorization grant.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
