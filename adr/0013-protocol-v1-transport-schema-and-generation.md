# ADR-0013: Public protocol v1 transport, schema, and generation

**Status:** Accepted
**Date:** 2026-08-16
**Owners:** OGVCS-041

## Context

ADR-0005 requires a minimal public protocol before R1 service work, but it does
not select the wire profile, schema authority, negotiation algorithm, or
generated-binding strategy. Leaving those choices implicit would let the first
service implementation freeze private HTTP behavior and language-specific data
models. The baseline must integrate the existing canonical repository format,
authorization contract, and path contract without redefining any of them.

The R0 package needs to work from retained artifacts on Windows, macOS, and
Linux, including in disconnected environments. It also needs four generated
schema consumers without requiring four handwritten codecs or a network service
for generation. Domain APIs and physical pack/upload-session designs do not yet
exist and remain owned by their R1 PRDs.

## Decision

### Reference control profile

Protocol v1 selects `ogvcs.control.https-json@1` as its sole required control
profile:

- non-loopback connections use TLS 1.3 and HTTP/1.1; hostname and certificate
  verification are mandatory, cleartext downgrade is forbidden, and a client
  never silently retries with an older TLS or protocol profile;
- R0 negotiation and every mutation-capable protocol operation require HTTPS
  over TLS 1.3. `loopbackConformance` never authorizes cleartext negotiation and
  is not a receipt mode; HTTP negotiation fails before selection or receipt
  issuance. Any cleartext loopback allowance is confined to the non-production
  envelope conformance harness and cannot produce negotiation or release
  evidence;
- proxies use an explicit HTTP `CONNECT` configuration. Untrusted forwarded
  headers do not define origin, subject, tenant, repository, or authorization;
- redirects are not followed for mutations, transfer grants, or requests that
  carry an idempotency key. Other redirects require an explicit same-origin
  client policy;
- control requests and responses use bounded I-JSON objects described by closed
  JSON Schema Draft 2020-12 schemas. Producers emit RFC 8785 JCS bytes.
  Receivers reject duplicate keys, invalid Unicode, non-finite or unsafe
  integers, schema-unknown fields outside the extension container, excessive
  bytes/depth/nodes/collections, and invalid UTF-8 before semantic action;
- a receiver may accept duplicate-free noncanonical I-JSON, but it parses and
  validates first and then computes fingerprints from the semantic JCS
  projection. Raw received JSON bytes are never a request fingerprint;
- control-message content coding is disabled in v1. Every decoder enforces both
  declared and actual byte ceilings before allocating the decoded graph;
- streaming uses independently bounded canonical JSON lines. A registered
  terminal, gap, cancellation, or error frame ends a stream; EOF or transport
  closure without a terminal frame is incomplete, never success.

HTTP/2, HTTP/3, gRPC, protobuf, alternative content codings, and other stream
framings require separately negotiated profiles. They cannot silently replace
the R0 control profile.

### Schema and generated bindings

One declarative protocol model is the authority for message names, immutable
numeric field assignments, JSON member names, types, presence, limits,
sensitivity, fingerprint participation, and lifecycle. The model generates:

- normative closed JSON Schemas and the version/field/schema registries;
- TypeScript, Rust, C++, and C# type packages and assignment constants;
- compatibility and code-generation manifests that bind every source and
  output digest; and
- golden semantic values, JCS bytes, and request fingerprints.

The four generated packages are schema models, not four bespoke JSON/TLS
runtimes. Applications use a bounded runtime appropriate to their language.
Generation uses repository-owned Node code with no remote plugins, timestamps,
absolute paths, host-dependent ordering, or handwritten output patches. The
generator rejects an unsupported model/schema feature. Clean regeneration in a
different directory must reproduce every checked-in source byte. Reassignment
or reuse of a field number/name is incompatible and requires a new major model.

JSON was selected rather than protobuf for the R0 profile because the existing
authorization and path authorities are JSON Schema contracts, the required
base envelopes are small control messages, and an offline four-plugin/runtime
toolchain would otherwise become a second release-critical authority. The
numbered model preserves explicit immutable assignments and makes a later
protobuf profile possible without allowing generated languages to invent
their own field map.

### Negotiation and mutation binding

Negotiation selects protocol, message-schema, repository-format,
authorization-contract, path-contract/profile, event, transfer, and extension
capabilities independently from a machine-readable compatibility registry.
Repository-specific required features and path settings come from authenticated
server state rather than an untrusted client list. Selection is deterministic.
Unknown required capabilities, an empty intersection, a forbidden lifecycle
state, or removal of a client minimum fails before mutation. Entries carried in
the optional `extensions` list are intrinsically optional and an unknown entry
is ignored; an extension that affects correctness or authorization must instead
be registered and selected as a required capability.

New sessions select only candidate or ratified compatibility entries.
Deprecated compatibility entries are retained as historical registry data but
are never selected for a new mutation-capable session.

A successful selection returns a short-lived opaque receipt authenticated by
the server. The receipt binds the selected tuple and registry digest to the
subject, tenant, authority epoch, session, client/server nonces, and expiry.
Every mutation presents that receipt; a bare tuple digest is not proof of a
negotiated or authorized session. A changed, expired, foreign, or downgraded
receipt fails before state changes.

### Errors, retries, cursors, and streams

Errors use a closed authorization-safe subset of RFC 9457 problem details. A
registry fixes each code's HTTP status, type URI, title/message class,
retryability, allowed bounded details, and conflict/current-generation
visibility. Free-form `detail`, dereferenceable `instance`, stack data,
credentials, grants, policy text, protected paths/objects, hidden counts, and
arbitrary extension members are forbidden. HTTP status, body status, and retry
headers must agree.

Every permitted parameter name has a closed value grammar; an allowed field
name is not permission to emit arbitrary text. The generic R0 baseline has no
domain authorization proof for exposing a current generation, so it never
emits one. A later domain API may expose that value only through a registered
contract that carries an authenticated visibility decision.

Every retryable mutation carries a bounded idempotency key. Its fingerprint is
the domain-separated SHA-256 of the validated semantic JCS projection defined
by the generated field policy, excluding correlation/deadline/receipt fields
and including every operation input. Same key and same fingerprint returns the
original outcome; same key and different fingerprint is rejected. Loss of the
response after commit cannot cause a second mutation.

Cursors are opaque random handles to server-owned state. State binds subject,
tenant, repository, operation/query digest, generation, position, issue time,
and expiry. Scope mismatch, tamper/unknown token, expiry, or retention gap has a
distinct stable result. Pages and streams carry explicit completion/gap state;
clients never infer completion from an empty page or closed connection.

### Transfer carrier boundary

`ogvcs.transfer.range-resume-probe@1` specifies an application-neutral carrier
and synthetic conformance probe only. It fixes identity content encoding,
bounded byte ranges/offsets, strong validators, RFC 9530 content digests,
explicit completion, retry safety, interruption, and grant carriage. It does
not define production object routes, upload-resource/session lifecycle,
multipart behavior, pack layout, compression, placement, or availability;
those remain OGVCS-008 responsibilities.

The carrier never puts a grant in a query string. Its HTTP authorization value
can carry only the bounded canonical OGVCS-003 envelope using a request-root
grant with an empty explicit object set. Large explicit-set grants are rejected
at the carrier boundary and must be replaced by an authority-issued request-root
grant. The transfer verifier still validates the exact OGVCS-003 claims and
signature; protocol code does not reissue, reinterpret, or broaden them.
RFC 9530 proves transferred representation bytes and does not replace
OGVCS-002 object/chunk identity verification.

### Extensions and compatibility

All extension entries declare an owner, namespaced identifier, lifecycle,
required/optional use, fallback, data/security impact, affected schemas, and
minimum capability tuple. Additive optional fields live only in the explicit
extension container. The compatibility registry enumerates allowed version
tuples and required features. R0 does not define a deprecated-read compatibility
window: deprecated and reserved extensions are not selected, emitted, or
interpreted. Supporting historical extension payloads later requires an
explicitly negotiated read-only profile and vectors.

Release preflight rejects unknown required features, an unregistered tuple,
reassignment, a predecessor digest outside the declared candidate range, or a
same-major change to the generated semantic fingerprint of an existing field,
error, limit, capability, message, or extension assignment.

The R0 preflight admits a new optional extension only when the frozen
predecessor contract already pre-reserved its exact assignment and semantic
fingerprint in `allowedAdditions`. Authenticating an arbitrary newly proposed
registry is deferred to a future release-preflight version with an explicit
candidate-manifest input; R0 does not infer that authority from caller data.

## Alternatives rejected

- **Private in-process DTOs or OpenAPI generated after implementation:** would
  record accidental service behavior rather than define it.
- **Protobuf/gRPC as the R0 mandatory profile:** requires protoc plus four
  pinned plugin/runtime closures, duplicates existing JSON grant/path contracts,
  and does not provide a canonical request fingerprint. It may be added later as
  a negotiated profile with equivalent semantics.
- **Canonical CBOR control messages:** would reuse object-format machinery but
  lacks the required mature four-language generated schema-consumer path and
  would couple service evolution to repository-object encoding.
- **Strictly hashing received JSON bytes:** makes harmless serialization
  differences semantic and does not safely address duplicate keys.
- **HTTP closure as stream completion:** turns proxy disconnects into false
  success and loses explicit gap semantics.
- **A production resumable-upload state machine in OGVCS-041:** overlaps
  OGVCS-008's route, session, storage, pack, and placement ownership.
- **Transfer grants in URLs or unbounded headers:** leak through intermediaries
  and cannot carry the authorization contract's largest explicit sets safely.

## Compatibility and data consequences

Protocol/model major version 1 freezes transport semantics, field assignments,
error codes, fingerprint projections, and negotiation selection. Compatible
minor releases may add registered optional extensions with safe fallback. A
changed field meaning, removed required field, widened sensitive detail,
fingerprint change, or reassigned number/name requires a new negotiated major.

The compatibility manifest pins the predecessor package versions and digests
used for a candidate, but OGVCS-041 cannot be ratified or moved to `done` until
OGVCS-002 and OGVCS-004 are complete. Rebuilding a candidate after either
predecessor changes regenerates and re-runs the compatibility evidence rather
than silently accepting drift.

## Threat and failure analysis

Negotiation stripping, proxy header injection, downgrade, malformed or deeply
nested JSON, decompression amplification, duplicate keys, idempotency-key reuse,
lost responses, cursor replay/scope confusion, EOF before terminal, transfer
grant disclosure/replay, oversized ranges, and error-oracle detail are explicit
negative vectors. All precondition, compatibility, parsing, authorization, and
resource failures happen before mutation. Reports retain stable codes, safe
classes, normalized trace/state digests, mutation count, and resource summaries;
they never retain credentials, grants, protected identifiers, or payloads.

Synchronous host I/O cannot be preempted safely. Implementations checkpoint
before and after bounded calls; promise-based hooks race a shared deadline and
receive cancellation. Output remains staged and untrusted until success.

## Proof

OGVCS-041 first publishes a `1.0.0-rc.1` candidate. It publishes the model,
schemas, registries, compatibility manifest,
four generated type packages, two independent semantic adapters, bounded
reference client/server stubs, golden/malformed/resource/security traces, and
an offline packed contract runner. Linux, macOS, and Windows compare the same
semantic outcomes and generated-source digests. OGVCS-005 consumes the
candidate profile before `1.0.0` ratification. A separate exact-scale campaign
is not part of this protocol proof.

## Rollback

Before downstream adoption, withdraw the candidate package and keep domain
mutation routes disabled. After adoption, a server may disable new sessions but
must not reinterpret a v1 receipt, cursor, idempotency record, field assignment,
or error. Replacement uses a separately negotiated version and a compatibility
entry; rollback never accepts a downgraded receipt or replays a committed
mutation.

## Primary references

- IETF, [TLS 1.3 (RFC 8446)](https://www.rfc-editor.org/rfc/rfc8446).
- IETF, [HTTP Semantics (RFC 9110)](https://www.rfc-editor.org/rfc/rfc9110)
  and [HTTP/1.1 (RFC 9112)](https://www.rfc-editor.org/rfc/rfc9112).
- IETF, [JSON (RFC 8259)](https://www.rfc-editor.org/rfc/rfc8259),
  [I-JSON (RFC 7493)](https://www.rfc-editor.org/rfc/rfc7493), and
  [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785).
- IETF, [Problem Details for HTTP APIs (RFC 9457)](https://www.rfc-editor.org/rfc/rfc9457).
- IETF, [Digest Fields (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530).
- OpenGameVCS, [authorization contract v1](0011-authorization-contract-v1.md)
  and [path/filesystem contract v1](0012-path-and-workspace-filesystem-contract-v1.md).
