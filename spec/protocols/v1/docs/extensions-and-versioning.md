# Extensions and compatibility

Every extension has an immutable numeric assignment, namespaced identifier,
owner, lifecycle, optional/required state, fallback, security/data impact,
affected schemas, and minimum protocol. Payloads live only in the explicit
closed extension map. Unknown top-level members never become extensions.

Only candidate and ratified entries may be selected or emitted, and only where
their lifecycle and selected compatibility tuple allow. Deprecated and reserved
entries are neither selected, emitted, nor interpreted in R0. This v1 contract
declares no deprecated-read compatibility window; such behavior would require a
future explicitly negotiated profile. The deprecated registry entry remains
solely as a rejection witness. Identifiers in the
optional `extensions` list are intrinsically optional and unknown entries are
ignored. Anything required appears in `requiredCapabilities`, where an unknown
or unnegotiated entry fails before mutation. Registry fallback applies only to
known registrations and never upgrades an optional list member into a
requirement.

The compatibility registry enumerates allowed independent selections and pins
authorization, path, and repository predecessor manifests. A release preflight
rejects a tuple not present in that registry, a changed predecessor digest, an
unknown required capability, or reuse/reassignment of a message/field/registry
number, name, or semantic SHA-256. The semantic digest is SHA-256 over
`ogvcs.protocol/release-assignment-semantics/v1\0 || JCS({kind,scope,name,code,policy})`.
Field policy includes the complete declarative type and bounds, presence,
fingerprint and sensitivity policy, and owning cross-field constraints. Other
assignment kinds bind their complete registered policy semantics; descriptions
are excluded. Release preflight is executed by the frozen predecessor contract,
which compares proposed rows with its embedded prior rows. R0 admits only
additions explicitly pre-reserved in that predecessor's authenticated
`allowedAdditions`; the positive vector exercises that closed authority. Each
pre-reserved addition must be candidate-state, declared optional, same-major,
and unique by both kind/scope/name and kind/scope/code against prior and sibling
rows. Arbitrary new extension registration requires a future release-preflight
version that authenticates the proposed registry and manifest evidence.
Changing field meaning, presence, fingerprint participation, or safety policy
requires a new negotiated major version.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
