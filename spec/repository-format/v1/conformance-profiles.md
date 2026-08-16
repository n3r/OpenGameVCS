# OpenGameVCS format-v1 conformance profiles

## 1. Scope and validation mode

This document is normative for every `conformance-only` entry owned by
OGVCS-002 in [`registries/profiles.json`](registries/profiles.json). These
profiles exist solely to make the format, object graph, logical-record, fixture
adapter, and registry-evolution vectors fully interpretable before production
profile owners publish ratified behavior.

A validator accepts one of two explicit modes:

- `conformance` accepts a conformance-only profile only while validating a
  declared OGVCS-002 vector or the OGVCS-001 fixture adapter corpus;
- `production` rejects every conformance-only profile with
  `PROFILE_CONFORMANCE_ONLY`.

Registry read/write decisions use the following exhaustive state table. A
`read` is ordinary interpretation outside a declared conformance run;
`conformance` includes validation or construction of this specification's
declared corpora; and `production-write` includes every new durable production
object or record.

| Registry state | read | conformance | production-write |
|---|---|---|---|
| `ratified` | accept | accept | accept |
| `deprecated` | accept | accept | `PROFILE_STATE_FORBIDDEN` |
| `conformance-only` | `PROFILE_CONFORMANCE_ONLY` | accept | `PROFILE_CONFORMANCE_ONLY` |
| `reserved` | `PROFILE_STATE_FORBIDDEN` | `PROFILE_STATE_FORBIDDEN` | `PROFILE_STATE_FORBIDDEN` |

Profile family checking precedes profile-specific behavior. A known profile in
the wrong field family is `SCHEMA_FIELD_INVALID`; a missing profile is
`PROFILE_UNKNOWN`; a reserved or otherwise forbidden registry state is
`PROFILE_STATE_FORBIDDEN`. None of the profiles below grants authorization,
proves authenticity, supplies a production policy, or changes an ObjectID
preimage.

## 2. Generic profiles

### 2.1 `path.test/opaque@1`

This profile accepts exactly the core path value rules in `object-model.md`:
NFC segments, segment and joined-measure hard maxima, and rejection of empty,
dot, dot-dot, slash-containing, or NUL-containing segments. It adds no case
folding, reserved-name, filesystem, symlink, or materialization rule. Therefore
passing this profile is not evidence that a path is safe on any host platform.

### 2.1.1 `path.test/reject-reserved@1`

This conformance-only profile applies all `path.test/opaque@1` rules and then
rejects any complete joined path containing a segment exactly equal to the NFC
text `reserved`. The failure is `PATH_PROFILE_INVALID` at semantic layer 3.
It exists solely to make profile-specific path rejection independently
executable; it does not model a host filesystem or production naming policy.

### 2.2 `chunking.test/external-boundaries@1`

This profile does not calculate boundaries. A conformance vector supplies an
ordered list of positive chunk lengths. Every length is at most 64 MiB, the
count is at most 1,048,576, and a checked accumulator rejects as soon as the sum
exceeds the 1 TiB logical ceiling; otherwise the sum equals the manifest logical
length. The referenced chunk bytes, chunk IDs, and final file
digest are still verified by the core manifest rules. Repeated chunk IDs are
valid. This profile is never a production chunking algorithm.

### 2.3 `content-policy.test/opaque@1` and `content-policy.test/alternate@1`

These profiles add no restriction beyond core entry kind, mode, target, size,
and descriptor-membership validation. They are distinct deterministic profile
tags so conflict-kind `policy` vectors can carry two valid unequal policy
values. Neither profile classifies content, selects chunking, grants access, or
makes retention claims.

### 2.4 `group.test/opaque@1`

This profile accepts the core `AssetGroup` shape. The declared primary must be
a member, members remain sorted and unique, and each FileID must resolve once in
the snapshot tree. It requires no particular role cardinality and declares no
cross-group external-key uniqueness beyond the core uniqueness rules within one
group.

### 2.5 `group-role.test/member@1`

This profile is a generic member role. It carries no primary/secondary,
sidecar, ordering, or cardinality meaning. The separate core `primary-file-id`
field remains authoritative for the primary member.

### 2.6 `external-key.test/opaque@1`

This profile accepts any nonempty byte-string external-key value within the
generic 16 MiB ceiling. Equality is exact byte equality. It declares no parsing,
normalization, or uniqueness across groups.

### 2.7 `identity.test/opaque@1`

This profile accepts any nonempty identifier bytes within the generic 16 MiB
ceiling and an optional NFC display name within that ceiling. Identifier
equality is exact byte equality. The profile does not assert a person, service,
login, issuer, or authorization identity.

### 2.8 `policy.test/allow@1`

This profile is valid only when `PolicyResult.decision` is `1` (`pass`). The
generation is any core unsigned integer and the result digest is any correctly
shaped SHA-256 `TypedDigest`. No policy engine is run and the digest is opaque;
this profile records a vector assertion only and grants no authorization.

### 2.9 `provenance.test/opaque@1`

This producer profile gives no interpretation to provenance statement bytes.
Core validation still requires the statement digest to match when bytes are
present, validates every typed input reference, and rejects graph cycles. It
does not establish origin, reproducibility, trust, or non-disclosure.

### 2.10 `attestation.test/opaque@1`

This predicate accepts any payload byte string within the generic 16 MiB
ceiling. It gives the payload no semantic truth value. Subject identity,
issuer-shape, timestamp, and signature-field coupling remain core requirements.

### 2.11 `signature.test/opaque@1`

This profile accepts any nonempty signature bytes within the generic 16 MiB
ceiling and performs **no cryptographic verification**. An attestation using it
is a shape/identity vector, never authenticity, authorization, or trust
evidence. Production code must reject the profile even if the byte string looks
like a real signature.

### 2.12 `annotation.test/opaque@1`

This profile accepts annotation payload bytes of length 0..16 MiB without
interpreting them. The annotation remains a non-object logical record; its
logical-record identity and bundle transcript protect the bytes, while the
subject ObjectID remains unchanged.

### 2.13 `bundle-role.test/root@1`

This profile labels any syntactically valid object or logical-record root in an
OGVCS-002 supplied-closure vector. It adds no repository-completeness,
authorization, export, projection, fidelity, restoration, or import meaning.

### 2.14 `importer.test/fixture-adapter@1`

This profile is limited to the OGVCS-001 v2 fixture adapter. In an
`import-mapping` record:

- `source-namespace-digest` is the 32 bytes represented by the fixture
  `requestDigest` lowercase hexadecimal value;
- `source-identity-digest` is
  `SHA-256(ASCII("OpenGameVCS fixture FileID\0") || uint16be(2) || F)`, where
  `F` is the exact 16-byte fixture FileID;
- the target FileID is the value persisted in the adapter ledger; and
- state follows the core reserved/materialized/published code.

Retry identity is the exact tuple `(repository descriptor, importer
ProfileRef, source-namespace-digest, source-identity-digest)`. This profile
describes a public conformance adapter and is not a production import protocol.

### 2.15 `conflict-driver.test/opaque@1`

This profile may appear only on choice `custom` in a resolved conflict. It
accepts the exact declared result side without executing code or interpreting
the result. Core validation still requires subject-type equality, final replay
equality, and exactly one matching merge-resolution operation. The profile is
not evidence that a driver was deterministic, safe, authorized, or executed.

## 3. Fixture-major-2 profiles

All `fixture-*.opengamevcs.test/*@2` profiles are conformance-only. Their exact
mapping and semantic rules are normative in
[`fixture-adapter.md`](fixture-adapter.md):

- `fixture-content.opengamevcs.test/*@2` preserves the public inventory role as
  a content-policy tag and adds no production policy;
- `fixture-group.opengamevcs.test/*@2`,
  `fixture-role.opengamevcs.test/*@2`, and
  `fixture-key.opengamevcs.test/synthetic-guid@2` implement the stated fixture
  group cardinality, role, and GUID rules;
- `fixture-event.opengamevcs.test/operation@2` requires one of the exact
  registered operation-kind tokens and binds the exact canonical public event
  digest.

No fixture profile turns workload events into native immutable history without
the complete bindings required by the adapter contract.

## 4. Conformance obligations

The normative vector set MUST include at least one valid use of every profile
family above and failures for wrong-family use and production-mode use. The
registry-evolution corpus separately proves unknown, reserved, ratified,
deprecated, and conformance-only behavior. A generic profile implementation
MUST NOT infer meaning from namespace or identifier text beyond the exact
behavior defined here.
