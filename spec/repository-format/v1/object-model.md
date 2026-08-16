# OpenGameVCS repository object model, format v1

## 1. Status and scope

This document is normative for the language-neutral immutable object graph and
pure repository-context validation defined by OGVCS-002. It implements
ADR-0008, ADR-0009, and the ownership boundary in ADR-0010. The companion CDDL
is [`repository-format.cddl`](repository-format.cddl).

This specification does not define joined-path admissibility, case folding,
filesystem materialization, a production chunking algorithm, a database
layout, an authorization policy, a finalize transaction, or a repository
export. Those remain with the owners named in ADR-0010.

The words MUST, MUST NOT, SHOULD, and MAY are normative.

## 2. Deterministic CBOR and common types

Every metadata object is exactly one deterministic-CBOR item using the
ADR-0008 profile. It uses definite containers, shortest-form integers and
lengths, NFC text, and unsigned integer map keys in deterministic order. A
strict reader MUST reject floats, tags, `null`, undefined or other simple
values, bignums, indefinite containers, duplicate keys, non-minimal values,
invalid UTF-8, non-NFC text, or trailing bytes. It MUST NOT repair and accept
noncanonical input.

Every metadata object map contains:

| Key | Field | Type | Rule |
|---:|---|---|---|
| 0 | `format-version` | unsigned integer | exactly `1` |
| 1 | `object-kind` | unsigned integer | registered code below |
| 2 | `required-features` | array of unsigned integers | present and strictly increasing |
| 3 | `extensions` | map from canonical extension-key text to deterministic extension values | optional; omit when empty; deterministic text-key order |

Kind-specific fields begin at key 16. An extension map has at most 128
entries and at most 16 MiB of aggregate extension value bytes. Unknown required
features prevent semantic interpretation. Unknown extensions do not alter base
semantics and MUST be retained byte-for-byte by a lossless round trip.

Common values are:

- `RepositoryID`, `FileID`, `GroupID`, `ShelfID`, and `PrincipalID`: exactly 16
  bytes and not all zero. They have no UUID semantics.
- `Digest`: exactly 32 bytes.
- `TypedDigest`: map `{0: algorithm, 1: digest}`. Algorithm `1` is SHA-256.
  Any other algorithm value is `SCHEMA_FIELD_INVALID` at layer 2;
  `OBJECT_REFERENCE_FORMAT_UNSUPPORTED` is reserved for `ObjectRef` format or
  algorithm fields.
- `ObjectRef`: map `{0: format, 1: expected-kind, 2: algorithm, 3: digest}`.
  Format and algorithm are `1`; the digest is 32 bytes. The referenced object
  MUST have the expected kind and recomputed ID.
- `ProfileRef`: map `{0: namespace, 1: id, 2: major}`. Define `token` as
  `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`. Namespace matches
  `token(?:\.token)+` in at most 253 ASCII bytes, id matches `token` in at most
  63 ASCII bytes, and major is independently encoded in `1..4294967295`.
  These are exact ASCII grammars, not broad NFC strings.
  The canonical rendering is `<namespace>/<id>@<major>`; major is never
  embedded in id.
- `IdentityRef`: map `{0: scheme, 1: identifier, ?2: display-name}` where
  `scheme` is a `ProfileRef`, identifier is a nonempty byte string, and display
  name is optional NFC text. Generic values use the 16 MiB hard maximum.
- Timestamp: signed 64-bit Unix nanoseconds.
- Logical length: unsigned integer not greater than 1 TiB
  (`1,099,511,627,776`).
- Path value: a definite array of 1..256 NFC segment strings. Each segment is
  1..255 UTF-8 bytes and is not `.`, `..`, or a string containing `/` or NUL.
  The joined byte measure is the sum of segment UTF-8 lengths plus one slash
  byte between adjacent segments and is at most 4096, but slash joining is not
  part of canonical path bytes. The descriptor's path profile performs all
  additional joined-path and platform validation. These core values are hard
  maxima, not repository defaults; a profile may select lower limits.

Object kind assignments are immutable:

| Code | Kind |
|---:|---|
| 1 | raw chunk |
| 2 | content manifest |
| 3 | tree |
| 4 | change set |
| 5 | asset-group set |
| 6 | repository descriptor |
| 7 | snapshot |
| 8 | shelf revision |
| 9 | provenance |
| 10 | attestation |
| 11 | conflict set |

For kind code `K` and payload bytes `P`:

```text
ObjectID = SHA-256(
  ASCII("OpenGameVCS object\0") ||
  uint16be(1) ||
  uint16be(K) ||
  P
)
```

For a chunk, `P` is its raw logical bytes. For every other kind, `P` is the
complete deterministic-CBOR item. A chunk is 0..64 MiB. A metadata payload is
at most 512 MiB. The durable reference text is
`ogvcs:v1:<kind>:sha256:<64-lowercase-hex>`; FileID text is
`fid:<32-lowercase-hex>`.

## 3. Profile references and repository descriptor

The registry provides conformance-only `path.test/opaque@1`,
`chunking.test/external-boundaries@1`, the remaining generic object-profile
families, and explicit fixture-adapter families. Their exact semantics are
defined in [`conformance-profiles.md`](conformance-profiles.md) and
[`fixture-adapter.md`](fixture-adapter.md). They may be used in vectors and
fixture adaptation but MUST NOT be written to a production repository. Ratified
profiles are additive registry entries and do not change these object shapes.

Profile families are context-checked, not interchangeable strings:

| Use | Allowed registry family |
|---|---|
| descriptor path profile | `path` |
| descriptor/tree content policy | `content-policy` or `fixture-content-policy` |
| descriptor/group profile | `group` or `fixture-group` |
| descriptor/manifest chunk profile | `chunking` |
| group member role | `group-role` or `fixture-group-role` |
| group external-key scheme | `external-key` or `fixture-external-key` |
| identity scheme | `identity` |
| import mapping importer | `importer` |
| custom conflict resolution driver | `conflict-driver` |
| policy result | `policy` |
| provenance producer | `provenance` |
| attestation predicate/signature | `attestation-predicate` / `signature` |
| annotation payload, bundle root, fixture event | `annotation-payload`, `bundle-root-role`, `fixture-event` |

Using a registered profile from the wrong family is `SCHEMA_FIELD_INVALID`.
Every currently assigned profile is conformance-only; semantic production mode
therefore rejects it even when the family is correct.

### 3.1 Repository descriptor — kind 6

| Key | Field | Type |
|---:|---|---|
| 16 | `repository-id` | `RepositoryID` |
| 17 | `path-profile` | `ProfileRef` |
| 18 | `content-policy-profiles` | nonempty sorted unique array of `ProfileRef` |
| 19 | `group-profiles` | sorted unique array of `ProfileRef` |
| 20 | `chunk-profiles` | sorted unique array of `ProfileRef`; optional and omitted when empty |

Profile arrays sort by the deterministic CBOR bytes of `ProfileRef`. Every
repository-scoped object below references this exact descriptor ObjectID. A
descriptor intentionally does not point to a root snapshot, because that would
form a hash cycle. A repository context supplies the one designated root.

## 4. Content objects

### 4.1 Raw chunk — kind 1

A chunk payload is exactly 0..64 MiB of raw logical bytes. It has no CBOR
envelope, repository binding, compression, pack, placement, or transfer hints.
An empty file has no chunks, so an empty chunk is legal but normally
unreachable.

### 4.2 `ContentManifestV1` — kind 2

| Key | Field | Type |
|---:|---|---|
| 16 | `logical-length` | logical length |
| 17 | `whole-file-digest` | SHA-256 `TypedDigest` |
| 18 | `chunk-profile` | `ProfileRef` |
| 19 | `chunks` | ordered array of `ChunkPart`, 0..1,048,576 |

`ChunkPart` is `{0: chunk-ref, 1: logical-length}`. The reference MUST expect
kind 1 and SHA-256. Each part length is 1..64 MiB. A checked accumulator with a
ceiling of 1 TiB MUST reject as soon as the logical sum exceeds that ceiling;
otherwise the final sum MUST equal the manifest logical length. Streaming the referenced bytes
in order MUST produce the whole-file digest. A zero-length manifest has no
parts and uses SHA-256 of the empty byte string. Repeated chunk references are
valid. Nonidentity annotations are separate logical records and never fields
of the manifest.

This object fixes only the ordered boundary container. The referenced profile
owns production boundary generation and validation.

## 5. Directory trees

### 5.1 Tree — kind 3

| Key | Field | Type |
|---:|---|---|
| 16 | `repository-descriptor` | kind-6 `ObjectRef` |
| 17 | `entries` | array of `TreeEntry`, 0..1,000,000 |

A tree represents exactly one directory. `TreeEntry` fields are:

| Key | Field | Type |
|---:|---|---|
| 0 | `basename` | NFC text, 1..255 UTF-8 bytes, not `.`, `..`, or containing `/` or NUL |
| 1 | `entry-kind` | code below |
| 2 | `file-id` | `FileID` |
| 3 | `portable-mode` | code below |
| 4 | `target` | typed `ObjectRef` |
| 5 | `logical-size` | logical length |
| 6 | `content-policy` | `ProfileRef` |

Entry and portable-mode codepoints are:

| Entry kind | Code | Required mode | Target |
|---|---:|---:|---|
| directory | 1 | 1 (`directory`) | kind 3 tree |
| regular | 2 | 2 (`regular`) | kind 2 manifest |
| executable | 3 | 3 (`executable`) | kind 2 manifest |
| symlink | 4 | 4 (`symlink`) | kind 2 manifest |

Entries sort strictly by the UTF-8 bytes of `basename`; duplicate bytes are
invalid. CDDL enforces nonempty text, byte length, slash and NUL exclusion;
known-kind schema validation additionally rejects `.` and `..` with
`PATH_CORE_INVALID`. A directory's logical size is exactly zero. Known-kind schema validation
rejects locally invalid kind, mode, target-kind, and directory-size combinations with
`TREE_ENTRY_TARGET_INVALID` at layer 2. A file, executable, or symlink size equals its resolved
manifest length; tree expansion rejects disagreement with `TREE_ENTRY_TARGET_INVALID` at layer 3
in the `repository-semantics` stage. Core validation does not interpret symlink bytes or
declare a filesystem-safe path; those decisions belong to the path profile.
Descriptor-bound tree expansion additionally applies the core `PathValue`
segment-count and joined-byte ceilings to every composed root-relative entry
path. This graph check does not add slash-joined text to canonical tree bytes
and does not perform the platform/collision rules owned by the path profile.

Every named entry, including a directory, has a nonzero FileID. The fully
expanded snapshot tree MUST contain each FileID exactly once. Hard links and
aliases are not representable in v1. All descendant trees reference the same
descriptor. Every entry content-policy profile is listed by that descriptor.
Every reached manifest chunk profile is likewise listed; omission of descriptor
key 20 therefore permits only a graph with no reached manifests.

## 6. Asset groups

### 6.1 Asset-group set — kind 5

| Key | Field | Type |
|---:|---|---|
| 16 | `repository-descriptor` | kind-6 `ObjectRef` |
| 17 | `groups` | array of `AssetGroup`, 0..10,000 |

`AssetGroup` fields are:

| Key | Field | Type |
|---:|---|---|
| 0 | `group-id` | `GroupID` |
| 1 | `profile` | `ProfileRef` |
| 2 | `primary-file-id` | `FileID` |
| 3 | `members` | sorted unique array of `GroupMember`, 1..64 |
| 4 | `external-keys` | sorted unique array of `ExternalKey`; optional |

`GroupMember` is `{0: file-id, 1: role-profile}`. `ExternalKey` is
`{0: scheme-profile, 1: value}`, with a nonempty byte-string value. Groups sort by
GroupID; members sort by `(encoded role-profile, FileID)`; external keys sort by
`(encoded scheme-profile, value)`.

The set profile must be listed by the descriptor. Every member resolves exactly
once in the expanded tree and the primary is a member. A FileID belongs to at
most one group in v1. Registered group profiles own role cardinality and
external-key uniqueness. Thus a missing required sidecar and a duplicated
unique GUID are encodable but fail semantic validation.

An absent snapshot group-set field means the empty group set. There is no
distinguished hashed empty group object requirement.

## 7. Exact changes and FileID proofs

### 7.1 Entry state

An `EntryState` describes a named entry at a joined path:

```text
{0: path-segment-array, 1: entry-kind, 2: file-id, 3: portable-mode,
 ?4: target, 5: logical-size, 6: content-policy}
```

For regular, executable, and symlink states, target is required and carries the
same target/size constraints as a tree entry. A directory state omits target
and has size zero: its child-tree ObjectID is derived when the flat replay state
is materialized, avoiding synthetic modify operations on every ancestor after
a leaf change. It is not an independent object.

### 7.2 Allocation and restore proof shapes

An `AllocationProof` is:

```text
{0: repository-descriptor, 1: allocation-kind, ?2: import-mapping-key}
```

Allocation kind `1` is native and `2` is import. Native proof omits key 2;
import proof requires the 32-byte mapping key defined below. The descriptor MUST
match the change set. FileID bytes themselves are the native CSPRNG output; no
nonce or allocation-claim identifier is serialized because neither could prove
registry uniqueness. This proof states the requested origin only. The
pre-publication context and working additions below establish pure-validation
freshness; finalization checks and atomically updates the authoritative registry.
CDDL can make key 2 optional but cannot couple its presence to key 1; violating
that coupling is `SCHEMA_FIELD_INVALID` at layer 2.

An import mapping key is:

```text
SHA-256(
  ASCII("OpenGameVCS import mapping\0") || uint16be(1) ||
  deterministic-cbor([
    repository-descriptor, importer-profile,
    source-namespace-digest, source-identity-digest
  ])
)
```

A `RestoreProof` is:

```text
{0: repository-descriptor, 1: source-snapshot, 2: source-path-segment-array,
 3: delete-snapshot}
```

Define `ancestor-or-self(A,B)` as reflexive reachability from `B` by following
any parent edge, and `strict-ancestor(A,B)` as the same relation with `A != B`.
Both proof snapshots MUST belong to the same repository. The source snapshot
contains the exact restored `EntryState` at the source path. The delete snapshot
is a strict descendant of the source, its own change set contains the exact
delete of that state, and it is an ancestor-or-self of the candidate base. The
candidate base is parent zero and therefore the candidate is strictly after the
delete snapshot. The FileID is absent from the complete base tree. The restore
`after` state equals the source state byte-for-byte, including path, target,
kind, mode, size, policy, and FileID. Restoring elsewhere is expressed as
restore followed by move or rename.

### 7.3 Change set — kind 4

| Key | Field | Type |
|---:|---|---|
| 16 | `repository-descriptor` | kind-6 `ObjectRef` |
| 17 | `base-snapshot` | kind-7 `ObjectRef`; optional and absent only for a root |
| 18 | `operations` | array of `Operation`, 0..1,000,000 |

Sequence numbers start at zero and are contiguous. Operation codes and exact
fields are:

| Code | Operation | Required fields |
|---:|---|---|
| 1 | create | `{0:seq,1:code,3:after,5:allocation-proof}` |
| 2 | modify | `{0:seq,1:code,2:before,3:after}` |
| 3 | copy | `{0:seq,1:code,3:after,4:source,5:allocation-proof}` |
| 4 | move | `{0:seq,1:code,2:before,3:after}` |
| 5 | rename | `{0:seq,1:code,2:before,3:after}` |
| 6 | delete | `{0:seq,1:code,2:before}` |
| 7 | restore | `{0:seq,1:code,3:after,6:restore-proof}` |
| 8 | group-create | `{0:seq,1:code,8:group-after}` |
| 9 | group-update | `{0:seq,1:code,7:group-before,8:group-after}` |
| 10 | group-delete | `{0:seq,1:code,7:group-before}` |
| 11 | merge-resolution | `{0:seq,1:code,9:conflict-id,10:subject-kind,?11:result}` |

Merge-resolution subject `1` is an entry and subject `2` is a group. `result`
is the corresponding state; omission means deletion. Its conflict ID must
resolve in the snapshot's conflict set and its result must equal that record's
resolved result.

Replay rules are exact:

- Create requires an absent path and a FileID absent from both the pre-candidate
  lifetime records and earlier working lifetime additions.
- Modify requires an exact `before`; `after` preserves path and FileID and
  changes at least one of target, kind/mode, size, or policy.
- Copy applies only to a regular, executable, or symlink source. It requires an
  exact source and absent destination. `after` has a new FileID and otherwise
  initially equals source except for path. Directory copy is a parent-first
  series of directory creates and leaf copies, allocating every new FileID.
- Move requires an exact `before`, absent destination, a changed parent path,
  and otherwise identical state including FileID.
- Rename has the same rules, but the parent path is unchanged and basename
  differs. Core represents a case-only rename; the path profile decides whether
  it is admissible.
- Moving or renaming a directory atomically rewrites the path prefix of all
  descendants while preserving their states and FileIDs; the destination
  prefix must be absent. Creating a directory requires its parent to exist.
- Delete requires exact `before` and removes it. A directory must be empty at
  that operation, so recursive deletion is descendant-first and records every
  consumed FileID. The FileID remains consumed.
- Restore may reactivate a consumed historical leaf or empty-directory FileID
  and must satisfy its proof. It creates no lifetime addition. Restoring a nonempty directory is an explicit
  parent-first series so every descendant has a proof.
- Group transitions require exact before/absence and preserve GroupID on
  update.

Operations apply in order to parent zero's tree and group set, or empty states
for the designated root. The result MUST equal the snapshot's declared tree and
group roots. A merge is represented by snapshot parents, not by an operation.

## 8. Conflicts

### 8.1 Conflict set — kind 11

| Key | Field | Type |
|---:|---|---|
| 16 | `repository-descriptor` | kind-6 `ObjectRef` |
| 17 | `conflicts` | nonempty sorted array of `ConflictRecord` |

Conflict kinds are assigned by `registries/semantic-enums.json`: `1 content`,
`2 divergent-move`, `3 delete-modify`, `4 type`, `6 policy`, `7 group`, and
`8 path-collision`. Code 5 retains the name `mode` as a reserved assignment and
MUST NOT occur in a format-v1 conflict. Portable mode is derived exactly from
entry kind in v1, so two sides cannot have the same kind and distinct valid
portable modes.

A record contains:

```text
{0: conflict-id, 1: conflict-kind, 2: typed-subject,
 ?3: base-side, ?4: left-side, ?5: right-side, 6: resolution}
```

An entry subject is `[1, file-ids, paths]`, with each nested array sorted,
unique, and containing 1..3 values. A group subject is `[2, GroupID]`. A side is
exactly one of `{0:1, 1:EntryState}` or `{0:2, 2:AssetGroup}`; absence of a side
means absent state. Conflict ID is
`SHA-256(ASCII("OpenGameVCS conflict\0") || uint16be(1) || P)`, where `P` is
the deterministic-CBOR map
`{0:kind,1:typed-subject,?2:base-side,?3:left-side,?4:right-side}`. Explicit keys
make every combination of absent sides unambiguous; resolution is excluded.
Records sort by conflict ID.

Known-kind schema validation enforces the typed shapes and cardinalities;
violations are `SCHEMA_FIELD_INVALID` at layer 2. Semantic validation enforces
the following exact subject/side relationships and returns
`CONFLICT_SUBJECT_INVALID` at layer 3:

| Kind | Subject | Required side relationship |
|---:|---|---|
| 1 content | entry: one FileID, one path | base, left, right entry sides present; all match subject FileID/path; left and right targets differ |
| 2 divergent-move | entry: one FileID, 2..3 paths | base, left, right entry sides present; all match the FileID; left and right paths differ and every side path is listed |
| 3 delete-modify | entry: one FileID, one path | base entry present; exactly one of left/right absent; present alternative matches subject and differs from base |
| 4 type | entry: one FileID, one path | all three entry sides present and match subject; left/right entry kinds differ |
| 6 policy | entry: one FileID, one path | all three entry sides present and match subject; left/right content-policy values differ |
| 7 group | group: one GroupID | base group present; at least one of left/right present; every present side is a group with the subject GroupID and left/right are not equal |
| 8 path-collision | entry: 2..3 FileIDs, one path | left and right entry sides present at the subject path with distinct listed FileIDs; base is absent or an entry side using a listed FileID |

No side of the other subject type is permitted. “Differs” and “equals” mean
equality of the complete deterministic-CBOR side value, not a profile-defined
approximation.

Resolution `{0:0}` is unresolved. Resolved shapes are exact: base/left/right are
`{0:1,1:choice,2:result-side}`; delete is `{0:1,1:4}`; custom is
`{0:1,1:5,2:result-side,3:driver-profile}`. For base/left/right, the result side
MUST equal the named present side byte-for-byte. Delete has no result or driver.
Custom requires a result of the subject's side type and a registered
`conflict-driver` family profile. A driver is forbidden for every other choice.

Published snapshots MUST omit a conflict set when no conflict evidence is being
published and MUST NOT reference an unresolved record. Every resolved record in
a published snapshot has exactly one merge-resolution operation; its subject
kind and optional result equal the resolution (deletion omits the operation
result), and replay produces the same final tree/group state. Shelf revisions
and pending-change-reference logical records MAY reference unresolved records;
an unresolved record MUST NOT have a merge-resolution operation. A resolved
shelf conflict follows the same one-operation/equality rule.

## 9. History objects

### 9.1 Policy result

`PolicyResult` is
`{0: profile, 1: generation, 2: decision, 3: result-digest}`. Decision `1` is
pass and `2` is an explicitly recorded override. The result digest is typed
SHA-256. Policy evaluation is outside this format; the immutable result binds
what the publisher asserted.

### 9.2 Snapshot — kind 7

| Key | Field | Type |
|---:|---|---|
| 16 | `repository-descriptor` | kind-6 `ObjectRef` |
| 17 | `parents` | ordered unique array of kind-7 refs, 0..8 |
| 18 | `root-tree` | kind-3 `ObjectRef` |
| 19 | `change-set` | kind-4 `ObjectRef` |
| 20 | `group-set` | kind-5 `ObjectRef`; optional, absence means empty |
| 21 | `author` | `IdentityRef` |
| 22 | `committer` | `IdentityRef` |
| 23 | `authored-at` | timestamp |
| 24 | `committed-at` | timestamp |
| 25 | `message` | NFC text, at most 1 MiB |
| 26 | `policy-result` | `PolicyResult` |
| 27 | `provenance` | sorted unique array of kind-9 refs; optional |
| 28 | `conflict-set` | kind-11 ref; optional |

A repository context designates exactly one zero-parent snapshot as root.
Every other snapshot has one to eight ordered unique parents, shares the
descriptor, and reaches that root. Parent zero exactly equals the change-set
base. Missing, wrong-kind, cyclic, duplicate, cross-repository, second-root,
and ninth-parent graphs are invalid.

Because each parent edge is inside its source snapshot's ObjectID preimage, a
finite cycle of byte-valid snapshots would require a SHA-256 fixed point. Any
ordinary payload substitution is `OBJECT_ID_MISMATCH` at layer 1 before cycle
detection. Implementations MUST still use a bounded visiting/visited algorithm;
`SNAPSHOT_PARENT_CYCLE` is exercised at semantic layer 3 through the typed
prevalidated symbolic graph schema routed by README, not misrepresented as a
canonical-object byte vector.

Provenance is created before the snapshot and MUST NOT reference the snapshot
or any object that reaches it. Attestations are inbound: a snapshot never
contains an attestation reference that signs that snapshot.

### 9.3 Shelf revision — kind 8

| Key | Field | Type |
|---:|---|---|
| 16 | `repository-descriptor` | kind-6 `ObjectRef` |
| 17 | `shelf-id` | `ShelfID` |
| 18 | `revision-number` | `1..2^32-1` |
| 19 | `previous-revision` | kind-8 ref; optional |
| 20 | `base-snapshot` | kind-7 ref |
| 21 | `change-set` | kind-4 ref |
| 22 | `result-tree` | kind-3 ref |
| 23 | `group-set` | kind-5 ref; optional, absence means empty |
| 24 | `conflict-set` | kind-11 ref; optional |
| 25 | `author` | `IdentityRef` |
| 26 | `created-at` | timestamp |
| 27 | `message` | NFC text, at most 1 MiB |
| 28 | `policy-result` | `PolicyResult` |
| 29 | `provenance` | sorted unique array of kind-9 refs; optional |

A previous revision has the same descriptor and ShelfID and revision number
exactly one less. Revision one omits it; later revisions require it. Replaying
the change set from the base snapshot produces the result tree/group set.
Unresolved conflicts are permitted. The shelf revision is content-complete but
does not advance a branch.

### 9.4 Provenance — kind 9

| Key | Field | Type |
|---:|---|---|
| 16 | `producer` | `ProfileRef` |
| 17 | `inputs` | sorted unique array of `ObjectRef` |
| 18 | `statement-digest` | SHA-256 `TypedDigest` |
| 19 | `statement` | byte string, 0..16 MiB; optional |

If statement bytes are present, their SHA-256 equals the statement digest.
Inputs are ordinary outbound graph edges. A snapshot-reachable provenance
object must be acyclic and have no path back to the referencing snapshot.
The same content-addressed fixed-point constraint and abstract-graph test route
described for snapshot-parent cycles applies to `PROVENANCE_CYCLE`.

### 9.5 Attestation — kind 10

| Key | Field | Type |
|---:|---|---|
| 16 | `subject` | `ObjectRef` |
| 17 | `predicate` | `ProfileRef` |
| 18 | `issuer` | `IdentityRef` |
| 19 | `issued-at` | timestamp |
| 20 | `payload` | byte string, 0..16 MiB |
| 21 | `signature-profile` | `ProfileRef`; optional |
| 22 | `signature` | byte string, 1..16 MiB; required iff key 21 is present |

An attestation references an already completed subject. It is inbound and does
not alter the subject ObjectID. Signature verification semantics belong to the
registered signature profile.

## 10. Repository-context validation

Pure object decoding is insufficient for lifetime and graph claims. A
repository validation invocation supplies:

```text
RepositoryContext {
  descriptor: ObjectRef(kind 6),
  designated_root: ObjectRef(kind 7),
  immutable_objects: lookup(ObjectRef -> exact bytes),
  fileid_registry: lookup(FileID -> immutable LifetimeRecord),
  working_lifetime_additions: ordered LifetimeRecord additions,
  import_mappings: lookup(mapping key -> FileID),
  validation_mode: conformance | production
}
```

The temporal instant is always immediately before the candidate snapshot. The
candidate snapshot bytes and its new outbound objects are present in the
caller-supplied immutable-object lookup, but the candidate is not yet part of
the designated published history, lifetime registry, or import-mapping state.
`working_lifetime_additions` are derived in operation order from candidate create/copy operations and are checked
against the pre-candidate registry and each earlier addition. This convention
prevents a candidate's own first consumption from being mistaken for reuse.

Validation proceeds in this order:

1. Strictly decode and recompute every supplied ObjectID.
2. Type-check every reference and descriptor binding.
3. Verify the one-root, parent-count, ancestry, and acyclic graph rules.
4. Stream trees and use a bounded disk-backed index for joined paths and global
   FileID uniqueness. Invoke, but do not redefine, the selected path profile.
5. Verify manifests and referenced chunk bytes.
6. Replay each change set against parent zero, validating exact entry/group
   transitions, restore ancestry, resolved conflicts, and declared roots.
7. Check permanent FileID lifetime/import evidence.
8. In production mode reject every conformance-only profile.

A lifetime record is repository-scoped immutable evidence of the first
consumption only. Its origin is exactly native-create, native-copy, or import;
it names the first change-set ObjectRef and operation sequence, and import also
names its mapping key. Origin and operation must agree: native-create is a
native create, native-copy is a native copy, and import is an import allocation
on create or copy with the same mapping key. Restore is never an origin and
never adds or mutates a lifetime record. A malformed or contradictory record is
`FILEID_LIFETIME_EVIDENCE_INVALID` at layer 3. Delete never frees the ID;
delete/recreate needs a new ID; create then delete in one change still adds one
first-consumption record. Equal raw FileID bytes may independently exist in different repositories.
There is no lifetime `reserved`/`consumed` state in v1: existence of the record
means permanently consumed. `reserved/materialized/published` applies only to
the separate import mapping workflow.
Cross-repository rejection applies to descriptors, source proofs, mappings, and
transitions.

A tombstone is the branch-relative historical delete operation naming the
exact prior FileID and state. It is not a global `deleted` registry status,
because another branch may still contain the same FileID. The permanent
`consumed` lifetime record prevents reuse independently of branch presence.

Import states are reserved, materialized, and published. State advances only in
that order and never changes the tuple or FileID. `reserved` means the candidate
change set and first operation already exist and reservation atomically inserted
the source mapping and matching immutable import lifetime record; thus even an
abandoned reservation permanently consumes the ID. `materialized` additionally
means every object needed by that import operation is available and verified;
`published` means a snapshot containing the operation was successfully
finalized. Retry of the exact `(repository,
importer profile, source namespace digest, source identity digest)` tuple returns
the original FileID and current state after a lost acknowledgement. The same
tuple with another FileID, another tuple claiming that FileID, or a mapping key
that disagrees with the tuple is `FILEID_IMPORT_MAPPING_CONFLICT`. Competing
mapping or native allocation of an already consumed ID is a typed collision. A finalize-time
collision has one winner; every loser leaves its branch/reference unchanged.
This document validates the proof/result shape but does not define the database
or transaction protocol.

## 11. Hard limits

In addition to the field-specific limits above, CBOR nesting is at most 32.
Configured object, byte, time, memory, and scratch limits MAY be smaller and
produce the corresponding resource error. Encoders MUST know exact container
counts or use bounded external sorting; decoders MUST not allocate from an
untrusted declared length before checking all hard and configured limits.

Stable failure `(code, layer, stage)` sites are defined in
[`errors.json`](errors.json). Logical
bundle ordering, closure, and integrity are defined in
[`logical-bundle.md`](logical-bundle.md). OGVCS-001 mapping is defined in
[`fixture-adapter.md`](fixture-adapter.md).

## 12. Intentionally unresolved outside this slice

- Ratified production path-profile behavior and case-collision keys.
- Ratified production chunking profiles and boundary algorithms.
- Ratified production content-policy, group/role/key, identity, policy,
  provenance, attestation/signature, annotation, bundle-role, path, and
  chunking profile assignments. OGVCS-002 supplies conformance-only entries so
  every object shape and fixture mapping can be emitted in tests without
  pretending those profiles are production policy.
- Registry persistence/database schemas and finalize isolation.
- Authorization, ref/lock/review service state machines, and audit semantics.
- Export selection, fidelity/projection, signing, volumes, increments,
  restoration, and import evidence.

Implementations MUST report an unsupported/missing profile or context rather
than inventing any of these semantics.
