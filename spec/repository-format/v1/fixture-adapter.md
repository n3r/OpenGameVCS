# OGVCS-001 profile-v2 fixture adapter

## 1. Purpose and boundary

This document defines the public, language-neutral adaptation of OGVCS-001
profile-v2 artifacts into format-v1 conformance objects and typed logical
records. The adapter reads only the packaged schemas, manifest, inventory,
groups, scenario, operations, large-file descriptor, and deterministic content
interfaces. It MUST NOT import fixture-generator private source.

The adapter output is conformance data. Fixture IDs are fixed synthetic test
data, not evidence that a native client used a cryptographically secure random
allocator. The conformance-only path and chunk profiles MUST NOT be written to
a production repository. A logical bundle produced from the mapping remains a
caller-supplied closure and MUST NOT be described as an export.

## 2. Required input and validation

The adapter accepts only profile version `2.0.0` and these schema bindings:

- `ogvcs.fixture/inventory-record/v2`;
- `ogvcs.fixture/operation-scenario/v2`;
- the v2 group-relationship schema;
- the v2 fixture manifest/request/profile and, when present, large-file schema.

Before mapping, it MUST run the OGVCS-001 normative structural and deep semantic
verification boundary. In particular it verifies manifest artifact paths and
digests, contiguous inventory/operation indexes, operation/scenario equality,
NFC portable paths, content recipes/digests, FileID lineage, revision/branch
state, group membership, and declared negative cases. A generic JSON Schema
pass that ignores `x-ogvcs-*` keywords is insufficient.

Every fixture FileID must be exactly 16 nonzero bytes. The v2 schema's 32-hex
pattern admits all zero, so the adapter adds this rejection. Duplicate fixture
FileIDs, stale source/result effects, undeclared groups, or incoherent revision
state fail before object construction.

### 2.1 Bounded conformance implementation

The format-v1 JavaScript adapter is a deliberately bounded conformance
implementation. It MUST apply these finite hard maxima before retaining the
corresponding input or state:

| Resource | Hard maximum | Failure |
|---|---:|---|
| aggregate bytes read from adapter-owned fixture artifacts | 64 MiB | `LIMIT_MEMORY` |
| inventory records | 100,000 | `LIMIT_COUNT` |
| operation records | 100,000 | `LIMIT_COUNT` |
| groups | 100,000 | `LIMIT_COUNT` |
| directory, file, and group ledger mappings | 300,000 | `LIMIT_COUNT` |
| emitted immutable-object references | 500,000 | `LIMIT_COUNT` |
| parts in one emitted content manifest | 65,536 | `LIMIT_COUNT` |
| retained tree nodes | 200,000 | `LIMIT_COUNT` |
| adapter elapsed time | 10 minutes | `LIMIT_TIME` |
| retained emitted payload/reference accounting | 256 MiB | `LIMIT_MEMORY` |

NDJSON parsing uses a fixed 64 KiB line buffer. The adapter MUST compare the
declared profile counts with its configured ceilings before reading inventory
or operation streams, and its configured values MAY only lower the hard
maxima. The payload ceiling includes a fixed conservative charge for every
retained emitted ObjectRef even when an external object sink owns the payload.

The elapsed-time ceiling governs every awaited external boundary, not only
local loops. The verifier, allocator, target-repository lookup, boundary and
content providers, ledger persistence, and staged object sink receive one
shared `AbortSignal`; the adapter races their promises against its deadline and
returns `LIMIT_TIME` on expiry. Those callbacks MUST stop on abort, and durable
persistence or sink commit MUST recheck the signal before publication. Adapter
output is not trusted merely because a callback settles after the adapter has
already rejected it.

These bounds cover the five profile-v2 families and their OGVCS-002
conformance corpora; they do not claim the OGVCS-001 one-million-path reference
scale or every value accepted by the fixture schema. A larger otherwise-valid
fixture fails with the typed limit above. Large-scale tree, manifest, and
logical-bundle processing is exercised through the separate bounded streaming
interfaces, not through this adapter.

## 3. Descriptor and conformance profiles

Profile references keep major version separate from the id. The
adapter descriptor uses:

```text
path profile = {
  namespace: "path.test", id: "opaque", major: 1
}

chunk profile = {
  namespace: "chunking.test", id: "external-boundaries", major: 1
}
```

The profile registry assigns conformance-only fixture families with major `2`:

- content policy: `fixture-content.opengamevcs.test/<inventory-role>@2`;
- group: `fixture-group.opengamevcs.test/<group-kind>@2`;
- member role: `fixture-role.opengamevcs.test/<role>@2`;
- external key: `fixture-key.opengamevcs.test/synthetic-guid@2`; and
- event: `fixture-event.opengamevcs.test/operation@2`.

These entries describe only fixture corpus expectations; they are not
production Unity, Unreal, path, or chunking policies and production writes MUST
reject them.

The adapter does not decide case folding, reserved names, platform safety,
symlink materialization, or any other joined-path rule. It splits already
verified fixture logical paths into NFC basename segments and uses their exact
UTF-8 bytes. A ratified path-profile adapter may perform additional checks in a
separate production context.

## 4. Persistent mapping ledger

The adapter requires a repository-scoped mapping ledger independent of native
history objects:

```text
AdapterLedger {
  schemaVersion: "ogvcs.fixture-adapter/ledger/v1",
  requestDigest: SHA-256,
  repositoryId: RepositoryID,
  directoryIds: source-directory-key -> FileID,
  groupIds: fixture-group-id -> GroupID,
  fileIds: fixture-FileID -> target FileID,
  revisionSnapshots: fixture-revision -> Snapshot ObjectRef,
  importMappings: (requestDigest, fixture-FileID) -> target FileID
}
```

Those camel-case names are the exact public JSON field names. All five mapping
objects are present even when empty. `revisionSnapshots` remains empty unless
the input supplies real snapshot bindings; the baseline adapter never invents
history. Each `importMappings` value must equal the corresponding `fileIds`
value and is persisted before object construction.

On first mapping, directory and group IDs are allocated as nonzero random
128-bit values and persisted before use. They are never computed from mutable
path text. A retry reads the ledger. Normative cross-language vectors provide a
prepopulated ledger so bytes are reproducible; this does not redefine native
allocation.

Fixture file IDs MAY be retained as target IDs only through explicit import
mapping records scoped by `(fixture request digest, fixture FileID)`. If the
target registry already consumed an ID under another mapping, adaptation fails
with `FILEID_IMPORT_MAPPING_CONFLICT`; it does not silently allocate a different
identity. An implementation MAY instead prepopulate a ledger with distinct
target IDs, but retries must use the same mapping.

The public adapter therefore requires a repository-scoped consumed-ID lookup for
every retained or newly allocated directory/FileID mapping. Its query binds the
candidate FileID and exact directory/import owner key; it returns available only
when the ID is unused or already belongs to that exact mapping. A lookup failure,
different owner, or consumed ID aborts before ledger persistence with
`FILEID_IMPORT_MAPPING_CONFLICT`.

Those mapping records use the conformance-only importer profile
`importer.test/fixture-adapter@1`; it describes this public adapter identity,
not a production import service. Its two exact source-digest preimages and retry
tuple are defined in [`conformance-profiles.md`](conformance-profiles.md).

A directory source key is `(fixture request digest, exact ordered path
segments)`. It is a lookup key only; the stored FileID was independently
allocated. Directory rename in a hand-authored history vector moves the ledger
identity rather than allocating by its new text.

## 5. Inventory and content mapping

Each inventory record becomes a regular or executable entry state:

| Fixture field | Format-v1 field |
|---|---|
| `logicalPath` | exact segmented tree location |
| mapped `fileId` | entry FileID |
| `mode=100644` | entry kind/mode `regular`/`regular` |
| `mode=100755` | entry kind/mode `executable`/`executable` |
| `role` | `fixture-content.opengamevcs.test/<role>@2` content policy |
| selected content bytes | manifest target and logical size |

All intermediate directories are one-directory tree entries using persisted
directory FileIDs. Trees sort immediate basenames by NFC UTF-8 bytes. The
adapter MUST reject a basename duplicate before invoking any production path
profile; it does not invent case-fold collisions.

For `semantic-v2` and `deterministic-binary` content, the adapter streams the
publicly described selected bytes, verifies the fixture digest, applies a
caller-supplied external-boundary ledger, writes raw chunks, and constructs
`ContentManifestV1`. The boundary ledger contains positive lengths whose sum is
the exact content length and whose parts do not exceed 64 MiB. It is input to
the conformance-only profile, not a chunking algorithm.

For `large-version-recipe`, the inventory digest identifies the recipe, not
necessarily a selected file version. The adapter reads and verifies the public
large-file descriptor, selects the explicitly requested version, streams that
version through the public fixture interface, verifies its declared whole-file
digest, and applies supplied external boundaries. Virtual/sparse metadata alone
is insufficient; if bytes cannot be streamed and verified, mapping fails with
`FIXTURE_CONTENT_UNAVAILABLE` rather than fabricating a manifest.

The core 1 TiB manifest ceiling and 64 MiB chunk ceiling still apply. The
adapter does not select or define a content-defined-chunking profile.

## 6. Group mapping

Each declared fixture group maps through the persistent GroupID ledger. Member
paths resolve to mapped FileIDs before a group object is emitted. Members are
then sorted by `(role ProfileRef bytes, FileID)`. The first fixture member is
the conformance profile's primary member; that rule is limited to fixture major
2 and makes no production group-policy claim.

Fixture group kind and member-role mappings are:

| Fixture group kind | Member role source |
|---|---|
| `package-sidecars` | inventory roles `package` and `sidecar` |
| `map-external-actors` | `map` and `external-actor` |
| `asset-meta` | `scene`/`prefab`/`binary-import`/`asset` and `meta` |
| `binary-version-family` | `binary-version` or `mutable-large-file` |
| `site`, `team`, `asset` | each member's inventory role |

Unity `syntheticGuid` becomes an external key using
`fixture-key.opengamevcs.test/synthetic-guid@2`. Its 16 decoded bytes are
the external-key value. The fixture profile declares this scheme unique across
groups.

Group profiles use `fixture-group.opengamevcs.test/<group-kind>@2`. Package and
map families retain their exact `package`/`sidecar` and
`map`/`external-actor` member roles. Asset/meta families use `primary` and
`meta`; binary-version and global-studio families use `member`. Those roles are
under `fixture-role.opengamevcs.test` at major 2. For each fixture group
profile, this stated role set is exhaustive: a member carrying any other role
is `GROUP_REQUIRED_ROLE_MISSING`, even when that other role is registered for a
different fixture group profile. Cardinality is checked only after this
allowed-role check.

An enabled `missing-sidecar` case is encoded as the group/member set actually
present and then must fail the asset-meta profile's required-meta cardinality
with `GROUP_REQUIRED_ROLE_MISSING`. A `duplicate-guid` case is encoded and must
fail with `GROUP_EXTERNAL_KEY_DUPLICATE`. Negative evidence files that are not
group members remain ordinary entries.

## 7. Operation classification and adaptation

The OGVCS-001 operation stream is a workload/state-transition contract, not a
format-v1 change set. Every operation is validated, then classified:

| Fixture kind | Format-v1 treatment |
|---|---|
| `create` | create transition when exact content/entry state is supplied |
| `edit` | modify transition when base/result content states are supplied |
| `copy` | copy transition; fixture result ID is an import-mapped new ID |
| `move` | move transition preserving mapped FileID |
| `rename` | rename transition preserving mapped FileID |
| `delete` | delete transition; lifetime remains consumed |
| `branch` | mutable branch-ref logical record when revision mapping exists |
| `merge` | multi-parent snapshot plan when both parent snapshots and exact result transitions exist |
| `submit` | workload event; successful fixture status does not prove an authoritative finalize |
| `branch-update` | mutable-ref transition plan, not immutable history |
| `lock-acquire`, `lock-conflict`, `lock-loss` | lock-reference/workload records, never snapshot edges |
| `review` | workload event; a shelf revision is not invented |
| `selective-sync`, `ci-materialize` | workload events pinned to mapped snapshots when available |
| `interrupt`, `network-condition` | workload-only events |

Every classified operation produces a fixture-event logical record containing
the scenario digest, sequence, the profile
`fixture-event.opengamevcs.test/operation@2`, the exact registered fixture
operation-kind token, and the SHA-256 digest of the exact canonical public
operation record. The original
fixture artifact remains the interpretable source; the digest is not an
unversioned escape field and is not an immutable repository operation.

A file mutation becomes a change-set operation only if the adapter input binds
the complete format-v1 before/after/source state and all referenced content.
Current OGVCS-001 operations name synthetic revisions but do not carry complete
repository entry objects or content ObjectIDs for their history-only targets.
Therefore the baseline adapter MUST classify those operations and MUST NOT
invent empty bytes, manifests, snapshot IDs, or merge results. A future fixture
schema may add a registered binding artifact; until then, hand-authored native
vectors provide exact change-set history coverage.

The public adapter exposes a fail-closed native-history requirement flag. When
that flag is true for a profile-v2 fixture, verification MUST stop before ledger
persistence with `FIXTURE_NATIVE_BINDING_MISSING`, because profile v2 has no
registered complete native binding artifact. This is an executable protection
against relabelling workload events as immutable history, not a claim that the
baseline adapter can emit snapshots.

## 8. Per-profile obligations

### `code-heavy@2.0.0`

- Map all source/header/script/configuration/documentation records.
- Preserve `100755` as executable kind/mode.
- Classify create/edit/copy/rename/delete transitions.
- Treat branch and merge events as plans unless exact snapshot/result bindings
  are provided.

### `unreal-like@2.0.0`

- Map package, map, source, header, configuration, and sidecar records without
  claiming proprietary file semantics.
- Map `package-sidecars` and `map-external-actors` groups by FileID.
- Preserve rename identity.
- Classify lock acquisition/contention and submit outside immutable history.

### `unity-like@2.0.0`

- Map scene, prefab, binary-import/asset, and meta records.
- Map asset/meta groups and synthetic GUID external keys.
- Preserve move identity.
- Produce the normative validation failures for actual missing-sidecar and
  cross-group duplicate-GUID cases; never repair them.

### `large-binary@2.0.0`

- Stream and verify deterministic binary content and explicitly selected large
  versions; never buffer a complete large file.
- Map binary-version families by FileID.
- Treat content recipes and external boundaries separately.
- Classify create/edit/copy/submit without treating submit as finalize proof.

### `global-studio@2.0.0`

- Validate the initial revision/branch/file/lock state model and all linked
  participants, ACL decisions, retry keys, network profiles, and outcomes.
- Map inventory groups `site`, `team`, and `asset` under fixture-only profiles.
- Populate revision-to-snapshot mappings only when the adapter input supplies
  actual snapshots.
- Classify selective sync, lock lifecycle, submit, branch update, review, CI,
  interruption, and network conditions as logical/workload records.

## 9. Native cases absent from OGVCS-001

The adapter corpus does not replace hand-authored format vectors. OGVCS-002 must
separately provide:

- zero-parent root, exact one-parent commit, and ordered two/eight-parent DAGs;
- second root, duplicate/cyclic/cross-repository/missing/ninth parents;
- symlink entries and a one-million-entry single directory;
- exact complete snapshot change-set replay and resolved merge conflicts;
- explicit restore with ancestral delete proof and invalid restore variants;
- delete/recreate with a fresh ID and prohibited reuse;
- import lost-ack retry, conflicting source mapping, and native/import collision;
- concurrent FileID allocation with one winner and unchanged loser ref;
- cross-repository source proof with independently legal equal raw FileID bytes;
- immutable shelf revision chains and unresolved shelf conflicts;
- wrong-kind/missing graph edges, unsupported features/profiles, and logical
  bundle missing/extra/relabeling cases.

Absence of these cases in a successfully adapted fixture MUST NOT be reported as
native repository-format coverage.
