# Private local-checkpoint metadata candidate

This unpublished Rust 1.82 crate is a bounded OGVCS-014 implementation
candidate. It provides local checkpoint creation, complete-only
listing, show, metadata verification, incomplete-creation recovery, and a
bounded read-only selected-record application preview. It is not wired into
the native CLI, a server route, or any public protocol.

## Boundary

The caller supplies an already formed local projection. The crate records:

- one optional complete local parent;
- an OGVCS-002 repository-descriptor reference and base-snapshot reference;
- fixed workspace and selection-spec SHA-256 bindings;
- the OGVCS-004 path profile and case mode;
- a contiguous ordered `add`/`modify`/`copy`/`move`/`delete` sequence with
  OGVCS-002 `FileId` values;
- typed OGVCS-002 content-manifest and ordered chunk references, whole-file
  digest, and checked logical-length ledger under the OGVCS-007 1 TiB
  per-file ceiling;
- bounded message and millisecond timestamp fields; and
- a lock-receipt snapshot whose only state is
  `historical-untrusted-exclusivity-unverified`.

The manifest/chunk projection is validated for typed identity, chunk lengths
in `1..=2 MiB`, checked sum, order, count, and logical ceiling. Repeated chunk
identities must retain one length across the whole checkpoint, and repeated
manifest identities must retain one exact projection. This crate does not
read a manifest payload or chunk byte, prove that the supplied identities
describe available cache content, pin cache content, re-encode content, or
grant cache/server authority. `FileId` allocation or lifetime authority is
also not established here.

Every parent must already be complete. Its repository, base snapshot,
workspace, spec, path profile, and case mode must exactly equal the child
bindings. Complete-chain verification is bounded to 1,024 nodes and rejects a
missing parent, self-parent, cycle, duplicate/mismatched checkpoint identity,
binding drift, or over-depth chain. Creation and recovery refuse to seal a
child when its already-complete parent chain has 1,024 nodes, so the child can
never become an admitted 1,025th node.

## Read-only selected-record application preview

`preview_checkpoint_application` loads the selected record only through the
complete-manifest and complete-parent-chain verifier. The caller must repeat
the exact repository, base snapshot, workspace, selection-spec, path-profile,
and case-mode bindings. The function then folds the selected record's ordered
operations into its final touched-path effects: add/modify/copy affect the
destination, move affects its source and destination, and delete affects its
source. Repeated touches retain their first/last ordinals and count while the
last recorded effect wins. Repository and platform collision keys are
re-derived, retained in each result, and aliases fail closed.

This is intentionally narrower than checkpoint diff or restore. Ancestors are
verified for completeness and binding continuity, but their operations and the
base snapshot tree are not replayed. The preview therefore says only what the
selected record says about the paths it touches. It cannot discover an
untouched newer path, reconstruct a target tree, prove operation semantics, or
declare a workspace restorable.

The caller supplies an exact observation for every final affected path:
absent, regular file with FileID/whole-file digest/logical length, directory,
symlink/reparse, inaccessible, or unknown. It also supplies one exact content
fact for every final content-bearing ordinal, binding that ordinal, FileID,
manifest, whole-file digest, logical length, and ordered chunk projection.
Content availability is reported only as `AvailableUnverified` or
`Unavailable`. The former means the caller reported availability; this crate
does not read, hash, authenticate, or pin a workspace/cache byte. Missing,
extra, duplicate, colliding, or substituted facts fail closed.

`PreviewReplacementIntent::PreserveCurrentWorkspace` is the default. A
different known regular file is `ReplacementProtected` and a known regular
file that the record would remove is `RemovalProtected`. The explicit
`ReplaceRecordedPaths` value changes those two classifications to replacement
or removal *intended*; it is not authorization or permission and performs no
operation. It never bypasses directory, symlink/reparse, inaccessible, unknown,
path-collision, or `Unavailable` content blockers. The preview method contains
no ordinary-workspace/cache open and no create, write, rename, remove, or
truncate path.

The result has a domain-separated SHA-256 that binds the exact checkpoint ID
and record digest, complete-chain depth, immutable bindings, selected-record
operation count, replacement intent, sorted repository/platform collision
keys, exact supplied workspace/content observations, folded result items, and
the fixed `historical-untrusted-exclusivity-unverified` warning. Input order
does not change the digest. It is a deterministic local comparison token, not
authentication, authorization, lock authority, or a durable restore receipt.
Historical lock receipts are not consulted and the result explicitly reports
that fact.

## Immutable record and identity

The record is deterministic struct-ordered JSON with one final newline.
Readers parse and re-encode it and require exact byte equality, so alternate
JSON spellings are not admitted. The local checkpoint ID is:

```text
SHA-256(
  ASCII("OpenGameVCS local checkpoint record\0") ||
  uint16be(1) ||
  exact canonical record bytes
)
```

The record excludes its checkpoint ID and the final completion manifest. The
ID is a private local-checkpoint identifier, not an OGVCS-002 `ObjectRef` and
not a server snapshot. Canonical repository object, manifest, chunk, and
`FileId` identities retain the existing OGVCS-002 durable text forms; the
crate does not invent substitutes for them.

The create intent binds the expected checkpoint ID, plain record SHA-256, and
exact record byte length. A separate domain-separated, unkeyed intent digest
detects changes to that binding; it is integrity framing, not caller
authentication. Recovery will not create a completion manifest unless a
second immediate reread proves the exact intent-to-record ID, digest, length,
canonical encoding, semantic bounds, parent, and immutable bindings.

## Fixed namespace and publication order

The caller selects only the workspace root. Metadata always stays below the
already established private control directory:

```text
<workspace>/.ogvcs/local-checkpoints-v1/entries/
  <64-lowercase-hex-checkpoint-id>/
    intent-v1.json
    record-v1.json
    complete-v1.json
```

Workspace root, control, store, entry, and artifact types are checked without
following a symbolic link. Windows reparse points are rejected. Unix private
metadata directories/files must have no group/other permission bits, and Unix
directories are created with a private mode in the atomic `mkdir` operation.
Regular artifact handles must have exactly one hard link, using Unix metadata
or Windows by-handle information before bytes are admitted. The fixed parent
relationship is revalidated before every metadata mutation. Files use
create-new publication. No checkpoint operation intentionally opens, deletes,
renames, truncates, or writes an ordinary workspace path.

The exact publication sequence is:

1. create the content-derived entry directory, set private permissions,
   revalidate and sync it, then sync `entries/`;
2. create and sync `intent-v1.json`, then revalidate and sync the entry
   directory;
3. create and sync `record-v1.json`, then revalidate and sync the entry
   directory;
4. reread and revalidate the exact intent and record, complete parent chain,
   immutable bindings, and exact two-artifact namespace; sync both existing
   files and the entry directory, then repeat the exact reread;
5. create and sync `complete-v1.json` last, then revalidate and sync the entry
   directory.

`PublicationBoundary` can stop after each of those seven file/directory
durability points. The fault matrix proves that a prior complete checkpoint
remains readable at every point. A manifest visible after its file sync but
before the directory sync is treated as complete by the deterministic
in-process simulator; real power-loss durability is established only after
the final directory sync.

There is no mutable “latest checkpoint” pointer or overwriteable catalog.
Complete-only list/show discover immutable entry directories. An incomplete
entry cannot replace or shadow a previous complete checkpoint.

## Recovery

`recover_incomplete` scans at most 10,000 names in bytewise name order and
returns a separate recovery report:

- empty entry (after its parent sync) or exact intent only:
  `IncompleteReported`;
- exact, valid intent plus record and complete parent chain: a create-new
  completion manifest is published and `RecoveredComplete` is returned;
- unknown names, a record without its intent, extraneous artifacts, link/reparse objects,
  corruption, substitution, invalid graph/bindings, or malformed metadata:
  `CorruptReported` with a typed reason;
- an already valid complete entry is omitted from the recovery report; a
  corrupt complete entry is reported and never overwritten.

Recovery never deletes or quarantines metadata, never overwrites an artifact,
and never intentionally addresses an ordinary workspace path. It rejects every
unknown or extraneous entry artifact before sealing. At recovery start it
re-syncs the entries directory; before sealing it syncs the exact intent and
record, and before omitting an already-valid complete entry it re-syncs all
three exact artifacts and their directory. These idempotent barriers reconcile
files that survived a failed sync or a crash before directory persistence.

## Bounds

| Resource | Candidate maximum |
|---|---:|
| Checkpoint entry directories | 10,000 |
| Ordered operations per checkpoint | 10,000 |
| Ordered chunk references per checkpoint | 100,000 |
| Historical lock receipts | 10,000 |
| Message bytes | 16,384 |
| Aggregate operation/receipt path bytes | 64 MiB |
| One canonical record | 64 MiB |
| Raw complete-record bytes admitted by one list | 256 MiB |
| Verified parent-chain depth | 1,024 |
| Preview final/current paths | 20,000 |
| Preview final content facts | 10,000 |
| Preview operation/current-fact path bytes | 8 MiB |
| Preview verified-chain raw record bytes | 256 MiB |
| Preview verified-chain operations | 100,000 |
| Preview work-unit ledger | 600,000 |
| Preview retained-allocation ledger | 64 MiB |
| One projected chunk length | 2 MiB |
| Logical bytes per content projection | min(1 TiB, 100,000 × 2 MiB) = 209,715,200,000 bytes |

Creation checks the current entry count and refuses before entry creation when
the store already contains 10,000 names. All count, byte, and logical
arithmetic is checked. Operation ordinals must be contiguous. Add/copy FileIDs
cannot repeat within one checkpoint candidate;
broader repository-lifetime allocation proof remains outside this local
metadata boundary. Repeated ordered chunk identities are valid only with one
consistent length, matching the OGVCS-002/007 manifest contract. These shape
and identity checks do not replay the operations against a base tree or prove
that their transitions are semantically valid.

The record and store byte ceilings are raw canonical-input ledgers. File
length is checked before reading past a ceiling, but serde-derived values and
allocator overhead are not separately memory-accounted. That bounded-input
model is not an exact peak-memory claim.

Preview rejects aggregate chain bytes/operations and supplied count, path-byte,
chunk-reference, work, and retained-allocation ledgers before allocating its
maps or result vector. Cancellation is checked before record loading, at each
bounded parent/operation/fact pass, and immediately before retained projection.
The retained ledger conservatively charges fixed map/item overhead plus exact
re-derived repository-key, platform-key, and canonical-path lengths at their
maximum simultaneous copy counts. Per-record JSON decoding is still governed
by the existing 64 MiB raw-record ceiling and is not an exact allocator peak.

## Residuals and nonclaims

This candidate intentionally has no:

- full checkpoint/base-tree diff, restore, workspace overwrite, open-copy,
  delete, squash, retention, grace-period, or mutable message operation; the
  selected-record application preview is inspection only;
- cache pin, eviction, availability, cache-read verification, transfer, or
  refetch implementation;
- public CLI/JSON schema, route, auth/permission/grant check, publish handoff,
  or server interaction;
- lock acquisition/renewal/validation authority—the stored receipt digest is
  historical and untrusted, and exclusivity is always unverified;
- telemetry upload or remote diagnostics;
- hosted Windows/macOS/Linux portability result, exact-scale campaign, cache
  race proof, restore proof, or OGVCS-014 acceptance-criterion claim.

Path checks and create-new writes narrow link and replacement attacks, but
paths are reopened between checks. A malicious same-authority process can race
the metadata namespace, including by replacing a checked path after a handle
check; held-handle/dirfd-relative mutation and a process lock remain future
hardening. The Windows reparse, by-handle hard-link, and directory-flush paths
are source-covered but need hosted execution. Unix mode and link-count checks
do not establish a complete ACL/ownership policy; Windows inherited ACL and
owner policy are not independently verified. The supplied workspace/spec
digests and repository/base references are not compared with an authenticated
workspace metadata producer. Operation records omit entry kind, mode, policy,
group transitions, restore semantics, and base-tree replay. These limits keep
the crate private and unwired.

## Local gates

From the repository root with the cached Rust 1.82 toolchain:

```sh
cargo +1.82.0 fmt --manifest-path client/local-checkpoint/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path client/local-checkpoint/rust/Cargo.toml --locked --offline
cargo +1.82.0 clippy --manifest-path client/local-checkpoint/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
sh client/local-checkpoint/rust/scripts/test-packed.sh
node --test tools/local-checkpoint-policy.test.mjs
npm run test:roadmap
```
