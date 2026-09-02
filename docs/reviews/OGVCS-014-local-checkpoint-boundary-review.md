# OGVCS-014 private local-checkpoint metadata boundary review

## Decision

Accept this tranche only as an unpublished, unwired Rust 1.82 local metadata
candidate. It establishes a bounded immutable record, content-derived local
checkpoint ID, create-new/manifest-last publication order, complete-only
list/show/verification, and conservative incomplete recovery. It does not
satisfy an OGVCS-014 acceptance criterion and OGVCS-014 remains **Todo**.

The exact candidate base before this tranche is
`a0c7bfdad33aca6e512069c5324c022cad5f35a8`.

## Identity and input boundary

The record binds one optional local parent, OGVCS-002 repository descriptor
and base snapshot references, a workspace digest, selection-spec digest,
OGVCS-004 path profile/case mode, contiguous operations, message/time, and a
historical lock-receipt snapshot. Operation content carries the existing
OGVCS-002 `FileId`, `ObjectRef(ContentManifest)`, and ordered
`ObjectRef(Chunk)` types. Chunk lengths are limited to the OGVCS-007 2 MiB
maximum and the checked logical sum remains below its per-file ceiling;
repeated chunk identities require one length across the checkpoint, while a
repeated manifest identity requires one exact projection.

The local checkpoint ID is domain-separated SHA-256 over the exact canonical
record bytes. The record does not contain that ID or a completion manifest.
Intent metadata binds both this expected ID and an independent plain record
SHA-256 plus exact byte length, and has its own domain-separated unkeyed
integrity digest. Completion metadata binds all of those values and the intent
digest. These hashes detect changes but do not authenticate the local caller.
All local JSON is struct-ordered, newline-terminated, parsed, re-encoded, and
required to match byte-for-byte; one full-record checkpoint ID is pinned as a
known answer.

This validates a caller-supplied metadata projection. It does not read or
semantically verify a canonical content-manifest payload, read/hash a chunk,
prove cache availability, pin or evict cache content, validate a FileID
allocation/lifetime receipt, or re-encode content. The typed identities retain
their existing OGVCS-002 formats, but neither the caller nor this crate becomes
server/cache authority. The root is not compared with an authenticated
workspace/spec producer.

## Parent and graph boundary

A parent must already have a valid completion manifest. Every child requires
exact repository, base snapshot, workspace, spec, path-profile, and case-mode
equality with every ancestor. Verification is limited to 1,024 nodes and fails
on a missing or incomplete parent, self-parent, cycle, duplicate/mismatched
checkpoint identity, binding drift, or depth overflow. Create and recovery
admission account for the prospective child and reject a 1,024-node parent
chain before a 1,025th entry can be sealed.

The format contains one parent per checkpoint in this first tranche. Broader
DAG editing, rebase/merge, squash, and publish conversion are not implemented.
The abstract graph tests exercise cycle defenses directly; a real
content-derived cycle would additionally require a SHA-256 fixed point.

## Publication and recovery boundary

The namespace is fixed below
`.ogvcs/local-checkpoints-v1/entries/<checkpoint-id>/`. The caller cannot
select a metadata-relative path. Workspace/control/store/entry/artifact types
are revalidated at each mutation boundary. Unix link and permission-bit checks
and Windows reparse checks reject unsafe nodes; Unix directory creation applies
the private mode in `mkdir`, and Unix/Windows artifact handles must report one
hard link before bytes are admitted. Writes use create-new files.

Publication has seven injected durability boundaries:

1. entry directory created, synced, and then its parent synced;
2. intent file synced;
3. entry directory synced after intent;
4. record file synced;
5. entry directory synced after record;
6. completion manifest file synced last; and
7. entry directory synced after completion.

Immediately before the last file is created, the crate performs a second exact
intent+record reread, validates the complete parent chain and immutable
bindings again, and requires the entry namespace to contain exactly the two
expected artifacts. It then syncs both existing files and their directory and
repeats the exact reread before manifest creation. Every injected create stop
preserves the prior complete checkpoint. There is no overwriteable
active/latest pointer.

List and show expose only integrity-checked complete entries. Recovery has a
separate deterministic report. An empty or exact valid intent-only entry is reported incomplete;
an exact valid intent+record can receive a create-new completion manifest;
corrupt, substituted, linked, missing-parent, or extraneous-artifact entries
are reported and not modified. Already-valid complete entries are omitted;
corrupt complete entries and complete children with corrupt ancestry are
reported and never overwritten. Recovery never intentionally opens or changes
an ordinary workspace file. Recovery re-syncs the entries root, exact
recoverable files before sealing, and all exact completed artifacts plus their
directory before omitting a valid entry from the report.

A manifest file visible to the injected simulator after its own `sync_all`
but before the directory `sync_all` can be read as complete in that running
process. The final barrier is established by boundary seven or an idempotent
recovery re-sync; no actual power-loss campaign is claimed.

## Bounds and failure behavior

The candidate caps one store at 10,000 entry directories, one checkpoint at
10,000 operations, 100,000 chunk references, 10,000 historical lock receipts,
16,384 message bytes, 64 MiB combined operation/receipt paths, 64 MiB for one
record, 256 MiB of raw complete record bytes admitted by list, and 1,024 parent
nodes. Each projected chunk is at most 2 MiB, so the lower 100,000-reference
cap makes 209,715,200,000 bytes the effective per-checkpoint content-projection
maximum despite the outer 1 TiB logical ceiling. Every sum uses checked arithmetic. A handle length and bounded read are
checked before parsing, and canonical record semantics are revalidated after
parsing. Serde-derived values and allocator overhead are not separately
memory-accounted, so these raw-byte ceilings are not an exact peak-memory
claim. Store-count admission occurs before a new entry directory is created.

Create never emits a trusted checkpoint before the manifest-last marker.
Errors are typed. Recovery never deletes, renames, truncates, overwrites, or
silently hides an incomplete/corrupt entry in its separate report.

## Test relevance

The Rust tests cover deterministic identity and list/show/verify, all seven
create publication boundaries, prior-checkpoint preservation, recovery with a
sentinel newer workspace file, corrupt record bytes, unknown artifacts,
missing/mismatched/corrupt parents, substituted intent-only metadata,
path/object/message/operation/chunk/receipt/logical and exact/max+1 bounds,
same-identity manifest/chunk projection conflicts, safe arbitrary-name
reporting, abstract self/cycle/missing/duplicate-ID/over-depth graphs, and Unix
symlinked or hard-linked artifact rejection. The packed gate builds exact dependency crates,
extracts the candidate, regenerates its lockfile offline against those
packages, and repeats its tests. The Node policy gate protects the unwired
private boundary, literal limits, direct canonical dependencies, manifest-last
layout, explicit lock warning, Todo lifecycle, and prohibited public/destructive
claims.

This is bounded local source evidence. It is not three-OS hosted proof, actual
power-cut testing, cache pin/eviction concurrency, manifest/chunk byte
verification, restore safety, or acceptance evidence.

## Security and portability residuals

The crate revalidates paths and uses no-follow/reparse checks around each
metadata mutation, but it reopens pathnames. A malicious same-authority
process can race the namespace between those checks, including after the
single-link handle check; a held directory handle, dirfd/handle-relative
mutation model, and process lock remain required. Unix mode/link checks do not
establish complete ACL or owner policy; Windows inherited ACL/owner policy is
not independently verified. Windows reparse, by-handle link-count, and
directory-flush paths need hosted execution. No claim is made for hostile
filesystem or power-loss behavior beyond this bounded source model.

Stored lock-receipt material is a digest-only historical snapshot. The only
reported state is `historical-untrusted-exclusivity-unverified`; it cannot be
used to assert or renew exclusivity. There is no authorization, permission,
grant, request-root, publish, telemetry, or remote diagnostic path.

## Residuals blocking OGVCS-014

- No diff, restore, open-copy, overwrite confirmation, delete, squash,
  retention/grace, mutable message, checkpoint DAG editing, or publish handoff.
- No real shared-cache pin/eviction/availability integration, transfer, corrupt
  cache-byte handling, or selection/workspace-removal race proof.
- No authenticated operation/manifest/cache producer and no canonical
  manifest/chunk-byte verification at this boundary. Ordered operation shapes
  are limited to add/modify/copy/move/delete and omit entry kind, mode, policy,
  group and restore data. They are not replayed against the base tree, so they
  do not prove transition semantics.
- No public native CLI/JSON contract, GUI, route, authorization, lock
  validation, telemetry consent/upload, or production rollout.
- No three-OS hosted crash/corruption matrix, real screen/support journey,
  actual power-cut campaign, scale result, restore obstruction matrix, or
  acceptance-criterion proof.

## Verdict

Ship/no-ship for this exact tranche: **ship only as a private unwired candidate
after all local source, package, policy, and roadmap gates pass; no-ship for a
public command, restore, cache-pin, publish, lock, authorization, rollout, or
OGVCS-014 completion claim.**
