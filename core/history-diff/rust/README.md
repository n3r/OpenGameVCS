# OGVCS-015 private history/diff kernel rc.1

This unpublished Rust 1.82 crate is a bounded, read-only candidate for two
small OGVCS-015 prerequisites:

- deterministic traversal of the immutable OGVCS-002 Snapshot parent DAG; and
- deterministic metadata diffing of two Snapshot root Trees by stable FileID.

It is deliberately unwired. It has no branch/reference lookup, network route,
server database, workspace or checkpoint adapter, authorization decision,
grant, audit event, mutation, publish, merge, merge-base, conflict resolution,
revert, or content-payload output. The source boundary must already represent a
caller-preauthorized immutable view. That statement is an integration
precondition, not an authorization brand supplied by this crate.

## Canonical input and generation boundary

`ImmutableObjectSource` returns one bounded `Vec<u8>` plus a 32-byte generation
marker. The vector length **and capacity** must not exceed the requested object
cap. Every metadata read is bracketed by source-generation checks and also
checks the marker returned with the object. The source must assign the marker
atomically with each returned object and never reuse it for a different view.
A different marker fails with `GenerationChanged`; it never produces a page or
cursor. Each call also performs a release fence after preparing its records.

Each fetched RepositoryDescriptor, Snapshot, Tree, and referenced
ContentManifest passes the canonical OGVCS-002 Rust authority in this order:

1. typed reference-kind check;
2. exact domain-separated ObjectID recomputation;
3. deterministic-CBOR framing and configured decode limits;
4. known-kind schema validation; and
5. registry/profile semantic validation.

Format v1 does not yet have a production-write-eligible Snapshot identity,
policy, and content-profile set. This private candidate therefore validates an
explicitly **conformance-scoped** immutable view with
`ValidationMode::Conformance`. It must not be wired to a production history
read merely because the pure kernel accepts those conformance objects. The
RepositoryDescriptor path profile must also be one of the ratified OGVCS-004
profiles implemented by `ogvcs-path-contract`. Diff additionally requires each
Tree-entry content policy and each ContentManifest chunk profile to belong to
that descriptor's declared sets.

## Ancestry pages

`history_page` uses iterative ordered-parent DFS and emits one deterministic
post-order record per Snapshot. Parent order is the canonical Snapshot order.
Valid merge-DAG convergence is black-node deduplicated. A duplicate parent in
one Snapshot, self-parent, gray back-edge, descriptor mismatch, non-designated
zero-parent Snapshot, or designated root with parents fails closed. The typed
cycle defense remains meaningful even though a canonical content-addressed
self-cycle would require a SHA-256 fixed point and normally fails identity
first.

An ancestry page proves only its generation-pinned validated prefix. A later
page can still discover missing or corrupt deeper input. Only `complete: true`
means every reachable parent from the requested start was visited and every
leaf was the designated root. No terminal failure returns the records or next
cursor that were accumulated by that call.

## Snapshot diff pages

The first `diff_page` call fully validates both Snapshot objects, both complete
root-Tree projections, and every referenced ContentManifest before releasing
the first diff record or cursor. Each side has its own explicit iterative tree
stack. Within either side, repeated/shared Tree references are rejected rather
than expanded twice; gray references are cycles and black references are
ambiguous shared subtrees. Reusing one ContentManifest at multiple files is
valid and is verified once per operation.

Every joined path passes the ratified OGVCS-004 repository-path and collision
key implementation under the case mode supplied from the caller-preauthorized
repository context; an arbitrary end-user preference is not sufficient. Exact
path, repository key, platform key, and FileID duplicates fail closed. The
kernel retains no
inferred identity: add/delete decisions come from FileID presence, and
`Rename`/`Move` are conservative hints only when the same canonical FileID is
present on both sides. A same-parent spelling change is a rename hint; a parent
change is a move hint.

One retained record may carry independent flags for content-manifest target,
directory-tree metadata target, entry type, mode, content policy, logical
size, and path. A directory/file transition reports both target domains when
their references differ. Every non-directory Tree logical size must equal its
validated ContentManifest logical size. Records are sorted by opaque FileID
bytes. Neither object bytes, file bytes, Snapshot messages, nor identities
appear in output.

This is not complete repository-graph/replay validation. Diff intentionally
does not traverse Snapshot parents, ChangeSets, chunks, asset groups,
provenance, or conflicts. Those remain predecessor or later OGVCS-015 work.

## Cursors and restart

History and diff cursors are canonical private binary values with distinct
domain-separated SHA-256 seals. The sealed body binds its version/operation,
generation, request roots and descriptor, case mode where applicable, every
limit, traversal frontier/colors or diff projection and position, path profile,
and cumulative ledger. Decoding checks the outer byte cap before copying,
checks authenticated counts against remaining bytes and charged-memory limits
before allocation, requires canonical set/order/stack relationships, and then
rechecks current generation. A fresh kernel/source instance can resume the
cursor. Replaying the same cursor against the same immutable view is permitted
and produces the same page; it is not a one-time token. Changing roots,
descriptor, generation, case mode, limits, operation, or retained position is
rejected.

The seal is integrity detection, not a MAC, capability, permission, grant, or
authorization proof. A caller that can construct and hash arbitrary bytes is
still untrusted. Only exact cursor bytes emitted by this private kernel are a
valid integration input; a future public service must use its own opaque
authenticated cursor contract and fresh authorized view.

## Exact work and charge ledger

`WorkLedger` is cumulative across cursors and counts generation/cancellation
checks, source reads/bytes, validated metadata objects, Snapshot/Tree edges,
Tree entries, comparisons, emitted records, cursor bytes encoded/decoded,
cursor records decoded, and semantic work units with checked arithmetic. The
linear live-stack comparisons used by ancestry cycle detection are charged, so
deep traversal cannot hide quadratic comparison work behind a linear counter.

`charged_memory_bytes` and `peak_charged_memory_bytes` are exact values under
this candidate's conservative admission model, not allocator/RSS measurements:

- cursor/frontier/index/record nodes use the documented fixed charge plus exact
  retained string/reference lengths;
- an active source read reserves returned `Vec` capacity, the exact canonical
  input copy retained by OGVCS-002, the complete configured OGVCS-002 decode
  working reservation, and 512 bytes of wrapper state;
- cursor bytes can raise the retained charge to their exact encoded length plus
  512 bytes; and
- page records cloned into the caller's returned `Vec`, source-adapter state,
  allocator metadata, registry static data, and caller-retained cursor copies
  are outside the model. Callers must bound their own retention.

All additions are checked before they become trusted state. Limits cover page
records, history Snapshots, Tree objects and entries per side, diff records,
source reads/bytes, one object, work units, cursor bytes, charged memory, and
OGVCS-002 decode working memory. Exceeding any bound returns a typed `Limit`
outcome and no page.

## Explicit nonclaims and residuals

This rc.1 does not satisfy an OGVCS-015 acceptance criterion. In particular it
does not implement or claim:

- an authorized public branch/history/FileID/path view or hidden-history
  non-disclosure;
- branch CRUD/protection, branch consistency tokens, or OGVCS-006 pagination;
- merge-base policy, textual/binary/semantic merge, driver sandboxing,
  conflicts, or merge submission;
- revert or any workspace/checkpoint/cache operation;
- OGVCS-010 publication, current authorization/policy/lock validation,
  lifecycle fencing, receipts, audit, or outbox state;
- public protocol schemas/routes/cursors, service rollout, scale evidence, or
  OGVCS-015 completion.

The final generation fence narrows the release race but is not an atomic lease:
an integration that requires a view to remain current through transport must
serialize invalidation or hold a source-side lease through delivery. Likewise,
the kernel cannot authenticate the externally supplied repository case mode or
an unkeyed resealed cursor. Traversal selects the first failure in deterministic
parent/path order; it does not claim the whole-closure sibling error-ranking
policy of the OGVCS-002 repository validator. Repeated Tree references are
rejected more strictly than the general immutable-object graph permits in order
to avoid ambiguous path expansion in this bounded candidate.

## Local gates

From the repository root, with Rust 1.82 installed:

```text
cargo +1.82.0 fmt --manifest-path core/history-diff/rust/Cargo.toml -- --check
cargo +1.82.0 test --manifest-path core/history-diff/rust/Cargo.toml --locked --offline
cargo +1.82.0 test --manifest-path core/history-diff/rust/Cargo.toml --locked --offline --release
cargo +1.82.0 clippy --manifest-path core/history-diff/rust/Cargo.toml --locked --offline --all-targets -- -D warnings
sh core/history-diff/rust/scripts/test-packed.sh
node --test tools/history-diff-kernel-policy.test.mjs
node prd/validate-roadmap.mjs
node --test prd/validate-roadmap.test.mjs
```
