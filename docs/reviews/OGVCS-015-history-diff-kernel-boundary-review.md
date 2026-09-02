# OGVCS-015 private history/diff kernel boundary review

- **Review date:** 2026-09-02
- **Source boundary:** uncommitted candidate based exactly on
  `3e11ac826563e7f9ec8e8cac3164f711e98b3148`
- **State:** independent adversarial review complete; **SHIP** for this bounded,
  private, unwired candidate only
- **PRD verdict:** OGVCS-015 remains Todo; no acceptance criterion is closed

## Authority and scope

This bounded tranche reads OGVCS-015 together with the OGVCS-002, OGVCS-006,
OGVCS-010, and OGVCS-014 PRDs, the settled OGVCS-002 critical review, and the
OGVCS-010 contract-boundary review. It reuses the exact OGVCS-002 Rust object
authority and the ratified OGVCS-004 Rust path/collision authority. It creates
no language-neutral schema or public protocol assignment.

The candidate owns only pure read-side computation over a caller-supplied,
generation-pinned immutable view:

- ordered Snapshot-parent ancestry pages with designated-root validation; and
- two-Snapshot root-Tree flattening plus deterministic FileID diff pages.

It does not own branch visibility, authorization, hidden-history redaction,
mutable references, FileID lifetime storage, submit publication, local
checkpoints, or any merge/revert/write behavior.

## Invariants implemented

1. **Generation:** every object read is bracketed by current-generation checks
   and carries the same non-reused, atomically assigned marker. Fresh and
   resumed calls perform a final generation fence before releasing a page.
2. **Canonical object authority:** ObjectID, deterministic CBOR, known schema,
   semantic profiles, typed reference kind, RepositoryDescriptor binding, and
   configured limits run through OGVCS-002. The present profile gap makes this
   explicitly conformance-scoped, never a production-read claim.
3. **Ancestry:** ordered-parent DFS is iterative and bounded. Valid merge-DAG
   convergence deduplicates; duplicate parents, self/back cycles, designated
   root with parents, and any other zero-parent leaf reject.
4. **Tree flattening:** both sides complete before output. Each side rejects
   gray cycles, black/shared Tree references, duplicate FileIDs, exact paths,
   repository collision keys, and platform collision keys. Referenced
   ContentManifests are canonical-validated; Tree logical sizes must match,
   and entry content policies plus manifest chunk profiles must belong to the
   descriptor. Chunks and file payloads are never fetched.
5. **Classification:** FileID presence alone decides add/delete/retained.
   Content-manifest, Tree-metadata, type, mode, policy, size, and path changes
   are independent flags; a directory/file transition can carry both target
   flags. Rename/move is only a same-FileID hint.
6. **Failure atomicity:** missing, ambiguous, corrupt, source failure, limit,
   generation change, cancellation, cursor corruption, and option mismatch
   return no page or next cursor from that call.
7. **Cursor integrity:** distinct canonical sealed bodies bind operation,
   generation, full request/view, options/limits, traversal or diff state,
   position, and counters. Exact decoded-state and byte preflight occurs before
   retained frame/record allocation. Replay is deterministic, while root,
   descriptor, generation, operation, case-mode, and limit substitution fails.
   The unkeyed seal is not authority.
8. **Resources:** all counters use checked arithmetic. Source length/capacity,
   source bytes/reads, object/decode reservations, persistent indexes, cursor
   bytes, records, Tree/Snapshot counts, and semantic work are explicitly
   bounded. Ancestry live-stack comparisons are individually charged. Returned
   page clones and caller/source state are documented exclusions rather than
   silently claimed measurements.

## Independent findings resolved

The adversarial review identified and fixed nine candidate-local defect
classes before the freeze gates:

1. Tree entries did not prove logical-size equality with their manifests.
2. Descriptor content-policy and chunk-profile membership was not enforced.
3. Directory/file transitions could omit one of the two changed target domains.
4. Calls lacked a final generation fence immediately before page release.
5. Diff classification retained an uncharged temporary FileID union.
6. Cursor decode could allocate authenticated state before exact retained-charge
   and cumulative-work/overflow preflight, and cursor finalization encoded a
   provisional copy.
7. Semantic Tree/history limits were incorrectly reused as generic CBOR
   container limits, rejecting valid one-node configurations.
8. History gray-stack scans consumed potentially quadratic comparison work
   without charging those comparisons to the cumulative work limit.
9. OGVCS-002's configured decode-working-memory exhaustion was mislabeled as
   object corruption instead of the kernel's typed charged-memory limit.

## Ordinary verification inventory

The candidate includes 43 unit/integration tests spanning independent JSON
golden, table/adversarial,
deterministic generated-property, pagination, fresh-instance restart, cursor
mutation, source corruption, generation race, cancellation, duplicate identity
and collision, shared-subtree, missing/ambiguous, and configured-bound tests.
The canonical cycle defense has a typed self-parent test because a finite
canonical ObjectID cycle otherwise requires a SHA-256 fixed point and normally
selects identity mismatch first.

## Frozen verification results

- Rust 1.82 format and warnings-denied Clippy: clean.
- Rust 1.82 locked/offline tests: 43/43 debug and 43/43 release.
- Packed fresh-consumer extraction: 16 packaged crate files and 43/43 tests.
- Node v24.9.0 private-boundary policy: 2/2.
- Roadmap validator: 46 PRDs (39 Todo, 7 Done), 898 IDs; validator tests 8/8.
- Focused predecessor checks: OGVCS-002 conformance 17/17 and repository 27/27;
  OGVCS-004 Rust contract vectors 3/3 and generated-source sync clean.
- `git diff --check`: clean. The candidate remains uncommitted on exact base
  `3e11ac826563e7f9ec8e8cac3164f711e98b3148`.

## Residuals and blockers

- OGVCS-006 still owns public authorized history/tree pagination and a
  consistency-token-backed service view. No route is registered here.
- OGVCS-003/009 must supply current authorization and mixed-visibility history
  non-disclosure. A caller-preauthorized source is not a substitute.
- Format v1 lacks the production Snapshot identity/policy/content profile set;
  therefore this candidate remains conformance-scoped and unwired.
- Diff does not prove complete Snapshot graph/replay, ChangeSet, group,
  conflict, provenance, manifest chunk closure, lifecycle health, or content
  availability.
- An ancestry page is a validated prefix; only its final complete page proves
  the requested parent traversal reached the designated root on every leaf.
- The final generation check is not a source-side lease. A transport requiring
  atomic currentness through delivery must serialize invalidation or hold such
  a lease, and generation identifiers must never be reused for another view.
- The kernel receives case mode from its preauthorized repository context but
  cannot authenticate that external fact. Its unkeyed private cursor seal also
  cannot stop a caller from constructing and resealing arbitrary state; a
  public adapter must authenticate an opaque cursor and bind fresh authority.
- Failure selection is deterministic traversal-first, not the OGVCS-002 full
  closure's ranked sibling-error policy. Shared Tree references are rejected
  more strictly here to avoid ambiguous expansion under multiple joined paths.
- Merge-base selection, path/FileID history search, copy inference, sidecar
  semantics, binary/semantic/external-driver merge, durable conflicts, merge
  submit, revert, checkpoint publication, protocol cursor authentication,
  scale, and rollout remain unimplemented. A later private built-in text-only
  candidate is reviewed separately in
  [OGVCS-015-private-text-merge-kernel-review.md](OGVCS-015-private-text-merge-kernel-review.md);
  it does not change this read-side review's authority or acceptance verdict.

Consequently OGVCS-015-AC-01 through AC-05 all remain open.
