# OGVCS-006 — Repository metadata and snapshot service

**Status:** In development

**Candidate contract:** `@opengamevcs/repository-metadata-contract-v1` 0.3.0

**Date:** 2026-09-01

## 2026-09-05 authorized zero-page contract

- Retained the authenticated 0-through-10,000 `pageSize` range for all seven
  public page request bodies and documented the privacy-safe zero-page
  algorithm. The repository dispatcher scans privately only to the first
  authorized sentinel or bounded exhaustion and returns no items. A sentinel
  produces `more` plus a fresh cursor bound to the same decoded `after`
  position, or the internal empty-byte start sentinel when no cursor was
  supplied; exhaustion produces `complete` with no cursor. A later positive
  page can return the sentinel, so the zero page skips nothing and reveals no
  denial status.
- Reserved a separate `PostgresMetadataPageDispatcher` for exactly the six
  repository-scoped page operations: `tree.page`, `reference.list`, the three
  history page variants, and `file-id.history`. Project-scoped
  `repository.list` remains excluded and network-closed.
- This contract/source-policy tranche does not implement the dispatcher or
  claim live/hosted page evidence. The semantic query digest remains supplied
  by the metadata owner and is not independently reconstructed by the
  authorization primitive. OGVCS-006 stays in `prd/todo`; all six acceptance
  criteria remain open.

## Hosted v13 aggregate mapping evidence

- Exact integrated source `aa13161cca228d5f92154928508f9f866225d9f5`
  passed GitHub Actions run
  [33506824950](https://github.com/n3r/OpenGameVCS/actions/runs/33506824950).
  Locked Node 24/Rust 1.82 checks passed on Windows, macOS, and Ubuntu;
  PostgreSQL 15 additionally passed the full bounded v13 aggregate mapping,
  content-manifest availability, and thirteen-boundary hard-restart matrices.
- The v13 bridge now requires the immutable exact identity-to-lifecycle item
  relation described below. This is hosted private-participant evidence, not a
  production mapping writer, public route, request-root proof, or exact-scale
  result. OGVCS-006 remains **In development**.

## Hosted boundary evidence and portable protocol time

- Retained successful Node 24/Rust 1.82 hosted conformance for source
  `e3c325c7f2b69a8ffb57a4723b814f2286569ba5` as GitHub Actions run
  [33454673693](https://github.com/n3r/OpenGameVCS/actions/runs/33454673693).
  The locked default and feature-gated tests passed on Windows and macOS;
  Ubuntu additionally passed formatting, both Clippy profiles, identity-bound
  regressions, and the bounded live PostgreSQL 15 report.
- Kept self-dating idempotency timestamps as validated Unix-millisecond
  integers until the server-clock future/expiry decision is complete. This
  preserves the exact protocol maximum on hosts whose `SystemTime` cannot
  represent that far-future instant, without weakening reservation-window
  enforcement. Response tests likewise avoid constructing an unrepresentable
  platform clock while the parser still proves the exact wire maximum.
- That earlier hosted packet remains bounded: it does not claim the production
  dispatcher, aggregate lifecycle bridge, or million-entry campaign.

## Local OGVCS-041 envelope tranche

- Added the authenticated OGVCS-041 request/response envelopes, distinct
  artifact and negotiation registry identities, and exact static protocol
  assignments for all 22 metadata operations. The production `networkRoutes`
  inventory remains empty: every assigned method/path tuple closes as
  `PROTOCOL_UNSUPPORTED` before body parsing, and no syntax-only request can
  reach persistence.
- Added MAC-first negotiation-receipt verification, exact JCS receipt and
  semantic-idempotency commitments, bounded correlation handling, and typed
  protocol failure envelopes. Negotiation alone cannot construct a success
  response or confer OGVCS-009 authorization.
- Regenerated the metadata, identity-policy, and untrusted-sandbox authority
  chain and passed local Node 24, Rust 1.82, PostgreSQL 16, static, package,
  and predecessor checks. This `0.3.0` tranche does not yet have a retained
  hosted run; the hosted run above authenticates only the earlier `0.2.0`
  source revision.
- Per-array, member, key, and string limits are enforced during decoding. The
  shared depth, node, and aggregate counters remain a post-decode check and are
  an explicit pre-network residual while the route inventory is empty.

## Public service-contract boundary tranche

- Added a framework-neutral Rust adapter for all 22 authenticated candidate
  operation assignments. It binds stable operation codes, classes,
  permissions, resource types, idempotency policy, payload carriers, and the
  exact candidate manifest SHA-256 without assigning an HTTP route, status, or
  media type.
- Added closed, duplicate-rejecting request validation with bounded JSON depth,
  nodes, collections, members, strings, keys, and one-MiB control messages.
  Operation validation covers UUIDs, canonical object references and FileIDs,
  profile families, sorted feature sets, NFC/path byte limits, digests, history
  work, metadata stream size, lease limits, and every exact body member set.
  Object streams admit only the nine persistence-owned metadata kinds, and
  canonical path checks reject both separators, C0/DEL, and `.ogvcs` while
  preserving allowed C1 scalars. Persistence-bound owner/consumer identifiers
  carry the existing 256 UTF-8-byte/NUL receiver constraint; reference names
  similarly retain their existing 512-byte/NUL persistence boundary.
- Added the public page-size boundary of 10,000, distinct canonical `cur1`
  48-byte and `ct1` 47-byte forms, minimum-consistency-token capture, and
  response constructors that carry a supplied opaque consistency token.
  Binding that token to the exact authorized read remains dispatcher work.
  Internal PostgreSQL page primitives keep their existing stricter 1,000-row
  working bound.
- Added OGVCS-041 semantic idempotency projection and exact JCS-compatible
  fingerprint evidence. The key and transport member ordering are excluded;
  operation and normalized body remain bound, including convergence of JSON
  Schema-equivalent integer lexemes (`1`, `1.0`, and `1e0`). Conversion to the
  persistence reservation requires an explicit server clock and validates the
  canonical self-dating key window before any mutation.
- Added schema-shaped success/page/history/stream/allocation/idempotency/error
  carriers with bounded streaming serialization before page-item
  materialization. The generic error constructor emits bounded retry timing
  only for its two assigned errors and suppresses all unrelated
  caller-populated facts.
  Reference-conflict generation stays hidden until a future constructor can
  require the exact transaction-bound visibility proof.

## Production safety boundary

This tranche does not add a public route or a storage dispatcher. Syntax
validation is not authorization. Repository creation (which includes root
publication), reference CAS, FileID tombstone, and FileID restore remain
coordinator-required; outbox lease operations remain internal-only. Both the
adapter guard and production identity transaction entry reject them, and no
generic publish operation is present. They must remain closed until the
authenticated aggregate coordinator can consume and revalidate its key-ring
receipt in the same PostgreSQL transaction.

## Deliberate remaining work

OGVCS-006 remains in development. A future protocol release must assign routes,
statuses, media types, stream framing, and deployment policy. The 22 operations
still need a production dispatcher that derives exact OGVCS-009 resources,
revalidates profile lifecycle for production writes, composes object streaming,
and maps the already implemented PostgreSQL methods without weakening the
coordinator gate. That dispatcher must also add a visibility-proof-bound path
for the optional `currentGeneration` conflict parameter; the generic error
constructor deliberately cannot disclose it. It must likewise issue each page
consistency token from the same authorized transaction/view rather than trust a
shape-only opaque token supplied to the response codec. Hosted
SLO/backup/restore/metrics evidence and the explicit million-entry acceptance
campaign remain outstanding; ordinary presubmit does not claim exact-scale
evidence.
