# OGVCS-002 — Core object library and open repository format

**Validation candidate:** 2026-08-20

**Release:** R0 — Engineering Foundation

**Packages:** `@opengamevcs/repository-format-v1` 0.1.0,
`@opengamevcs/object-model` 0.1.0, and `ogvcs-object-model` 0.1.0

## Delivered candidate

OpenGameVCS now has a language-neutral repository-format-v1 authority and two
independently implemented object-model libraries. The format defines canonical
bytes and identities without depending on a database layout, hosted service,
private schema, or either implementation. JavaScript and Rust expose the same
typed object references, deterministic metadata codec, repository validation,
tree and manifest streaming, logical-bundle verification, registry lifecycle,
and bounded failure model.

The candidate authority contains 2,815 authenticated artifacts, 573 scenario
envelopes, 486 traceable obligations, 81 stable error codes, and ten ordered
validation stages. It independently audits 58,520 systematic bit mutations and
7,303 proper-prefix truncations. Every executable rejection is compared as the
complete `(code, layer, stage)` result rather than by message text or a
precomputed expected-value shortcut.

## Canonical bytes, identity, and durable references

- Format v1 uses a strict deterministic-CBOR subset: definite containers,
  shortest integers and lengths, NFC scalar UTF-8 text, ordered unsigned schema
  keys, and no floats, tags, bignums, null-like values, duplicate keys,
  nonminimal encodings, invalid Unicode, or trailing bytes.
- Immutable ObjectIDs use the registered object kind and domain-separated
  SHA-256 preimage. Raw chunks and canonical metadata therefore have one
  reproducible identity rule across both languages.
- Binary and durable-text ObjectRefs bind format version, object kind, hash
  algorithm, and full digest. Parser shape/length faults, unsupported versions,
  wrong kinds, and declared-identity mismatches have frozen error precedence.
- Metadata decoding and encoding are bounded independently from semantic
  registry interpretation, so unsupported features may be scanned, hashed, and
  preserved without being treated as understood.

## Repository graph and FileID semantics

- Canonical objects cover chunks, content manifests, one-directory trees,
  change sets, asset groups, repository descriptors, snapshots, shelves,
  provenance, attestations, and conflict sets.
- Snapshot validation enforces one repository root, zero-to-eight ordered unique
  parents, parent-zero replay, complete declared closure, and cycle-safe graph
  behavior. Route-specific validators follow exactly the closure they promise;
  full candidate validation additionally authenticates every supplied object.
- Change replay verifies create, modify, copy, move, rename, delete, restore,
  group transitions, and merge resolution against exact before/after state.
- FileIDs are opaque nonzero 16-byte repository-scoped values. Native allocation
  uses operating-system entropy, bounded collision retries, and no path, time,
  counter, or deterministic fallback. Move and rename preserve identity; copy
  and create allocate; delete/recreate reuse and forged or cross-repository
  proofs fail closed.
- Lifetime and import validation authenticates prior mappings, repository
  binding, derived mapping keys, importer profile family/lifecycle, lost-ack
  retry, working additions, and unchanged caller state on rejection.
- Conflict, group, shelf, provenance, and candidate validators perform complete
  lower-layer reference discovery before registry or repository semantics. They
  rank combined-invalid inputs by the normative catalogue rather than traversal
  or insertion order.

## Streaming manifests, trees, and logical bundles

- `ContentManifestV1` verifies positive chunk lengths, checked logical sums,
  whole-file identity, profile authority, and ordered source bytes. Metadata is
  preflighted across the complete repeatable source before content callbacks;
  independent chunk failures are collected so later identity corruption cannot
  be hidden by an earlier semantic mismatch.
- Tree readers and ordered/sorted writers validate complete bounded entry sets,
  canonical basename order, kinds, modes, FileIDs, descriptor binding, path
  profiles, and content policy. FileID indexes are transactional, bounded as
  part of one aggregate working set, and reusable after an aborted attempt.
- Deep tree discovery uses explicit bounded work stacks. Caller-provided path
  validators and index adapters cannot run before closure and registry phases
  have succeeded.
- The logical-bundle sequence deterministically orders immutable objects,
  logical records, and roots; authenticates transcript/accounting/trailer data;
  validates supplied closure; and never claims repository completeness,
  authorization, projection, fidelity, generation, restoration, or import.
- Streaming bundle scanners charge cumulative active and retained canonical-map
  key captures, including transient replacement allocations. Nested keys can no
  longer amplify memory beyond the caller's configured ceiling.
- Stateful and convenience writers collect safely discoverable sequence,
  identity, schema, and lifecycle faults across each bounded section before
  selecting the frozen winner. Any rejected staging attempt is terminal and
  cannot later be committed as success.

## Registries and compatibility

- Twelve packaged registries freeze object kinds, fields, features, extensions,
  entry kinds, portable modes, hash algorithms, logical records, and profile
  assignments. The language-neutral registry-set digest is
  `6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6`.
- Loaders authenticate the complete same-handle byte set, exact additive
  schemas, immutable assignments, limits, family ownership, and lifecycle.
- Reserved entries cannot appear; conformance-only entries remain test-only;
  ratified entries are readable and writable; deprecated entries remain
  readable but cannot be selected for new production writes; removed IDs stay
  reserved.
- Unknown required features block semantics while canonical bytes remain
  preservable. Unknown optional extensions do not change base semantics and are
  retained by lossless paths.
- Registry and Unicode authority sync checks run for both distributed language
  packages and in the three-platform object-model workflow.

## Public tooling and package boundary

- The JavaScript package ships the `ogvcs-object` inspector/verifier CLI and the
  public OGVCS-001 fixture adapter. The adapter consumes all five packaged
  profile-v2 fixture corpora without source-tree imports or private service
  state, binds consumed bytes and target FileID state, and publishes no partial
  trusted result after a failure.
- Both language packages ship public metadata, repository, tree, manifest, and
  logical-bundle APIs. Rust exposes a scenario reporter and the same normative
  byte validation for every representable shared carrier; JavaScript-only rows
  are limited to the PRD-assigned fixture adapter plus JavaScript host-shape or
  raw carriers that Rust's closed public types cannot represent, such as
  Proxies, accessors, arbitrary kind maps, and unchecked unknown-kind writers.
- Format, JavaScript, fixture, Rust crate, and offline-distribution packages all
  carry byte-identical MIT license text and matching package metadata.
- Packed checks install from retained local archives without network access,
  verify distribution manifests, compare public source and package behavior,
  and exclude generator/test internals from runtime authority.
- OGVCS-041 protocol generation now pins the exact repository-format manifest
  and registry-set digest, so negotiation cannot silently select a different
  object-model corpus.

## Security and resource behavior

- All public limits are capped by hard maxima and checked before unsafe reads,
  allocations, callbacks, or publication. Memory accounting includes retained
  decoded graphs, caches, iterator state, indexes, scratch runs, capture buffers,
  transient copies, and aggregate high-level working sets.
- Deadlines use monotonic operation-scoped guards. Memory/count/scratch failures
  roll back operation counters and newly retained cache entries, leaving the
  same lookup or scratch authority reusable when the normative recovery mode
  permits it.
- External-sort scratch data lives in private workspaces, binds same-handle file
  identity and whole-run digests, and rejects replacement between write and
  merge.
- Public JavaScript data boundaries accept only inert exact records and branded
  adapters where required; accessors, Proxies, sparse arrays, hostile iterables,
  and caller-controlled configuration cannot execute during schema preflight.
- Diagnostics expose stable codes, layers, stages, counts, and non-sensitive
  resource measurements. Payloads, paths, messages, raw IDs, extensions,
  credentials, and private repository state are excluded by default.

## Bounded validation result

The frozen language-neutral candidate manifest is
`2d0acb01a01b64c23d883d855d2802d939a8dc99622f2774de07af1c8af8d2b9`.
The bounded JavaScript report executes 571 rows with two exact-scale inventory
rows, zero failures, and result SHA-256
`7eeb9091263530ac5f8703adb58de71f536d96f9a541f914b7b9f6e50864d153`.

Rust has 550 applicable rows: 548 executable and the same two exact-scale
inventory rows; 23 JavaScript host-object rows are explicitly not applicable.
The Rust implementation and reporter have been statically closed against the
same authority, but this workstation does not have the Rust toolchain. Pinned
Rust 1.82 compilation, formatting, clippy, packaging, and the fresh Linux,
macOS, and Windows comparison remain the ordinary hosted proof for this
candidate and must pass before the PRD advances to `Validation`.

Generator replay, independent vector auditing, specification validation,
mutation/truncation execution, JavaScript source/package suites, offline package
tests, protocol predecessor generation, and diff hygiene pass locally. Exact
package and hosted identities are recorded in the evidence packet after the
ordinary three-platform workflow completes.

## Deliberately deferred exact-scale evidence

Per maintainer direction, this delivery did **not** run either exact-scale
workload:

- `tree-million-entries`; or
- `manifest-one-tib`.

They remain two authenticated inventory-only rows for the final R0 campaign.
That campaign must retain both implementations' wall time, peak RSS, scratch
high-water mark, processed counts/bytes, identities, and cross-language result
comparison. Until then OGVCS-002 cannot be `Done`: AC-02 remains incomplete and
the exact 1-TiB portion of AC-09 remains incomplete. The bounded candidate does
not substitute a smaller run for either claim.

## Rollout and rollback

Repository format v1 remains a validation candidate. Readers, schemas,
registries, vectors, and both codec implementations ship before production
write enablement. A defective writer or profile can be disabled without
reinterpreting existing objects; deprecated readers and immutable assignments
remain available. Any incompatible correction requires a new format version
and explicit migration preview, never an in-place assignment or preimage change.
