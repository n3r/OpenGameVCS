# OGVCS-002 — Core object library and open repository format

**Status:** In development
**Release:** R0 — Engineering Foundation  
**Priority:** P0  
**Owner:** Codex and OpenGameVCS maintainers
**Depends on:** OGVCS-001  
**Blocks:** OGVCS-004, OGVCS-005, OGVCS-006, OGVCS-007, OGVCS-017, OGVCS-020, OGVCS-029, OGVCS-033, OGVCS-036, OGVCS-041
**Source:** [ADR-0008 deterministic CBOR and object identity](../../adr/0008-format-v1-deterministic-cbor-and-object-identity.md)
**Last updated:** 2026-08-16

## Outcome

Developers have a language-neutral format-v1 specification, public registries and schemas, two independently implemented codecs, a bounded inspector/verifier, and normative vectors that produce identical bytes and ObjectIDs. The format represents immutable repository history, stable FileID transitions, bounded logical exchange/reference projections, and independently readable logical object graphs without a proprietary service or database.

## Problem

Storage, client, path, content, protocol, and recovery work cannot proceed independently while canonical encoding, object identity, graph reachability, content-manifest structure, FileID transitions, and extension behavior remain implicit. Assigning those contracts to a database layout or a single implementation would make clean-room compatibility and long-term repository readability unverifiable.

## Scope

### In scope

- The strict deterministic-CBOR profile, canonical scalar/container rules, hard decoder ceilings, hash domains, typed ObjectIDs, and durable text forms.
- Immutable schemas and invariants for chunk, `ContentManifestV1`, one-directory tree, change set, asset-group set, repository descriptor, snapshot, shelf revision, provenance, attestation, and conflict set.
- Canonical envelopes for bounded logical exchange/reference projections without exhausting or constraining their owners' authoritative mutable schemas and state machines.
- Root-based graph reachability, ordered parent-DAG rules, exact transition replay, conflict placement, group membership, and FileID proof semantics.
- Additive object-kind, field, feature, extension, entry/mode, profile, hash-algorithm, and logical-record registries.
- A bounded deterministic logical bundle for a caller-supplied object/record set and declared roots; it is an exchange and conformance artifact, not a repository export.
- Public golden, malformed, adapter, mutation, limit, and large streaming vectors plus a standalone inspector/verifier CLI.

### Out of scope

- Joined-path case folding, collision profiles, platform materialization, and filesystem safety, owned by OGVCS-004.
- Production content-defined chunking profiles and algorithms, owned by OGVCS-007, and physical pack/compression/transfer representation, owned by OGVCS-008.
- Durable FileID lifetime/import storage and finalize-time transaction enforcement, owned by OGVCS-006 and OGVCS-010.
- Network/API transport, database schema, authorization decisions, and authoritative service state machines.
- Fidelity/projection selection, authorization, containers, signatures, volumes, increments, restoration, and import, owned by OGVCS-033 and OGVCS-036.

## Users and journeys

- **Server engineer:** stores optimized rows and pages while proving their ordered logical projection has the canonical bytes and IDs.
- **Client engineer:** streams object encoding, hashing, decoding, and verification without server-private knowledge or whole-tree buffering.
- **Tool vendor:** implements the public specification and verifies object graphs and logical bundles without importing production code.
- **Operator:** inspects identity, reachability, transition, and corruption results offline with typed bounded failures.

## Requirements

### Functional

- **OGVCS-002-FR-01:** Format v1 SHALL use the ADR-0008 deterministic-CBOR subset: definite values, shortest integers and lengths, NFC scalar UTF-8 text, unsigned numeric schema keys in deterministic order, and no floats, tags, null/undefined values, bignums, indefinite containers, duplicate keys, invalid UTF-8, nonminimal encodings, or trailing bytes. Public APIs SHALL separately report canonical-framing scan, known-kind schema validation, and semantic feature/profile validation; every rejection SHALL expose its normative error code, validation layer, and actual precedence stage; no layer SHALL normalize noncanonical input or promote a framing-only result.
- **OGVCS-002-FR-02:** Every immutable object SHALL use the registered kind and the exact domain-separated SHA-256 preimage `ASCII("OpenGameVCS object\0") || uint16be(1) || uint16be(kind) || payload`; raw logical bytes are the chunk payload and deterministic CBOR is every metadata payload. Binary and durable text references SHALL bind format, expected kind, algorithm, and full digest without silent algorithm substitution.
- **OGVCS-002-FR-03:** A snapshot SHALL bind its repository descriptor, zero to eight ordered unique parents, root tree, identity/timestamps/message, change set, policy result, and optional group/provenance roots. Each repository SHALL have exactly one designated zero-parent root; every other snapshot SHALL reach it, parent zero SHALL be the replay base, and attestations/signatures SHALL reference the completed snapshot rather than create a hash cycle.
- **OGVCS-002-FR-04:** A canonical tree SHALL represent exactly one directory and contain a definite array of immediate entries strictly ordered by NFC UTF-8 basename bytes. Every named entry, including directories, SHALL carry a nonzero FileID, registered entry kind and portable mode, typed child reference, logical size, and content-policy class; physical paging SHALL not affect bytes or identity.
- **OGVCS-002-FR-05:** Ordered change sets SHALL encode create, modify, copy, move, rename, delete, restore, group transition, and merge resolution with exact pre/post state. Create/copy SHALL allocate new FileIDs, move/rename SHALL preserve them, restore SHALL reactivate an existing lifetime under exact ancestral-delete/state proof without creating a new origin, and replay from parent zero SHALL exactly reproduce the declared tree and group roots.
- **OGVCS-002-FR-06:** Graph validation SHALL type-check every reference, enforce one repository/root and an acyclic bounded parent graph, require complete caller-declared reachability, reject unresolved conflicts in published snapshots, and reconstruct immutable snapshot contents without branch, lock, pending, review, audit, lifecycle, or FileID-registry state. Cycle-algorithm tests SHALL use the typed prevalidated abstract-reference-graph harness because a finite canonical content-addressed cycle requires a SHA-256 fixed point; attempted-cycle byte mutations fail ObjectID validation first.
- **OGVCS-002-FR-07:** The logical-bundle format SHALL encode a deterministic bounded CBOR sequence of caller-selected immutable objects and typed logical records, declared roots, and an integrity trailer, and SHALL validate the supplied closure. It SHALL make no authorization, consistent-generation, repository-completeness, fidelity, projection, signature, volume, incremental, restoration, or import claim.
- **OGVCS-002-FR-08:** Every object SHALL declare required feature IDs and may carry only the registered namespaced extension map. A canonical framing scan MAY hash, store, forward, and byte-preserve an object with unsupported required features but SHALL refuse semantic interpretation; unknown optional extensions SHALL not change base semantics and SHALL be byte-preserved by any promised lossless round trip.
- **OGVCS-002-FR-09:** Normative byte vectors SHALL cover every representable core object and transition, empty and Unicode cases, all entry kinds/modes, one-million-entry trees, logical 1 TiB manifests, zero/one/two/eight-parent histories, resolved/unresolved conflicts, shelves, sidecar groups, unknown extensions/features, hash tampering, malformed encoding, and every hard limit. Typed abstract-reference-graph scenarios SHALL separately cover unreachable defense-in-depth cycles without claiming canonical bytes.
- **OGVCS-002-FR-10:** FileID SHALL be an opaque nonzero 16-byte repository-scoped value with no UUID semantics. Native create/copy allocation SHALL use a cryptographically secure random source, a consumed ID SHALL never be reused in that repository, identical raw bytes MAY exist independently in different repositories, and cross-repository source proofs or mappings SHALL be rejected.
- **OGVCS-002-FR-11:** Pure validation as of immediately before the candidate snapshot SHALL combine immutable prior lifetime/import state with ordered candidate working additions and reject duplicate FileIDs across an expanded tree, create/copy reuse, forged move/restore, delete/recreate reuse, invalid ancestry, missing/wrong-kind edges, malformed group membership, cross-repository proofs, and allocation/import collisions; retry of the same importer/source identity SHALL resolve to the same mapping and current state.
- **OGVCS-002-FR-12:** `ContentManifestV1` SHALL contain logical length, typed whole-file SHA-256, a registered chunk-profile reference, and ordered typed chunk-ID/logical-length pairs. Chunk lengths SHALL be positive, a checked sum SHALL reject logical-ceiling excess and otherwise equal the declared length, and ordered bytes SHALL reconstruct the declared file digest; an empty file SHALL have no chunks. A nonidentity hint SHALL be a non-object typed logical annotation record with a subject ObjectRef and registered payload `ProfileRef`, excluded from the subject preimage but covered by bundle/export integrity.
- **OGVCS-002-FR-13:** `ProfileRef` SHALL use a lowercase ASCII reverse-DNS namespace, lowercase ASCII identifier, separate positive major, and canonical `<namespace>/<identifier>@<major>` text form with no IDNA/case folding. Registry assignments SHALL be immutable: reserved entries cannot appear, conformance-only entries are test-only, ratified entries are readable/writable, deprecated entries remain readable but cannot be selected for new production writes, removed IDs remain reserved, and unknown required entries fail semantics.
- **OGVCS-002-FR-14:** A public OGVCS-001 adapter SHALL consume all five profile-v2 fixtures through only packaged schemas/manifests/artifacts, treat fixture IDs as test data rather than native allocation evidence, synthesize and persist stable directory/group mappings, classify workload-only events outside immutable history, and reject zero or semantically invalid IDs.

### Quality attributes

- **OGVCS-002-NFR-01:** Independently authored Rust and JavaScript implementations MUST encode every golden object and logical bundle byte-identically, compute identical IDs, and reject the same malformed corpus with identical `(code, layer, stage)` results without sharing codec implementation code.
- **OGVCS-002-NFR-02:** Encoding, hashing, decoding, reachability verification, bundle processing, and global FileID/order checks MUST be streaming or bounded-memory. A one-million-entry single directory SHALL verify below 1 GiB peak RSS through ordered iterators or bounded disk-backed indexes, never an in-memory million-entry object graph.
- **OGVCS-002-NFR-03:** Existing kind, field, enum, profile, preimage, or semantic assignments MUST NOT change in place. An incompatible change requires a new format version; additive immutable registry entries and optional extensions do not change format-v1 identity rules.
- **OGVCS-002-NFR-04:** Hostile lengths, nesting, fanout, malformed Unicode, integer overflow, configured byte/object/time/memory/scratch limits, and truncated inputs MUST produce stable typed failures without panic, process OOM, partial trusted output, or unbounded allocation.
- **OGVCS-002-NFR-05:** Published specifications, registries, vectors, packages, CLI help, and examples MUST install and run offline from packed artifacts and MUST require no vendor credential, service, or private repository state.

## Interfaces and data

The PRD delivers `spec/repository-format/v1/` with the normative prose, CDDL, integer and profile registries, hard-limit table, object/hash preimages, logical-bundle framing, error vocabulary, and positive/malformed vector manifests. `core/object-model/rust/` and `core/object-model/js/` both expose canonical encode/decode/hash, typed references, pure semantic validation, and ordered streaming tree/bundle APIs. The JavaScript package additionally exposes the public OGVCS-001 fixture adapter and the packaged `ogvcs-object` CLI (`inspect`, `verify`, `id`, `bundle verify`, and registry discovery); its black-box package tests are the acceptance boundary for FR-14 rather than an unimplemented claim on both language packages. Production path and chunk profiles plug into the frozen `ProfileRef` registries without changing core bytes; later fidelity/projection export consumes canonical bytes but is a distinct contract.

## Development plan

1. **Specification and registry freeze:** Publish the exact deterministic-CBOR grammar, numeric schemas, preimage formulas, object/field/feature/profile registries, hard bounds, error codes, and hand-auditable seed vectors. Exit when independent calculation reproduces the published seed bytes and IDs and roadmap/architecture ownership is internally consistent.
2. **Independent codec slice:** Implement canonical primitives, strict decoding, typed references, and all core object schemas independently in Rust and JavaScript. Keep shared inputs limited to the language-neutral spec/vectors; exit when both implementations generate the same corpus and mutation tests cannot preserve an original ID.
3. **Graph and transition slice:** Implement ordered tree streaming, repository/root/parent validation, FileID and group indexes, change-set replay, conflict/shelf rules, content-manifest verification, and disk-backed bounded indexes. Exit when all normative positive/negative parent, transition, manifest, and lifetime vectors agree across languages.
4. **Logical exchange and fixture slice:** Implement the bounded logical-bundle reader/writer, integrity trailer, public inspector/verifier CLI, and five-profile OGVCS-001 adapter. Exit when separate-process CLI tests verify supplied closure, reject incomplete/relabelled sets, and map one normative corpus from each of the five fixture profiles without private imports.
5. **Hostile-input and scale slice:** Run malformed/truncation/fuzz/property suites, configured resource limits, a single-wide-directory one-million-entry benchmark, logical 1 TiB manifest streaming, and cross-platform package tests. Exit only with measured peak RSS/time/scratch evidence and typed failure for every exceeded bound.
6. **Ratification and handoff slice:** Publish versioned offline-installable packages, generated reference documentation, compatibility policy, consumer examples, and conformance reports; run an independent critical review and fix every P0–P2 finding. Ratify writer profiles only after both readers, package boundaries, and all acceptance proofs pass; rollback disables writing while retaining readers and vectors.

## Acceptance criteria

- **OGVCS-002-AC-01:** Clean-room Rust and JavaScript codecs encode/decode every golden vector and produce byte-identical payloads, logical bundles, typed text references, and ObjectIDs; neither implementation imports the other's codec.
- **OGVCS-002-AC-02:** Both the library and packaged CLI verify a one-million-entry single directory under 1 GiB peak RSS, with identical output from an already ordered iterator and a bounded disk-backed sort/index path.
- **OGVCS-002-AC-03:** For every representative small object and bundle, each single-bit mutation is either structurally/semantically rejected or recomputes to a different ID/integrity digest; no changed bytes validate under the original identity.
- **OGVCS-002-AC-04:** The public adapter maps all five OGVCS-001 profile-v2 corpora without an unregistered escape field. Separately, the public core validators execute the hand-authored restore, import lost-ack retry, forged/cross-repository proof, collision, root/parent, shelf, and unresolved-conflict cases; those native cases are not adapter inputs.
- **OGVCS-002-AC-05:** Architecture and clean-room portability review finds no database row, server module, credential, private schema, or vendor service required to inspect canonical objects, validate a caller-supplied closure, or reproduce any vector; the review confirms this is not fidelity/projection export evidence.
- **OGVCS-002-AC-06:** Zero-parent root, one-parent commit, ordered two-parent merge, maximum eight-parent merge, second-root, missing/duplicate/cross-repository parent, and ninth-parent byte vectors produce the normative identical result in both implementations; typed prevalidated abstract-reference-graph scenarios produce identical bounded snapshot/provenance cycle results, while an attempted-cycle byte mutation selects `OBJECT_ID_MISMATCH` at layer 1.
- **OGVCS-002-AC-07:** Zero, duplicate, reused, forged, move/rename, copy, delete/recreate, ancestral restore, cross-repository proof, import retry/conflict, and concurrent-allocation FileID vectors produce identical normative results, including an unchanged loser state.
- **OGVCS-002-AC-08:** The full malformed and boundary corpus, including maximum-plus-one length/count/depth cases and truncation at every byte boundary of seed records, fails within configured memory/time/scratch bounds with stable error classes and no trusted partial output.
- **OGVCS-002-AC-09:** Empty, repeated-chunk, multi-chunk, corrupt-chunk, logical-length ceiling excess/final-sum mismatch, unknown-profile, 1 TiB logical, and annotation-invariance manifest vectors agree cross-language; changing a separate annotation never changes the manifest ID. Defensive arithmetic-overflow injection remains an implementation property test, not a representable format-v1 uint64 vector.
- **OGVCS-002-AC-10:** Logical-bundle tests prove deterministic ordering, root closure, bounded logical-reference preservation, trailer integrity, duplicate/missing/extra/wrong-kind rejection, and refusal to treat or relabel the bundle as fidelity or projection evidence.
- **OGVCS-002-AC-11:** Registry conformance tests reject duplicate/reassigned/invalid entries and prove reserved, conformance-only, ratified, and deprecated read/write behavior. An older codec canonical-scans, re-hashes, and byte-preserves an unsupported-required-feature object while refusing semantics, and byte-preserves an unknown optional extension through lossless round trip.
- **OGVCS-002-AC-12:** Native Rust and JavaScript FileID allocators use their documented operating-system entropy APIs, reject zero, retry bounded injected collisions, return a typed failure after exhaustion, and contain no path-, clock-, counter-, or deterministic fallback.

## Verification plan

- Cross-language golden generation followed by byte-for-byte and ID comparison from clean processes and packed offline installs.
- Positive and malformed schema suites, canonical-CBOR property tests, mutation/truncation matrices, graph/replay model tests, and deterministic fuzz corpora with stable seeds.
- OGVCS-001 black-box adapter runs against all five packaged fixtures; no fixture-generator source import is allowed.
- Resource-isolated one-million-wide-tree and logical-1-TiB streaming runs recording wall time, peak RSS, scratch high-water mark, processed bytes/entries, and stable summary digests.
- Linux, macOS, and Windows jobs plus network-disabled package install/consumer tests; generated artifacts and cross-platform summaries are retained for independent comparison.
- Independent architecture, format, security/resource, and clean-room implementation review before status may move to Done.

## Telemetry and operations

Library and CLI results expose format/kind/profile versions, bytes and objects processed, verification phase/duration, peak-memory and scratch estimates where measurable, required-feature failures, and stable `(code, layer, stage)` errors. Diagnostics exclude payload bytes, paths, messages, identities, extensions, and raw identifiers by default; callers opt into content-bearing inspection explicitly.

## Rollout and rollback

Format v1 remains draft while readers, writers, registries, and vectors are under this PRD. Ratification follows read-before-write deployment: both independent readers and all declared consumers must accept the exact frozen corpus before any production profile is writable. A writer or profile can be disabled without changing stored objects; readers, schemas, and vectors remain available indefinitely. Any incompatible correction receives a new format version and explicit migration plan—never an in-place reinterpretation or an assumed export/reimport shortcut.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A compact binary format becomes implementation-defined | Normative byte examples, CDDL plus stricter prose, two clean-room codecs, and reject-not-normalize decoding |
| A million-entry tree forces unbounded memory | Ordered streaming APIs, exact counts, disk-backed sorting/indexes, and measured single-wide-directory acceptance |
| Core identity waits for later path/chunker/export designs | Immutable `ProfileRef` registries with conformance-only profiles and explicit ownership boundaries |
| FileID rules disagree with branches, restores, or imports | Pure replay/proof model plus lifetime, lost-ack, collision, and cross-repository vectors |
| Logical exchange is mistaken for a complete export | Type/profile names forbid the claim, bundle metadata states supplied closure only, and negative relabelling tests |
| Parser limits reject legitimate repositories or permit denial of service | Published hard ceilings, smaller configured budgets, max/max-plus-one vectors, and versioned migration for future expansion |

## Completion evidence

The implementation and ordinary conformance candidate is MIT-licensed and passes
local source/packed checks plus clean hosted Linux, macOS, and Windows comparison
at commit `6295cb54b29bc5a9ac6dadf34bc2c52a337eba49`; see
[`docs/evidence/OGVCS-002/`](../../docs/evidence/OGVCS-002/). By maintainer
decision on 2026-08-16, the exact one-million-entry tree and logical-1-TiB
manifest jobs are deferred to the final R0 campaign and were not run. Status
remains In development and the final evidence fields below remain intentionally
open until those acceptance runs, final publication, and ratification complete.

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
