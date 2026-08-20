# ADR-0010: Core profile registries and logical-bundle boundary

**Status:** Accepted
**Date:** 2026-08-15
**Owners:** OGVCS-002, OGVCS-004, OGVCS-007, OGVCS-008, OGVCS-033

## Context

OGVCS-002, OGVCS-004, OGVCS-007, and OGVCS-033 each claimed parts of canonical paths, content manifests, hash preimages, or export. Without one ownership split, a later path/chunker/export implementation could silently change R0 object identity, while requiring R3 fidelity export for R0 completion would make the roadmap impossible.

## Decision

OGVCS-002 owns deterministic object bytes, object/chunk hash domains, the structural `ContentManifestV1` envelope, core segment wire encoding and entry/mode codepoints, the `ProfileRef` shape, additive registries, typed logical records, and root-based graph validation.

A `ProfileRef` contains an ASCII lowercase reverse-DNS namespace of at most 253 bytes, an ASCII lowercase identifier of at most 63 bytes, and a separate positive 32-bit major version. Each namespace label and identifier is a lowercase letter followed by letters/digits or single hyphen-separated letter/digit runs; labels cannot begin/end with a hyphen, and no IDNA or case folding applies. The canonical text form is `<namespace>/<identifier>@<major>` with no leading zero in the major. Registry entries are never reassigned or redefined. A `reserved` entry cannot appear in data; `conformance-only` is valid only in declared test artifacts; `ratified` is readable and writable; `deprecated` remains readable but cannot be selected for a new production write. Unknown required entries fail semantic validation.

OGVCS-002 publishes conformance-only profiles whose exact payload and validation semantics are fixed by `spec/repository-format/v1/conformance-profiles.md`, including `path.test/opaque@1` and `chunking.test/external-boundaries@1`. The first applies only lexical NFC segment rules; the second accepts vector-supplied boundaries and is not a production chunker.

`ContentManifestV1` fixes logical length, typed whole-file SHA-256, registered chunk-profile reference, and ordered typed chunk ID/length pairs. OGVCS-007 owns content-defined boundary algorithms, fingerprint initialization/input, parameters, thresholds, policy selection, streaming generation/reconstruction, and ratified chunk-profile entries; it consumes but never redefines the OGVCS-002 container or hash preimages. OGVCS-008 owns pack, compression, placement, and transfer framing. A nonidentity hint is a non-object typed logical annotation record containing a subject ObjectRef and a registered annotation-payload `ProfileRef`; it is excluded from the subject preimage but protected by logical-bundle or export integrity. OGVCS-002 owns the annotation envelope and profile owners register payload schemas.

OGVCS-002 fixes tree basename bytes/order and entry/mode codepoints. OGVCS-004 owns joined-path validity, case folding/collision keys, supported-platform profiles, repository path/depth limits, reserved names, symlink/materialization behavior, and filesystem safety. A case-only rename changes tree bytes while preserving FileID; OGVCS-004 decides whether a configured profile admits it.

For a ratified external path profile, the pure OGVCS-002 repository validator
requires a version-pinned owner adapter. The authenticated repository context
supplies the repository's immutable `case-sensitive` or `case-folded` setting;
the adapter pin binds both that case mode and the exact `ProfileRef`. Each
accepted path returns bounded, nonempty repository-mode and platform collision
keys, and either duplicate is invalid. Case mode is repository configuration,
not a format-v1 descriptor field or a change to canonical tree bytes.

Every semantic repository operation and every public typed metadata, tree,
manifest, or logical-bundle emitter that claims a format-v1 object requires a
complete immutable registry snapshot and an explicit validation/write mode.
The generic deterministic-CBOR primitive may remain registry-free because it
makes no object-schema or production-write claim. Other registry-free helpers
may prove only their documented framing, identity, or known-schema layer and
cannot report layer-three or production-write success.

Registry-aware codec readers, including supplied-closure logical-bundle
verification, use an explicit lifecycle operation of `read`, `conformance`, or
`production-write`. `read` admits ratified and deprecated assignments but not
conformance-only assignments; `conformance` admits the declared test-only
profiles; and `production-write` admits only assignments eligible for a new
production write. Registry-free bundle verification may be requested
explicitly as a layer-two supplied-closure check, but it cannot claim semantic
or repository validity. Typed emitters never accept `read`, and whole-repository
semantic validators instead require the closed `conformance` or `production`
repository mode. A bundle verifier's optional repository-semantic callback is
separate from its codec lifecycle and requires that complete repository context.
An explicit layer-two/`semantic:false` route rejects both a caller registry and a
lifecycle operation, and uses only the frozen format-v1 kind, field, and profile-
family tables. Registry presence always selects the semantic route and therefore
requires its explicit lifecycle operation before any payload or source is read.

OGVCS-002 also defines a deterministic logical bundle: a bounded CBOR-sequence record set containing caller-selected immutable objects and typed logical records, declared roots, and an integrity trailer. It can validate the supplied set and root closure but makes no authorization, consistent-generation, repository completeness, fidelity, projection, signature, volume, incremental, restoration, or import claim. It is not a product export.

OGVCS-033 alone owns repository-complete fidelity and authorized-projection selection, manifests, signatures, physical containers/volumes, resumability, increments, authorization, non-disclosure, import, and restoration evidence. Fidelity embeds unchanged OGVCS-002 bytes/IDs. Every projection creates a distinct repository descriptor carrying a registered required projection feature, a new repository identity, a public non-disclosing projection-provenance reference, and the declared projection identity class. OGVCS-033 SHALL add those values through an additive required-feature assignment and registered descriptor-extension assignment; OGVCS-002 vectors cover the generic unknown-required-feature and unknown-optional-extension rules, not projection semantics. Every repository-scoped projected tree, change set, group set, shelf, conflict set, and snapshot references that descriptor, mechanically forcing new repository-scoped IDs even for a full-view projection. Path-independent content manifests and chunks may retain their source content IDs. Projection does not redefine core hash preimages. Its independent verifier implements the OGVCS-002 specification/vectors without importing the production OGVCS-002 implementation library.

## Alternatives considered

- **Letting core implement every path, chunking, transfer, and export policy** was
  rejected because it would couple object identity to unfinished owners and make
  independent evolution impossible.
- **Leaving profile references as arbitrary strings or redefinable registry rows**
  was rejected because two readers could assign different semantics to the same
  canonical bytes.
- **Calling a logical bundle a repository export** was rejected because a
  caller-selected closure cannot prove authorization, completeness, fidelity,
  projection, restoration, or import safety.
- **Waiting for R3 export before freezing R0 identity** was rejected because the
  dependency would block every repository consumer without improving the core
  supplied-closure contract.

## Compatibility and data consequences

Profile and logical-record assignments are immutable and owner/version scoped.
Owners add ratified profiles without changing format-v1 preimages; deprecated
entries remain readable and removed IDs remain reserved. The repository case
mode and external validator are authenticated context, so selecting them does
not rewrite existing tree bytes. A logical bundle preserves included canonical
bytes and identities but creates no durable repository-completeness claim. A
future fidelity/projection format uses its own registered feature/extension and
new repository identity where required.

## Threat and failure analysis

Exact family, lifecycle, version, mode, and registry checks prevent a test-only,
reserved, unknown, deprecated-write, or wrong-family profile from being used as
production semantics. External path results are fail-closed, bounded before
retention, and provide both repository and platform collision keys; a missing,
mismatched, malformed, or colliding result is invalid. Logical-bundle validation
checks canonical framing, declared accounting, identity, transcript, typed roots,
and supplied closure while refusing forbidden export/fidelity labels. Unsupported
required features stop semantics, and no optional extension gains authority over
base fields. Authority and lifecycle selectors are validated before payload work,
so a malformed object cannot mask a missing registry or ambiguous operation.

## Test vectors and proof

OGVCS-004 directly depends on OGVCS-002. OGVCS-033 directly depends on OGVCS-004 and OGVCS-007 in addition to its existing prerequisites. R0 can freeze object identity with conformance profiles while production path and chunk profiles arrive through their owners. Tests prove manifest annotation invariance, later-profile additive registration, byte-preserving unknown optional extensions, unsupported required-profile rejection, canonical logical-bundle closure, and rejection of any logical bundle relabeled as fidelity/projection evidence.

Registry vectors cover every lifecycle state, family mismatch, immutable
assignment, required feature, and lossless unknown extension. Cross-package path
vectors exercise ratified profiles, both case modes, repository/platform
collisions, empty trees, malformed owner decisions, and adapter pin mismatch.
Bundle vectors cover deterministic order, duplicates, missing/extra/wrong-kind
members, declaration limits, transcript tampering, and forbidden claim relabeling.
Lifecycle vectors also prove that deprecated bundle profiles remain readable,
conformance-only profiles are confined to conformance, and neither class is
eligible for a new production write.

## Rollback and migration

A faulty profile or writer is disabled for new production writes while its
assignment, readers, and canonical vectors remain available. Registry rows are
never reassigned; a compatible replacement receives a new profile major or
additive assignment. Logical-bundle transport may be withdrawn without changing
stored objects because it is not authoritative repository state. An incompatible
core container or identity change requires a new format version and explicit
migration; a later export format cannot reinterpret an existing logical bundle
as fidelity evidence.
