# ADR-0010: Core profile registries and logical-bundle boundary

**Status:** Proposed
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

OGVCS-002 also defines a deterministic logical bundle: a bounded CBOR-sequence record set containing caller-selected immutable objects and typed logical records, declared roots, and an integrity trailer. It can validate the supplied set and root closure but makes no authorization, consistent-generation, repository completeness, fidelity, projection, signature, volume, incremental, restoration, or import claim. It is not a product export.

OGVCS-033 alone owns repository-complete fidelity and authorized-projection selection, manifests, signatures, physical containers/volumes, resumability, increments, authorization, non-disclosure, import, and restoration evidence. Fidelity embeds unchanged OGVCS-002 bytes/IDs. Every projection creates a distinct repository descriptor carrying a registered required projection feature, a new repository identity, a public non-disclosing projection-provenance reference, and the declared projection identity class. OGVCS-033 SHALL add those values through an additive required-feature assignment and registered descriptor-extension assignment; OGVCS-002 vectors cover the generic unknown-required-feature and unknown-optional-extension rules, not projection semantics. Every repository-scoped projected tree, change set, group set, shelf, conflict set, and snapshot references that descriptor, mechanically forcing new repository-scoped IDs even for a full-view projection. Path-independent content manifests and chunks may retain their source content IDs. Projection does not redefine core hash preimages. Its independent verifier implements the OGVCS-002 specification/vectors without importing the production OGVCS-002 implementation library.

## Consequences and proof

OGVCS-004 directly depends on OGVCS-002. OGVCS-033 directly depends on OGVCS-004 and OGVCS-007 in addition to its existing prerequisites. R0 can freeze object identity with conformance profiles while production path and chunk profiles arrive through their owners. Tests prove manifest annotation invariance, later-profile additive registration, byte-preserving unknown optional extensions, unsupported required-profile rejection, canonical logical-bundle closure, and rejection of any logical bundle relabeled as fidelity/projection evidence.
