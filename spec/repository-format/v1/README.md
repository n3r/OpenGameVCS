# OpenGameVCS repository format v1

**Status:** Ratified format-v1 contract
**Format version:** 1

This directory is the ratified language-neutral format-v1 contract. ADR-0008,
ADR-0009, and ADR-0010 are accepted design authorities, and OGVCS-002 completed
its independent ordinary, packed, and exact-scale acceptance gates on
2026-08-24. The ADR table and each ADR file must agree. Format ratification does
not promote conformance-only profiles or invent production policy: a production
write still requires every selected profile to be independently ratified and
write-eligible.

## Normative artifacts and precedence

The format fails closed when its authorities disagree. The governing ADRs own
architecture and scope; [`encoding.md`](encoding.md) owns deterministic encoding,
identity, text forms, and decoder behavior; the JSON registries own numeric
assignments, names, states, profile tuples, and limits; [`object-model.md`](object-model.md)
owns object semantics and graph validation; [`logical-bundle.md`](logical-bundle.md)
owns the bounded supplied-closure exchange; and
[`repository-format.cddl`](repository-format.cddl) mirrors wire shapes. CDDL,
prose, and registries must agree and no implementation may silently select a
more permissive source.

The complete routed artifact set is:

- [`encoding.md`](encoding.md) — restricted deterministic CBOR, hashes,
  validation layers, and registry governance;
- [`object-model.md`](object-model.md) — immutable objects, transitions,
  repository graph, and FileID rules;
- [`conformance-profiles.md`](conformance-profiles.md) — exact behavior of the
  OGVCS-002 conformance-only profile registry entries;
- [`logical-bundle.md`](logical-bundle.md) — canonical logical-record sequence,
  roots, transcript integrity, closure, and explicit no-export boundary;
- [`unicode/`](unicode/) — the versioned Unicode 15.0 `Age` source, license,
  provenance notice, and generated manifest-bound compact repertoire table;
- [`fixture-adapter.md`](fixture-adapter.md) — public OGVCS-001 profile-v2
  adaptation contract;
- [`repository-format.cddl`](repository-format.cddl) — data-model wire shapes;
- [`abstract-reference-graph.schema.json`](abstract-reference-graph.schema.json)
  — typed, prevalidated symbolic input used only to test defense-in-depth cycle
  algorithms that cannot be materialized as valid content-addressed bytes;
- [`validation-scenario.schema.json`](validation-scenario.schema.json) — exact
  operation, validation context, pre-publication state, resource recipe and
  normative result for each semantic vector;
- [`vector-manifest.schema.json`](vector-manifest.schema.json) — manifest,
  artifact, scenario and generator-provenance shape for future normative vector
  releases;
- [`errors.json`](errors.json) — stable machine-readable error catalogue with
  exact validation-stage/layer sites and deterministic precedence;
- [`registries/object-kinds.json`](registries/object-kinds.json),
  [`registries/hash-algorithms.json`](registries/hash-algorithms.json), and
  [`registries/common-fields.json`](registries/common-fields.json) — identity
  and envelope assignments;
- [`registries/kind-fields.json`](registries/kind-fields.json) — all object,
  helper, operation, logical-record, conflict-preimage, and bundle map-field
  assignments, including their CDDL rule bindings;
- [`registries/entry-kinds.json`](registries/entry-kinds.json) and
  [`registries/entry-modes.json`](registries/entry-modes.json) — tree entry and
  portable-mode pairings;
- [`registries/required-features.json`](registries/required-features.json),
  [`registries/extensions.json`](registries/extensions.json), and
  [`registries/profiles.json`](registries/profiles.json) — additive capability
  and profile governance;
- [`registries/logical-record-types.json`](registries/logical-record-types.json)
  — typed non-object record assignments;
- [`registries/semantic-enums.json`](registries/semantic-enums.json) — numeric
  semantic choices not owned by another registry, including operations,
  allocation, conflicts, lifetime/import state, bundles and policy decisions;
  and
- [`registries/limits.json`](registries/limits.json) — non-overridable v1 hard
  maxima.

The checked-in [`vectors/manifest.json`](vectors/manifest.json) conforms to
`vector-manifest.schema.json`, lists every schema-valid scenario document, and
binds every generated artifact by byte length, media type, and SHA-256. The
scenario index explicitly distinguishes byte-materialized, executable,
prevalidated-abstract, and inventory-only cases. Inventory-only scale plans are
not interoperability evidence until an independent runner records their exact
output identities and measured resource high-water marks. A generator is a
reproducibility tool, not a semantic oracle: regenerating its own expected
results is not independent validation. The clean-room implementations consume
the scenario context without importing or executing the generator and must
reproduce each claimed normative result.
Scenario `inputs` bind the exact bytes operated on. `requirementIds`, object lookups, roots, lifetime additions, and import
mappings are sorted by their schema identity/comparator keys. A reject result's
code MUST exist in `errors.json`; the schema's code grammar is not permission to
invent an error. `registrySetSha256` is `SHA-256(ASCII("OpenGameVCS registry
set\0") || uint16be(1) || records)`, where `records` contains every registry
JSON file in README order as `uint32be(path-byte-length) || path-UTF8 ||
uint64be(file-byte-length) || exact-file-bytes`. It selects one exact registry
snapshot without embedding registry state into canonical object bytes.

`resources.summary.summarySha256` is `SHA-256(ASCII("OpenGameVCS resource
summary\0") || uint16be(1) || uint64be(bytes) || uint64be(items) ||
uint64be(traversalEdges) || uint64be(indexEntries) ||
uint64be(peakMemoryBytes) || uint64be(scratchBytes))`. All counters are exact
unsigned values; an unmeasured runtime high-water mark is zero only when the
scenario recipe explicitly marks that measurement as not asserted. An accept
result repeats this digest in `expected.output.summarySha256`.

A `validate-abstract-reference-graph` scenario starts at semantic layer 3 and
MUST carry an input conforming to `abstract-reference-graph.schema.json`. Its
`assumedValidation` marker means layers 1 and 2 are test-harness preconditions,
not fabricated successes. Such a scenario tests bounded cycle detection only;
it is not a canonical-CBOR, ObjectID, bundle, or interoperability vector and
MUST NOT be accepted by an object decoder. A byte-materialized attempted cycle
changes at least one content-addressed payload and therefore selects
`OBJECT_ID_MISMATCH` at layer 1 before a cycle code, absent a SHA-256 fixed point.
Abstract nodes and roots sort strictly by node-ID UTF-8 bytes; edges sort by
`(kind UTF-8 bytes,target node-ID UTF-8 bytes)` and are unique. Every root and
edge target names exactly one node. `snapshot-parent` graphs contain only
snapshot nodes and `parent` edges and select `SNAPSHOT_PARENT_CYCLE` on a cycle;
`provenance-input` graphs contain only provenance nodes and
`provenance-input` edges and select `PROVENANCE_CYCLE`. Violating this harness
shape invalidates the scenario itself rather than producing a format error.

The design authority is recorded in
[`ADR-0008`](../../../adr/0008-format-v1-deterministic-cbor-and-object-identity.md),
[`ADR-0009`](../../../adr/0009-format-v1-object-graph-and-fileid-validation.md),
[`ADR-0010`](../../../adr/0010-core-profile-registries-and-logical-bundle-boundary.md),
and the [`ADR index`](../../../adr/README.md).

## Versioned conformance package

This directory is also the data-only npm package
`@opengamevcs/repository-format-v1@0.1.0`. Its package root contains the
normative prose, CDDL, JSON schemas, exact registries, generated vectors, and
their manifest, plus the versioned Unicode 15.0 repertoire source and notices.
A clean consumer imports `formatVersion`, `formatRootUrl`,
`registriesUrl`, and `vectorsUrl` from the package root; it does not reach back
into a source checkout.

Create and install the artifact without network access as follows:

```sh
npm pack ./spec/repository-format/v1 --pack-destination artifacts --ignore-scripts
npm install --offline ./artifacts/opengamevcs-repository-format-v1-0.1.0.tgz
```

The JavaScript package contract and Rust offline-distribution smoke tests both
consume this packed artifact and validate its vector manifest and registry
snapshot.

The full packed-artifact conformance gate additionally packages both codec
implementations, runs their applicable scenario and golden corpus against the
installed format package, binds each archive by SHA-256, and compares every
applicable shared-scope outcome. Its output directory retains the exact fixture-generator,
JavaScript implementation, format, and Rust crate archives used by the run,
alongside their hashes and both reports:

```sh
node tools/run-packed-object-model-conformance.mjs --output artifacts/packed-object-model-conformance
```

CI requires a clean package source. `--allow-dirty` exists only for local
pre-commit diagnosis; its archive hashes are not release evidence.

## Self-validation

The validator has no package dependencies and checks the complete registry set,
error catalogue, JSON schemas and their frozen enums, CDDL/prose assignments,
local links, ADR status table, and source hygiene. If a `cddl` executable is on `PATH`, it also invokes
`cddl --ci compile-cddl --cddl <schema>` and requires successful compilation;
absence of the optional tool does not make the dependency-free self-check fail.
From the repository root run exactly:

```sh
node spec/repository-format/v1/validate-spec.mjs
```

Run its isolated mutation suite with:

```sh
node --test spec/repository-format/v1/validate-spec.test.mjs
```

Success prints `repository-format-v1: valid`. Any diagnostic is a specification
defect; fix the conflicting source rather than weakening validation.

The vector generator and the independent corpus auditor are separate gates. The
auditor does not import or execute generator code; it recomputes inventory,
registry, scenario/resource, required-obligation, stable-error, mutation,
truncation, and scale-recurrence invariants directly from the published files:

```sh
node tools/reference-vector-generator/generate.mjs --check
node tools/verify-reference-vectors.mjs
node --test tools/verify-reference-vectors.test.mjs
```

The mutation test also changes corpus bytes and semantic coverage while
refreshing the top-level inventory hash, proving that a self-consistent manifest
alone cannot satisfy the audit.
