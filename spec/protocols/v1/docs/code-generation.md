# Generation and binding boundary

## One authority

`model.mjs` is the sole authority for message and field numbers, wire names,
types, presence, limits, sensitivity, fingerprint participation, lifecycle,
registries, and executable scenario constructors. The offline Node generator validates that
model before writing. Unknown types/constraints, mixed primitive enums,
unbounded strings/collections, duplicate names/numbers, unresolved references,
unsafe integers, or host-dependent values make generation fail.

Generation emits RFC 8785 JSON schemas/registries/vectors, LF documentation,
and Rust, C++, C#, and TypeScript type packages. It uses no network, timestamp,
absolute output path, locale ordering, random value, or remote plugin.
`--check` recomputes expected bytes and reports drift. The independent spec
validator does not import model or generator code; it verifies canonical bytes,
inventory/digests, schema closure/bounds/references, assignments, predecessor
pins and declared offline generator inputs, semantic goldens, complete trace
goldens, the executable byte-identical golden JSONL stream, all 70 reduced
configured-limit executions, release preflights, and binding provenance.

RunnerCase contains only public operation input, configured ceilings,
deterministic clock/cancellation controls, and sensitive server context needed
to make leak tests non-vacuous. Oracle fields stay in the harness. An adapter
returns its actual bounded body, header rows, frames, log rows, and semantic
output in AdapterResult. The harness scans that trace before projecting
RunnerResult; `semanticDigest` is SHA-256 of RFC 8785 semanticOutput and
`traceDigest` is SHA-256 of the complete canonical AdapterTrace. Every scenario
contains a manifest-bound harness-only trace digest, and `golden-traces.jsonl`
contains the independently canonicalizable closed trace used to derive it.
Neither artifact is present in RunnerCase or the adapter execution view. AdapterResult
and every process line are capped by maxControlMessageBytes, header aggregates
by maxHeaderBytes, and all structural limits remain active. Reports retain
neither trace nor server context.

The 35 limit pairs use lowered ceilings only. Measurements come from actual
input bytes, collections, schema steps, stream frames, registry inventory, or
the operation clock—not expected results. Runner clock samples are
nondecreasing safe timestamps; elapsed time is the checked difference between
the final and first samples. A decreasing sequence is PROTOCOL_MALFORMED before
operation dispatch. The working-memory parser route
reserves `128 + 4 * rawInputUtf8Bytes`; elapsed time reaches its exclusive
deadline at `elapsed >= maxOperationTimeMs`. The configured lower ceiling
applies when present, while the normative 120000ms hard/default ceiling remains
active when the override is absent. All configured ceilings are positive except
the deliberate maxErrorParameters zero-ceiling pair. The
conformance-only `rawInputUtf16CodeUnits` carrier lets an adapter materialize a
JS unpaired code unit immediately before raw-input validation without making
the authenticated vector set itself non-I-JSON.

## Noncircular manifests and bindings

The contract manifest lists every distributed normative artifact except
itself. The vector manifest lists vector artifacts except itself. The
negotiation registry digest excludes compatibility so compatibility can pin it;
the complete registry digest includes compatibility. The binding manifest
points one way to the contract-manifest digest and lists every binding artifact
except itself. No digest graph is circular.

The contract manifest authenticates `adapter-execution-view.json` as a one-way
support view exposing only schemas, registries, profiles, limits, and
predecessor pins. It excludes vectors, expected outcomes, trace goldens, and the
authorization manifest/grant/license files declared as offline generator
inputs, so an external adapter receives randomized cases over stdin without
access to either oracle corpus or predecessor-vector outcomes.

Bindings contain standard-library type models and immutable assignment/limit/
error constants only. Applications provide bounded JSON/JCS, JSONL, HTTP/TLS,
MAC, cursor, authorization, and storage runtimes. Hand-patching generated output
or treating a binding as a wire runtime is nonconformant.

## Normative authority

The generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.

License: MIT.
