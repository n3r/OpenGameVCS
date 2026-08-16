# OGVCS-041 critical review

- **Review date:** 2026-08-16
- **Reviewer:** Independent Codex critical-review pass
- **Initial verdict:** Not definition-of-ready; later not acceptance-ready
- **Current verdict:** Implementation candidate acceptance-ready; hosted and predecessor gates remain external

## Scope and method

The review began before implementation and challenged the PRD, architecture,
and candidate ADR for unresolved ownership, transport, framing, negotiation,
fingerprinting, grant, compatibility, generation, and rollback decisions. It
then examined ADR-0013, the declarative model and generator, every generated
schema/registry/profile/vector/document, all four generated binding packages,
the reference runtime, the independent process adapter, public API declarations,
offline packages, execution-view confinement, report tools, and three-OS
workflow.

The dynamic review included 28,889 bounded deterministic shallow RunnerCase
mutations across all nine executable operations: 12,036 over cursor,
idempotency, and transfer cases and 16,853 over negotiation, envelope, stream,
contract-load, runner-batch, and release-preflight cases. It also injected
duplicate fields, noncanonical Unicode/base64url, combined-invalid receipts,
lost responses, late commits, denied replay authorization, cursor scope drift,
EOF and malformed frames, malformed ranges/digests/ETags, proxy/TLS faults,
predecessor grant abuse, oracle reads, stderr/trace leaks, and configured resource
ceilings. The exact one-million-entry tree and logical-1-TiB cases were not run.

## Findings and remediation

| Area | Initial gap | Settled remediation |
|---|---|---|
| Contract authority | Transport, schema language, negotiation, fingerprint, cursor/grant carrier, transfer ownership, and generator were unresolved. | Accepted ADR-0013 fixes one bounded TLS1.3/HTTP1.1 JSON/JCS profile, JSONL streams, application-neutral Range carrier, authority boundaries, versioning, and rollback. |
| Independent semantics | The first adapter classified vector labels and loaded too little authority. | A separate engine authenticates schemas/registries/profiles itself, uses no reference runtime, and receives randomized oracle-free cases through a confined process. |
| Oracle isolation | Descriptive IDs, vector files, predecessor cases, and unrestricted filesystem access could reveal expected outcomes. | Runner-local opaque handles/order, expected-field removal, manifest-authenticated vector-free execution view, physically isolated package closure, and Node read permissions prevent oracle access. |
| Resource proof | Early max/max+1 rows compared virtual numbers and several callers allocated before checking combined memory. | All 35 limits execute through real reduced caller paths; loaders, parsers, streams, transfer, runners, replay, output, deadline, and retained-state paths preflight or account combined work. |
| Error privacy | Generic string parameters and error serialization could emit protected paths, policy, credentials, or cardinalities. | Closed per-code typed grammars, no generic detail/current-generation in R0, safe serialization, derived encoded/hash canaries, and full response/log/stderr trace scanning fail closed. |
| Idempotency | Deadline loss could release an in-flight reservation and duplicate a committed mutation; replay auth and tombstone/key lifetime were unsafe. | Pending mutations settle into durable outcomes, retries reconcile, authorization is fail-closed and rechecked, keys self-date within skew/lifetime bounds, and reused committed namespaces cannot silently mutate again. |
| Negotiation | Receipts did not always bind the selected tuple, deprecated rows could be selected, and extension branches were under-covered. | Mutation verification requires the tuple; MAC precedes expiry/binding disclosure; new sessions select candidate/ratified rows only; every selectable/required extension has positive/negative deterministic vectors. |
| Cursor/stream | Scope validation, expiry retirement, gap code, terminal schema, malformed-frame mapping, and EOF semantics could diverge. | Closed five-field scope schemas run before lookup; stable lifecycle outcomes and gap constraints are explicit; contract-required frames use fixed terminal kinds and EOF/mid-frame closure is incomplete. |
| Transfer | Grant vectors initially bypassed carried bytes; memory/deadline checks, resume validators, Range mapping, status precedence, ETag and Content-Digest enforcement were incomplete. | Each case carries concrete envelope/context/JWK and invokes the exact OGVCS-003 verifier; non-grant preflight precedes verification; actual bytes, ranges, strong ETags, RFC9530 digests, 200/206/416 rules and completion are executed. |
| Compatibility governance | Release preflight did not bind semantic drift or lifecycle and implied arbitrary additions. | 476 semantic assignment hashes freeze meaning; 24 release rows reject tuple/pin/assignment/lifecycle drift; R0 admits only exact predecessor-pre-reserved optional additions. |
| Generated bindings | Public declarations and non-JS wire-name/type descriptors could drift from schemas. | One model emits complete 46-message/352-field immutable descriptor tables and generated public TypeScript declarations for all four packages; validators compare every descriptor to schema/field authority. |
| Offline provenance | Packed scripts omitted sources, builds polluted retained trees, actions were mutable, and predecessor vector provenance was incomplete. | Closed source manifests reject extras; builds use staged copies; six exact MIT archives and generator inputs are digest-bound; workflow actions are commit-pinned and direct helper paths trigger CI. |

## Acceptance verdict

| Requirement | Verdict | Basis |
|---|---|---|
| FR-01 | Pass | ADR-0013 and executable transport/transfer profiles freeze TLS, proxy, redirect, compression, timeout, streaming, Range, validator, digest, and completion behavior without taking OGVCS-008 production ownership. |
| FR-02 | Pass | All ten independently negotiated dimensions have supported/unsupported evidence, including required/offered and deterministic multi-extension selection. |
| FR-03 | Pass | Forty-six closed schemas and 35 finite limits have executable reduced boundaries, cancellation/deadline behavior, and unknown-field policy. |
| FR-04 | Pass | Twenty-five stable errors use fixed safe status/title/retry/parameter domains; R0 deliberately omits current generation without an authenticated visibility contract. |
| FR-05 | Pass | Semantic JCS fingerprints, required descriptors, key reuse, response loss, late commit, replay authorization, expiry, and first-attempt/retry schedules are executable. |
| FR-06 | Pass | Opaque five-dimension cursors, expiry/gap/invalidation, page/stream state, terminal frames, and incomplete EOF are explicit and tested. |
| FR-07 | Pass | Exact predecessor manifest/vector provenance and 16 request-root verifier executions plus two explicit-object pre-verifier exclusions prove no claim reinterpretation. |
| FR-08 | Pass | Extension owner, namespace, lifecycle, requirement, fallback, security/data impact, affected schema, tuple, and pre-reserved-addition rules are machine-readable. |
| FR-09 | Pass at implementation boundary | One model generates four complete manifest-bound consumers; local TypeScript/C++ builds pass and retained Rust/C# compilation is a hosted evidence gate. |
| FR-10 | Pass | Offline runner covers all nine operations, exact traces, malformed, retry, cursor, downgrade, resource, release, security, and transfer cases. |
| NFR-01 | Pass locally | Clean generation and installed-package regeneration are byte-stable; comparator requires exact package/source/decision equality across three hosts. |
| NFR-02 | Pass | All finite bounds run through real reduced routes with pre-mutation results, combined accounting, safe errors, and protected-output scanning. Exact scale is explicitly separate. |
| NFR-03 | Pass | All source/generated/package artifacts carry the identical MIT text and the six-package closure installs, regenerates, and executes offline. |
| AC-01 | Pass | Genuinely separate engines receive only public authority, pass 360/360 exact rows, and cannot read either oracle corpus. |
| AC-02 | Pass | 273 rejects cover required failure classes with exact trace digest, stable code, pre-mutation flag, and mutation count. |
| AC-03 | Local implementation pass | Generation and local TS/C++ compile pass; hosted Rust/C#/three-OS retained-source compilation remains pending evidence. |
| AC-04 | Pass | Twenty-eight tagged red-team rejects plus sensitive-carrier/encoded/hash scanning find no protected error, negotiation, cursor, grant, trace, stdout, or stderr output. |
| AC-05 | Pass | Twenty-four release rows cover unknown/omitted/extra requirements, absent tuples, pin drift, reassignment/removal, lifecycle, semantic drift, and exact pre-reserved addition. |

## Residual boundary and roadmap dependency

No live P0 or P1 local implementation defect remains. The convenience
`conformance:external` script is not the durable isolation proof; the source and
packed evidence runners supply the explicit permitted adapter root. General
admission of an arbitrary new candidate manifest is intentionally deferred to a
future release-preflight version; R0 supports only predecessor-pre-reserved
additions. These are documented boundaries, not hidden compatibility claims.

The first hosted Ubuntu/macOS/Windows workflow and comparator remain external
evidence. OGVCS-002 is still in development because the maintainer deferred its
one-million-entry tree and logical-1-TiB tests to the final R0 campaign, and
OGVCS-004 consequently remains in Validation. The roadmap correctly prevents
OGVCS-041 from becoming Done or its 1.0.0 contract from being ratified while
those dependencies remain open.

## Recommendation

Accept ADR-0013 and preserve the frozen `1.0.0-rc.1` candidate. Keep OGVCS-041
in Validation. Run the ordinary hosted three-OS workflow and retain its package,
source, consumer-build, and report-comparison evidence without dispatching the
separate exact-scale job. At the final R0 campaign, close OGVCS-002's deferred
scale evidence and the OGVCS-004 dependency before ratification or moving this
PRD to `prd/done`.
