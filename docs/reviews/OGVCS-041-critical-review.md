# OGVCS-041 critical review

- **Review completed:** 2026-08-25
- **Implementation revision:** [`dfdd7ad`](https://github.com/n3r/OpenGameVCS/commit/dfdd7adcf07a3e6c964e97d21434f370c3664250)
- **Reviewer:** independent Codex critical-review passes
- **Final verdict:** no live P0, P1, or P2

## Scope and method

The review challenged the PRD and ADR before implementation, then examined
ADR-0013, the numbered declarative model, generator and independent validator,
every generated schema/registry/profile/vector/document, all four generated
binding packages, the reference runtime, independent process adapter, public
types, offline packages, execution-view confinement, report tools, and hosted
three-OS workflow.

Dynamic work included 28,889 bounded deterministic RunnerCase mutations across
all nine executable operations. It injected duplicate/unknown fields,
noncanonical Unicode/base64url, combined-invalid receipts, lost responses, late
commits, denied replay authorization, cursor-scope drift, malformed/partial
streams, invalid ranges/digests/ETags, proxy/TLS faults, predecessor-grant abuse,
oracle reads, stderr/trace leaks, callbacks/proxies/accessors, and reduced
resource ceilings. The final pass audited every public host-language boundary,
retained allocation, cancellation transition, external process crossing, and
same-stage error selection.

The OGVCS-002 million-entry/logical-1-TiB campaign is a separate completed
acceptance surface. It was not dispatched during this bounded protocol review.

## Findings and remediation

| Area | Initial or final-review gap | Settled remediation |
|---|---|---|
| Contract authority | Transport, schema language, negotiation, fingerprint, cursor/grant carrier, generation, and rollback were initially unresolved. | Accepted ADR-0013 fixes one bounded TLS1.3/HTTP1.1 JSON/JCS profile, JSONL streams, application-neutral Range carrier, authority boundaries, versioning, and rollback. |
| Independent semantics | The first adapter classified vector labels and authenticated too little public authority. | A separate engine authenticates schemas/registries/profiles itself, shares no semantic runtime, and receives randomized oracle-free cases through a confined process. |
| Hostile JS inputs | Public operations could inspect proxies/accessors or retain mutable caller records and callback results. | Exact inert snapshots reject proxies, accessors, inherited/extra fields, mutable aliases, and non-data collections before semantic use. |
| Resource accounting | Early limit rows and individual checks did not cover simultaneous retained plans, traces, streams, transfer data, and runner buffers. | A single operation budget charges every retained/captured representation and transient replacement before allocation; reduced max/max+1 regressions cover actual routes. |
| Deadlines | Reused signals/listeners and late settlement could make classification order-dependent or retain operations. | Operation-scoped composed signals, fixed first-boundary selection, listener cleanup, and immutable settlement preserve deterministic cancellation and replay. |
| Error privacy | Generic strings or exception paths could emit protected data. | Closed per-code grammars, inert details, encoded/hash canaries, trace/stdout/stderr scanning, and typed caller-failure mapping fail closed. |
| Idempotency | Response loss, pending settlement, replay authorization, and key expiry could duplicate or reinterpret mutations. | Stored records bind authority/fingerprint/outcome; retries reconcile immutable settlement, reauthorize, and reject mismatched or retired keys. |
| Negotiation | Receipts did not always bind the selected tuple; lifecycle and extension branches were incomplete. | Mutation verification requires the tuple; MAC precedes expiry/binding disclosure; only candidate/ratified rows are selectable; every required/optional extension branch has evidence. |
| Cursor/stream | Scope validation, gap/expiry outcomes, terminal schema, malformed frames, and EOF semantics could diverge. | Closed five-field scope validation, stable lifecycle results, fixed terminal kinds, bounded frame parsing, and explicit incomplete EOF are enforced. |
| Transfer | Grant vectors initially bypassed carried bytes; content/resource/range precedence was incomplete. | Concrete grant/context/JWK bytes invoke the exact OGVCS-003 verifier; transfer bodies have their own bounded data path; actual bytes, ranges, strong ETags, RFC9530 digests, 200/206/416 rules, and completion execute. |
| External runner | Descriptor getters, captured output, and JSON parsing could execute/allocate outside the declared operation budget. | Descriptors are inert-snapshotted before isolation; stdin, stdout, stderr, decoded output, and returned results are separately bounded and charged. |
| Compatibility | Release preflight did not bind all semantic/lifecycle drift. | 476 semantic assignment hashes and 24 release rows reject tuple/pin/assignment/lifecycle drift and admit only the exact predecessor-reserved optional addition. |
| Generated bindings | Public declarations and non-JS descriptors could drift from schemas. | One model emits the complete 46-message/352-field immutable descriptor authority; clean generation and all four retained consumers validate it. |
| Offline provenance | Packed scripts omitted sources or allowed build pollution/mutable workflow actions. | Closed source manifests reject extras; builds use staged copies; six exact MIT archives bind generator inputs; workflow actions use Node-24-compatible commit-pinned releases. |

## Security and reliability assessment

The independent adapter cannot read expected outcomes or predecessor vector
corpora. Every permission root and execution-view file is manifest-bound.
Successful executions require empty stderr, and all returned problems, traces,
stdout, encoded fields, and hashes are scanned for raw and derived protected
canaries. Transfer grants remain an imported OGVCS-003 authority; the protocol
does not reinterpret issuer, subject, repository, operation, epoch, expiry, or
replay claims.

All 35 finite limits have executable reduced boundaries. Composite working
memory accounts for simultaneous representations instead of comparing only
individual values. Resource/deadline stops are terminal, occur before mutation,
and remain stable across callback order. Idempotency settlement and cursor
lifecycle state are immutable once committed. No unbounded caller collection,
stream frame, trace, provider output, or external-process response enters a
semantic path.

## Requirement and acceptance matrix

| Requirement | Verdict | Evidence |
|---|---|---|
| FR-01 | Pass | ADR-0013 and executable transport/transfer profiles freeze TLS, proxy, redirect, compression, timeout, streaming, Range, validator, digest, and completion behavior without taking OGVCS-008 route ownership. |
| FR-02 | Pass | All independently negotiated dimensions have supported/unsupported evidence, including required/offered and deterministic multi-extension selection. |
| FR-03 | Pass | Forty-six closed schemas and 35 finite limits have real reduced boundaries, cancellation/deadline behavior, and explicit unknown-field policy. |
| FR-04 | Pass | Twenty-five stable errors use fixed safe status/title/retry/parameter domains and omit unauthenticated current-generation detail. |
| FR-05 | Pass | Semantic JCS fingerprints, required descriptors, key reuse, response loss, late settlement, replay authorization, expiry, and retry schedules execute. |
| FR-06 | Pass | Opaque five-dimension cursors, expiry/gap/invalidation, page/stream state, terminal frames, and incomplete EOF are explicit and tested. |
| FR-07 | Pass | Exact predecessor provenance and concrete request-root verifier executions prove the grant carrier does not reinterpret authorization claims. |
| FR-08 | Pass | Extension owner, namespace, lifecycle, requirement, fallback, impact, affected schema, tuple, and reserved-addition rules are machine-readable. |
| FR-09 | Pass | One model generates four complete manifest-bound consumers; retained Rust/C++/C#/TypeScript builds execute on Ubuntu, macOS, and Windows. |
| FR-10 | Pass | The offline runner covers all nine operations, exact traces, malformed input, retry, cursor, downgrade, resources, release, security, and transfer. |
| NFR-01 | Pass | Clean and installed-package generation are byte-stable; the hosted comparator proved package/source/decision equality across three hosts. |
| NFR-02 | Pass | All declared bounds run through actual reduced routes with pre-mutation results, composite accounting, safe errors, and protected-output scanning. |
| NFR-03 | Pass | All source/generated/package artifacts carry the same MIT text; the complete six-package closure installs, regenerates, and executes offline. |
| AC-01 | Pass | Separate engines receive only authenticated public authority, pass 360/360 exact rows, and cannot read either oracle corpus. |
| AC-02 | Pass | The 273 exact rejects cover every named fault class with stable code, trace, pre-mutation flag, and mutation count. |
| AC-03 | Pass | Generation is clean and retained Rust/C++/C#/TypeScript consumers compile/execute on all three hosted operating systems. |
| AC-04 | Pass | Twenty-eight tagged red-team rejects and derived-canary scans find no protected error, negotiation, cursor, grant, trace, stdout, or stderr output. |
| AC-05 | Pass | Twenty-four release rows cover unknown/omitted/extra requirements, tuple/pin drift, reassignment/removal, lifecycle, semantic drift, and the exact reserved addition. |

## Hosted and package verification

Workflow
[`32843391920`](https://github.com/n3r/OpenGameVCS/actions/runs/32843391920)
passed on the exact implementation source. Its three platform jobs compiled and
executed all four retained consumers and ran both adapters from offline-installed
archives. The comparator checked every archive, offline-source entry, manifest,
report, and result row. An independent replay over the downloaded artifacts was
byte-identical to the retained
[`comparison`](../evidence/OGVCS-041/conformance-comparison-2026-08-25.json).
The benchmark/fault-harness compatibility run
[`32843391941`](https://github.com/n3r/OpenGameVCS/actions/runs/32843391941)
also passed at the same commit.

## Final verdict

No live P0, P1, or P2 remains in OGVCS-041. All direct predecessors are Done;
the implementation, bounded security/resource proof, generated consumers,
offline package boundary, three-host comparison, documentation, rollback, and
every acceptance criterion are complete.

The public version remains `1.0.0-rc.1` by deliberate ADR lifecycle design.
OGVCS-005 is the first downstream consumer and may expose integration defects;
only a later compatible ratification change can mark `1.0.0`. This does not
permit private protocol forks or silent field/semantic reassignment and does not
leave an OGVCS-041 completion gate open.
