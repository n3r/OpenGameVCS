# OGVCS-043 private CLI evidence validator boundary review

- **Review date:** 2026-09-02
- **Source boundary:** uncommitted candidate based exactly on
  `101d5673252290de362844f381b5176ad33c470d`
- **Candidate verdict:** **SHIP** for integration only as this bounded private,
  unpublished, unwired validator seam; **HOLD** for product evidence, release
  evidence, or any OGVCS-043 completion claim
- **PRD verdict:** OGVCS-043 remains Todo; AC-01 through AC-05 remain open

## Owned boundary

This candidate owns only a pure, fixed-cardinality validator for a supplied
compatibility inventory and a supplied ordered R1 CLI journey transcript. It
composes the OGVCS-002 Rust `ObjectRef` for Snapshot identity. It defines no
replacement for an owning component's public protocol, behavior, durable
state, authorization, recovery, or platform contract.

The canonical inventory names the native CLI and the seven direct OGVCS-043
dependencies: OGVCS-021, OGVCS-041, OGVCS-011, OGVCS-012, OGVCS-013,
OGVCS-016, and OGVCS-010. The fixed scenario preserves the PRD journey order,
including artifact/compatibility preflight before a declared mutation and the
second-workspace fetch/verification boundary.

## Enforced properties

- Exactly eight compatibility records and sixteen scenario records are
  accepted, in one canonical order.
- Artifact, component, protocol, format, capability, selection, root, and
  exact-byte commitments are nonzero fixed-width values. Executed request and
  result commitments are nonzero; skipped records use canonical zero values.
- Structured versions are nonzero, and every component agrees on the same
  protocol and format commitment/version pair.
- Artifact provenance/compatibility facts must be affirmative, every route is
  public/versioned, and every mutation phase declares a prior capability
  check. A private-fallback value always fails.
- Executed timings are monotonic within and across steps. Safe result/recovery
  pairs are typed, and a closed phase matrix covers every non-`None` recovery
  class. A terminal safe failure/cancellation forces every later phase to be
  explicitly not run with zero ticks and prevents the successful disposition.
- The two workspaces and two identities cannot alias within or across binding
  kinds. The two selections, selected root, and exact-byte-verification
  commitments are pairwise distinct. No raw identity, path, or content field
  exists, and their opaque wrappers redact `Debug` output.
- Submit, recovery, fetch, and exact-byte verification use the OGVCS-002
  Snapshot reference kind and converge on one identity when completed.
- Selected item/byte and excluded-nonmaterialization counts are checked. Only
  an excluded count, not excluded paths, is represented.
- The redaction status must be allowlist-verified.
- A domain-separated deterministic digest binds all accepted report fields and
  returned summary fields, including fixed record counts and the distinct
  executed-step count, except operational acceptance limits, which are
  explicitly not report semantics. It is not keyed or signed.
- Literal hard maxima, checked accounting, borrowed fixed input, a fixed
  retained-state reservation, and cancellation fences bound validation. All
  terminal failures return no report digest or summary.

## Adversarial review findings resolved

The first self-audit found that a fail-closed or cancelled step could be
followed by later successful records while still returning only a generic
incomplete label. The validator now enforces causal stop semantics: after a
terminal result, every later fixed phase must be `NotRunAfterSafeStop`, carry
no Snapshot, and claim no mutation. Regression tests cover both a success
after stop and a skip without an earlier stop.

The digest projection was also made explicit and expanded to bind the derived
disposition, common Snapshot, timing summary, record counts, charged work, and
retained-state reservation. Caller-selected operational limits remain outside
the digest by design and are documented as such. The retained reservation was
made a fixed 768-byte cross-platform value, guarded by a compile-time modeled
state assertion, so host layout cannot change otherwise identical digests.

Independent review found that records marked `NotRunAfterSafeStop` still
carried arbitrary nonzero request/result commitments and fabricated-looking
timestamps, and those timestamps extended the returned elapsed-time summary.
Skipped records now require canonical zero evidence/ticks and do not advance
executed timing. The summary now distinguishes fixed record cardinality from
the number of executed steps. The same review added a cancellation poll after
digest finalization and before report release, redacted opaque bindings from
derived debug output, prohibited cross-purpose binding aliasing, and removed
a nonexistent docs.rs public-documentation target from the unpublished
package.

A follow-up independent review found incomplete recovery causality: only
submit resolution, lock reacquisition, and content refetch were phase-scoped.
The validator now has an exhaustive matrix for all eight non-`None` recovery
classes. Exact-request retry and cancellation resume are meaningful in every
fixed phase; reauthentication is limited to authenticated phases 4–14;
branch refresh/restage to submit and submit-result recovery; lock reacquisition
to hard-lock edit and submit; content refetch to the two sync/fetch phases and
byte verification; and disk recovery to phases 3, 6, 7, 9, 10, 13, 14, and 16.
All 128 recovery/phase cells are exercised independently, while the existing
result/recovery pairing checks retain precedence.

## Nonclaims and residuals

The crate never opens an artifact, process, socket, file, repository,
workspace, credential store, service, database, or object store. It neither
executes nor observes install, authentication, sync, status, lock, submit,
recovery, fetch, byte verification, clean-host provisioning, fault injection,
or redaction. Its affirmative facts are caller assertions whose truth requires
the future public adapters and hermetic/hosted evidence owner. On an incomplete
result, predeclared context and compatibility commitments are not evidence
that skipped phases ran.

There is no language-neutral schema, public CLI output contract, evidence
signature, diagnostics bundle, product package provenance verifier, fault
schedule, clean-host installed-CLI runner, release artifact, private adapter,
persistence, or route registration. The path-scoped three-OS workflow compiles
and tests only this private source boundary. OGVCS-010/011/012/013/016/021/041
remain the behavior owners. OGVCS-030 remains the release-signature owner.

Consequently this source seam cannot satisfy any part of OGVCS-043-AC-01
through AC-05 and cannot advance the R1 release gate.

## Frozen source gates

- Rust 1.82 format and warnings-denied Clippy: clean.
- Locked/offline validator tests: 67/67 debug and 67/67 release.
- Cargo package verification: 11 packaged entries; unpublished manifest.
- Freshly extracted package integration tests: 67/67.
- Node v24.9.0 source/package/PRD/workflow policy: 4/4.
- A path-scoped Node 24/Rust 1.82 Linux/macOS/Windows source-regression
  workflow is retained; this frozen packet claims no hosted run result.
- Roadmap: 46 PRDs (39 Todo, 7 Done), 898 IDs; validator tests 8/8.
- Focused OGVCS-002 predecessor checks: conformance 17/17 and repository
  27/27, including typed references and Snapshot/repository semantics.
- OGVCS-043 remained Todo and its full acceptance-criteria section remained
  byte-for-byte exact at SHA-256
  `285256a0ad5afe001af90fd0c90324a348f2228ef7531e10d4e2a2652ddb4b5e`;
  only the date and precise bounded completion-evidence/non-rollout fields were
  updated. `git diff --check` was clean.

All gates ran from the uncommitted branch `r1-cli-evidence-v1` at exact HEAD
`101d5673252290de362844f381b5176ad33c470d` with build targets confined to
`/private/tmp`.
