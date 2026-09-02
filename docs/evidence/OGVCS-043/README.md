# OGVCS-043 bounded validator source evidence

This directory records only source/package verification for the private
`ogvcs-cli-evidence-validator` candidate based on
`101d5673252290de362844f381b5176ad33c470d`.

The candidate contains a fixed eight-component compatibility inventory, fixed
sixteen-phase transcript, OGVCS-002 Snapshot identity composition, typed safe
results/recoveries, monotonic timing checks, opaque participant/selection/root
commitments, redaction status, domain-separated digesting, checked resource
ceilings, and cancellation. The Rust test corpus includes the stable known
answer
`274826a1cb6c0f7987c064efb8d118abb626fbd1ea4f156a1c4b55eae9f5d1e9`.

Frozen source gates on 2026-09-02, followed by independent audit hardening,
produced:

- 67/67 locked/offline Rust 1.82 tests in debug and 67/67 in release;
- clean Rust format and warnings-denied all-target Clippy;
- an 11-entry Cargo package and 67/67 packaged integration tests from a
  freshly extracted crate with the packed OGVCS-002 dependency;
- 5/5 Node v24.9.0 source/package/PRD/workflow/evidence policy tests;
- a valid roadmap containing 46 PRDs (39 Todo and 7 Done) and 898 IDs, plus
  8/8 roadmap validator regressions;
- focused OGVCS-002 conformance 17/17 and repository 27/27; and
- a clean `git diff --check` at exact HEAD
  `101d5673252290de362844f381b5176ad33c470d`.

Generated build output is intentionally not retained here. Hosted push run
[33629145724](https://github.com/n3r/OpenGameVCS/actions/runs/33629145724)
passed the path-scoped Node 24/Rust 1.82 source regression on Linux, Windows,
and macOS for exact integrated commit
`c7049fd5063adaf40f6ad2f694104713966ed6c6`. The retained
[`hosted-source-run-33629145724.json`](hosted-source-run-33629145724.json)
binds all three successful job IDs and the exact bytes/SHA-256 digests of the
workflow and private crate source/package/test inputs. The bounded verdict is
SHIP for integration only as private, unpublished, unwired source and HOLD for
product evidence, release evidence, or PRD completion.

This is three-OS portability evidence for the private validator source only.
It is not a clean-host installed-CLI run, preview-artifact provenance result,
authenticated workflow, sync/lock/submit/fetch proof, workspace exact-byte
observation, redaction audit, signed evidence bundle, rollout, or
acceptance-criterion closure. OGVCS-043 remains in `prd/todo`; its completion
evidence records only this bounded source tranche and explicit non-rollout.
The full acceptance-criteria section remains byte-for-byte unchanged, and
AC-01 through AC-05 remain open.

## Additive route-less starter-deployment composition

The later private rc.2 candidate, based on exact integration parent
`8b6c55259bfad367e4d9c67598f561d957f19d35`, adds a fixed-width
`StarterDeploymentPreflightProjection`. It invokes OGVCS-021's bounded
supplied-fact builder directly and returns a projection only for a structurally
bound, live, ready result. It accepts no prebuilt report and creates no
compatibility record, scenario step, public route, credential carrier,
authorization fact, request-root proof, or mutation capability. The original
report-v1 transcript and known-answer digest remain unchanged.

The projection's 17 private fields have read-only getters. It has no
public constructor, setter, or mutable view; a compile-fail doctest proves safe
downstream code cannot replace a binding with Rust struct-update syntax. Only
the owning composition module can construct it after the predecessor checks.
This seal is a source-integrity boundary, not a signature, authority, or proof
of the caller-supplied facts.

Follow-on push run [33664922248](https://github.com/n3r/OpenGameVCS/actions/runs/33664922248)
passed the additive rc.2 source/package gate on Linux, macOS, and Windows for
exact revision `fa61786b272a019b82f4e96eaaa47dbef60c5b6c`. The retained
[`hosted-source-run-33664922248.json`](hosted-source-run-33664922248.json)
binds all three job identities and the exact workflow/crate source, package,
and test bytes, including the route-less projection. Public GitHub Actions
HTML supplied the creation time and displayed duration, so the recorded
completion time is their sum rather than an API-returned timestamp; public XHR
matrix fragments supplied the job identities, conclusions, and roadmap-step
dispositions.

This follow-on is exact-revision source portability only; it is not deployed,
clean-host, product, release, or acceptance evidence. OGVCS-043 remains
**Todo**, and AC-01 through AC-05 remain open.

The local bounded gates passed 75/75 debug tests, 75/75 release tests, and
75/75 tests from a freshly extracted 13-entry validator package, plus the
private-field compile-fail doctest 1/1 against both source and extracted
package. Rust format, warnings-denied all-target Clippy, separate packaging of
the OGVCS-021 predecessor, 6/6 Node v24.9.0 boundary-policy tests, the
46-PRD/898-ID roadmap, and 8/8 roadmap regressions also passed. These results
were produced in an isolated clone with build/package targets under
`/private/tmp`; they are source verification, not execution of an OGVCS-043
journey.
