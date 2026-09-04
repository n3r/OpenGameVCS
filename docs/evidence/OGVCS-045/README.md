# OGVCS-045 sandbox candidate evidence

This packet retains bounded hosted evidence for the private Linux reference
sandbox and portable credential-free protocol candidate, including the exact
restart-hardening integration revision. It is not completion evidence for
OGVCS-045 and does not change the PRD's **Todo** status.

## Hosted boundary

- Exact restart-hardening source: [`3563167763a54b97eb8166ded1db895aa3a5b7cd`](https://github.com/n3r/OpenGameVCS/commit/3563167763a54b97eb8166ded1db895aa3a5b7cd)
- Exact-head workflow: [run 33636956770](https://github.com/n3r/OpenGameVCS/actions/runs/33636956770), completed successfully on 2026-09-02
- Exact-head machine record: [`github-actions-run-33636956770.json`](github-actions-run-33636956770.json)
- Exact-head closed Linux report: [`linux-reference-conformance-2026-09-02-run-33636956770.json`](linux-reference-conformance-2026-09-02-run-33636956770.json)
- Historical initial source: [`8e863b503bf2c0ebc66d1f80cf7935e1575575d0`](https://github.com/n3r/OpenGameVCS/commit/8e863b503bf2c0ebc66d1f80cf7935e1575575d0), [run 33484044441](https://github.com/n3r/OpenGameVCS/actions/runs/33484044441), and its [machine record](github-actions-run-33484044441.json)

The restart-hardening exact-head run passed the live Linux Docker/cgroup/seccomp
lane and the portable protocol lanes on Ubuntu, macOS, and Windows with Node
24. The closed Linux report contains 43 bounded case records: dummy importer/converter
success, inaccessible network/credential/host/sibling/undeclared/device/
namespace targets, denied symlink/recursive/disk/bomb/crash outputs, bounded
hang/fork/memory/CPU/output termination, and a clean importer result after
every hostile case. The same successful live step also executes cancellation,
restart replay, revocation of prior and new jobs, credential-free durable
evidence inspection, and exact cleanup assertions.

The latest retained report is byte-for-byte accepted by the candidate's closed
report builder. Its SHA-256 is
`b3e292a64173ac76857c04545e3c41fb2a6b0a7c76e63b0271c380b050e7c472`;
it contains 3,621 bytes and no failure payload. The portable lanes also execute
the restart-detection and closed-diagnostic regressions; the workflow does not
perform authenticated orphan settlement.

## Non-hosted source-only v2 models

The [`source-only-v2`](source-only-v2/README.md) directory records deterministic
models bound to source revision
`22a6b801b6d32283dca8a6f8ca57a4d91a91296f` and source-set SHA-256
`2baa1c704468812d689783e95e0d07113c761b11cc42a9a0ecff493d49df0c98`.
It contains declared-target Linux/macOS/Windows portable reports and their
comparison, a Linux v2 schema fixture that preserves the existing v1 cases and
digests, and a non-executed 13-boundary restart-disposition model.

These files were not produced by a new hosted run. They explicitly deny host
isolation, live Docker, exact runtime observation, child execution where
applicable, public admission, publication authority, and hosted retention. The
Linux fixture uses synthetic `unobserved` runtime facts and records
`runtimeBinaryBinding: "unproven"`; the historical run's exact runc
version/commit and complete controller set are unknown. The existing v1 reports
above remain unchanged.

## Deliberately unclaimed

The exported constructor remains candidate-named and is not a production or
public entry point. Exact deployed `runc` binary attestation, approved
authenticated daemon-orphan settlement, the complete broker/runner/output-
validator kill-boundary matrix, independent isolation review, consumer rollout,
and public conformance admission remain open. OGVCS-045 therefore remains
**Todo**.
