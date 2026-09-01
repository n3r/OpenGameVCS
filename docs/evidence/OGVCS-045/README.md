# OGVCS-045 sandbox candidate evidence

This packet retains bounded hosted evidence for the private Linux reference
sandbox and portable credential-free protocol candidate. It is not completion
evidence for OGVCS-045 and does not change the PRD's **Todo** status.

## Hosted boundary

- Exact source: [`8e863b503bf2c0ebc66d1f80cf7935e1575575d0`](https://github.com/n3r/OpenGameVCS/commit/8e863b503bf2c0ebc66d1f80cf7935e1575575d0)
- Workflow: [run 33484044441](https://github.com/n3r/OpenGameVCS/actions/runs/33484044441), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33484044441.json`](github-actions-run-33484044441.json)
- Closed Linux report: [`linux-reference-conformance-2026-09-01.json`](linux-reference-conformance-2026-09-01.json)

The exact-head run passed the live Linux Docker/cgroup/seccomp lane and the
portable protocol lanes on Ubuntu, macOS, and Windows with Node 24. The closed
Linux report contains 43 bounded case records: dummy importer/converter
success, inaccessible network/credential/host/sibling/undeclared/device/
namespace targets, denied symlink/recursive/disk/bomb/crash outputs, bounded
hang/fork/memory/CPU/output termination, and a clean importer result after
every hostile case. The same successful live step also executes cancellation,
restart replay, revocation of prior and new jobs, credential-free durable
evidence inspection, and exact cleanup assertions.

The retained report is byte-for-byte accepted by the candidate's closed report
builder. Its SHA-256 is
`27ff15154b4a6cfadd6626fed323a359b9907b3dc2b3c3eb9ac43a3fbce0b0fb`;
it contains 3,620 bytes and no failure payload.

## Deliberately unclaimed

The exported constructor remains candidate-named and is not a production or
public entry point. Exact deployed `runc` binary attestation, authenticated
daemon-orphan reconciliation, the complete broker/runner/output-validator
kill-boundary matrix, independent isolation review, consumer rollout, and
public conformance admission remain open. OGVCS-045 therefore remains
**Todo**.
