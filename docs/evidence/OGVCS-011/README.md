# OGVCS-011 native CLI candidate evidence

This packet retains bounded hosted evidence for the verified local-foundation
candidate. It closes the previously pending three-OS runtime check, but it is
not completion evidence for OGVCS-011 and does not change the PRD's **Todo**
status.

## Hosted boundary

- Production source: [`e23437f4762e7639bf40033546919211a2b4ce9b`](https://github.com/n3r/OpenGameVCS/commit/e23437f4762e7639bf40033546919211a2b4ce9b)
- Integrated equivalent: [`ebfa77f9ebd40e472301afcf8471aa8fe4118a86`](https://github.com/n3r/OpenGameVCS/commit/ebfa77f9ebd40e472301afcf8471aa8fe4118a86)
- Evidence source: disposable ref [`0493d298fd367ed2115f8218a3f784e2a8a46e90`](https://github.com/n3r/OpenGameVCS/commit/0493d298fd367ed2115f8218a3f784e2a8a46e90)
- Workflow: [run 33463547586](https://github.com/n3r/OpenGameVCS/actions/runs/33463547586), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33463547586.json`](github-actions-run-33463547586.json)

Node 24 and Rust 1.82 contract generation/synchronization, independent spec
tests, formatting, native tests, Clippy with warnings denied, and offline
packed-crate execution passed on Ubuntu, macOS, and Windows. The Windows job
executed the private protected-DACL creation and validation, real file and
directory flushes, root/ancestor/source detach denial, forced destination
collision, handle-relative no-replace rename, and hostile Windows component
tests on the hosted Windows kernel.

The evidence source uses a disposable replacement of the already registered
`path-filesystem.yml` workflow solely to make the branch dispatchable. That
carrier commit is excluded from integration; only the audited production
commits were cherry-picked.

## Installed-artifact hermetic boundary

- Integrated source: [`fadb76e0a8cae1429d1547cfcbdfb923d107aff2`](https://github.com/n3r/OpenGameVCS/commit/fadb76e0a8cae1429d1547cfcbdfb923d107aff2)
- Registered workflow: [`.github/workflows/native-cli-local-candidate.yml`](../../../.github/workflows/native-cli-local-candidate.yml)
- Workflow: [run 33496814160](https://github.com/n3r/OpenGameVCS/actions/runs/33496814160), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33496814160.json`](github-actions-run-33496814160.json)

The registered push workflow passed on Ubuntu, macOS, and Windows from the
exact integrated source. In addition to the contract, native, Clippy, and
packed-crate gates above, each host built the normal release target, installed
only its declared runtime payload into a fresh directory, built the independent
test controller elsewhere, and exercised the installed binary through process
restart. The gate rejects build/source leakage, mutation on hostile roots,
credential or locator disclosure, and cross-command secret persistence. The
Windows controller creates the valid fixture root with the product's native
protected-DACL primitive and separately proves that an Everyone-writable root
is rejected before `.ogvcs` creation.

This later run supersedes the earlier packet only for the hermetic
installed-artifact and Windows fixture-root checks. It does not turn the local
candidate into a public service or satisfy the unfinished adapters and
integrated journeys below.

## Deliberately unclaimed

The first-party OGVCS-006/008/009 public adapters, local OGVCS-041 receipt-MAC
verification, remote end-to-end journeys, and later sync/status/materialize/
submit/lock integration remain open. Same-authority between-command namespace
replacement and the `CreateDirectoryW`-to-validation interval remain explicit
local residuals. OGVCS-011 therefore remains **Todo**.
