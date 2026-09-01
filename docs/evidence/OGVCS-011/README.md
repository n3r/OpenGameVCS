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

## Deliberately unclaimed

The first-party OGVCS-006/008/009 public adapters, local OGVCS-041 receipt-MAC
verification, remote end-to-end journeys, and later sync/status/materialize/
submit/lock integration remain open. Same-authority between-command namespace
replacement and the `CreateDirectoryW`-to-validation interval remain explicit
local residuals. OGVCS-011 therefore remains **Todo**.
