# OGVCS-020 bounded preflight source evidence

Pinned push run [33638102757](https://github.com/n3r/OpenGameVCS/actions/runs/33638102757)
passed the private Node 24/Rust 1.82 Git/LFS preflight source and package gates
on Linux, macOS, and Windows for exact revision
`0e714329a903573c7aa0d16a58adda8bf67e1088`. The adjacent machine record
retains the exact run, job IDs, and bounded claim.

Follow-on push run [33664922211](https://github.com/n3r/OpenGameVCS/actions/runs/33664922211)
passed the expanded private preflight and strict one-tree-frame decoder gates
on all three operating systems for exact revision
`fa61786b272a019b82f4e96eaaa47dbef60c5b6c`. Its adjacent
[`hosted-source-run-33664922211.json`](hosted-source-run-33664922211.json)
binds the observed job identities to the exact workflow/crate source,
package, test, and golden-input bytes. The run creation time and displayed
duration came from public GitHub Actions HTML, so the recorded completion time
is their sum rather than an API-returned timestamp; public XHR matrix fragments
supplied the job identities and conclusions.

This is source-portability evidence only. It is not evidence of a full Git
repository parser or traversal, LFS attribute discovery, conversion,
persistence, authenticated import, repository reconciliation, scale,
publication, or release. OGVCS-020 remains **Todo**, and AC-01 through AC-07
remain open.
