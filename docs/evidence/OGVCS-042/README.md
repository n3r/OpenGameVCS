# OGVCS-042 bounded local-agent IPC source evidence

Pinned push run [33636845159](https://github.com/n3r/OpenGameVCS/actions/runs/33636845159)
passed the private Node 24/Rust 1.82 IPC source and package gates on Linux,
macOS, and Windows for exact revision
`3563167763a54b97eb8166ded1db895aa3a5b7cd`. The adjacent machine record
retains the exact run and job identities.

Follow-on push run [33664922199](https://github.com/n3r/OpenGameVCS/actions/runs/33664922199)
passed the expanded private IPC model and strict client-hello decoder
source/package gates on all three operating systems for exact revision
`fa61786b272a019b82f4e96eaaa47dbef60c5b6c`. Its adjacent
[`hosted-source-run-33664922199.json`](hosted-source-run-33664922199.json)
binds the observed job identities to the exact workflow/crate source, package,
and test bytes. The run creation time and displayed duration came from public
GitHub Actions HTML, so the recorded completion time is their sum rather than
an API-returned timestamp; public XHR matrix fragments supplied the job
identities and conclusions.

This is source-portability evidence only. It is not an agent process, OS-local
endpoint, OS-user authentication, credential path, public schema/binding,
authenticated product journey, scale result, rollout, or release result.
OGVCS-042 remains **Todo**, and AC-01 through AC-05 remain open.
