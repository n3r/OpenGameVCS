# OGVCS-014 bounded local-checkpoint source evidence

Pinned push run [33664922225](https://github.com/n3r/OpenGameVCS/actions/runs/33664922225)
passed the private Node 24/Rust 1.82 local-checkpoint source and package gates
on Linux, macOS, and Windows for exact revision
`fa61786b272a019b82f4e96eaaa47dbef60c5b6c`. The adjacent
[`hosted-source-run-33664922225.json`](hosted-source-run-33664922225.json)
uses the `ogvcs.local-checkpoint/hosted-source-run/v1` convention and binds
the public run/job identities to the exact bytes and SHA-256 digests of the
workflow and private crate source/package inputs.

The public GitHub Actions HTML supplied the run creation time and displayed
duration; the recorded completion time is their sum, not an API-returned
timestamp. Public XHR matrix fragments supplied the job identities and
conclusions because the unauthenticated API quota was exhausted. This
collection boundary is also explicit in the machine record.

This is exact-revision source-portability evidence only. It is not checkpoint
creation, checkpoint restore, a crash/corruption or real-power-loss matrix,
an installed product journey, scale evidence, rollout, or release evidence.
OGVCS-014 remains **Todo**, no acceptance criterion is claimed, and AC-01
through AC-05 remain open.
