# OGVCS-012 private workspace-index hosted evidence

This packet retains bounded hosted evidence for the private workspace-index
candidate. The current record covers the rc.4 status state-matrix tranche in
addition to the earlier fence, retention, and repair-equivalence work. It is
not completion evidence for OGVCS-012 and does not change the PRD's **Todo**
status.

## Hosted boundary

- Integrated source: [`a0c7bfdad33aca6e512069c5324c022cad5f35a8`](https://github.com/n3r/OpenGameVCS/commit/a0c7bfdad33aca6e512069c5324c022cad5f35a8)
- Registered workflow: [`.github/workflows/native-cli-local-candidate.yml`](../../../.github/workflows/native-cli-local-candidate.yml)
- Workflow: [run 33538231831](https://github.com/n3r/OpenGameVCS/actions/runs/33538231831), completed successfully on 2026-09-01
- Machine record: [`github-actions-run-33538231831.json`](github-actions-run-33538231831.json)

The exact integrated source passed the registered Node 24 and Rust 1.82
candidate workflow on hosted Linux, macOS, and Windows. Each job checked the
authenticated private contract and synchronized vectors through the default
native tests, including the rc.4 state matrix and repair-equivalence cases,
denied Clippy warnings, tested the packed crate, and exercised the separately
installed release binary through the hermetic controller. The setup logs bind
Node 24.19.0 on Linux and Windows and Node 24.18.0 on macOS; every job used
Rust 1.82.0.

The workflow did not execute the two ignored bounded-release tests, mint a
production watcher-continuity claim, expose a public status route, or run the
million-path SLO campaign. The production wrapper still installs unavailable
watcher authority and therefore fails closed. These results establish only
that this exact private candidate and its unavailable-authority behavior pass
the registered default gate on all three hosted operating systems.

## Remaining boundary

Native USN, FSEvents, and inotify authority; the public baseline/status/
repair/compaction surfaces; the remaining operation/native-fault matrix; a
safe public repair/reseed operation; the exact million-path SLO; telemetry;
rollout; and final acceptance remain open. OGVCS-012 remains **Todo**.

The earlier status-fence record remains retained as
[`github-actions-run-33513695931.json`](github-actions-run-33513695931.json).
