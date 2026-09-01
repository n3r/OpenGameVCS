# OGVCS-045 sandbox runtime boundaries

This package keeps two boundaries deliberately separate:

- the default export is the portable, candidate-only protocol supervisor used by
  the three-OS contract tests; and
- `@opengamevcs/untrusted-sandbox/linux` contains a candidate-named Linux x86_64
  reference worker backed by a local Docker Engine and cgroup v2.

The Linux constructor remains named `openLinuxReferenceSandboxCandidate` until
the exact shipped profile has passed its hosted live-kernel conformance gate.
It fails closed with the safe `SANDBOX_UNAVAILABLE` code on every other platform
or whenever Docker, cgroup v2 CPU/memory/PID controllers, seccomp, private
cgroup namespaces, the owned seccomp digest, or the signed runtime image are
unavailable.

## Linux reference boundary

The broker accepts only exact signed Ed25519 tool/runtime manifests. A job binds
the immutable input, tool, runtime, manifest, resource policy, options, actor,
purpose, deadline, and idempotency key. The source adapter and its narrow
read-only credential stay in the broker process. The parser receives only three
read-only held-file-descriptor mounts (input, canonical job, executable tool),
an empty declared image configuration, and a private bounded output volume.

Each parser container is created before it is started and is run as uid/gid
65532 with no network, a read-only root, all capabilities dropped,
`no-new-privileges`, private PID/cgroup/IPC namespaces, the owned default-deny
seccomp allowlist, cgroup memory/PID/CPU controls, rlimits, and bounded no-exec
scratch/output tmpfs mounts. Container ID and random name removal are both
verified before a result can settle.

The parser is removed before output validation begins. A separate trusted shim
then mounts only the output volume and a fresh 256-bit frame secret. Its
exclusive stdout emits a bounded binary stream containing sorted portable paths,
per-file lengths and SHA-256 digests, and a terminal count/byte/stream
commitment. The host revalidates every byte and adds HMAC-authenticated
provenance with a broker-only evidence key. The parser never receives the frame
secret or evidence key.

Durable state lives under an operator-selected, owner-only root. It uses a
single-process boot/PID/start-time lease, atomic fsync-backed job/idempotency/
revocation/evidence records, immutable staged inputs, no-replace output commits,
a 64-job admission ceiling, restart denial for interrupted work, and quarantine
of outputs invalidated by tool/runtime revocation. A final commit and revocation
share the same serializer, so either publication wins and is then quarantined,
or revocation wins and publication is denied.

## Evidence and nonclaims

The Ubuntu hosted lane builds a one-layer `scratch` image containing only the
pinned trusted shim, then exercises real Docker create/start/cleanup, uid 65532
mount readability, network/credential/host/sibling/undeclared-input isolation,
namespace/device/traversal denial, symlink/recursion validation, bomb/hang/fork/
memory/disk/stdout/crash bounds, cancellation, restart, idempotency, revocation,
and next-job health. Portable protocol tests continue on Linux, macOS, and
Windows; they are not kernel-isolation claims for macOS or Windows.

The Docker daemon, Linux kernel, broker host administrator, signed-manifest
authority, acquisition adapter, and evidence-key custody remain trusted. This
package does not expose Git/Perforce credentials to tools, provide repository
publication authority, validate consumer-specific semantics, or claim defense
against a compromised daemon/kernel/host administrator. OGVCS-045 remains Todo
until the authenticated public contract, hosted evidence, crash-boundary matrix,
and all PRD acceptance evidence are frozen together.
