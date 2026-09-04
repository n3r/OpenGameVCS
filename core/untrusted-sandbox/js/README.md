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
read-only credential stay in the broker process. The state authority makes
bounded positional copies from verified handles into random, immutable named
aliases, fsyncs each alias and its owner-only temporary directory, and gives the
container adapter handles only. The adapter derives each ordinary host path
from its held descriptor, revalidates the registered path/inode/mode before
start and after settlement, and rejects procfs magic links, deleted names,
symlinks, or substitutions. Names remain present until the corresponding
container has settled and are then unlinked and directory-synced; startup
recovery removes crash leftovers. The parser receives only three read-only
mounts (input, canonical job, executable tool), an empty declared image
configuration, and a private bounded output volume.

Each parser container is created before it is started and is run as uid/gid
65532 with no network, a read-only root, all capabilities dropped,
`no-new-privileges`, private PID/cgroup/IPC namespaces, the owned default-deny
seccomp allowlist, cgroup memory/PID/CPU controls, rlimits, and bounded no-exec
scratch/output tmpfs mounts. The adapter explicitly selects a daemon-registered
OCI runtime named `runc`, labels the exact job and parser/output-shim/volume-anchor role,
requests private non-recursive bind propagation, and inspects the security,
resource, namespace, and mount projection while the container is still stopped.
Docker/Moby encodes its default private PID namespace as an empty inspected
`HostConfig.PidMode`; the adapter requires that exact value because the literal
`private` mode is not a valid Docker PID-mode input.
It requires the standard protected `/proc` and `/sys` masks/read-only paths but
admits additional daemon hardening paths. The output volume is also inspected
for the exact local tmpfs driver, options, ownership labels, and mountpoint used
by the container. Container ID and random name removal are both verified before
a result can settle.

The local-driver tmpfs volume is lazy-mounted and disappears when its last
container reference is removed. A pinned pause-only `volume-anchor` container
therefore mounts `/output` read-only before the parser starts and remains
running through the parser-to-shim handoff. It receives no tool, input, job,
binding, credential, environment, argument, or writable output mount; its only
writable filesystem is the same bounded private no-exec scratch tmpfs. Its exact
stopped and running projections are inspected, including its role/job labels,
entrypoint, volume source, read-only access, PID, lifecycle state, and every
ordinary isolation control. Anchor death closes the operation and settles the
exact anchor and volume; only the exact branded volume may replay an already
verified settlement.

Signed CPU budgets have whole-second kernel-enforcement granularity: the closed
profile accepts only 1,000 through 30,000 milliseconds in 1,000-millisecond
increments. It never rounds a smaller declared budget up to a larger rlimit.

The parser is removed before output validation begins while the read-only
anchor retains the tmpfs reference. A separate trusted shim then mounts only
the output volume and a fresh 256-bit frame secret. Its exclusive stdout emits
a bounded binary stream containing sorted portable paths, per-file lengths and
SHA-256 digests, and a terminal count/byte/stream commitment. The collector,
anchor, and volume settle as one owned unit before the host revalidates every
byte and adds HMAC-authenticated provenance with a broker-only evidence key.
The parser and anchor never receive the frame secret or evidence key.

Durable state lives under an operator-selected, owner-only root. It uses a
single-process boot/PID/start-time lease, atomic fsync-backed job/idempotency/
revocation/evidence records, immutable staged inputs, no-replace output commits,
a 64-job admission ceiling, restart denial for interrupted work, and quarantine
of outputs invalidated by tool/runtime revocation. A final commit and revocation
share the same serializer, so either publication wins and is then quarantined,
or revocation wins and publication is denied.

The state root also owns one private `0600` daemon-authority record. Its random
256-bit HMAC key derives an opaque authority ID; the key is copied into the
adapter only while the service is open and zeroed on release. Newly allocated
containers and tmpfs volumes carry the authority ID plus a keyed binding over
their random name, job, role, volume relationship, policy, runtime, and mount
plan. Startup now performs bounded exact-authority list and inspect calls before
it locally denies interrupted jobs. Unknown jobs, bad bindings, duplicate or
cross-bound graphs, malformed/truncated/over-limit responses, and control
timeouts produce only closed codes and hashed resource fingerprints in durable
quarantine and prevent the service from accepting work.

## Evidence and nonclaims

The source-only conformance tranche adds a canonical revision/source-set
snapshot, a private two-case importer/converter runner, and exact test-only
hard-kill hooks at 13 durable service boundaries. Portable reports are declared
target models: they require Node 24 and two `VALIDATED` results with no broker
credential or publication capability, but they do not claim host isolation.
The hard-kill child can run on POSIX hosts; restart-disposition conformance is
Linux-only because stale service-lease recovery depends on authenticated boot
ID, PID, and `/proc` start ticks. macOS therefore proves only child self-kill and
durable pre-restart state, while Windows skips POSIX `SIGKILL` cases.

The Linux v2 report schema accepts only allowlisted control facts and always
records `runtimeBinaryBinding` as `unproven`; a relative daemon runtime name is
not an exact OCI binary identity. The committed v2 document is a synthetic,
non-hosted schema fixture because the historical run has no retained exact runc
version/commit or complete controller observation. Likewise, the committed kill
document is an explicitly non-executed disposition model. Genuine three-OS,
live-Docker v2, and Linux restart reports still require a future authorized run
and retention decision. The historical v1 script and sole upload payload are
unchanged.

The Ubuntu hosted lane deterministically archives only the pinned trusted output
shim and volume anchor and imports that exact two-file rootfs as a one-layer
Linux/amd64 image with an empty image-authored environment and the exact runtime
labels. It does not use the Dockerfile frontend because that frontend injects a
default `PATH` even for a `scratch` stage. The lane is configured to exercise
real Docker create/start/cleanup, uid 65532 mount readability,
network/credential/host/sibling/undeclared-input isolation,
namespace/device/traversal denial, symlink/recursion validation, bomb/hang/fork/
clone/clone3 namespace/memory/disk/stdout/crash/CPU bounds, cancellation,
restart, expired-deadline terminal replay, idempotency, revocation, and next-job
health. Every failure after live-conformance entry retains only a closed
command/stage/result/diagnostic report; the workflow uploads that report even
when the live step fails. Portable protocol tests continue on Linux, macOS, and Windows. The
POSIX-owned reference-state tests are skipped on Windows without weakening
Linux ownership/mode admission; none of these portable tests are
kernel-isolation claims for macOS or Windows.

The Docker daemon, Linux kernel, broker host administrator, signed-manifest
authority, acquisition adapter, and evidence-key custody remain trusted. This
package does not expose Git/Perforce credentials to tools, provide repository
publication authority, validate consumer-specific semantics, or claim defense
against a compromised daemon/kernel/host administrator. Selecting and inspecting
the `runc` runtime name does not attest or version-pin the daemon-configured
runtime binary; that supply-chain proof remains a completion blocker. OGVCS-045
remains Todo until the authenticated public contract, a green hosted proof,
crash-boundary matrix, and all PRD acceptance evidence are frozen together.
The current restart tranche is detection-and-quarantine only: it does not yet
delete even a fully authenticated daemon orphan. Automatic container/tmpfs
settlement remains gated on explicit destructive-action approval. Discovery is
also intentionally scoped to the current authority ID. Legacy resources with no
authority label and resources owned by another authority are left untouched and
are not part of its absence proof. An operator that requires exclusive ownership
of a whole Docker daemon would additionally need a bounded brand-wide inventory
that fails closed on every legacy, missing, or foreign authority resource; this
candidate does not claim that stronger single-daemon guarantee. OGVCS-045 stays
Todo.
