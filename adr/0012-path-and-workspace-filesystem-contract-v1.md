# ADR-0012: Path and workspace filesystem contract v1

**Status:** Accepted
**Date:** 2026-08-16
**Owners:** OGVCS-004

## Context

OGVCS-002 fixes canonical NFC basename bytes, ordered tree encoding, entry-kind
and portable-mode assignments, `FileID`, and hard path-value ceilings. It does
not decide whether a complete path is safe or colliding on Windows, macOS, or
Linux, nor how a client may mutate a workspace without following an unintended
filesystem target. Those decisions must be frozen before repository services,
workspace lifecycle, status, sync, engine integrations, or the public protocol
can build compatible behavior.

Host locale and native filesystem comparisons are not a portable authority.
Windows, APFS, Linux filesystems, network mounts, and process APIs differ in
case, normalization, reserved names, symlinks/reparse points, replacement,
durability, executable bits, and change notifications. A library that merely
calls a host lowercase or path-normalization routine would allow repository
semantics to drift with the machine or runtime version.

## Decision

Path contract v1 consumes but never rewrites OGVCS-002 segment strings. A
repository path is a nonempty array of already-NFC segments and its display
form is their relative `/` join. Empty, dot, dot-dot, slash, backslash, NUL,
unpaired-surrogate, non-NFC, or over-limit inputs are rejected rather than
repaired. Repository creation permanently selects `case-sensitive` or
`case-folded` mode and one ratified platform profile.

`case-folded` uses the complete default Unicode case fold from Unicode 16.0.0:
the `C` and `F` mappings in the pinned `CaseFolding.txt`, excluding the optional
Turkic `T` mappings. The mapping is applied code point by code point to an NFC
input and the resulting code-point sequence is compared as UTF-8 bytes without
host-locale operations or post-fold normalization. The original NFC path stays
the display and identity value. The contract package ships the exact Unicode
source, digest, generated mapping, license, and golden cases.

Version 1 ratifies four profiles:

- `path.opengamevcs/portable@1` is the conservative Windows/macOS/Linux
  intersection and is the default production profile;
- `path.opengamevcs/windows@1`, `path.opengamevcs/macos@1`, and
  `path.opengamevcs/linux@1` declare a single supported host family.

Every profile stays within the OGVCS-002 maxima. The portable and Windows
profiles reject Win32 separators/control/device names, superscript COM/LPT
device aliases, alternate-data-stream colons, and trailing dot/space. macOS
profiles treat canonically equivalent names as colliding and declare both APFS
case variants. A platform collision key is always applied in addition to the
repository-mode key, so a case-sensitive repository cannot select Windows or
default case-insensitive macOS support while containing names those hosts
cannot distinguish.

Regular, executable, directory, and symlink entries retain the exact OGVCS-002
kind/mode meanings. A symlink payload is UTF-8 link-target text stored through
its content manifest; materialization never follows it. Symlink creation is
disabled unless the selected profile and measured workspace capability both
allow it. Version 1 preserves only the regular-file executable intent bit; it
does not claim portable ACL, owner, xattr, sparse allocation, or timestamp
identity. Read-only state is a nonversioned best-effort lock hint.

Workspace mutation uses a closed, module-branded preflight plan binding the
complete output set, repository case/profile selection, platform, measured
capabilities, and one workspace handle; the capability snapshot is rechecked
before mutation. It then uses a private owner-bound stage, exclusive
temporaries, no-follow inspection of every existing component, file and staged
content identity/digest checks around replacement, bounded directory-state
fingerprints for kind removal, bounded retry, a durable transaction
record, and an explicit commit marker. A detected link/reparse point,
capability mismatch, target identity change, crash remnant, or ambiguous
replacement fails closed. Case-only renames and rename cycles use deterministic
reserved temporary names. Directory/file replacement is staged before removal;
locked-open or antivirus interference returns a stable busy result and leaves
recoverable state rather than silently falling back to an unsafe copy.

The Node reference adapter protects against hostile repository input,
pre-existing links/reparse points, ordinary creator/replacement races, and
faults injected at every declared boundary. Like other path-string APIs, it
cannot preempt an actor with the same operating-system authority that can
continuously rename trusted ancestors between otherwise indivisible host API
calls. Supported deployments therefore provide a private workspace root whose
ancestors are not concurrently mutable by untrusted same-authority code. A
native adapter may strengthen this boundary with directory-handle-relative
operations, but must preserve the same visible outcomes. This boundary never
turns a detected race into success.

The portable Node adapter detects symlinks and junction-shaped entries but
cannot inspect every Windows reparse tag; a deployment admitting other reparse
classes supplies a stronger native adapter. File notifications are acceleration only. A persisted watcher state records an
adapter kind, opaque cursor, generation, clean/reconciling state, and session
marker. Cursor mismatch, overflow, unsupported resume, adapter error, state
corruption, or unclean shutdown irreversibly requires bounded reconciliation.
Only a completed full reconciliation at the expected generation may publish an
authoritative clean state. The portable Node adapter subscribes before running
the required bounded reconciliation callback, so changes in the former
reconcile-to-subscribe gap are either included by the scan or queued behind its
new cursor. Because `fs.watch` exposes no queue-drained barrier, its ordinary
notifications never promote a live index to authoritative clean; a stronger
journal adapter may do so only when its native cursor proves completeness.

## Consequences and proof

The language-neutral package publishes the profiles, errors, schemas, pinned
Unicode data, path/collision/materialization/rename/watcher vectors, and exact
manifest. The public JavaScript package implements the pure contract,
capability/preflight APIs, staged mutation, crash recovery, and watcher state
machine without private repository imports. Offline package tests and a
three-operating-system matrix compare every pure result byte-for-byte and run
native filesystem adversarial cases appropriate to each host.

The 2026-08-16 candidate reproduced 62 pure decisions and ten bounded native
proofs from offline-installed MIT packages. GitHub Actions run 31939458256
passed all 72 rows on Linux, macOS, and Windows, compared exact package bytes
and pure results, and retained a Linux syscall trace with zero outside-root
references. Its exact hashes and independent critical review are recorded in
the [OGVCS-004 evidence packet](../docs/evidence/OGVCS-004/README.md).
That historical evidence was superseded after final review; the current
ratification record and three-host run are linked from the OGVCS-004 evidence
packet. OGVCS-002's separate million-tree and logical-1-TiB acceptance campaign
is complete and is not represented as path-materializer evidence here.

Case mode, fold version, and platform profile are repository-immutable. A
changed mapping, collision rule, or meaning requires a new profile major and a
separate migration with collision preview. Rollback may disable materialization
or watcher acceleration, but never reinterpret an existing repository's keys
or mark an unreconciled workspace clean.

## Primary references

- Unicode Consortium, [CaseFolding-16.0.0.txt](https://www.unicode.org/Public/16.0.0/ucd/CaseFolding.txt)
  and [default case conversion](https://www.unicode.org/versions/Unicode16.0.0/core-spec/chapter-5/).
- Microsoft, [Naming Files, Paths, and Namespaces](https://learn.microsoft.com/windows/win32/fileio/naming-a-file).
- Apple, [Apple File System FAQ](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html).
- Node.js, [`fs` API](https://nodejs.org/docs/latest-v22.x/api/fs.html),
  including `lstat`, exclusive open, rename, link, watcher, and flush behavior.
