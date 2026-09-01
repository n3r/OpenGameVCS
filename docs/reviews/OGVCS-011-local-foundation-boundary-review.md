# OGVCS-011 verified local-foundation candidate boundary review

**Reviewed integration baseline:** `12512b4d75f93e4c3136be5dca68a2317e27ebfe`
**Candidate contract:** `spec/cli-workspace/v1` version `0.2.0-rc.2`
**Verdict:** a substantial fail-closed local tranche; OGVCS-011 remains Todo.

## What this tranche establishes

The candidate has a native command tree, exact fieldwise nonsecret config
precedence, stable human/JSON errors, explicit noninteractive behavior,
secret-safe headless/OS credential interfaces, typed versioned public ports,
and a real binary that fails before mutation when an owning public route is
unavailable.

Workspace v2 create/configure use digest-bound pending metadata and journals;
open/list/configure/remove/staging require a complete journal matching current
metadata. Recovery commits prepared transitions, removes validated stale
pending state, and reconciles deterministic root-bound removal records.
Configure/list/remove and diagnostics serialize only redacted reports.

Local add/move/delete/revert use OGVCS-004 canonical/collision keys and
server-issued FileIDs, retain a bounded local intent journal, and never upload
or submit. Add accepts only a completed, predecessor-reconciled allocation
handoff; it does not call `file-id.allocate`. The private journal retains the
opaque `far1` receipt and allocation idempotency-key digest for later first
registration, while every public report is digest-only. Linux/macOS mutations
use pinned parent descriptors and atomic no-replace rename primitives with both
parents synced. Windows has a
cross-compiled source-handle plus pinned destination-parent
`SetFileInformationByHandle` no-replace adapter.

Unix owner/mode/link checks, macOS extended ACL rejection, and Windows
owner/DACL/reparse/multi-link checks protect metadata. Windows DACLs must be
protected from inheritance and may grant access only to the owner, LocalSystem,
or Administrators. Creation-time Windows security descriptors prevent a broad
inherited-DACL publication interval; files and active lock handles deny delete
sharing. `CreateDirectoryW` still requires a subsequent no-follow validation
open, leaving a documented same-authority namespace interval. Failure there
leaves uncertain directory cleanup to explicit recovery rather than deleting a
possibly substituted handle. A persistent private root-level lock serializes
cooperating create/configure/stage/remove/recover operations and survives
`.ogvcs` detach.

## Evidence at this branch

The local Rust 1.82 gates include all-target tests, clippy with warnings denied,
an x86_64 Windows cross-compile, authenticated schema/vector checks, and an
offline packed artifact set containing the CLI plus the unpublished OGVCS-002
and OGVCS-004 Rust crates. Hostile cases cover:

- cancellation before publication and after create/configure/staging journals;
- deterministic removal crash reconciliation and concurrent remove/recover;
- symlink, junction, reparse, unsafe mode, inherited/broad DACL, and hostile
  lock/removal namespace entries;
- kernel-level racing-destination no-replace behavior;
- exact registry capability skew before mutation;
- credential redaction and explicit secret-byte zeroization;
- receipt redaction/zeroization and lost-handoff response with no local journal;
- explicit/private diagnostic creation with no path, endpoint, locator,
  identity, or secret output.

Hosted three-OS runtime evidence is pending. The workflow matrix is defined for
Linux, macOS, and Windows with Node 24 and Rust 1.82, but the workflow file is
not on the repository default branch and cannot yet be dispatched by path from
this branch. An evidence-only ref using an already discoverable default-branch
workflow may be used; no PR is part of this review.

## Exact residual matrix

| Residual | Current behavior | Owning completion condition |
| --- | --- | --- |
| OGVCS-009 authentication route | `UnavailablePublicRoutes` fails before mutation | Publish and integrate the public authentication/session route |
| OGVCS-006 discovery/binding route | Typed port and fakes only; no private DB access | Publish repository discovery and binding validation routes |
| OGVCS-006 FileID allocation/status | Not called by `stage_add`; the command requires a complete preallocated fact | Publish an idempotent allocation/status adapter that reconciles lost responses and hands off FileID + `far1` receipt |
| OGVCS-008 lifecycle/FileID lookup | Typed resolve/presentation seams and fakes only | Publish the owning lifecycle and registered-identity authority |
| OGVCS-041 receipt proof | Exact selected facts/registry pins and receipt digest are checked; client does not MAC-verify full claims | Branded verified receipt from an exact MAC-first verifier, or client-visible claims/session-key verification |
| Remote E2E | No first-party network adapter exists | Exercise real authentication/discovery/binding without invented routes |
| Hosted Windows runtime | Adapter cross-compiles; runtime result pending | Green Windows lifecycle/mutation/ACL/reparse/race workflow evidence |
| Same-authority namespace attack | Root lock serializes cooperating processes; Windows denies delete sharing while held, but Unix detach and Windows between-command replacement plus `CreateDirectoryW`→validation races remain | Stronger root/dirfd or native directory-handle namespace exclusion if same-authority malicious replacement is in threat scope |
| Later CLI journeys | No sync/status/materialize/submit/locks | Integrate owning PRDs through OGVCS-043 |

The `public-service-verified` metadata label therefore means “validated through
the typed adapter contract” in this candidate. It is not independent evidence
of a real remote receipt until the residual above is closed.

## Release decision

This commit is suitable for integration as an incomplete, executable local
foundation. It must not move the PRD to Done, claim remote compatibility, or
ship as a trusted production binding until the public routes, receipt proof,
and hosted three-OS evidence are complete.
