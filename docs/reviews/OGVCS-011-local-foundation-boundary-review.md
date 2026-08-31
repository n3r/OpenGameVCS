# OGVCS-011 local-foundation candidate boundary review

**Reviewed integration baseline:** `252deacef1df273102dca99e9d49b1ea83b1f722`
**Candidate contract:** `spec/cli-workspace/v1` version `0.1.0-rc.1`
**Verdict:** safe to cut as a local-only, explicitly unverified candidate.

## Why this limited contract is safe now

OGVCS-006 and OGVCS-009 still leave their public protocol bindings assigned to
a future release. OGVCS-008 is a development candidate rather than an
authoritative client lifecycle integration, and OGVCS-041 supplies generic
envelope ownership without an OGVCS-011/domain route. No local metadata field
can honestly certify a remote repository, capability, authentication session,
or lifecycle state at this baseline.

The candidate consequently owns only local values whose authority it can prove:
source resolution, a manifest-bound versioned result envelope, private metadata layout,
post-publication interruption recovery, a credential **availability** seam, and redaction. Its
declaration values are retained as one-way digests labelled
`unverified-local-declaration`; no server or raw credential is touched.

## Explicit non-goals and predecessor blockers

The candidate does not preflight OGVCS-004 working-tree semantics because it
does not mutate a repository path. It fails closed where its own filesystem
ownership/permission check is not supportable. macOS owner, mode, and extended
ACL checks are enforced; a Windows ACL adapter remains a required predecessor
before claiming cross-platform workspace safety. Continuously hostile
same-authority namespace replacement remains outside this local candidate's
documented boundary, and the binary does not yet expose user-facing progress or
signal cancellation.

The following must wait for predecessor contracts:

| Deferred surface | Required owner/binding |
| --- | --- |
| repository discovery and capability negotiation | OGVCS-006 public route/capability contract plus OGVCS-041 message binding |
| sign-in/token persistence or device flow | OGVCS-009 identity/credential contract |
| verified repository/branch/baseline/spec binding | OGVCS-006 repository identity plus OGVCS-008 lifecycle authority |
| working-tree add/move/delete/revert | OGVCS-004 native path adapter and an OGVCS-008 transaction/lifecycle seam |
| sync, submit, status, locks | their feature PRDs and OGVCS-043 integration ownership |
| Windows private metadata claim | native ACL ownership/permission adapter and hostile Windows coverage |

This is therefore an implementation tranche, not an OGVCS-011 Done claim and
not a compatibility promise for unfinished remote commands.
