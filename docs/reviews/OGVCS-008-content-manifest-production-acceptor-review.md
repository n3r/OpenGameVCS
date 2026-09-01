# OGVCS-008 content-manifest production acceptor candidate review

**Review date:** 2026-09-01

**Verdict:** additive bounded candidate is ready for integration review; real
authority transport and request-root scale remain open

## Proven boundary

The opt-in object-transfer service path accepts only an opaque port built by
`createRepositoryMetadataContentManifestCandidatePort()`. It maps grant slugs
through the trusted metadata adapter, reads the durable stored manifest rather
than upload/session bytes, and fetches every referenced chunk from the same
tenant/repository authority. Lifecycle and backend identities are checked
before and after every bounded range. `verifyManifest()` creates the fresh
one-use receipt; a complete snapshotted OGVCS-002 registry is required; and the
metadata availability call occurs only inside `commitProductionManifest()`'s
commit callback.

The owning adapter must provide one atomic transaction, authorize every chunk
against the exact signed object set, and lock or revalidate all observed
dependency generations through commit. The package independently binds a
sorted dependency-generation digest into the accepted command and committed
proof. Commit recovery requires an authenticated current proof binding the
exact authority, subject, tenant scope, manifest/object/backend identity,
generation, immutable production statement, verification digest, and original
finalize semantic fingerprint. Lifecycle state `available` without that proof
fails closed.

Adapter dispatch and mutable transactions remain behind WeakMap brands.
Capabilities, registry inputs, requests, mappings, lifecycle records, commands,
and proofs are snapshotted; port/authority/transaction cross-instance and
prototype/proxy substitution is denied. Raw adapter messages, causes, getters,
symbols, proxies, and thrown values are converted to fixed transfer error
classes without paths, identifiers, grants, or secret details.

## Bounded hostile evidence

The focused 13-case local suite covers:

- early, middle, and last missing, corrupt, wrong-length, wrong-ID,
  wrong-receipt, and unauthorized dependencies;
- stored-manifest mutation and durable-source enforcement;
- lifecycle quarantine/generation changes before and after reads and an exact
  dependency-generation change immediately before commit;
- precommit abort exactly once, settled commit/response loss plus restart,
  mismatched response repair, and rejection of an available row without proof;
- partial/duplicate registries, raw/proxy/prototype/cross-instance port and
  handle forgeries, mutable passive inputs, and hostile adapter error values.

The fake metadata adapter recomputes the dependency generation-set digest and
revalidates every exact recorded field at commit. No generic lifecycle CAS is
opened by this candidate; the frozen rc.6 transaction participant and semantic
vectors are unchanged.

## Exact non-claims

The capability profile is `explicit-grant-object-set/v1`: at most 4,096 unique
objects including the manifest. It advertises
`requestRootDependencyClosure=false`. Supporting the 100-GiB profile requires
a verifier-owned bounded request-root closure tied to a stable session
principal and the real OGVCS-003/006/009 adapter; attempting to infer or swap
that authority locally would weaken the session binding. Therefore this
candidate is non-scale and cannot satisfy gate 3 for OGVCS-007 ratification.

No JS-to-Rust/PostgreSQL production transport, public route, shared-registry
ratification, hosted production deployment, or exact 100-GiB run exists in this
change. OGVCS-008 remains Todo.
