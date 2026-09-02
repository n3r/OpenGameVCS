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

The stable replay field is `authorizationClosureSha256`, exactly
`SHA-256("OGVCS-OBJECT-TRANSFER-AUTHORIZATION-CLOSURE-V1\0" ||
canonicalBytes({objectIds: sortedUniqueExplicitObjectIds, requestRoot: null}))`.
It is derived inside the service from verified claims and crosses the authority
request, lookup, commit command, and immutable proof. Nonce and grant times are
excluded so a fresh equivalent grant can authenticate a settled commit;
narrower and substituted sets are rejected before proof disclosure.

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

## Route-less explicit composition follow-up

The Rust repository-metadata module now exposes an instance-branded composition
around the existing v12 participant. It accepts only an already
negotiation-verified OGVCS-041 `object.put` request brand and matches its
correlation, tenant, repository, authority epoch, identity subject, manifest
ObjectID, canonical byte length, and raw stream SHA-256 to the complete
explicit-set commit or reconciliation input. It re-verifies the negotiation
receipt at the database clock before the OGVCS-009 participant authorizes every
page, and it delegates the only mutation to the existing SERIALIZABLE v12
transaction. Cross-instance handles, principal/scope substitutions, and exact
set substitutions fail before protected state is consulted.

This reuses the public OGVCS-041 request envelope only as authenticated internal
control facts. `object.put` remains unregistered, the metadata route inventory
remains empty, and no OGVCS-041 success envelope can be constructed by the
composition. The public transfer carrier is still request-root-only and rejects
explicit object sets, so it is intentionally not used or changed.

The self-dating OGVCS-041 idempotency carrier is revalidated for currentness at
the database clock, but no public mutation is dispatched or stored. It is not
equated to the existing private finalize fingerprint because those fingerprints
are independently domain-separated and describe different commands.

## Exact non-claims

The capability profile is `explicit-grant-object-set/v1`: at most 4,096 unique
objects including the manifest. It advertises
`requestRootDependencyClosure=false`. Supporting the 100-GiB profile requires
a verifier-owned bounded request-root closure tied to a stable session
principal and the real OGVCS-003/006/009 adapter; attempting to infer or swap
that authority locally would weaken the session binding. Therefore this
candidate is non-scale and cannot satisfy gate 3 for OGVCS-007 ratification.

No JS-to-Rust/PostgreSQL invocation transport, grant-subject-to-identity
mapping authority, multi-object grant issuer, public route, shared-registry
ratification, hosted composition evidence, production deployment, or exact
100-GiB run exists in this change. OGVCS-008 remains Todo.
