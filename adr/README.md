# OpenGameVCS architecture decisions

This directory records accepted cross-cutting decisions behind the normative behavior in [`architecture.md`](../architecture.md). ADRs are immutable after acceptance except for status, supersession links, and factual corrections. A changed decision receives a new ADR and coordinated architecture/PRD updates.

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-format-v1-root-snapshots-and-fileid.md) | Accepted | Root snapshots and FileID allocation/lifetime |
| [0002](0002-export-fidelity-and-authorized-projection.md) | Accepted | Separate fidelity and authorized-projection exports |
| [0003](0003-object-lifecycle-and-gc-fencing.md) | Accepted | Transactionally fenced object lifecycle and GC |
| [0004](0004-dr-authority-security-epochs.md) | Accepted | DR authority epochs and lost-acknowledgement reconciliation |
| [0005](0005-early-public-protocol-baseline.md) | Accepted | Freeze a minimal public protocol before R1 service work |
| [0006](0006-local-agent-security-boundary.md) | Accepted | Early local agent and explicit same-user threat boundary |
| [0007](0007-fixture-profile-v2.md) | Accepted | Replace the deficient fixture profile v1 draft with v2 |
| [0008](0008-format-v1-deterministic-cbor-and-object-identity.md) | Proposed | Deterministic CBOR, object IDs, layered validation, and hard format limits |
| [0009](0009-format-v1-object-graph-and-fileid-validation.md) | Proposed | Immutable graph, transition replay, groups, conflicts, and FileID proof |
| [0010](0010-core-profile-registries-and-logical-bundle-boundary.md) | Proposed | Core/path/chunk/export ownership and additive profile registries |
| [0011](0011-authorization-contract-v1.md) | Accepted | Authorization decision, authorized-view, transfer-grant, audit, and threat-contract v1 |
