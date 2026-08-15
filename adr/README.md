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
