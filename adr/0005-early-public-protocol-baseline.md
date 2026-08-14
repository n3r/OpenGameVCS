# ADR-0005: Early public protocol baseline

**Status:** Accepted  
**Date:** 2026-08-14  
**Owners:** OGVCS-041, extended by OGVCS-036

## Context

R1 services and clients cannot develop independently if transport, version negotiation, errors, pagination, idempotency, and schema generation are owned only by an R3 conformance PRD.

## Decision

- OGVCS-041 delivers the minimal normative control/transfer protocol baseline in R0 before R1 API implementation.
- R1 services own domain messages but conform to OGVCS-041 envelopes, negotiation, limits, errors, cursors, idempotency, and generated-binding rules.
- OGVCS-030 builds its initial package compatibility matrix from the baseline registry.
- OGVCS-036 does not redefine the initial wire contract; it expands public black-box conformance, ecosystem profiles, deprecation, and LTS coverage after production surfaces exist.

## Consequences and proof

R0 gains one critical-path PRD and is reforecast. Every R1 public API must pass protocol vectors before its PRD can complete.

