# ADR-0002: Export fidelity and authorized projection

**Status:** Accepted  
**Date:** 2026-08-14  
**Owners:** OGVCS-033, OGVCS-036

## Context

A canonical snapshot commits to its complete root tree. Omitting a protected path changes that tree and every descendant snapshot ID, so one export cannot both preserve source IDs and redact part of a mixed-visibility snapshot.

## Decision

- Repository-complete fidelity export requires authorization for every selected reachable record and fails atomically on incomplete visibility. It preserves canonical IDs and supports identical-root restoration.
- Authorized projection export constructs a new derived graph containing only the caller's authorized view. It has distinct IDs, explicit projection provenance, non-disclosing omission markers, and no full-fidelity claim.
- A projection cannot overwrite, impersonate, or be reported as the source repository during import.
- Both modes have separate verifier profiles, manifests, signatures, and acceptance evidence.

## Consequences and proof

Tests must cover mixed-visibility snapshots, indirect parent/tree disclosure, counts/errors/manifests, deterministic projected IDs, fidelity round-trip, and rejection of a projection presented as a fidelity artifact.

