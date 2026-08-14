# ADR-0003: Object lifecycle and GC fencing

**Status:** Accepted  
**Date:** 2026-08-14  
**Owners:** OGVCS-008, OGVCS-010, OGVCS-018

## Context

A captured reachability generation and object-store deletion precondition do not prevent metadata from creating a new reference after mark. Backup completion also cannot depend on the production object store it is intended to recover.

## Decision

- Authoritative object lifecycle is `staged → available ↔ quarantined → deleting → deleted`, with a generation on every transition.
- Submit publishes only objects in `available`. It may atomically cancel an exact quarantine generation while bytes remain verified; it never references `deleting` or `deleted`.
- GC performs a current-root check before quarantine and again before CAS acquisition of `deleting`. Physical deletion is preconditioned on that generation and records a durable receipt.
- Crash recovery resumes lifecycle state rather than inferring it from storage listing alone.
- Backup completes only when every reachable object has a verified copy in the designated independently credentialed and retained backup target.

## Consequences and proof

The submit/GC implementation needs shared transactional lifecycle records. Model checking and fault tests must cover every submit, quarantine, revive, delete, repair, pin, shelf, and backup race.

