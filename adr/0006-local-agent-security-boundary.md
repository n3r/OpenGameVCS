# ADR-0006: Local-agent delivery and security boundary

**Status:** Accepted  
**Date:** 2026-08-14  
**Owners:** OGVCS-042, extended by OGVCS-038

## Context

First-party Unreal and Unity integrations require local workspace/lock orchestration before the R4 public SDK. Existing requirements also implied reliable identification of hostile processes running with the same OS user privileges, which common desktop platforms cannot universally guarantee.

## Decision

- OGVCS-042 delivers the minimal authenticated local agent and first-party IPC before engine integrations.
- OGVCS-038 later adds public SDK languages, simulator breadth, third-party compatibility, and ecosystem conformance on the established protocol.
- The agent defends against other OS users, unauthenticated clients, endpoint exposure, replay, stale grants, and capability overreach.
- Same-user malware is outside the guaranteed isolation boundary. Sensitive operations require scoped consent or trusted desktop confirmation; no reusable server/object-store credential is released to integrations.

## Consequences and proof

Security claims and tests distinguish other-user attacks, unregistered same-user clients, and fully compromised same-user sessions. Documentation must not claim that IPC authentication defeats same-user malware.
