# OGVCS-026 — Sandboxed asset previews and diffs

**Status:** Todo  
**Release:** R2 — Studio Alpha  
**Priority:** P1  
**Owner:** Unassigned  
**Depends on:** OGVCS-003, OGVCS-009, OGVCS-025, OGVCS-045  
**Blocks:** OGVCS-031, OGVCS-035, OGVCS-039  
**Source:** [OpenGameVCS proposal](../../GAME_DEV_VCS_ANALYSIS.md)  
**Last updated:** 2026-08-14

## Outcome

Authorized reviewers can inspect useful derived previews and comparisons for common game assets without granting parsers network, host, repository, or credential access and without trusting generated output as source content.

## Problem

Visual review is valuable, but game assets and their converters are untrusted inputs and complex native code. Running preview tools inside the server or desktop trust boundary creates a high-impact code-execution and data-exfiltration path. Generated artifacts also need exact provenance and authorization-aware caching.

## Scope

### In scope

- Isolated asynchronous preview/diff jobs, signed allowlisted converter manifests, strict input/output/resource contracts, output sanitization, and provenance.
- Authorization-aware derived-artifact storage/cache and review integration.
- Reference text/image/audio/basic structured-metadata renderers sufficient to validate the platform.

### Out of scope

- Full digital-asset management, arbitrary repository scripts/plugins, authoritative semantic merge, video transcoding farm, or public third-party converter marketplace.

## Users and journeys

- **Reviewer:** requests a preview/diff for an authorized shelf revision, receives a clearly labeled derived artifact, and can always download/open the source using normal permissions.
- **Operator:** disables a vulnerable converter version, invalidates its cache, and audits affected jobs.
- **Security engineer:** proves the worker cannot reach metadata services, credentials, network, host filesystem, or unrelated objects.

## Requirements

### Functional

- **OGVCS-026-FR-01:** A job SHALL bind exact input object IDs, authorized requester/review context, converter ID/version/digest, options, resource class, and output policy.
- **OGVCS-026-FR-02:** Inputs SHALL be copied through the OGVCS-045 acquisition/input broker into a fresh read-only sandbox; converters SHALL receive no repository token, user credential, object-store credential, or path enumeration API.
- **OGVCS-026-FR-03:** Converter execution SHALL use an OGVCS-045 conforming runner that denies network by default, isolates process/user/mount namespace as supported, uses a read-only runtime, writable scratch quota, syscall/capability restrictions, and wall/CPU/memory/output limits.
- **OGVCS-026-FR-04:** Only signed allowlisted converter manifests and immutable runtime images SHALL execute; revocation SHALL block new jobs and invalidate affected cached outputs.
- **OGVCS-026-FR-05:** Outputs SHALL be type/size/count validated and sanitized/re-encoded where applicable before publication; active content SHALL be rejected or served under a constrained content policy.
- **OGVCS-026-FR-06:** Derived artifacts SHALL be labeled non-authoritative and keyed by all input digests, converter identity, options, and security-policy generation.
- **OGVCS-026-FR-07:** Fetch/list/event access SHALL re-evaluate authorization for the source inputs/review; possession of a derived-artifact ID SHALL not grant access.
- **OGVCS-026-FR-08:** Job errors SHALL expose safe typed diagnostics without returning converter stderr, source paths, or hidden metadata to unauthorized users.
- **OGVCS-026-FR-09:** Jobs SHALL be queued, cancellable, retry-bounded, idempotent, and resistant to decompression bombs, recursive formats, parser hangs, and excessive fanout.
- **OGVCS-026-FR-10:** Every artifact SHALL retain provenance and audit links to inputs, converter/runtime digests, policy, job, timestamps, and sanitization outcome.
- **OGVCS-026-FR-11:** Preview-specific output sanitization, authorization and cache policy SHALL layer on OGVCS-045 without weakening its credential separation, tool revocation, provenance, safe errors or required worker profile.

### Quality attributes

- **OGVCS-026-NFR-01:** Sandbox escape and credential/network/host access attempts in the adversarial corpus MUST fail and generate security telemetry.
- **OGVCS-026-NFR-02:** Preview unavailability or failure MUST never block source download, review decision recording, repository submit, or content integrity.
- **OGVCS-026-NFR-03:** Cache hits MUST produce byte-identical artifacts for deterministic converters or be explicitly marked nondeterministic and non-reusable.

## Interfaces and data

Define an OGVCS-045 converter profile, job request/state, derived artifact, sanitization result, preview provenance extension, cache key, revocation, and safe error taxonomy. The review service stores references, not trusted source replacements.

## Development plan

1. Implement preview converter profiles/signing/revocation and job/artifact/provenance schemas on the OGVCS-045 broker/runner contracts.
2. Add any required preview worker adapters while retaining OGVCS-045 no-network/credential-free isolation, limits, cleanup and safe errors on supported platforms.
3. Implement reference converters, output type/size validation and sanitization, authorization-aware artifact storage/cache/retrieval, and review integration.
4. Complete escape/resource/parser/output/auth-revocation red-team suites, add worker operations/runbooks, and enable one converter/repository at a time.

## Acceptance criteria

- **OGVCS-026-AC-01:** Adversarial converters cannot access network, host files, credentials, metadata APIs, sibling jobs, or undeclared objects on every supported worker platform.
- **OGVCS-026-AC-02:** Bomb/hang/crash/fork/output-flood/malformed-output cases terminate within declared limits, clean up, and leave the service healthy.
- **OGVCS-026-AC-03:** Removing user permission immediately prevents retrieval/reuse of an existing artifact and direct-ID probes reveal no source/review existence.
- **OGVCS-026-AC-04:** Revoking a converter prevents new execution and cache delivery for that converter generation while preserving audited evidence.
- **OGVCS-026-AC-05:** Golden reference assets produce correct labeled previews/diffs with exact input/tool provenance and source fallback.
- **OGVCS-026-AC-06:** Every converter profile passes OGVCS-045 conformance and seeded attempts to acquire credentials/network/direct publication or weaken a required control fail before execution.

## Verification plan

Sandbox red-team corpus, network/credential canaries, parser fuzzing, resource-exhaustion tests, output active-content scans, authorization/revocation races, deterministic cache tests, worker crash recovery, and manual review usability checks.

## Telemetry and operations

Expose queue age, job duration/result, resource-limit kills, converter/runtime version, cache hit, sanitizer rejects, and sandbox security violations. Source names/content and user identity stay out of shared metrics; detailed audit is access-controlled.

## Rollout and rollback

Disable by default, then enable one pure/reference converter at a time for selected repositories. Emergency rollback revokes converter/runtime digests and stops workers; reviews continue with source download and existing decisions.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Native parser escapes isolation | Defense-in-depth sandbox, no credentials/network, patched immutable images |
| Generated HTML/media attacks reviewer | Re-encode/sanitize, constrained serving origin/content policy |
| Cache leaks revoked source | Authorization recheck on every retrieval and revocation-aware key |
| Preview is mistaken for canonical truth | Prominent derived label, provenance, source access path |

## Completion evidence

- Implementation changes:
- Test and benchmark results:
- Security/reliability review:
- Documentation/runbooks:
- Rollout result:
