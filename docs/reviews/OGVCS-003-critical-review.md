# OGVCS-003 critical review

- **Review date:** 2026-08-16
- **Reviewer:** Independent Codex critical-review pass
- **Initial verdict:** Not acceptance-ready
- **Final verdict:** Accepted; no residual P0, P1, or P2 implementation or CI defect found

## Scope and method

The review examined the PRD, architecture, ADR, all language-neutral schemas and
registries, generated sources, policy fixtures, decision/grant/abuse vectors,
independent auditor, public JavaScript API and CLI, external-adapter protocol,
offline packages, comparator, and pinned three-platform workflow. It treated a
content hash as public identity, assumed every holder/client/adapter value was
hostile, and tested mixed-failure selection, self-consistent manifest changes,
deep and large canonical JSON, stale epochs and keys, grant replay/scope,
authorized-view aliases, malformed NDJSON, invalid UTF-8, output overflow,
nonsettling children, package tampering, and OS-specific archive metadata.

The review used the principles in [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final),
the [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html),
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), and
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700). The packaged example adapter
was treated as protocol evidence only. It was not credited as proof of a future
production server; such an adapter must execute each vector through its real
public boundary.

## Findings and remediation

| Area | Initial gap | Settled remediation |
|---|---|---|
| Public denial oracle | Explicit deny and absence of allow were externally distinguishable. | Both collapse to `DENY_NOT_AUTHORIZED`; internal policy detail is audit-only. |
| Transfer grants | Holder-controlled request roots, membership, key material, or incompletely bound claims could enable confused-deputy use. | Ed25519 claims bind issuer/key ID and generation, subject, permission/operation, tenant/repository, audience, epoch, time, nonce/replay, and object plan. The verifier recomputes the domain-separated root from trusted local plan state and selects its JWK from trusted issuer configuration. |
| Registry evolution | Assignment hashes froze names/codes but a self-consistent semantic change could refresh the manifest. | The independent validator now pins both assignments and all 13 complete canonical registry documents; semantic-drift mutations fail. |
| Decision and audit relationships | Closed shapes did not alone prove allowed/code polarity or audit-class permission coupling. | Generated schemas, runtime validators, generated types, and independent mutation tests freeze both exact relationships. |
| Authorized views | Candidate aliases, hidden counts, global cursors, or post-filter aggregation could disclose protected state. | Duplicate IDs are rejected, filtering precedes every count/order/page operation, cursors bind only the authorized set, and protected fixture fields are stripped. |
| Hostile JSON and API inputs | Recursive/implicit JavaScript behavior could allocate, call accessors, accept ambiguous Unicode, or escape typed bounds. | Fatal UTF-8, canonical text, closed objects, depth/node/byte/string/key ceilings, accessor/symbol/hidden/sparse rejection, path bounds, and typed fail-closed errors cover every public input. |
| Adapter boundary | A child could hang, overflow, reorder, add fields, emit invalid UTF-8, or claim conformance without a clear real-boundary obligation. | The runner uses no shell, a minimal environment, canonical closed NDJSON, strict order/count/code checks, bounded stdout/stderr/line/time, process-tree termination, and explicit real-boundary attestation language. |
| Roadmap coverage | Public/protected and audit behavior could drift or omit a later PRD. | A frozen 45-row registry maps every roadmap PRD; the independent auditor compares it to `ROADMAP.md` and rejects omissions or invalid audit mappings. |
| Package and license | Initial packaging lacked a final license decision and exact retained cross-platform package proof. | The maintainer selected MIT; root/spec/runtime license text is byte-identical. Offline-installed packages retain exact hashes and are uploaded from every OS. |
| Archive reproducibility | npm encoded the declared CLI mode differently on Windows and POSIX hosts. | A bounded tar validator normalizes the CLI header/checksum and emits deterministic portable gzip blocks; the installed npm shim is black-box tested and all three archives now have identical SHA-256. |
| CI provenance | Mutable action tags or incomplete triggers could invalidate security evidence. | All actions use full commit SHAs, roadmap and contract sources trigger the workflow, all platform packages/reports are retained, and a separate job re-hashes and compares all six reports. |

## Threat verdict

All critical and high entries in the machine-readable threat registry are
`mitigated`, identify executable abuse cases, and passed the reference and
adapter runner paths. The sole accepted medium risk is aggregate timing
inference from repeated bounded requests. It names OGVCS-009/OGVCS-035 as owner,
OGVCS-035 as the roadmap item, and an explicit expiry; response-class padding,
rate limiting, and aggregate monitoring are required. No other accepted or
unresolved critical/high risk remains.

## Settled proof

The ordinary root presubmit passed with both existing exact-scale tests skipped
by their explicit opt-in gates. Authorization-specific results were 23/23
runtime tests, 15/15 language-neutral/package tests, and 1/1 packed report-tool
test. The independent authority validates 10 schemas, 13 registries, two
policies, 40 decisions, 30 abuse vectors, 16 grant cases, and all 45 roadmap
PRDs. Both exact MIT-licensed npm archives install offline.

[GitHub Actions run 31933804281](https://github.com/n3r/OpenGameVCS/actions/runs/31933804281)
passed on exact product source `dcaae7e2c3cb966e9698cf86ee52ecc81f6381d3`.
Ubuntu, macOS, and Windows each executed the complete spec/runtime/packed suite;
the comparison job independently re-hashed all retained files and required all
six reference/external-adapter reports to match result SHA-256
`6cf806951e198e71a616ed72362c7db5aedfb25230c3dd492fec897799d88c1f`.

## Acceptance verdict

| Criterion | Verdict | Basis |
|---|---|---|
| OGVCS-003-AC-01 | Pass | Trust zones, data flows, grant roots/keys, authorized views, tenant boundaries, audit, revocation, and sandbox controls are frozen; all critical/high threats have passing executable mitigations. |
| OGVCS-003-AC-02 | Pass | Thirty executed abuse vectors cover every named category and their forbidden disclosure fields. |
| OGVCS-003-AC-03 | Pass | All 45 roadmap PRDs have exact classification, surface, resource, permission, and audit mappings with mutation detection. |
| OGVCS-003-AC-04 | Pass | Independent and runtime evaluators reproduce all 40 internal-team/restricted-outsourcer decisions exactly. |
| OGVCS-003-AC-05 | Pass | The privacy review covers collected data, purpose, minimization, retention, access, redaction, subject controls, and audit boundaries. |

## Final recommendation

Accept ADR-0011 and move OGVCS-003 to `prd/done`. Downstream production policy,
identity, issuance, and audit services remain OGVCS-009 work and must run the
public adapter suite through their real boundaries. The maintainer-deferred
million-entry and logical-1-TiB tests belong to OGVCS-002's final R0 campaign;
they were not run and are not an OGVCS-003 completion dependency.
