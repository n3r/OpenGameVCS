# OGVCS-021 private deployment-preflight boundary review

**Decision:** SHIP only as a bounded, unpublished, unwired supplied-fact
candidate. Do not treat it as installation, environment inspection, health
authority, migration authorization, backup verification, administrator
bootstrap, or completion of OGVCS-021.

**Source baseline:** `fa221451b6b12d80bf54e9a48c3641e591639844`

## Reviewed seam

The candidate owns only a deterministic pure evaluation boundary:

1. accept exactly three listener, four secret-reference, and three service-
   account records in a canonical private shape;
2. reject unsafe supplied defaults, non-loopback cleartext, exposed
   administration/metrics records, zero/duplicate ports, public/diagnostic
   secret-reference facts, and root/interactive or duplicate principals;
3. bind one compatibility and configuration generation to exactly seven
   supplied dependency observations;
4. distinguish supplied process liveness from dependency readiness using only
   closed safe reason codes;
5. reject schema downgrades and bind a supplied irreversible-migration gate to
   the exact deployment, artifact set, source/target schema, source-state
   generations, verified manifest subject, separate source/target claims,
   evaluation time, and retention; and
6. return domain-separated configuration, observation, and structural-report
   commitments under an explicit caller-supplied observation-age fence plus
   work, memory, and cancellation envelopes.

The crate borrows caller records, checks exact cardinalities before traversal,
admits the reachable 18/19-unit logical work charge before semantic validation,
uses no validation-set heap allocation, stages reasons in a fixed buffer, and
admits a conservative 512–640-byte retained charge before result allocation.
All accepted collections have fixed small cardinality. These properties are
local deterministic accounting only, not exact allocator, CPU, latency,
capacity, or reference-scale evidence.

## Independent adversarial hardening

The frozen candidate was rejected until the independent pass repaired these
bounded defects:

- report construction had no evaluation time or observation-age fence, so an
  arbitrarily old observation and already-expired backup could still produce a
  newly issued ready report;
- irreversible evidence named opaque backup and verifier commitments but did
  not bind the deployment, source schema, relevant metadata, object-storage,
  verifier, backup, and schema observation generations,
  verified manifest subject, or separate source/target storage and credentials;
- optional backup evidence was silently accepted for non-irreversible intents;
- the public `mutation_ready` bit was redundant with `ready` after validation
  and implied authority this crate does not own; it was replaced by a narrowly
  factual evidence-presence bit used to reconstruct the work charge;
- validation allocated `BTreeSet`s before retained-memory admission while the
  documentation claimed pre-allocation admission;
- the advertised work and retained maxima were unreachable by the fixed shape,
  and retained bytes were overclaimed as exact allocator memory;
- structurally resealed reports could carry missing process reasons, multiple
  mutually exclusive states for one dependency, impossible work, or oversized
  reason collections;
- secret-reference commitments could alias across purposes; and
- default debug derives exposed listener, secret-reference, principal,
  generation, backup, and report commitments.

The independent integration audit also found that otherwise matching backup
evidence could be replayed across a different artifact set or irreversible
target schema. The private gate now binds and validates both fields, with
projection and mismatch regressions. The security-relevant shape change is
versioned as private rc.2 with V2 digest domains; V1 evidence/reports are not
accepted. This remains supplied evidence and does not make the gate mutation
authority.

The repair adds exact/max+1 cardinality and resource regressions, all 28
dependency-state mappings, temporal boundaries, stable error precedence,
complete configuration/observation/report projection mutation tests, backup
source-binding mutations, final pre-allocation cancellation polling, and
redacted logging checks.

## Security and authority review

The secret and principal values are opaque commitments. Boolean fields such as
`access_restricted`, `privileged_root`, and `included_in_diagnostics` are
untrusted supplied facts. The candidate cannot inspect permissions, detect a
default credential, verify a principal, read a secret provider, validate TLS,
own a listener, establish network policy, or inspect generated configuration,
images, command history, or diagnostic output.

Dependency generations and health states are likewise supplied facts. The
report's checksum is publicly recomputable and detects only accidental or
unrecomputed local field changes. It is not authentication, request-root
authorization, non-disclosure, freshness, or audit evidence and must not be
used as a bearer credential.

Evaluation time and the maximum 300-second observation-age policy are also
supplied facts. Binding them prevents silent omission from the checksum but
does not establish wall-clock truth or make a previously returned report fresh.
Default debug output is redacted, while explicit public fields remain available
to deliberate private callers.

## Migration and predecessor review

The private irreversible-migration gate rejects absent, zero, future-captured,
expired-at-evaluation, wrong-artifact/scope/source-or-target-schema/source-
generation, manifest-subject, source/target-alias, or non-irreversible backup
facts. Matching these supplied
fields does not prove that a backup contains the migration source state, that
the verification report was issued by OGVCS-017, that the manifest is complete
under OGVCS-018, that storage or credentials are actually separate, that
retention remains true after evaluation, or that migration and preflight share
one fenced transaction. A future adapter must authenticate and transactionally
bind all of those facts before any mutation. This candidate invokes neither
predecessor and has no authority to run, resume, roll back, or publish a
migration.

## Acceptance interpretation

- **AC-01:** open. There is no host install, bootstrap, repository creation,
  backup/restore execution, or verification drill.
- **AC-02:** bounded relevance only. Pure negative tests cover private
  listener, secret, principal, compatibility, generation, migration, resource,
  and supplied backup shapes without mutation. There is no real TLS,
  credential, permission, database, object-store, capacity, or clock probe.
- **AC-03:** bounded relevance only. The seven dependency classes and separate
  liveness/readiness result are modeled, but no injected production dependency
  failure or mutation gate exists.
- **AC-04:** bounded relevance only. Safe static defaults and absent raw secret
  values are represented, but no shipped image/configuration/listener,
  credential scan, diagnostics bundle, or security exercise exists.
- **AC-05:** open. There is no uninstall/reinstall behavior, named durable-data
  store, or recovery runbook.

## Residuals and nonclaims

OGVCS-021 remains Todo and all acceptance criteria remain open. Supported
versions and sizing, topology artifacts, prerequisite discovery, noninteractive
installation, first-admin bootstrap, real secret providers, public versioned
configuration, reload/restart behavior, migrations and ledger, OGVCS-017/018
integration, backup/restore, public health/metrics/logging, diagnostics,
repository creation, uninstall/reinstall, preserve/delete confirmation,
offline and clean-host runs, hosted cross-OS evidence, operator runbooks, timed
exercise, idempotency, scale/SLO proof, operations, rollout, and rollback remain
unimplemented.

The path-scoped hosted workflow is a pinned Linux/macOS/Windows source
portability gate only. Until an exact run is retained it is not evidence, and
even a green run is not deployment, clean-host, offline-runtime, upgrade,
rollback, recovery, or operator evidence.
