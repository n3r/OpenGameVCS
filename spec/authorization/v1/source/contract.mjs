export const CONTRACT_VERSION = '1.0.0';
export const REGISTRY_SCHEMA = 'ogvcs.authorization/registry/v1';

function entry(code, name, description, extra = {}) {
  return { code, name, description, ...extra };
}

export const permissions = Object.freeze([
  entry(1, 'discover', 'Learn that an authorized resource exists.'),
  entry(2, 'metadata.read', 'Read authorized metadata without materializing content.'),
  entry(3, 'content.materialize', 'Download or materialize authorized content.'),
  entry(4, 'content.upload', 'Upload content into an authorized bounded request.'),
  entry(5, 'lock.create', 'Create or renew a lock or edit-intent claim.'),
  entry(6, 'submit', 'Create or advance authoritative repository state.'),
  entry(7, 'review', 'Read, comment on, approve, or promote an authorized review.'),
  entry(8, 'export', 'Create an authorized fidelity or projection export.', { privileged: true, reasonRequired: true }),
  entry(9, 'policy.administer', 'Create, preview, or change authorization policy.', { privileged: true, reasonRequired: true }),
  entry(10, 'lock.force-unlock', 'Break or transfer another subject\'s lock.', { privileged: true, reasonRequired: true }),
  entry(11, 'repair', 'Quarantine, repair, or restore authoritative data.', { privileged: true, reasonRequired: true }),
  entry(12, 'retention.delete', 'Change retention or irreversibly delete retained state.', { privileged: true, reasonRequired: true }),
  entry(13, 'audit.read', 'Read or export protected audit records.', { privileged: true, reasonRequired: true }),
  entry(14, 'impersonate', 'Act through an explicitly recorded support impersonation.', { privileged: true, reasonRequired: true }),
]);

export const resources = Object.freeze([
  entry(1, 'repository', 'Repository identity, settings, and discoverability.'),
  entry(2, 'reference', 'Branch, tag, mutable reference, or head.'),
  entry(3, 'snapshot', 'Immutable snapshot and its authorized history view.'),
  entry(4, 'tree', 'Authorized tree or directory view.'),
  entry(5, 'path', 'Canonical repository path and FileID-bound state.'),
  entry(6, 'object', 'Immutable metadata object addressed by typed identity.'),
  entry(7, 'content', 'Manifest, chunk, file bytes, or transfer request root.'),
  entry(8, 'lock', 'Hard lock or advisory edit-intent record.'),
  entry(9, 'review', 'Shelf, review, approval, check, or promotion state.'),
  entry(10, 'search', 'Authorized search, facet, suggestion, or index view.'),
  entry(11, 'event', 'Authorized event, cursor, webhook, or automation view.'),
  entry(12, 'cache-entry', 'Tenant-scoped verified immutable cache entry.'),
  entry(13, 'export', 'Fidelity or authorized-projection export operation.'),
  entry(14, 'policy', 'Policy, group, role, credential, or identity administration.'),
  entry(15, 'audit', 'Protected append-only audit event or query.'),
  entry(16, 'retention', 'Backup, restore, legal hold, retention, or GC state.'),
  entry(17, 'repair-job', 'Integrity verification, quarantine, or repair operation.'),
  entry(18, 'sandbox-job', 'Hook, merge, import, preview, or parser sandbox execution.'),
]);

export const actorClasses = Object.freeze([
  entry(1, 'anonymous', 'Unauthenticated external caller.'),
  entry(2, 'human', 'Authenticated human user.'),
  entry(3, 'service', 'Nonhuman build or service identity.'),
  entry(4, 'administrator', 'Privileged human or break-glass administrator.'),
  entry(5, 'cache', 'Regional or local content cache verifier.'),
  entry(6, 'sandbox-worker', 'Credential-free untrusted-code worker.'),
]);

export const credentialClasses = Object.freeze([
  entry(1, 'anonymous', 'No authenticated credential.'),
  entry(2, 'session', 'Short-lived human session.'),
  entry(3, 'service-token', 'Scoped nonhuman service token.'),
  entry(4, 'transfer-grant', 'Audience- and resource-bound signed transfer grant.'),
  entry(5, 'offline-lock-receipt', 'Bounded offline lock proof that never authorizes content.'),
]);

export const decisionCodes = Object.freeze([
  entry(1, 'ALLOW_EXPLICIT', 'An explicit matching rule allowed the request.', { allowed: true, publicSafe: true }),
  entry(2, 'ALLOW_PUBLIC', 'The resource is explicitly public contract material.', { allowed: true, publicSafe: true }),
  entry(3, 'DENY_NOT_AUTHORIZED', 'No authority is disclosed; an explicit deny or absence of allow may have applied.', { allowed: false, publicSafe: true }),
  entry(4, 'DENY_CONTEXT_INCOMPLETE', 'Required authorization context is absent or invalid.', { allowed: false, publicSafe: true }),
  entry(5, 'DENY_POLICY_UNAVAILABLE', 'The current policy could not be evaluated.', { allowed: false, publicSafe: true }),
  entry(6, 'DENY_EPOCH_STALE', 'The authority/security epoch is stale.', { allowed: false, publicSafe: true }),
  entry(7, 'DENY_GRANT_INVALID', 'A transfer grant is malformed or its signature is invalid.', { allowed: false, publicSafe: true }),
  entry(8, 'DENY_GRANT_EXPIRED', 'A transfer grant is outside its validity window.', { allowed: false, publicSafe: true }),
  entry(9, 'DENY_GRANT_REPLAY', 'A single-use transfer grant nonce was already consumed.', { allowed: false, publicSafe: true }),
  entry(10, 'DENY_AUDIENCE_MISMATCH', 'A transfer grant does not target this verifier.', { allowed: false, publicSafe: true }),
  entry(11, 'DENY_RESOURCE_SCOPE', 'The requested subject, operation, or resource is outside the bounded grant.', { allowed: false, publicSafe: true }),
  entry(12, 'DENY_PRIVILEGED_REASON_REQUIRED', 'A privileged request has no acceptable reason.', { allowed: false, publicSafe: true }),
  entry(13, 'DENY_SANDBOX_REQUIREMENTS', 'An untrusted execution request exceeds the frozen sandbox profile.', { allowed: false, publicSafe: true }),
  entry(14, 'DENY_RATE_LIMITED', 'The caller exceeded a privacy-safe request class limit.', { allowed: false, publicSafe: true }),
  entry(15, 'DENY_POLICY_GENERATION_MISMATCH', 'The request does not bind the current policy generation.', { allowed: false, publicSafe: true }),
  entry(16, 'DENY_TENANT_BOUNDARY', 'The request would cross tenant deduplication, cache, encryption, or KMS scope.', { allowed: false, publicSafe: true }),
]);

export const auditClasses = Object.freeze([
  entry(1, 'policy.changed', 'Authorization policy or role membership changed.', { permission: 'policy.administer', reasonRequired: true, redaction: 'policy-diff-reference-only' }),
  entry(2, 'lock.force-unlocked', 'A lock was forcibly released or transferred.', { permission: 'lock.force-unlock', reasonRequired: true, redaction: 'target-class-only' }),
  entry(3, 'export.requested', 'A privileged export was requested.', { permission: 'export', reasonRequired: true, redaction: 'export-class-and-request-reference' }),
  entry(4, 'export.completed', 'A privileged export completed or failed.', { permission: 'export', reasonRequired: true, redaction: 'result-code-only' }),
  entry(5, 'retention.deleted', 'Retention or deletion state changed.', { permission: 'retention.delete', reasonRequired: true, redaction: 'generation-reference-only' }),
  entry(6, 'impersonation.started', 'A support impersonation began.', { permission: 'impersonate', reasonRequired: true, redaction: 'pseudonyms-only' }),
  entry(7, 'impersonation.ended', 'A support impersonation ended.', { permission: 'impersonate', reasonRequired: true, redaction: 'pseudonyms-only' }),
  entry(8, 'repair.executed', 'A repair, restore, or quarantine action ran.', { permission: 'repair', reasonRequired: true, redaction: 'job-reference-only' }),
  entry(9, 'audit.accessed', 'Protected audit data was read or exported.', { permission: 'audit.read', reasonRequired: true, redaction: 'query-class-only' }),
  entry(10, 'grant.revoked', 'A credential or grant generation was revoked.', { permission: 'policy.administer', reasonRequired: true, redaction: 'credential-class-only' }),
  entry(11, 'authority.epoch-changed', 'The write authority/security epoch changed.', { permission: 'policy.administer', reasonRequired: true, redaction: 'epoch-and-result-only' }),
]);

export const revocationClasses = Object.freeze([
  entry(1, 'session', 'Human interactive session.', { maximumValiditySeconds: 28800, maximumRevocationLagSeconds: 300, epochBound: true }),
  entry(2, 'service-token', 'Nonhuman service credential.', { maximumValiditySeconds: 3600, maximumRevocationLagSeconds: 60, epochBound: true }),
  entry(3, 'transfer-grant', 'Offline-verifiable content transfer grant.', { maximumValiditySeconds: 300, maximumRevocationLagSeconds: 300, epochBound: true }),
  entry(4, 'authorization-cache', 'Cached allow decision.', { maximumValiditySeconds: 30, maximumRevocationLagSeconds: 30, epochBound: true }),
  entry(5, 'offline-lock-receipt', 'Offline lock observation/receipt.', { maximumValiditySeconds: 300, maximumRevocationLagSeconds: 300, epochBound: true }),
]);

const baseSandbox = Object.freeze({
  schemaVersion: 'ogvcs.authorization/sandbox-requirements/v1',
  runtime: {
    cpuMilliseconds: 30000,
    elapsedMilliseconds: 60000,
    memoryBytes: 536870912,
    outputBytes: 268435456,
    fanout: 10000,
    processes: 8,
  },
  filesystem: {
    declaredInputsReadOnly: true,
    isolatedScratch: true,
    scratchBytes: 1073741824,
    hostPaths: false,
  },
  network: { default: 'deny' },
  credentials: 'none',
  toolchain: { pinned: true, signatureRequired: true },
});

export const sandboxProfiles = Object.freeze([
  { ...structuredClone(baseSandbox), id: 'hook-default', toolClass: 'hook' },
  { ...structuredClone(baseSandbox), id: 'merge-driver-default', toolClass: 'merge-driver' },
  { ...structuredClone(baseSandbox), id: 'import-parser-default', toolClass: 'import-parser' },
  { ...structuredClone(baseSandbox), id: 'preview-parser-default', toolClass: 'preview-parser' },
]);

export const trustZones = Object.freeze([
  entry(1, 'client-device', 'Potentially compromised user filesystem and process boundary.', { trust: 'untrusted', controls: ['short-lived-credential', 'server-validation', 'verified-download', 'confined-write'] }),
  entry(2, 'control-plane', 'Current-policy authority and metadata invariant boundary.', { trust: 'trusted-enforcer', controls: ['least-privilege', 'single-decision-contract', 'audit', 'fail-closed'] }),
  entry(3, 'metadata-store', 'Authoritative state subject to corruption and operator error.', { trust: 'authoritative-data', controls: ['restricted-principal', 'transactional-invariant', 'backup', 'integrity-check'] }),
  entry(4, 'object-store', 'Durability boundary without logical identity or user authorization authority.', { trust: 'durability-only', controls: ['opaque-key', 'scoped-grant', 'digest-verification', 'immutable-write'] }),
  entry(5, 'cache', 'Disposable regional/local cache.', { trust: 'untrusted-enforcer', controls: ['offline-grant-verification', 'tenant-namespace', 'end-to-end-digest'] }),
  entry(6, 'sandbox-worker', 'Hostile repository input/code execution boundary.', { trust: 'hostile-input', controls: ['no-credential', 'no-network', 'read-only-input', 'bounded-scratch', 'resource-cap'] }),
  entry(7, 'operator', 'Privileged insider and support boundary.', { trust: 'privileged-risk', controls: ['separate-role', 'reason-required', 'dual-control', 'append-only-audit'] }),
]);

export const dataFlows = Object.freeze([
  entry(1, 'authorize-metadata-view', 'Control plane constructs an authorized metadata input view before serialization.', { from: 'control-plane', to: 'client-device', permissions: ['discover', 'metadata.read'], protectedFields: ['path', 'object-id', 'history', 'message', 'count'] }),
  entry(2, 'issue-transfer-grant', 'Control plane issues a bounded grant after current policy evaluation.', { from: 'control-plane', to: 'client-device', permissions: ['content.materialize', 'content.upload'], protectedFields: ['object-set', 'request-root'] }),
  entry(3, 'verify-cache-grant', 'Cache verifies signature, epoch, audience, expiry, scope, and replay without broader policy access.', { from: 'client-device', to: 'cache', permissions: ['content.materialize', 'content.upload'], protectedFields: ['grant-claims'] }),
  entry(4, 'append-privileged-audit', 'Control plane appends a redacted reason-bearing privileged event.', { from: 'control-plane', to: 'metadata-store', permissions: ['policy.administer', 'lock.force-unlock', 'export', 'retention.delete', 'repair', 'impersonate'], protectedFields: ['actor-pseudonym', 'reason', 'change-reference'] }),
  entry(5, 'run-untrusted-tool', 'Credential-free worker consumes declared immutable input and publishes validated derived output.', { from: 'object-store', to: 'sandbox-worker', permissions: ['content.materialize'], protectedFields: ['declared-input'] }),
  entry(6, 'read-audit', 'Separately authorized auditor receives only event-class-approved fields.', { from: 'metadata-store', to: 'client-device', permissions: ['audit.read'], protectedFields: ['audit-details'] }),
]);

export const threats = Object.freeze([
  entry(1, 'guessed-hash-retrieval', 'External attacker guesses a content/object hash and treats it as a bearer credential.', { severity: 'high', status: 'mitigated', actors: ['external-attacker'], mitigations: ['scoped-transfer-grant', 'object-id-never-authorizes'], abuseCases: ['guessed-object-hash'] }),
  entry(2, 'metadata-enumeration', 'External or denied caller infers protected names/existence through response shape.', { severity: 'high', status: 'mitigated', actors: ['external-attacker', 'malicious-user'], mitigations: ['authorized-view-before-count', 'privacy-safe-code'], abuseCases: ['path-enumeration', 'search-enumeration'] }),
  entry(3, 'compromised-user-overreach', 'Compromised user credential reaches paths outside its explicit policy.', { severity: 'high', status: 'mitigated', actors: ['malicious-user', 'compromised-user'], mitigations: ['deny-overrides', 'canonical-context'], abuseCases: ['restricted-path-read'] }),
  entry(4, 'administrator-abuse', 'Administrator performs an unreasoned or unaudited privileged action.', { severity: 'high', status: 'mitigated', actors: ['administrator'], mitigations: ['separate-permission', 'reason-required', 'append-only-audit'], abuseCases: ['force-unlock-without-reason'] }),
  entry(5, 'build-identity-overreach', 'Build identity can materialize unrelated source or restricted assets.', { severity: 'high', status: 'mitigated', actors: ['build-identity'], mitigations: ['service-token-scope', 'path-policy'], abuseCases: ['build-token-overreach'] }),
  entry(6, 'cache-replay', 'Cache accepts an expired, replayed, wrong-audience, or stale-epoch grant.', { severity: 'high', status: 'mitigated', actors: ['cache-operator', 'external-attacker'], mitigations: ['offline-grant-verification', 'nonce-state', 'epoch-binding'], abuseCases: ['cache-grant-replay', 'wrong-cache-audience', 'stale-authority-epoch'] }),
  entry(7, 'hostile-import-file', 'Import file escapes parser confinement or reaches acquisition credentials.', { severity: 'critical', status: 'mitigated', actors: ['hostile-import-file'], mitigations: ['credential-free-parser', 'sandbox-profile'], abuseCases: ['import-parser-escape'] }),
  entry(8, 'plugin-hook-escape', 'Repository plugin or hook escapes filesystem/network/resource confinement.', { severity: 'critical', status: 'mitigated', actors: ['plugin', 'hook'], mitigations: ['sandbox-profile', 'validated-output'], abuseCases: ['hook-network-escape'] }),
  entry(9, 'preview-parser-escape', 'Hostile preview input executes outside its disposable worker.', { severity: 'critical', status: 'mitigated', actors: ['preview-parser'], mitigations: ['sandbox-profile', 'no-credential'], abuseCases: ['preview-parser-escape'] }),
  entry(10, 'stolen-device-session', 'A stolen device retains long-lived authority after revocation.', { severity: 'high', status: 'mitigated', actors: ['stolen-device'], mitigations: ['session-ttl', 'revocation-bound', 'epoch-binding'], abuseCases: ['revoked-session'] }),
  entry(11, 'confused-deputy', 'A privileged service reuses caller-controlled scope against another tenant/repository or transfer plan.', { severity: 'high', status: 'mitigated', actors: ['confused-deputy-service'], mitigations: ['full-context-binding', 'audience-binding', 'request-root-membership'], abuseCases: ['wrong-repository-grant', 'request-root-membership'] }),
  entry(12, 'cross-tenant-dedup-probe', 'Attacker learns another tenant has matching content.', { severity: 'high', status: 'mitigated', actors: ['malicious-user', 'cache-operator'], mitigations: ['tenant-scoped-dedup', 'generic-upload-result'], abuseCases: ['cross-tenant-dedup'] }),
  entry(13, 'mixed-visibility-inference', 'Hidden history/review operations leak via counts, parents, order, messages, or cursors.', { severity: 'high', status: 'mitigated', actors: ['restricted-user'], mitigations: ['authorized-view-before-count', 'authorized-cursor'], abuseCases: ['mixed-history', 'mixed-review'] }),
  entry(14, 'audit-data-leak', 'Audit query reveals protected resource or identity details.', { severity: 'high', status: 'mitigated', actors: ['auditor', 'administrator'], mitigations: ['audit-read-permission', 'event-class-redaction'], abuseCases: ['audit-detail-enumeration'] }),
  entry(15, 'revocation-lag', 'Session, service token, grant, cache decision, or lock receipt survives its bound.', { severity: 'high', status: 'mitigated', actors: ['compromised-user', 'stolen-device'], mitigations: ['revocation-registry', 'epoch-binding'], abuseCases: ['revoked-service-token', 'stale-cache-decision'] }),
  entry(16, 'aggregate-timing-inference', 'Repeated bounded requests statistically infer hidden workload shape.', { severity: 'medium', status: 'accepted', actors: ['restricted-user'], mitigations: ['response-class-padding', 'rate-limit', 'aggregate-monitoring'], owner: 'OGVCS-009/OGVCS-035', roadmapItem: 'OGVCS-035', expiry: 'R3 authorization-safe search scale', abuseCases: ['timing-class-probe'] }),
  entry(17, 'compromised-service-token', 'Broad or unrotated service identity is reused outside its job.', { severity: 'high', status: 'mitigated', actors: ['compromised-service'], mitigations: ['short-service-ttl', 'operation-scope', 'rotation'], abuseCases: ['service-token-wrong-operation'] }),
  entry(18, 'operator-key-boundary', 'Operator derives encryption authority from content identity or crosses tenant keys.', { severity: 'high', status: 'mitigated', actors: ['administrator', 'cache-operator'], mitigations: ['separate-kms-key', 'tenant-key-scope'], abuseCases: ['content-derived-key', 'cross-tenant-key'] }),
]);

export const abuseCases = Object.freeze([
  entry(1, 'guessed-object-hash', 'Guessed object identity cannot retrieve content.', { category: 'guessed-hash', kind: 'authorization' }),
  entry(2, 'path-enumeration', 'Denied path name/existence is absent from response.', { category: 'enumeration', kind: 'authorization' }),
  entry(3, 'restricted-path-read', 'Restricted user cannot read a protected path.', { category: 'path-policy', kind: 'authorization' }),
  entry(4, 'search-enumeration', 'Search ranks/counts only the authorized input view.', { category: 'search', kind: 'authorized-view' }),
  entry(5, 'event-enumeration', 'Event stream omits hidden operations without gap detail.', { category: 'events', kind: 'authorized-view' }),
  entry(6, 'mixed-history', 'Mixed history hides protected messages, parents, positions, and counts.', { category: 'mixed-visibility-history', kind: 'authorized-view' }),
  entry(7, 'mixed-review', 'Mixed review hides protected operations, checks, and counts.', { category: 'mixed-visibility-review', kind: 'authorized-view' }),
  entry(8, 'fidelity-export-incomplete-authorization', 'Fidelity export fails atomically when any selected record is hidden.', { category: 'export', kind: 'authorization' }),
  entry(9, 'projection-export-redaction', 'Projection export receives only authorized view and a distinct identity class.', { category: 'export', kind: 'authorized-view' }),
  entry(10, 'cross-tenant-dedup', 'Upload response cannot probe another tenant\'s content equality.', { category: 'deduplication-probe', kind: 'deduplication' }),
  entry(11, 'cache-grant-replay', 'A consumed single-use transfer grant is denied.', { category: 'cache-replay', kind: 'transfer-grant' }),
  entry(12, 'wrong-cache-audience', 'A grant for another cache endpoint is denied.', { category: 'cache-replay', kind: 'transfer-grant' }),
  entry(13, 'stale-authority-epoch', 'An old-epoch transfer grant is denied.', { category: 'token-revocation', kind: 'transfer-grant' }),
  entry(14, 'expired-transfer-grant', 'An expired transfer grant is denied.', { category: 'token-revocation', kind: 'transfer-grant' }),
  entry(15, 'wrong-repository-grant', 'A grant cannot be replayed across repository scope.', { category: 'confused-deputy', kind: 'transfer-grant' }),
  entry(16, 'altered-transfer-grant', 'A modified signed claim is denied generically.', { category: 'grant-integrity', kind: 'transfer-grant' }),
  entry(17, 'revoked-session', 'A revoked session cannot authorize new work beyond its bound.', { category: 'token-revocation', kind: 'authorization' }),
  entry(18, 'revoked-service-token', 'A revoked service token cannot authorize new work beyond its bound.', { category: 'token-revocation', kind: 'authorization' }),
  entry(19, 'stale-cache-decision', 'A cached allow expires inside its frozen bound.', { category: 'token-revocation', kind: 'authorization' }),
  entry(20, 'build-token-overreach', 'Build identity cannot read outside its declared paths.', { category: 'service-scope', kind: 'authorization' }),
  entry(21, 'service-token-wrong-operation', 'Service token cannot change operation class.', { category: 'service-scope', kind: 'authorization' }),
  entry(22, 'force-unlock-without-reason', 'Privileged force unlock without reason is denied.', { category: 'privileged-operation', kind: 'authorization' }),
  entry(23, 'audit-detail-enumeration', 'Audit readers receive event-class redacted fields only.', { category: 'audit', kind: 'authorized-view' }),
  entry(24, 'hook-network-escape', 'Hook cannot request network or host filesystem access.', { category: 'hook-escape', kind: 'sandbox' }),
  entry(25, 'preview-parser-escape', 'Preview parser cannot exceed process/memory/output confinement.', { category: 'preview-escape', kind: 'sandbox' }),
  entry(26, 'import-parser-escape', 'Import parser cannot receive acquisition credentials.', { category: 'import-escape', kind: 'sandbox' }),
  entry(27, 'timing-class-probe', 'Denied result uses one bounded response class and rate class.', { category: 'timing', kind: 'authorization' }),
  entry(28, 'content-derived-key', 'Encryption key selection is not derived from content identity.', { category: 'encryption-boundary', kind: 'deduplication' }),
  entry(29, 'cross-tenant-key', 'A tenant cannot address another tenant\'s encryption scope.', { category: 'encryption-boundary', kind: 'authorization' }),
  entry(30, 'request-root-membership', 'A signed request root cannot authorize an object outside the verifier-owned transfer plan.', { category: 'confused-deputy', kind: 'transfer-grant' }),
]);

function rule(id, effect, overrides = {}) {
  return {
    id,
    effect,
    actors: [],
    groups: [],
    actorClasses: [],
    tenants: ['tenant-alpha'],
    repositories: ['game-main'],
    references: [],
    pathPrefixes: [],
    resourceTypes: resources.map(({ name }) => name),
    permissions: permissions.map(({ name }) => name),
    ...overrides,
  };
}

const policyBase = Object.freeze({
  schemaVersion: 'ogvcs.authorization/policy-fixture/v1',
  version: 'v1',
  policyGeneration: 7,
  authorityEpoch: 3,
  default: 'deny',
  composition: 'deny-overrides-v1',
});

const ordinaryPermissions = permissions.filter(({ privileged }) => !privileged).map(({ name }) => name);
const privilegedPermissions = permissions.filter(({ privileged }) => privileged).map(({ name }) => name);

export const policies = Object.freeze({
  'internal-team.json': {
    ...policyBase,
    id: 'internal-team',
    rules: [
      rule('deny-outsourcer', 'deny', { groups: ['team-outsourcer'] }),
      rule('allow-internal', 'allow', { groups: ['team-internal'], permissions: ordinaryPermissions }),
      rule('allow-build', 'allow', {
        actors: ['build-ci'],
        pathPrefixes: ['Game/Build', 'Game/Shared'],
        resourceTypes: ['repository', 'reference', 'snapshot', 'tree', 'path', 'object', 'content'],
        permissions: ['discover', 'metadata.read', 'content.materialize'],
      }),
      rule('allow-cache-grant', 'allow', {
        actors: ['regional-cache'],
        resourceTypes: ['content', 'cache-entry'],
        permissions: ['content.materialize', 'content.upload'],
      }),
      rule('allow-admin-privileged', 'allow', { groups: ['team-admin'], actorClasses: ['administrator'], permissions: privilegedPermissions }),
    ],
  },
  'restricted-outsourcer.json': {
    ...policyBase,
    id: 'restricted-outsourcer',
    rules: [
      rule('deny-outsourcer-restricted', 'deny', {
        groups: ['team-outsourcer'],
        pathPrefixes: ['Game/Restricted', 'Game/Outsource/Restricted'],
      }),
      rule('deny-outsourcer-export', 'deny', { groups: ['team-outsourcer'], permissions: ['export', 'audit.read', 'policy.administer', 'retention.delete', 'repair', 'impersonate', 'lock.force-unlock'] }),
      rule('allow-outsourcer-scope', 'allow', {
        groups: ['team-outsourcer'],
        pathPrefixes: ['Game/Outsource', 'Game/Shared'],
        resourceTypes: ['repository', 'reference', 'snapshot', 'tree', 'path', 'object', 'content', 'lock', 'review', 'search', 'event'],
        permissions: ['discover', 'metadata.read', 'content.materialize', 'content.upload', 'lock.create', 'submit', 'review'],
      }),
      rule('allow-internal', 'allow', { groups: ['team-internal'], permissions: ordinaryPermissions }),
      rule('allow-build', 'allow', {
        actors: ['build-ci'],
        pathPrefixes: ['Game/Build', 'Game/Shared'],
        resourceTypes: ['repository', 'reference', 'snapshot', 'tree', 'path', 'object', 'content'],
        permissions: ['discover', 'metadata.read', 'content.materialize'],
      }),
      rule('allow-cache-grant', 'allow', {
        actors: ['regional-cache'],
        resourceTypes: ['content', 'cache-entry'],
        permissions: ['content.materialize', 'content.upload'],
      }),
      rule('allow-admin-privileged', 'allow', { groups: ['team-admin'], actorClasses: ['administrator'], permissions: privilegedPermissions }),
    ],
  },
});

export const goldenRepository = Object.freeze({
  schemaVersion: 'ogvcs.authorization/golden-repository/v1',
  tenant: 'tenant-alpha',
  repository: 'game-main',
  policyGeneration: 7,
  authorityEpoch: 3,
  actors: [
    { id: 'internal-alice', class: 'human', groups: ['team-internal'], credentialClass: 'session', credentialGeneration: 4, credentialStatus: 'active', authorityEpoch: 3 },
    { id: 'outsourcer-bob', class: 'human', groups: ['team-outsourcer'], credentialClass: 'session', credentialGeneration: 2, credentialStatus: 'active', authorityEpoch: 3 },
    { id: 'build-ci', class: 'service', groups: ['team-build'], credentialClass: 'service-token', credentialGeneration: 9, credentialStatus: 'active', authorityEpoch: 3 },
    { id: 'studio-admin', class: 'administrator', groups: ['team-admin', 'team-internal'], credentialClass: 'session', credentialGeneration: 7, credentialStatus: 'active', authorityEpoch: 3 },
    { id: 'regional-cache', class: 'cache', groups: ['team-cache'], credentialClass: 'transfer-grant', credentialGeneration: 11, credentialStatus: 'active', authorityEpoch: 3 },
    { id: 'preview-worker', class: 'sandbox-worker', groups: ['team-sandbox'], credentialClass: 'service-token', credentialGeneration: 5, credentialStatus: 'active', authorityEpoch: 3 },
    { id: 'anonymous', class: 'anonymous', groups: [], credentialClass: 'anonymous', credentialGeneration: 1, credentialStatus: 'active', authorityEpoch: 3 },
  ],
  resources: [
    { id: 'repository-root', type: 'repository', path: null, fileId: null, objectId: null, name: 'game-main', visibility: 'internal' },
    { id: 'main-reference', type: 'reference', path: null, fileId: null, objectId: null, name: 'main', visibility: 'internal' },
    { id: 'main-snapshot', type: 'snapshot', path: null, fileId: null, objectId: 'snapshot-main-0001', name: null, visibility: 'internal' },
    { id: 'game-tree', type: 'tree', path: 'Game', fileId: null, objectId: 'tree-main-0001', name: null, visibility: 'internal' },
    { id: 'public-readme', type: 'path', path: 'Game/Public/Readme.txt', fileId: '00000000000000000000000000000001', objectId: null, name: null, visibility: 'public-fixture' },
    { id: 'shared-object', type: 'object', path: 'Game/Shared/Props/Crate.uasset', fileId: '00000000000000000000000000000002', objectId: 'ogvcs:v1:manifest:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', name: null, visibility: 'shared' },
    { id: 'shared-crate', type: 'content', path: 'Game/Shared/Props/Crate.uasset', fileId: '00000000000000000000000000000002', objectId: 'ogvcs:v1:chunk:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', name: null, visibility: 'shared' },
    { id: 'outsourced-npc', type: 'content', path: 'Game/Outsource/Characters/NPC.uasset', fileId: '00000000000000000000000000000003', objectId: 'ogvcs:v1:chunk:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', name: null, visibility: 'outsourcer' },
    { id: 'restricted-hero', type: 'content', path: 'Game/Restricted/Hero/Face.uasset', fileId: '00000000000000000000000000000004', objectId: 'ogvcs:v1:chunk:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', name: null, visibility: 'restricted' },
    { id: 'build-config', type: 'path', path: 'Game/Build/Config.ini', fileId: '00000000000000000000000000000005', objectId: null, name: null, visibility: 'build' },
    { id: 'outsourcer-lock', type: 'lock', path: 'Game/Outsource/Characters/NPC.uasset', fileId: '00000000000000000000000000000003', objectId: null, name: 'lock-npc', visibility: 'outsourcer' },
    { id: 'outsourcer-review', type: 'review', path: 'Game/Outsource/Characters/NPC.uasset', fileId: '00000000000000000000000000000003', objectId: null, name: 'review-npc', visibility: 'outsourcer' },
    { id: 'game-search', type: 'search', path: 'Game', fileId: null, objectId: null, name: 'search-game', visibility: 'internal' },
    { id: 'game-events', type: 'event', path: 'Game', fileId: null, objectId: null, name: 'event-stream-main', visibility: 'internal' },
    { id: 'shared-cache', type: 'cache-entry', path: 'Game/Shared/Props/Crate.uasset', fileId: '00000000000000000000000000000002', objectId: 'ogvcs:v1:chunk:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', name: 'cache-entry-shared', visibility: 'shared' },
    { id: 'fidelity-export', type: 'export', path: null, fileId: null, objectId: null, name: 'fidelity-export', visibility: 'privileged' },
    { id: 'repository-policy', type: 'policy', path: null, fileId: null, objectId: null, name: 'repository-policy', visibility: 'privileged' },
    { id: 'repository-audit', type: 'audit', path: null, fileId: null, objectId: null, name: 'repository-audit', visibility: 'privileged' },
    { id: 'repository-retention', type: 'retention', path: null, fileId: null, objectId: null, name: 'repository-retention', visibility: 'privileged' },
    { id: 'repository-repair', type: 'repair-job', path: null, fileId: null, objectId: null, name: 'repository-repair', visibility: 'privileged' },
    { id: 'preview-job', type: 'sandbox-job', path: 'Game/Restricted/Hero/Face.uasset', fileId: '00000000000000000000000000000004', objectId: null, name: 'preview-job', visibility: 'restricted' },
  ],
  references: ['main', 'release'],
  snapshots: ['snapshot-main-0001', 'snapshot-release-0001'],
});

export const grantFixture = Object.freeze({
  privateJwk: {
    crv: 'Ed25519',
    d: 'lphglsBMEa_thUyunqHqXfIC2Xp6SyLAi9bZgwyqxOE',
    x: 'faKq3FI3CJgWUdQZR8my5YgKjM0CrTitbrtGi2V9-lc',
    kty: 'OKP',
  },
  publicJwk: {
    crv: 'Ed25519',
    x: 'faKq3FI3CJgWUdQZR8my5YgKjM0CrTitbrtGi2V9-lc',
    kty: 'OKP',
  },
  claims: {
    schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1',
    issuer: 'control-primary',
    keyId: 'conformance-key-1',
    keyGeneration: 11,
    authorityEpoch: 3,
    subject: 'outsourcer-bob',
    tenant: 'tenant-alpha',
    repository: 'game-main',
    permission: 'content.materialize',
    operation: 'download',
    audience: 'cache-maldives-1',
    issuedAt: 2000000000,
    expiresAt: 2000000300,
    nonce: 'grant-conformance-0001',
    replay: 'single-use',
    objectIds: ['ogvcs:v1:chunk:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],
    requestRoot: null,
  },
});

const roadmap = (prd, classification, resourceTypes, permissionNames, surfaces) => ({
  prd,
  classification,
  auditBehavior: classification === 'public-contract'
    ? 'public-no-audit'
    : permissionNames.some((permission) => permissions.find(({ name }) => name === permission)?.privileged)
      ? 'privileged-append-only'
      : 'authorization-decision',
  resourceTypes,
  permissions: permissionNames,
  surfaces,
});

export const roadmapSurfaces = Object.freeze([
  roadmap('OGVCS-001', 'public-contract', [], [], ['fixture schemas, CLI, synthetic profiles']),
  roadmap('OGVCS-002', 'mixed', ['object', 'content', 'snapshot', 'tree'], ['discover', 'metadata.read', 'content.materialize'], ['public format/specification', 'protected repository objects']),
  roadmap('OGVCS-003', 'public-contract', [], [], ['authorization schemas, registries, runner']),
  roadmap('OGVCS-004', 'public-contract', [], [], ['path and filesystem library']),
  roadmap('OGVCS-005', 'public-contract', [], [], ['benchmark/fault harness and public result format']),
  roadmap('OGVCS-006', 'protected', ['repository', 'reference', 'snapshot', 'tree', 'path'], ['discover', 'metadata.read', 'submit'], ['repository metadata, snapshots, references, history']),
  roadmap('OGVCS-007', 'protected', ['content', 'object'], ['metadata.read', 'content.materialize', 'content.upload'], ['chunking and manifest operations']),
  roadmap('OGVCS-008', 'protected', ['content', 'object', 'cache-entry'], ['content.materialize', 'content.upload'], ['object transfer and resumable upload/download']),
  roadmap('OGVCS-009', 'protected', ['policy', 'audit'], ['policy.administer', 'audit.read', 'impersonate'], ['identity, policy, grant, and audit APIs']),
  roadmap('OGVCS-010', 'protected', ['reference', 'snapshot', 'path', 'content'], ['submit'], ['draft, preflight, finalize, and idempotency status']),
  roadmap('OGVCS-011', 'mixed', ['repository', 'path', 'content', 'reference'], ['discover', 'metadata.read', 'content.materialize', 'content.upload', 'submit'], ['public CLI surface', 'protected workspace lifecycle']),
  roadmap('OGVCS-012', 'protected', ['path', 'reference'], ['discover', 'metadata.read'], ['workspace status and index reconciliation']),
  roadmap('OGVCS-013', 'protected', ['path', 'content'], ['discover', 'metadata.read', 'content.materialize'], ['selection and materialization plan']),
  roadmap('OGVCS-014', 'protected', ['path', 'content', 'snapshot'], ['metadata.read', 'content.materialize', 'submit'], ['checkpoint and offline recovery publication']),
  roadmap('OGVCS-015', 'protected', ['reference', 'snapshot', 'tree', 'path'], ['discover', 'metadata.read', 'submit'], ['branch, history, diff, merge, revert']),
  roadmap('OGVCS-016', 'protected', ['lock', 'path'], ['discover', 'lock.create', 'lock.force-unlock'], ['lock and edit-intent lifecycle']),
  roadmap('OGVCS-017', 'protected', ['repair-job', 'object', 'content', 'snapshot'], ['metadata.read', 'repair'], ['verification, quarantine, and repair']),
  roadmap('OGVCS-018', 'protected', ['retention', 'snapshot', 'content'], ['metadata.read', 'repair', 'retention.delete'], ['backup, restore, legal hold, retention, and GC']),
  roadmap('OGVCS-019', 'protected', ['event', 'snapshot', 'content'], ['discover', 'metadata.read', 'content.materialize'], ['automation event/cursor/webhook and CI snapshot']),
  roadmap('OGVCS-020', 'protected', ['sandbox-job', 'content', 'snapshot', 'reference'], ['content.upload', 'submit', 'repair'], ['Git/LFS acquisition, import, and reconciliation']),
  roadmap('OGVCS-021', 'protected', ['repository', 'policy', 'repair-job'], ['policy.administer', 'repair'], ['deployment bootstrap and administration']),
  roadmap('OGVCS-022', 'mixed', ['repository', 'path', 'content', 'lock', 'review'], ['discover', 'metadata.read', 'content.materialize', 'lock.create', 'review', 'submit'], ['public desktop client', 'protected artist operations']),
  roadmap('OGVCS-023', 'mixed', ['path', 'content', 'lock', 'event'], ['discover', 'metadata.read', 'content.materialize', 'lock.create', 'submit'], ['public Unreal integration', 'protected repository operations']),
  roadmap('OGVCS-024', 'protected', ['lock', 'reference', 'path'], ['discover', 'lock.create', 'lock.force-unlock'], ['branch-aware lock domains']),
  roadmap('OGVCS-025', 'protected', ['review', 'content', 'snapshot', 'event'], ['discover', 'metadata.read', 'content.materialize', 'review', 'submit'], ['shelf, review, approval, checks, promotion']),
  roadmap('OGVCS-026', 'protected', ['sandbox-job', 'review', 'content'], ['metadata.read', 'content.materialize', 'review'], ['preview and semantic diff sandbox']),
  roadmap('OGVCS-027', 'protected', ['cache-entry', 'content'], ['content.materialize', 'content.upload', 'repair'], ['regional cache fill/read/purge']),
  roadmap('OGVCS-028', 'protected', ['audit', 'repository', 'repair-job'], ['audit.read', 'metadata.read', 'repair'], ['observability, capacity, and diagnostic bundles']),
  roadmap('OGVCS-029', 'protected', ['sandbox-job', 'content', 'snapshot', 'reference'], ['content.upload', 'submit', 'repair'], ['Perforce acquisition, shadow import, reconciliation']),
  roadmap('OGVCS-030', 'mixed', ['policy', 'repair-job'], ['policy.administer', 'repair'], ['public signed packages', 'protected upgrade administration']),
  roadmap('OGVCS-031', 'mixed', ['sandbox-job', 'path', 'content', 'lock'], ['metadata.read', 'content.materialize', 'lock.create', 'submit'], ['public Unity integration', 'protected semantic merge']),
  roadmap('OGVCS-032', 'protected', ['policy', 'repair-job', 'retention'], ['policy.administer', 'repair'], ['HA, DR promotion, fencing, rolling upgrade']),
  roadmap('OGVCS-033', 'protected', ['export', 'snapshot', 'content'], ['export', 'metadata.read', 'content.materialize'], ['fidelity and authorized-projection export']),
  roadmap('OGVCS-034', 'protected', ['export', 'reference', 'event'], ['export', 'metadata.read', 'submit'], ['Git bridge and one-way mirror']),
  roadmap('OGVCS-035', 'protected', ['search', 'review'], ['discover', 'metadata.read', 'review'], ['authorization-safe search and review scale']),
  roadmap('OGVCS-036', 'mixed', ['policy', 'audit'], ['policy.administer', 'audit.read'], ['public compatibility suite', 'protected LTS administration']),
  roadmap('OGVCS-037', 'protected', ['path', 'content'], ['discover', 'metadata.read', 'content.materialize'], ['virtual workspace and hydration']),
  roadmap('OGVCS-038', 'public-contract', [], [], ['public integration SDK and local-agent simulator']),
  roadmap('OGVCS-039', 'mixed', ['sandbox-job', 'path', 'content'], ['metadata.read', 'content.materialize', 'submit'], ['public DCC integrations', 'protected repository operations']),
  roadmap('OGVCS-040', 'public-contract', [], [], ['hosting conformance and certification toolkit']),
  roadmap('OGVCS-041', 'public-contract', [], [], ['protocol schemas, bindings, negotiation, and conformance vectors']),
  roadmap('OGVCS-042', 'protected', ['path', 'content', 'lock', 'event'], ['discover', 'metadata.read', 'content.materialize', 'lock.create', 'submit'], ['local-agent IPC capabilities']),
  roadmap('OGVCS-043', 'mixed', ['repository', 'path', 'content', 'lock', 'reference'], ['discover', 'metadata.read', 'content.materialize', 'content.upload', 'lock.create', 'submit'], ['public CLI', 'protected vertical-slice operations']),
  roadmap('OGVCS-044', 'protected', ['review', 'content', 'event'], ['discover', 'metadata.read', 'content.materialize', 'review', 'submit'], ['desktop shelf/review workflow']),
  roadmap('OGVCS-045', 'protected', ['sandbox-job', 'content'], ['content.upload', 'repair'], ['credential broker acquisition and untrusted parser sandbox']),
]);

export const contract = Object.freeze({
  permissions,
  resources,
  actorClasses,
  credentialClasses,
  decisionCodes,
  auditClasses,
  revocationClasses,
  sandboxProfiles,
  trustZones,
  dataFlows,
  threats,
  abuseCases,
  roadmapSurfaces,
});
