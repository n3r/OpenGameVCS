import {
  ACTOR_CLASSES,
  PERMISSIONS,
  RESOURCE_TYPES,
  canonicalBytes,
} from '@opengamevcs/authorization-contract';
import { caseFold, validateRepositoryPath } from '@opengamevcs/path-filesystem';

import { identityFail } from './errors.mjs';

export const RUNTIME_LIMITS = Object.freeze({
  maxPolicyRules: 1_024,
  maxRuleSubjects: 128,
  maxRulePathPrefixes: 128,
  maxAuthorizedViewCandidates: 10_000,
  maxAuthorizedViewItems: 1_000,
  maxCredentials: 100_000,
  maxAuditRecordBytes: 16_384,
  maxAuditQueryRecords: 10_000,
  maxRateBuckets: 100_000,
  maxTokenBytes: 1_024,
  sessionMaxTtlSeconds: 28_800,
  serviceTokenMaxTtlSeconds: 3_600,
  transferGrantMaxTtlSeconds: 300,
});

const ID = /^[a-z][a-z0-9.-]{0,127}$/u;
const VERSION = /^[a-z][a-z0-9.-]{0,63}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    identityFail('INPUT_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    identityFail('INPUT_INVALID', `${label} has an invalid field set`);
  }
}

function text(value, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) identityFail('INPUT_INVALID', `${label} is invalid`);
  return value;
}

function integer(value, minimum, label) {
  if (!Number.isSafeInteger(value) || value < minimum) identityFail('INPUT_INVALID', `${label} is invalid`);
  return value;
}

function stringSet(value, options, label) {
  if (!Array.isArray(value) || value.length < (options.minimum ?? 0)) identityFail('INPUT_INVALID', `${label} is invalid`);
  if (value.length > options.maximum) identityFail('LIMIT_EXCEEDED', `${label} exceeds its bound`);
  const result = value.map((entry, index) => text(entry, options.pattern ?? ID, `${label}[${index}]`));
  if (new Set(result).size !== result.length) identityFail('INPUT_INVALID', `${label} repeats a value`);
  if (options.allowed && result.some((entry) => !options.allowed.includes(entry))) identityFail('INPUT_INVALID', `${label} contains an unassigned value`);
  return result;
}

export function deepFreeze(value) {
  const pending = [value];
  const seen = new Set();
  while (pending.length > 0) {
    const item = pending.pop();
    if (!item || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    pending.push(...Object.values(item));
    Object.freeze(item);
  }
  return value;
}

export function cloneBounded(value, options = {}) {
  try {
    canonicalBytes(value, {
      maxBytes: options.maxBytes ?? 1024 * 1024,
      maxDepth: options.maxDepth ?? 16,
      maxNodes: options.maxNodes ?? 50_000,
      maxStringBytes: options.maxStringBytes ?? 4_096,
      maxKeyBytes: 256,
    });
    return structuredClone(value);
  } catch (error) {
    identityFail(error?.code?.includes('LIMIT') ? 'LIMIT_EXCEEDED' : 'INPUT_INVALID', 'bounded JSON input is invalid', { cause: error });
  }
}

export function canonicalPrefix(value, { pathProfile, caseMode }) {
  if (value === '') return Object.freeze({ canonical: '', comparison: '' });
  let canonical;
  try { canonical = validateRepositoryPath(value, { profile: pathProfile }).canonical; }
  catch (error) { identityFail(error?.code?.includes('LIMIT') ? 'LIMIT_EXCEEDED' : 'INPUT_INVALID', 'policy path prefix is invalid', { cause: error }); }
  if (canonical !== value) identityFail('INPUT_INVALID', 'policy path prefix is not canonical');
  const comparison = caseMode === 'case-folded'
    ? canonical.split('/').map(caseFold).join('/')
    : canonical;
  return Object.freeze({ canonical, comparison });
}

function validateScope(scopeInput, pathOptions, label) {
  const scope = object(scopeInput, label);
  exact(scope, ['tenants', 'repositories', 'references', 'pathPrefixes', 'permissions'], label);
  const tenants = stringSet(scope.tenants, { maximum: 16, minimum: 1 }, `${label}.tenants`);
  const repositories = stringSet(scope.repositories, { maximum: 128, minimum: 1 }, `${label}.repositories`);
  const references = stringSet(scope.references, { maximum: 128 }, `${label}.references`);
  const permissions = stringSet(scope.permissions, { maximum: 64, minimum: 1, pattern: /^[a-z][a-z0-9.-]{0,127}$/u, allowed: PERMISSIONS }, `${label}.permissions`);
  if (!Array.isArray(scope.pathPrefixes)) identityFail('INPUT_INVALID', `${label}.pathPrefixes is invalid`);
  if (scope.pathPrefixes.length > RUNTIME_LIMITS.maxRulePathPrefixes) identityFail('LIMIT_EXCEEDED', `${label}.pathPrefixes exceeds its bound`);
  const pathPrefixes = scope.pathPrefixes.map((value) => canonicalPrefix(value, pathOptions).canonical);
  if (new Set(pathPrefixes).size !== pathPrefixes.length) identityFail('INPUT_INVALID', `${label}.pathPrefixes repeats a value`);
  return { tenants, repositories, references, pathPrefixes, permissions };
}

export function validatePolicyDocument(input) {
  const source = cloneBounded(input);
  const policy = object(source, 'policy');
  exact(policy, ['schemaVersion', 'id', 'version', 'generation', 'authorityEpoch', 'pathProfile', 'caseMode', 'default', 'composition', 'rules'], 'policy');
  if (policy.schemaVersion !== 'ogvcs.identity-policy/policy/v1' || policy.default !== 'deny' || policy.composition !== 'deny-overrides-v1') identityFail('INPUT_INVALID', 'policy envelope is invalid');
  text(policy.id, ID, 'policy.id'); text(policy.version, VERSION, 'policy.version');
  if (!ID.test(`${policy.id}.${policy.version}`)) identityFail('INPUT_INVALID', 'combined policy version is invalid');
  integer(policy.generation, 1, 'policy.generation'); integer(policy.authorityEpoch, 1, 'policy.authorityEpoch');
  if (!['case-sensitive', 'case-folded'].includes(policy.caseMode)) identityFail('INPUT_INVALID', 'policy.caseMode is invalid');
  if (typeof policy.pathProfile !== 'string' || policy.pathProfile.length > 328) identityFail('INPUT_INVALID', 'policy.pathProfile is invalid');
  try { validateRepositoryPath('policy-profile-probe', { profile: policy.pathProfile }); }
  catch (error) { identityFail('INPUT_INVALID', 'policy.pathProfile is unknown', { cause: error }); }
  if (!Array.isArray(policy.rules) || policy.rules.length === 0) identityFail('INPUT_INVALID', 'policy.rules is invalid');
  if (policy.rules.length > RUNTIME_LIMITS.maxPolicyRules) identityFail('LIMIT_EXCEEDED', 'policy.rules exceeds its bound');
  const ruleIds = new Set();
  for (const [index, candidate] of policy.rules.entries()) {
    const rule = object(candidate, `policy.rules[${index}]`);
    exact(rule, ['id', 'effect', 'subjects', 'tenant', 'repository', 'references', 'pathPrefixes', 'resourceTypes', 'permissions'], `policy.rules[${index}]`);
    text(rule.id, ID, `policy.rules[${index}].id`);
    if (ruleIds.has(rule.id)) identityFail('INPUT_INVALID', 'policy rule IDs repeat');
    ruleIds.add(rule.id);
    if (!['allow', 'deny'].includes(rule.effect)) identityFail('INPUT_INVALID', 'policy rule effect is invalid');
    text(rule.tenant, ID, 'rule.tenant'); text(rule.repository, ID, 'rule.repository');
    const subjects = object(rule.subjects, 'rule.subjects');
    exact(subjects, ['identities', 'groups', 'actorClasses'], 'rule.subjects');
    stringSet(subjects.identities, { maximum: RUNTIME_LIMITS.maxRuleSubjects }, 'rule.subjects.identities');
    stringSet(subjects.groups, { maximum: RUNTIME_LIMITS.maxRuleSubjects }, 'rule.subjects.groups');
    stringSet(subjects.actorClasses, { maximum: 32, allowed: ACTOR_CLASSES }, 'rule.subjects.actorClasses');
    stringSet(rule.references, { maximum: 128 }, 'rule.references');
    stringSet(rule.resourceTypes, { maximum: 64, minimum: 1, allowed: RESOURCE_TYPES }, 'rule.resourceTypes');
    stringSet(rule.permissions, { maximum: 64, minimum: 1, pattern: /^[a-z][a-z0-9.-]{0,127}$/u, allowed: PERMISSIONS }, 'rule.permissions');
    if (!Array.isArray(rule.pathPrefixes)) identityFail('INPUT_INVALID', 'rule.pathPrefixes is invalid');
    if (rule.pathPrefixes.length > RUNTIME_LIMITS.maxRulePathPrefixes) identityFail('LIMIT_EXCEEDED', 'rule.pathPrefixes exceeds its bound');
    const canonical = rule.pathPrefixes.map((value) => canonicalPrefix(value, policy).canonical);
    if (new Set(canonical).size !== canonical.length) identityFail('INPUT_INVALID', 'rule.pathPrefixes repeats a value');
    rule.pathPrefixes = canonical;
  }
  return deepFreeze(policy);
}

export function validateCredentialRecord(input, pathOptions) {
  const record = object(cloneBounded(input), 'credential record');
  exact(record, ['schemaVersion', 'id', 'subject', 'actorClass', 'credentialClass', 'generation', 'authorityEpoch', 'issuedAt', 'expiresAt', 'state', 'groups', 'scope', 'secretDigest'], 'credential record');
  if (record.schemaVersion !== 'ogvcs.identity-policy/credential-record/v1') identityFail('INPUT_INVALID', 'credential schema is invalid');
  text(record.id, ID, 'credential.id'); text(record.subject, ID, 'credential.subject');
  if (!ACTOR_CLASSES.includes(record.actorClass)) identityFail('INPUT_INVALID', 'credential.actorClass is invalid');
  if (!['session', 'service-token'].includes(record.credentialClass)) identityFail('INPUT_INVALID', 'credential.class is invalid');
  if (record.credentialClass === 'service-token' && record.actorClass !== 'service') identityFail('INPUT_INVALID', 'service token must identify a service');
  if (record.credentialClass === 'session' && !['human', 'administrator'].includes(record.actorClass)) identityFail('INPUT_INVALID', 'session actor class is invalid');
  integer(record.generation, 1, 'credential.generation'); integer(record.authorityEpoch, 1, 'credential.authorityEpoch');
  integer(record.issuedAt, 0, 'credential.issuedAt'); integer(record.expiresAt, 1, 'credential.expiresAt');
  if (record.expiresAt <= record.issuedAt) identityFail('INPUT_INVALID', 'credential validity window is invalid');
  const maximum = record.credentialClass === 'session' ? RUNTIME_LIMITS.sessionMaxTtlSeconds : RUNTIME_LIMITS.serviceTokenMaxTtlSeconds;
  if (record.expiresAt - record.issuedAt > maximum) identityFail('LIMIT_EXCEEDED', 'credential validity exceeds its class');
  if (!['active', 'revoked'].includes(record.state)) identityFail('INPUT_INVALID', 'credential state is invalid');
  stringSet(record.groups, { maximum: 64 }, 'credential.groups');
  record.scope = validateScope(record.scope, pathOptions, 'credential.scope');
  text(record.secretDigest, SHA256, 'credential.secretDigest');
  return deepFreeze(record);
}

export function scopeMatches(scope, request, pathOptions) {
  if (!scope.tenants.includes(request.tenant) || !scope.repositories.includes(request.repository)
      || !scope.permissions.includes(request.permission)) return false;
  if (scope.references.length > 0 && !scope.references.includes(request.context.reference)) return false;
  if (scope.pathPrefixes.length === 0) return true;
  if (typeof request.resource.path !== 'string') return false;
  let requestPath;
  try { requestPath = canonicalPrefix(request.resource.path, pathOptions).comparison; }
  catch { return false; }
  return scope.pathPrefixes.some((prefix) => {
    const comparison = canonicalPrefix(prefix, pathOptions).comparison;
    return comparison === '' || requestPath === comparison || requestPath.startsWith(`${comparison}/`);
  });
}
