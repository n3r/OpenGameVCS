import { createHash, createPrivateKey, sign } from 'node:crypto';

import { permissions } from './contract.mjs';

export const GRANT_DOMAIN = Buffer.from('OGVCS-AUTH-GRANT-V1\0', 'ascii');
export const REQUEST_ROOT_DOMAIN = Buffer.from('OGVCS-AUTH-REQUEST-ROOT-V1\0', 'ascii');

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('value is outside canonical JSON domain');
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value), 'utf8');
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function requestRootForObjectIds(objectIds) {
  if (!Array.isArray(objectIds) || objectIds.length === 0 || objectIds.length > 32_768 || new Set(objectIds).size !== objectIds.length) {
    throw new TypeError('request root requires a bounded, nonempty, unique object-ID set');
  }
  if (objectIds.some((value) => typeof value !== 'string' || !/^[A-Za-z0-9:._-]{1,160}$/.test(value))) {
    throw new TypeError('request root contains an invalid object ID');
  }
  return `sha256:${sha256(Buffer.concat([REQUEST_ROOT_DOMAIN, canonicalBytes([...objectIds].sort())]))}`;
}

function segmentPrefix(path, prefix) {
  return prefix === '' || path === prefix || path.startsWith(`${prefix}/`);
}

function anyIntersection(left, right) {
  return left.some((value) => right.includes(value));
}

function matches(rule, request) {
  if (rule.actors.length > 0 && !rule.actors.includes(request.actor.id)) return false;
  if (rule.groups.length > 0 && !anyIntersection(rule.groups, request.actor.groups)) return false;
  if (rule.actorClasses.length > 0 && !rule.actorClasses.includes(request.actor.class)) return false;
  if (!rule.tenants.includes(request.tenant) || !rule.repositories.includes(request.repository)) return false;
  if (rule.references.length > 0 && !rule.references.includes(request.context.reference)) return false;
  if (rule.pathPrefixes.length > 0 && (
    typeof request.resource.path !== 'string' ||
    !rule.pathPrefixes.some((prefix) => segmentPrefix(request.resource.path, prefix))
  )) return false;
  return rule.resourceTypes.includes(request.resource.type) && rule.permissions.includes(request.permission);
}

function decision(policy, request, allowed, code) {
  const fingerprintInput = {
    policy: {
      id: policy.id,
      version: policy.version,
      policyGeneration: policy.policyGeneration,
    },
    request,
  };
  return {
    schemaVersion: 'ogvcs.authorization/decision/v1',
    requestId: request.requestId,
    allowed,
    code,
    policyVersion: `${policy.id}.${policy.version}`,
    policyGeneration: policy.policyGeneration,
    decisionFingerprint: sha256(canonicalBytes(fingerprintInput)),
  };
}

export function evaluatePolicy(policy, request) {
  if (!request || typeof request !== 'object' || !request.actor || !request.context || !request.resource) {
    return decision(policy, { requestId: request?.requestId ?? 'invalid-request', ...request }, false, 'DENY_CONTEXT_INCOMPLETE');
  }
  if (request.context.policyGeneration !== policy.policyGeneration) {
    return decision(policy, request, false, 'DENY_POLICY_GENERATION_MISMATCH');
  }
  if (request.context.authorityEpoch !== policy.authorityEpoch || request.actor.authorityEpoch !== policy.authorityEpoch) {
    return decision(policy, request, false, 'DENY_EPOCH_STALE');
  }
  if (request.actor.credentialStatus !== 'active') {
    return decision(policy, request, false, 'DENY_EPOCH_STALE');
  }
  const permission = permissions.find(({ name }) => name === request.permission);
  if (!permission) return decision(policy, request, false, 'DENY_CONTEXT_INCOMPLETE');
  if (permission.reasonRequired && (typeof request.reason !== 'string' || request.reason.trim() === '')) {
    return decision(policy, request, false, 'DENY_PRIVILEGED_REASON_REQUIRED');
  }
  const matching = policy.rules.filter((rule) => matches(rule, request));
  if (matching.some(({ effect }) => effect === 'deny')) {
    return decision(policy, request, false, 'DENY_NOT_AUTHORIZED');
  }
  if (matching.some(({ effect }) => effect === 'allow')) {
    return decision(policy, request, true, 'ALLOW_EXPLICIT');
  }
  return decision(policy, request, false, 'DENY_NOT_AUTHORIZED');
}

export function makeRequest(repository, id, actorId, resourceId, permission, overrides = {}) {
  const actor = structuredClone(repository.actors.find(({ id: candidate }) => candidate === actorId));
  const resource = structuredClone(repository.resources.find(({ id: candidate }) => candidate === resourceId));
  if (!actor || !resource) throw new Error(`unknown golden fixture binding for ${id}`);
  delete resource.id;
  delete resource.visibility;
  return {
    schemaVersion: 'ogvcs.authorization/request/v1',
    requestId: id,
    actor,
    tenant: repository.tenant,
    repository: repository.repository,
    permission,
    reason: null,
    resource,
    context: {
      reference: 'main',
      snapshot: 'snapshot-main-0001',
      policyGeneration: repository.policyGeneration,
      authorityEpoch: repository.authorityEpoch,
    },
    ...structuredClone(overrides),
  };
}

export function signGrantFixture(grantFixture) {
  const claimsBytes = canonicalBytes(grantFixture.claims);
  const signature = sign(null, Buffer.concat([GRANT_DOMAIN, claimsBytes]), createPrivateKey({
    key: grantFixture.privateJwk,
    format: 'jwk',
  })).toString('base64url');
  return {
    schemaVersion: 'ogvcs.authorization/transfer-grant/v1',
    algorithm: 'Ed25519',
    keyId: grantFixture.claims.keyId,
    claims: structuredClone(grantFixture.claims),
    signature,
  };
}
