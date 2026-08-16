import { canonicalBytes, cloneJson, deepFreeze, sha256 } from './canonical.mjs';
import { PERMISSIONS } from './generated.mjs';
import { safeRequestId, validateAuthorizationRequest, validatePolicyFixture } from './validate.mjs';

function segmentPrefix(path, prefix) {
  return prefix === '' || path === prefix || path.startsWith(`${prefix}/`);
}

function intersects(left, right) {
  return left.some((value) => right.includes(value));
}

function matches(rule, request) {
  if (rule.actors.length > 0 && !rule.actors.includes(request.actor.id)) return false;
  if (rule.groups.length > 0 && !intersects(rule.groups, request.actor.groups)) return false;
  if (rule.actorClasses.length > 0 && !rule.actorClasses.includes(request.actor.class)) return false;
  if (!rule.tenants.includes(request.tenant) || !rule.repositories.includes(request.repository)) return false;
  if (rule.references.length > 0 && !rule.references.includes(request.context.reference)) return false;
  if (rule.pathPrefixes.length > 0 && (
    typeof request.resource.path !== 'string' ||
    !rule.pathPrefixes.some((prefix) => segmentPrefix(request.resource.path, prefix))
  )) return false;
  return rule.resourceTypes.includes(request.resource.type) && rule.permissions.includes(request.permission);
}

function result(policy, requestId, fingerprintRequest, allowed, code) {
  const fingerprintInput = {
    policy: { id: policy.id, version: policy.version, policyGeneration: policy.policyGeneration },
    request: fingerprintRequest,
  };
  return deepFreeze({
    schemaVersion: 'ogvcs.authorization/decision/v1',
    requestId,
    allowed,
    code,
    policyVersion: `${policy.id}.${policy.version}`,
    policyGeneration: policy.policyGeneration,
    decisionFingerprint: sha256(canonicalBytes(fingerprintInput)),
  });
}

export function evaluateFixturePolicy(policyInput, requestInput) {
  const policy = validatePolicyFixture(policyInput);
  let request;
  try {
    request = validateAuthorizationRequest(requestInput);
  } catch {
    const requestId = safeRequestId(requestInput);
    return result(policy, requestId, { invalid: true, requestId }, false, 'DENY_CONTEXT_INCOMPLETE');
  }
  if (request.context.policyGeneration !== policy.policyGeneration) {
    return result(policy, request.requestId, request, false, 'DENY_POLICY_GENERATION_MISMATCH');
  }
  if (request.context.authorityEpoch !== policy.authorityEpoch || request.actor.authorityEpoch !== policy.authorityEpoch || request.actor.credentialStatus !== 'active') {
    return result(policy, request.requestId, request, false, 'DENY_EPOCH_STALE');
  }
  const permission = PERMISSIONS.includes(request.permission) ? request.permission : null;
  if (!permission) return result(policy, request.requestId, request, false, 'DENY_CONTEXT_INCOMPLETE');
  const privileged = ['export', 'policy.administer', 'lock.force-unlock', 'repair', 'retention.delete', 'audit.read', 'impersonate'].includes(permission);
  if (privileged && (typeof request.reason !== 'string' || request.reason.trim() === '')) {
    return result(policy, request.requestId, request, false, 'DENY_PRIVILEGED_REASON_REQUIRED');
  }
  const matching = policy.rules.filter((rule) => matches(rule, request));
  if (matching.some(({ effect }) => effect === 'deny')) return result(policy, request.requestId, request, false, 'DENY_NOT_AUTHORIZED');
  if (matching.some(({ effect }) => effect === 'allow')) return result(policy, request.requestId, request, true, 'ALLOW_EXPLICIT');
  return result(policy, request.requestId, request, false, 'DENY_NOT_AUTHORIZED');
}

export function makeFixtureRequest(repository, id, actorId, resourceId, permission, overrides = {}) {
  const actorSource = repository?.actors?.find(({ id: candidate }) => candidate === actorId);
  const resourceSource = repository?.resources?.find(({ id: candidate }) => candidate === resourceId);
  const actor = actorSource === undefined ? undefined : cloneJson(actorSource);
  const resource = resourceSource === undefined ? undefined : cloneJson(resourceSource);
  if (!actor || !resource) throw new TypeError(`unknown golden fixture binding for ${id}`);
  delete resource.id;
  delete resource.visibility;
  const base = {
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
  };
  return validateAuthorizationRequest({ ...base, ...cloneJson(overrides) });
}
