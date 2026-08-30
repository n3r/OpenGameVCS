import {
  canonicalBytes,
  sha256,
  validateAuthorizationDecision,
  validateAuthorizationRequest,
} from '@opengamevcs/authorization-contract';

import { identityFail } from './errors.mjs';
import { validatePolicyDocument, canonicalPrefix } from './validate.mjs';

const SAFE_REQUEST_ID = /^[A-Za-z0-9._:-]{1,256}$/u;

function requestId(value) {
  try { return SAFE_REQUEST_ID.test(value?.requestId ?? '') ? value.requestId : 'invalid'; }
  catch { return 'invalid'; }
}
function intersects(left, right) { return left.some((value) => right.includes(value)); }

function result(policy, request, allowed, code, fingerprintInput = request) {
  return Object.freeze(validateAuthorizationDecision({
    schemaVersion: 'ogvcs.authorization/decision/v1',
    requestId: requestId(request),
    allowed,
    code,
    policyVersion: `${policy.id}.${policy.version}`,
    policyGeneration: policy.generation,
    decisionFingerprint: sha256(canonicalBytes({
      policy: { id: policy.id, version: policy.version, generation: policy.generation, authorityEpoch: policy.authorityEpoch },
      request: fingerprintInput,
    })),
  }));
}

function pathMatch(prefixes, requestPath, policy) {
  if (prefixes.length === 0) return true;
  if (typeof requestPath !== 'string') return false;
  const actual = canonicalPrefix(requestPath, policy).comparison;
  return prefixes.some((prefix) => {
    const expected = canonicalPrefix(prefix, policy).comparison;
    return expected === '' || actual === expected || actual.startsWith(`${expected}/`);
  });
}

function ruleMatches(rule, request, policy) {
  const subject = rule.subjects;
  if (subject.identities.length > 0 && !subject.identities.includes(request.actor.id)) return false;
  if (subject.groups.length > 0 && !intersects(subject.groups, request.actor.groups)) return false;
  if (subject.actorClasses.length > 0 && !subject.actorClasses.includes(request.actor.class)) return false;
  if (rule.tenant !== request.tenant || rule.repository !== request.repository) return false;
  if (rule.references.length > 0 && !rule.references.includes(request.context.reference)) return false;
  return rule.resourceTypes.includes(request.resource.type)
    && rule.permissions.includes(request.permission)
    && pathMatch(rule.pathPrefixes, request.resource.path, policy);
}

export class PolicyEngine {
  #failureHook;
  #policy;

  constructor(policyInput, options = {}) {
    this.#policy = validatePolicyDocument(policyInput);
    this.#failureHook = options.failureHook;
  }

  get policy() { return this.#policy; }

  deny(requestInput, code) {
    if (!['DENY_NOT_AUTHORIZED', 'DENY_EPOCH_STALE', 'DENY_RATE_LIMITED', 'DENY_POLICY_UNAVAILABLE'].includes(code)) {
      identityFail('INPUT_INVALID', 'unsupported explicit denial code');
    }
    return result(this.#policy, requestInput, false, code, { denial: code, requestId: requestId(requestInput) });
  }

  authorize(requestInput, options = {}) {
    let request;
    try {
      request = validateAuthorizationRequest(requestInput);
      if (request.resource.path !== null) canonicalPrefix(request.resource.path, this.#policy);
    } catch {
      return result(this.#policy, requestInput, false, 'DENY_CONTEXT_INCOMPLETE', { invalid: true, requestId: requestId(requestInput) });
    }
    try {
      const hookResult = this.#failureHook?.();
      if (hookResult && typeof hookResult.then === 'function') throw new TypeError('asynchronous policy hooks are unsupported');
      if (options.rateLimited === true) return result(this.#policy, request, false, 'DENY_RATE_LIMITED');
      if (request.context.policyGeneration !== this.#policy.generation) return result(this.#policy, request, false, 'DENY_POLICY_GENERATION_MISMATCH');
      if (request.context.authorityEpoch !== this.#policy.authorityEpoch
          || request.actor.authorityEpoch !== this.#policy.authorityEpoch) return result(this.#policy, request, false, 'DENY_EPOCH_STALE');
      if (request.actor.credentialStatus !== 'active') return result(this.#policy, request, false, 'DENY_NOT_AUTHORIZED');
      if (typeof options.credentialCheck !== 'function' || options.credentialCheck(request) !== true) return result(this.#policy, request, false, 'DENY_NOT_AUTHORIZED');
      const privileged = ['export', 'policy.administer', 'lock.force-unlock', 'repair', 'retention.delete', 'audit.read', 'impersonate'].includes(request.permission);
      if (privileged && (typeof request.reason !== 'string' || request.reason.trim() === '')) return result(this.#policy, request, false, 'DENY_PRIVILEGED_REASON_REQUIRED');
      const matching = this.#policy.rules.filter((rule) => ruleMatches(rule, request, this.#policy));
      if (matching.some(({ effect }) => effect === 'deny')) return result(this.#policy, request, false, 'DENY_NOT_AUTHORIZED');
      return matching.some(({ effect }) => effect === 'allow')
        ? result(this.#policy, request, true, 'ALLOW_EXPLICIT')
        : result(this.#policy, request, false, 'DENY_NOT_AUTHORIZED');
    } catch {
      return result(this.#policy, request, false, 'DENY_POLICY_UNAVAILABLE');
    }
  }
}
