import { createHash } from 'node:crypto';

import { validateAuthorizationRequest } from '@opengamevcs/authorization-contract';

import { identityFail } from './errors.mjs';
import { RUNTIME_LIMITS } from './validate.mjs';
import { buildAuthorizedView } from './views.mjs';

const SAFE_REQUEST_ID = /^[A-Za-z0-9._:-]{1,256}$/u;
const PROTOCOL_CORRELATION_ID = /^[A-Za-z0-9._~-]{16,128}$/u;

function authenticationDecision(policy, requestInput, code) {
  return policy.deny({ requestId: SAFE_REQUEST_ID.test(requestInput?.requestId ?? '') ? requestInput.requestId : 'invalid' }, code);
}

export class IdentityPolicyRuntime {
  #credentials;
  #policy;
  #problems;
  #rate;
  #rateSource;

  constructor({ policyEngine, credentialAuthority, rateLimiter, rateSource, protocolProblems = null }) {
    if (!policyEngine || typeof policyEngine.authorize !== 'function' || !credentialAuthority || typeof credentialAuthority.authenticate !== 'function'
        || !rateLimiter || typeof rateLimiter.consume !== 'function' || typeof rateSource !== 'function') {
      identityFail('INPUT_INVALID', 'identity runtime adapters are invalid');
    }
    this.#policy = policyEngine; this.#credentials = credentialAuthority; this.#rate = rateLimiter;
    this.#rateSource = rateSource; this.#problems = protocolProblems;
  }

  authorizeToken(token, requestInput, options = {}) {
    if (!options || typeof options !== 'object' || Array.isArray(options)
        || Object.keys(options).some((key) => !['requestClass', 'rateContext'].includes(key))) {
      identityFail('INPUT_INVALID', 'authorization runtime options are invalid');
    }
    const requestClass = options.requestClass ?? 'authorization';
    if (!/^[a-z][a-z0-9.-]{0,127}$/u.test(requestClass)) identityFail('INPUT_INVALID', 'authorization request class is invalid');
    let request;
    try { request = validateAuthorizationRequest(requestInput); }
    catch { return this.#outcome(this.#policy.authorize(requestInput, { credentialCheck: () => false })); }
    const boundedToken = typeof token === 'string' && Buffer.byteLength(token, 'utf8') <= RUNTIME_LIMITS.maxTokenBytes;
    const tokenRateKey = boundedToken
      ? createHash('sha256').update('OGVCS-RATE-V1\0').update(token).digest('hex')
      : 'invalid';
    let trustedRateSource;
    try { trustedRateSource = this.#rateSource(options.rateContext); }
    catch { trustedRateSource = null; }
    const boundedSource = typeof trustedRateSource === 'string'
      && trustedRateSource.length >= 1 && Buffer.byteLength(trustedRateSource, 'utf8') <= 256;
    const sourceRateKey = boundedSource
      ? createHash('sha256').update('OGVCS-RATE-SOURCE-V1\0').update(trustedRateSource).digest('hex')
      : 'invalid-source';
    let rate;
    try {
      const sourceRate = this.#rate.consume(sourceRateKey, `${requestClass}.source`);
      rate = sourceRate?.allowed === true ? this.#rate.consume(tokenRateKey, `${requestClass}.credential`) : sourceRate;
    }
    catch { return this.#outcome(authenticationDecision(this.#policy, request, 'DENY_POLICY_UNAVAILABLE')); }
    if (!rate || rate.allowed !== true) {
      const code = rate?.allowed === false ? 'DENY_RATE_LIMITED' : 'DENY_POLICY_UNAVAILABLE';
      return this.#outcome(authenticationDecision(this.#policy, request, code));
    }
    let principal;
    try { principal = this.#credentials.authenticate(token); }
    catch (error) {
      const code = error?.code === 'EPOCH_STALE' ? 'DENY_EPOCH_STALE' : 'DENY_NOT_AUTHORIZED';
      return this.#outcome(authenticationDecision(this.#policy, request, code), code);
    }
    const scoped = { ...request, actor: structuredClone(principal.actor) };
    const decision = this.#policy.authorize(scoped, {
      credentialCheck: (validated) => this.#credentials.authorizePrincipal(principal, validated),
    });
    return this.#outcome(decision, decision.code, principal);
  }

  authorizedView(token, options) {
    const authorization = this.authorizeToken(token, options.request, {
      requestClass: options.requestClass ?? 'enumeration', rateContext: options.rateContext,
    });
    if (!authorization.decision.allowed) return Object.freeze({ authorization, view: null });
    return Object.freeze({
      authorization,
      view: buildAuthorizedView({
        engine: this.#policy,
        principal: authorization.principal,
        credentialAuthority: this.#credentials,
        request: options.request,
        candidates: options.candidates,
        resourceFor: options.resourceFor,
        maxCandidates: options.maxCandidates,
        maxItems: options.maxItems,
      }),
    });
  }

  #outcome(decision, authorizationCode = decision.code, principal = null) {
    const correlationId = PROTOCOL_CORRELATION_ID.test(decision.requestId)
      ? decision.requestId
      : createHash('sha256').update('OGVCS-CORRELATION-V1\0').update(decision.requestId).digest('hex').slice(0, 32);
    let problem = null;
    if (!decision.allowed && this.#problems !== null) {
      try { problem = this.#problems.response('AUTHORIZATION_DENIED', { correlationId }); }
      catch (error) { identityFail('POLICY_UNAVAILABLE', 'protocol denial mapping failed closed', { cause: error }); }
    }
    return Object.freeze({ decision, authorizationCode, problem, principal });
  }
}
