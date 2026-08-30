import {
  canonicalBytes,
  validateAuthorizationRequest,
  validateTransferGrantClaims,
  validateTransferGrantEnvelope,
  verifyTransferGrant,
} from '@opengamevcs/authorization-contract';

import { AuthorityState } from './credentials.mjs';
import { asIdentityError, identityFail } from './errors.mjs';
import { RUNTIME_LIMITS, cloneBounded, deepFreeze } from './validate.mjs';

export class TransferGrantAuthority {
  #clock;
  #credentials;
  #issuer;
  #keyId;
  #keyResolver;
  #nonces;
  #revoking = new Set();
  #signer;
  #state;
  #policy;

  constructor({ authorityState, credentialAuthority, policyEngine, nonceLedger, issuer, keyId, signer, keyResolver, clock = () => Math.floor(Date.now() / 1000) }) {
    if (!(authorityState instanceof AuthorityState) || typeof issuer !== 'string' || typeof keyId !== 'string'
        || !credentialAuthority || typeof credentialAuthority.authorizePrincipal !== 'function'
        || !policyEngine || typeof policyEngine.authorize !== 'function'
        || !nonceLedger || typeof nonceLedger.accept !== 'function' || typeof nonceLedger.revoke !== 'function'
        || !signer || typeof signer.sign !== 'function' || typeof keyResolver !== 'function' || typeof clock !== 'function') identityFail('INPUT_INVALID', 'transfer grant authority is invalid');
    this.#state = authorityState; this.#credentials = credentialAuthority; this.#policy = policyEngine;
    this.#nonces = nonceLedger;
    this.#issuer = issuer; this.#keyId = keyId; this.#signer = signer; this.#keyResolver = keyResolver; this.#clock = clock;
  }

  issue(principal, options) {
    if (!principal?.actor || principal.actor.authorityEpoch !== this.#state.authorityEpoch) identityFail('EPOCH_STALE');
    const input = cloneBounded(options);
    let request;
    try { request = validateAuthorizationRequest({ ...input.authorizationRequest, actor: structuredClone(principal.actor) }); }
    catch (error) { identityFail('INPUT_INVALID', 'grant authorization request is invalid', { cause: error }); }
    if (request.tenant !== input.tenant || request.repository !== input.repository || request.permission !== input.permission
        || request.permission !== (input.operation === 'download' ? 'content.materialize' : 'content.upload')) identityFail('AUTHENTICATION_DENIED');
    if (input.requestRoot !== null && input.requestRoot !== undefined) identityFail('INPUT_INVALID', 'request-root grant issuance is not implemented in this cut');
    if (!Array.isArray(input.objectIds) || input.objectIds.length !== 1 || request.resource.objectId !== input.objectIds[0]) {
      identityFail('AUTHENTICATION_DENIED', 'grant object does not bind the authorized resource');
    }
    const decision = this.#policy.authorize(request, {
      credentialCheck: (validated) => this.#credentials.authorizePrincipal(principal, validated),
    });
    if (!decision.allowed) identityFail('AUTHENTICATION_DENIED');
    const now = this.#now();
    if (!Number.isSafeInteger(input.ttlSeconds) || input.ttlSeconds < 1 || input.ttlSeconds > RUNTIME_LIMITS.transferGrantMaxTtlSeconds) identityFail('LIMIT_EXCEEDED', 'transfer grant TTL exceeds its bound');
    let claims;
    try {
      claims = validateTransferGrantClaims({
        schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1',
        issuer: this.#issuer,
        keyId: this.#keyId,
        keyGeneration: this.#state.keyGeneration,
        authorityEpoch: this.#state.authorityEpoch,
        subject: principal.actor.id,
        tenant: input.tenant,
        repository: input.repository,
        permission: input.permission,
        operation: input.operation,
        audience: input.audience,
        issuedAt: now,
        expiresAt: now + input.ttlSeconds,
        nonce: input.nonce,
        replay: input.replay,
        objectIds: input.objectIds ?? [],
        requestRoot: input.requestRoot ?? null,
      });
    } catch (error) { identityFail('INPUT_INVALID', 'transfer grant claims are invalid', { cause: error }); }
    let envelope;
    try {
      envelope = validateTransferGrantEnvelope(this.#signer.sign(claims));
      if (!canonicalBytes(envelope.claims).equals(canonicalBytes(claims))) {
        throw new TypeError('transfer grant signer changed the authorized claims');
      }
    }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'transfer grant signer failed closed', { cause: error }); }
    return deepFreeze(envelope);
  }

  verify(envelopeInput, contextInput) {
    let envelope;
    try { envelope = validateTransferGrantEnvelope(envelopeInput); }
    catch { return Object.freeze({ result: 'deny', code: 'DENY_GRANT_INVALID' }); }
    if (envelope.keyId !== this.#keyId) return Object.freeze({ result: 'deny', code: 'DENY_GRANT_INVALID' });
    let key;
    try { key = this.#keyResolver(this.#keyId); }
    catch { return Object.freeze({ result: 'deny', code: 'DENY_GRANT_INVALID' }); }
    try {
      const decision = verifyTransferGrant(envelope, {
        ...cloneBounded(contextInput),
        issuer: this.#issuer,
        keyId: this.#keyId,
        authorityEpoch: this.#state.authorityEpoch,
        keyGeneration: this.#state.keyGeneration,
        now: this.#now(),
        consumedNonces: [],
      }, key);
      if (decision.result !== 'allow') return decision;
      const nonceResult = this.#nonces.accept(envelope.claims.nonce, envelope.claims.replay);
      if (nonceResult === 'accepted') return decision;
      if (nonceResult === 'replayed') return Object.freeze({ result: 'deny', code: 'DENY_GRANT_REPLAY' });
      return Object.freeze({ result: 'deny', code: 'DENY_GRANT_INVALID' });
    } catch { return Object.freeze({ result: 'deny', code: 'DENY_GRANT_INVALID' }); }
  }

  revokeNonce(nonce, { audit } = {}) {
    if (typeof nonce !== 'string' || !/^[A-Za-z0-9._:-]{1,256}$/u.test(nonce)) identityFail('INPUT_INVALID', 'grant nonce is invalid');
    if (this.#revoking.has(nonce)) identityFail('STATE_CONFLICT', 'grant revocation is reentrant');
    if (typeof audit !== 'function') identityFail('POLICY_UNAVAILABLE', 'grant revocation requires an audit sink');
    this.#revoking.add(nonce);
    try {
      const result = audit(Object.freeze({ credentialClass: 'transfer-grant' }));
      if (result && typeof result.then === 'function') throw new TypeError('asynchronous audit callback is unsupported');
    } catch (error) {
      identityFail('POLICY_UNAVAILABLE', 'grant revocation audit failed closed', { cause: error });
    } finally { this.#revoking.delete(nonce); }
    try { this.#nonces.revoke(nonce); }
    catch (error) { identityFail(error?.code === 'LIMIT_EXCEEDED' ? 'LIMIT_EXCEEDED' : 'POLICY_UNAVAILABLE', 'grant revocation store failed closed', { cause: error }); }
  }

  #now() {
    let value;
    try { value = this.#clock(); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
    if (!Number.isSafeInteger(value) || value < 0) identityFail('POLICY_UNAVAILABLE', 'clock failed closed');
    return value;
  }
}

export class MemoryGrantNonceLedger {
  #consumed = new Set();
  #entries = new Set();
  #maximum;
  #revoked = new Set();

  constructor({ maximum = 100_000 } = {}) {
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 100_000) identityFail('INPUT_INVALID', 'grant nonce bound is invalid');
    this.#maximum = maximum;
  }

  accept(nonce, replay) {
    if (this.#revoked.has(nonce)) return 'revoked';
    if (replay === 'idempotent') return 'accepted';
    if (replay !== 'single-use') identityFail('INPUT_INVALID', 'grant replay class is invalid');
    if (this.#consumed.has(nonce)) return 'replayed';
    this.#reserve(nonce);
    this.#consumed.add(nonce);
    return 'accepted';
  }

  revoke(nonce) {
    if (!this.#revoked.has(nonce)) this.#reserve(nonce);
    this.#revoked.add(nonce);
  }

  #reserve(nonce) {
    if (!this.#entries.has(nonce) && this.#entries.size >= this.#maximum) identityFail('LIMIT_EXCEEDED', 'grant nonce bound exceeded');
    this.#entries.add(nonce);
  }
}
