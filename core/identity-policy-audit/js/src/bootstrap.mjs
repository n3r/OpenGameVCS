import { createHash, timingSafeEqual } from 'node:crypto';

import { asIdentityError, identityFail } from './errors.mjs';
import { RUNTIME_LIMITS, cloneBounded, deepFreeze } from './validate.mjs';

const ID = /^[a-z][a-z0-9.-]{0,127}$/u;
const DOMAIN = Buffer.from('OGVCS-IDENTITY-BOOTSTRAP-RECOVERY-V1\0', 'ascii');

function digest(secret) { return createHash('sha256').update(DOMAIN).update(secret, 'utf8').digest('hex'); }

function equalDigest(left, right) {
  if (!/^[0-9a-f]{64}$/u.test(left ?? '') || !/^[0-9a-f]{64}$/u.test(right ?? '')) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function secretFrom(source) {
  let value;
  try { value = source('bootstrap-recovery'); }
  catch (error) { identityFail('POLICY_UNAVAILABLE', 'bootstrap secret source failed closed', { cause: error }); }
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) identityFail('POLICY_UNAVAILABLE', 'bootstrap secret source is invalid');
  return `ogvcs-recovery1.${Buffer.from(value).toString('base64url')}`;
}

function validateState(input) {
  const state = cloneBounded(input, { maxBytes: 8_192, maxDepth: 4, maxNodes: 32, maxStringBytes: 256 });
  const expected = [
    'schemaVersion', 'generation', 'administratorSubject', 'recoveryDigest',
    'recoveryConfigured', 'externalRecoveryConfigured', 'localLoginEnabled',
    'failedAttempts', 'authorityEpoch',
  ].sort();
  const keys = Object.keys(state).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
      || state.schemaVersion !== 'ogvcs.identity-policy/bootstrap-state/v1'
      || !Number.isSafeInteger(state.generation) || state.generation < 1
      || !ID.test(state.administratorSubject)
      || !/^[0-9a-f]{64}$/u.test(state.recoveryDigest)
      || typeof state.recoveryConfigured !== 'boolean'
      || typeof state.externalRecoveryConfigured !== 'boolean'
      || typeof state.localLoginEnabled !== 'boolean'
      || !Number.isSafeInteger(state.failedAttempts) || state.failedAttempts < 0
      || !Number.isSafeInteger(state.authorityEpoch) || state.authorityEpoch < 1
      || !state.recoveryConfigured
      || (!state.localLoginEnabled && !state.externalRecoveryConfigured)) {
    identityFail('POLICY_UNAVAILABLE', 'bootstrap state is invalid');
  }
  return deepFreeze(state);
}

export class BootstrapAuthority {
  #principals = new WeakSet();
  #rateLimiter;
  #rateSource;
  #secretSource;
  #store;

  constructor({ store, secretSource, rateLimiter, rateSource }) {
    if (!store || typeof store.read !== 'function' || typeof store.create !== 'function'
        || typeof store.compareAndSwap !== 'function' || typeof secretSource !== 'function'
        || !rateLimiter || typeof rateLimiter.consume !== 'function' || typeof rateSource !== 'function') {
      identityFail('INPUT_INVALID', 'bootstrap authority dependencies are invalid');
    }
    this.#store = store; this.#secretSource = secretSource; this.#rateLimiter = rateLimiter; this.#rateSource = rateSource;
  }

  initialize({ administratorSubject, authorityEpoch }) {
    if (!ID.test(administratorSubject ?? '') || !Number.isSafeInteger(authorityEpoch) || authorityEpoch < 1) {
      identityFail('INPUT_INVALID', 'bootstrap initialization is invalid');
    }
    const recoveryCode = secretFrom(this.#secretSource);
    const state = validateState({
      schemaVersion: 'ogvcs.identity-policy/bootstrap-state/v1', generation: 1,
      administratorSubject, recoveryDigest: digest(recoveryCode), recoveryConfigured: true,
      externalRecoveryConfigured: false, localLoginEnabled: true, failedAttempts: 0,
      authorityEpoch,
    });
    try { this.#store.create(state); }
    catch (error) { throw asIdentityError(error, 'STATE_CONFLICT'); }
    return deepFreeze({ recoveryCode, state: this.#publicState(state) });
  }

  recover(recoveryCode, options = {}) {
    if (!options || typeof options !== 'object' || Array.isArray(options)
        || Object.keys(options).some((key) => !['mode', 'rateContext'].includes(key))) identityFail('AUTHENTICATION_DENIED');
    const mode = options.mode ?? 'recovery';
    if (typeof recoveryCode !== 'string' || Buffer.byteLength(recoveryCode, 'utf8') > 128
        || !['login', 'recovery'].includes(mode)) identityFail('AUTHENTICATION_DENIED');
    let trustedRateSource;
    try { trustedRateSource = this.#rateSource(options.rateContext); }
    catch { trustedRateSource = null; }
    const source = typeof trustedRateSource === 'string' && trustedRateSource.length >= 1
      && Buffer.byteLength(trustedRateSource, 'utf8') <= 256 ? trustedRateSource : 'invalid-source';
    let rate;
    try { rate = this.#rateLimiter.consume(createHash('sha256').update('OGVCS-BOOTSTRAP-RATE-V1\0').update(source).digest('hex'), `bootstrap.${mode}`); }
    catch (error) { identityFail('AUTHENTICATION_DENIED', 'bootstrap rate control failed closed', { cause: error }); }
    if (!rate || rate.allowed !== true) identityFail('AUTHENTICATION_DENIED');
    const current = this.#read();
    if (current.failedAttempts >= RUNTIME_LIMITS.maxBootstrapFailedAttempts) identityFail('AUTHENTICATION_DENIED');
    if (mode === 'login' && !current.localLoginEnabled) identityFail('AUTHENTICATION_DENIED');
    if (!equalDigest(current.recoveryDigest, digest(recoveryCode))) {
      const failed = validateState({ ...current, generation: current.generation + 1, failedAttempts: current.failedAttempts + 1 });
      try { this.#store.compareAndSwap(current.generation, failed); }
      catch (error) { throw asIdentityError(error, 'AUTHENTICATION_DENIED'); }
      identityFail('AUTHENTICATION_DENIED');
    }
    const replacement = secretFrom(this.#secretSource);
    const next = validateState({
      ...current, generation: current.generation + 1, recoveryDigest: digest(replacement), failedAttempts: 0,
    });
    try { this.#store.compareAndSwap(current.generation, next); }
    catch (error) { throw asIdentityError(error, 'AUTHENTICATION_DENIED'); }
    const principal = this.#principal(next);
    return deepFreeze({ principal, replacementRecoveryCode: replacement, state: this.#publicState(next) });
  }

  configureExternalRecovery(principal) {
    const current = this.#authorized(principal);
    if (current.externalRecoveryConfigured) return deepFreeze({ principal, state: this.#publicState(current) });
    const next = validateState({ ...current, generation: current.generation + 1, externalRecoveryConfigured: true });
    try { this.#store.compareAndSwap(current.generation, next); }
    catch (error) { throw asIdentityError(error, 'STATE_CONFLICT'); }
    this.#principals.delete(principal);
    return deepFreeze({ principal: this.#principal(next), state: this.#publicState(next) });
  }

  disableLocalLogin(principal) {
    const current = this.#authorized(principal);
    if (!current.externalRecoveryConfigured) identityFail('STATE_CONFLICT', 'local login requires an independent recovery configuration before disablement');
    if (!current.localLoginEnabled) return deepFreeze({ principal, state: this.#publicState(current) });
    const next = validateState({ ...current, generation: current.generation + 1, localLoginEnabled: false });
    try { this.#store.compareAndSwap(current.generation, next); }
    catch (error) { throw asIdentityError(error, 'STATE_CONFLICT'); }
    this.#principals.delete(principal);
    return deepFreeze({ principal: this.#principal(next), state: this.#publicState(next) });
  }

  inspect() { return this.#publicState(this.#read()); }

  #authorized(principal) {
    if (!principal || typeof principal !== 'object' || !this.#principals.has(principal)) identityFail('AUTHENTICATION_DENIED');
    const current = this.#read();
    if (principal.subject !== current.administratorSubject || principal.authorityEpoch !== current.authorityEpoch
        || principal.bootstrapGeneration !== current.generation) identityFail('AUTHENTICATION_DENIED');
    return current;
  }

  #read() {
    let state;
    try { state = this.#store.read(); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'bootstrap state read failed', { cause: error }); }
    if (state === null) identityFail('STATE_CONFLICT', 'bootstrap authority is not initialized');
    return validateState(state);
  }

  #publicState(state) {
    const result = structuredClone(state); delete result.recoveryDigest;
    return deepFreeze(result);
  }

  #principal(state) {
    const principal = deepFreeze({
      subject: state.administratorSubject, actorClass: 'administrator', authorityEpoch: state.authorityEpoch,
      bootstrapGeneration: state.generation,
    });
    this.#principals.add(principal);
    return principal;
  }
}
