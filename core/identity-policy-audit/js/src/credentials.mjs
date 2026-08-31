import { createHash, timingSafeEqual } from 'node:crypto';

import { canonicalBytes, sha256 } from '@opengamevcs/authorization-contract';

import { asIdentityError, identityFail } from './errors.mjs';
import {
  RUNTIME_LIMITS,
  cloneBounded,
  deepFreeze,
  scopeMatches,
  validateCredentialRecord,
} from './validate.mjs';

const TOKEN = /^ogvcscred1\.([a-z][a-z0-9.-]{0,127})\.([A-Za-z0-9_-]{43})$/u;
const SECRET_DOMAIN = Buffer.from('OGVCS-IDENTITY-CREDENTIAL-V1\0', 'ascii');

function digestToken(token) {
  return createHash('sha256').update(SECRET_DOMAIN).update(token, 'utf8').digest('hex');
}

function safeEqualHex(left, right) {
  if (!/^[0-9a-f]{64}$/u.test(left) || !/^[0-9a-f]{64}$/u.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

export class AuthorityState {
  #authorityEpoch;
  #keyGeneration;
  #promoting = false;

  constructor({ authorityEpoch = 1, keyGeneration = 1 } = {}) {
    if (!Number.isSafeInteger(authorityEpoch) || authorityEpoch < 1
        || !Number.isSafeInteger(keyGeneration) || keyGeneration < 1) identityFail('INPUT_INVALID', 'authority state is invalid');
    this.#authorityEpoch = authorityEpoch;
    this.#keyGeneration = keyGeneration;
  }

  get authorityEpoch() { return this.#authorityEpoch; }
  get keyGeneration() { return this.#keyGeneration; }

  promote({ authorityEpoch, keyGeneration, audit }) {
    if (this.#promoting || !Number.isSafeInteger(authorityEpoch) || authorityEpoch <= this.#authorityEpoch
        || !Number.isSafeInteger(keyGeneration) || keyGeneration <= this.#keyGeneration
        || typeof audit !== 'function') {
      identityFail('STATE_CONFLICT', 'authority promotion must advance epoch and key generation');
    }
    const previous = Object.freeze({ authorityEpoch: this.#authorityEpoch, keyGeneration: this.#keyGeneration });
    this.#promoting = true;
    try {
      const result = audit(Object.freeze({ previous, next: Object.freeze({ authorityEpoch, keyGeneration }) }));
      if (result && typeof result.then === 'function') throw new TypeError('asynchronous audit callback is unsupported');
    } catch (error) {
      identityFail('POLICY_UNAVAILABLE', 'authority promotion audit failed closed', { cause: error });
    } finally { this.#promoting = false; }
    this.#authorityEpoch = authorityEpoch;
    this.#keyGeneration = keyGeneration;
    return Object.freeze({ previous, current: this.snapshot() });
  }

  snapshot() {
    return Object.freeze({
      schemaVersion: 'ogvcs.identity-policy/authority-state/v1',
      authorityEpoch: this.#authorityEpoch,
      keyGeneration: this.#keyGeneration,
    });
  }
}

export class MemoryCredentialStore {
  #maximum;
  #records = new Map();

  constructor({ maxCredentials = RUNTIME_LIMITS.maxCredentials } = {}) {
    if (!Number.isSafeInteger(maxCredentials) || maxCredentials < 1 || maxCredentials > RUNTIME_LIMITS.maxCredentials) identityFail('INPUT_INVALID', 'credential store bound is invalid');
    this.#maximum = maxCredentials;
  }

  get(id) { return this.#records.has(id) ? structuredClone(this.#records.get(id)) : null; }

  put(record) {
    if (!this.#records.has(record.id) && this.#records.size >= this.#maximum) identityFail('LIMIT_EXCEEDED', 'credential store bound exceeded');
    this.#records.set(record.id, structuredClone(record));
  }

  nextGeneration(subject, credentialClass) {
    let generation = 0;
    for (const record of this.#records.values()) {
      if (record.subject === subject && record.credentialClass === credentialClass) generation = Math.max(generation, record.generation);
    }
    return generation + 1;
  }
}

export class CredentialAuthority {
  #clock;
  #evidences = new WeakMap();
  #pathOptions;
  #principals = new WeakSet();
  #secretSource;
  #state;
  #store;
  #revoking = new Set();

  constructor({ store, authorityState, secretSource, clock = () => Math.floor(Date.now() / 1000), pathProfile = 'path.opengamevcs/portable@1', caseMode = 'case-sensitive' }) {
    if (!store || typeof store.get !== 'function' || typeof store.put !== 'function' || typeof store.nextGeneration !== 'function') identityFail('INPUT_INVALID', 'credential store adapter is invalid');
    if (!(authorityState instanceof AuthorityState) || typeof secretSource !== 'function' || typeof clock !== 'function') identityFail('INPUT_INVALID', 'credential authority adapter is invalid');
    this.#store = store; this.#state = authorityState; this.#secretSource = secretSource; this.#clock = clock;
    this.#pathOptions = Object.freeze({ pathProfile, caseMode });
  }

  issue(options) {
    const input = cloneBounded(options);
    const credentialClass = input?.credentialClass;
    if (!['session', 'service-token'].includes(credentialClass)) identityFail('INPUT_INVALID', 'credential class is invalid');
    const maximum = credentialClass === 'session' ? RUNTIME_LIMITS.sessionMaxTtlSeconds : RUNTIME_LIMITS.serviceTokenMaxTtlSeconds;
    const ttlSeconds = input.ttlSeconds;
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > maximum) identityFail('LIMIT_EXCEEDED', 'credential TTL exceeds its class');
    let secret;
    try { secret = this.#secretSource(); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
    if (!(secret instanceof Uint8Array) || secret.byteLength !== 32) identityFail('POLICY_UNAVAILABLE', 'secret source failed closed');
    const encoded = Buffer.from(secret).toString('base64url');
    const id = `credential.${createHash('sha256').update(secret).digest('hex').slice(0, 24)}`;
    let existing;
    try { existing = this.#store.get(id); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
    if (existing !== null) identityFail('STATE_CONFLICT', 'credential identifier collision');
    const token = `ogvcscred1.${id}.${encoded}`;
    if (Buffer.byteLength(token, 'utf8') > RUNTIME_LIMITS.maxTokenBytes) identityFail('LIMIT_EXCEEDED', 'credential token exceeds its bound');
    const now = this.#now();
    const record = validateCredentialRecord({
      schemaVersion: 'ogvcs.identity-policy/credential-record/v1',
      id,
      subject: input.subject,
      actorClass: input.actorClass,
      credentialClass,
      generation: this.#nextGeneration(input.subject, credentialClass),
      authorityEpoch: this.#state.authorityEpoch,
      issuedAt: now,
      expiresAt: now + ttlSeconds,
      state: 'active',
      groups: input.groups ?? [],
      scope: input.scope,
      secretDigest: digestToken(token),
    }, this.#pathOptions);
    this.#put(record);
    const descriptor = structuredClone(record);
    delete descriptor.secretDigest;
    return deepFreeze({ token, descriptor });
  }

  authenticate(token) {
    if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > RUNTIME_LIMITS.maxTokenBytes) identityFail('AUTHENTICATION_DENIED');
    const match = TOKEN.exec(token);
    if (!match) identityFail('AUTHENTICATION_DENIED');
    const record = this.#record(match[1]);
    if (record === null || !safeEqualHex(record.secretDigest, digestToken(token))) identityFail('AUTHENTICATION_DENIED');
    if (record.state !== 'active') identityFail('CREDENTIAL_REVOKED');
    if (record.authorityEpoch !== this.#state.authorityEpoch) identityFail('EPOCH_STALE');
    if (this.#now() >= record.expiresAt) identityFail('AUTHENTICATION_DENIED');
    const principal = deepFreeze({
      credentialId: record.id,
      actor: {
        id: record.subject,
        class: record.actorClass,
        groups: [...record.groups],
        credentialClass: record.credentialClass,
        credentialGeneration: record.generation,
        credentialStatus: 'active',
        authorityEpoch: record.authorityEpoch,
      },
      scope: structuredClone(record.scope),
    });
    this.#principals.add(principal);
    return principal;
  }

  authorizePrincipal(principal, request) {
    if (!principal || typeof principal !== 'object' || !this.#principals.has(principal)) return false;
    const record = this.#record(principal?.credentialId);
    if (record === null || this.#now() >= record.expiresAt) return false;
    const actor = principal?.actor;
    return record.state === 'active' && record.authorityEpoch === this.#state.authorityEpoch
      && actor?.credentialStatus === 'active' && actor.authorityEpoch === record.authorityEpoch
      && record.subject === actor.id && record.actorClass === actor.class
      && record.credentialClass === actor.credentialClass && record.generation === actor.credentialGeneration
      && Array.isArray(actor.groups) && actor.groups.length === record.groups.length
      && actor.groups.every((group, index) => group === record.groups[index])
      && scopeMatches(record.scope, request, this.#pathOptions);
  }

  transactionEvidence(token, { tenant, policyGeneration }) {
    if (typeof tenant !== 'string' || !/^[a-z][a-z0-9.-]{0,127}$/u.test(tenant)
        || !Number.isSafeInteger(policyGeneration) || policyGeneration < 1) identityFail('INPUT_INVALID', 'transaction evidence context is invalid');
    const principal = this.authenticate(token); const record = this.#record(principal.credentialId);
    if (record === null || !record.scope.tenants.includes(tenant)) identityFail('AUTHENTICATION_DENIED');
    const evidence = deepFreeze({
      schemaVersion: 'ogvcs.identity-policy/transaction-credential-evidence/v1',
      presentationDigest: digestToken(token),
      credentialId: record.id,
      credentialGeneration: record.generation,
      subjectDigest: createHash('sha256').update('OGVCS-IDENTITY-SUBJECT-V1\0').update(record.subject).digest('hex'),
      tenant,
      authorityEpoch: record.authorityEpoch,
      policyGeneration,
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt,
      authenticatedScopeDigest: sha256(canonicalBytes(record.scope)),
    });
    this.#evidences.set(evidence, principal);
    return evidence;
  }

  actorForTransactionEvidence(evidence) {
    const principal = this.#evidences.get(evidence);
    if (!principal || evidence.authorityEpoch !== this.#state.authorityEpoch || this.#now() >= evidence.expiresAt) {
      identityFail('AUTHENTICATION_DENIED');
    }
    const record = this.#record(evidence.credentialId);
    if (record === null || record.state !== 'active' || record.generation !== evidence.credentialGeneration
        || record.authorityEpoch !== evidence.authorityEpoch || !safeEqualHex(record.secretDigest, evidence.presentationDigest)
        || sha256(canonicalBytes(record.scope)) !== evidence.authenticatedScopeDigest) identityFail('AUTHENTICATION_DENIED');
    return deepFreeze(structuredClone(principal.actor));
  }

  authorizeTransactionEvidence(evidence, request) {
    const principal = this.#evidences.get(evidence);
    if (!principal) return false;
    try { this.actorForTransactionEvidence(evidence); }
    catch { return false; }
    return this.authorizePrincipal(principal, request);
  }

  revoke(id, { audit } = {}) {
    const record = this.#record(id);
    if (record?.state === 'revoked') return true;
    if (typeof audit !== 'function') identityFail('POLICY_UNAVAILABLE', 'credential revocation requires an audit sink');
    if (this.#revoking.has(id)) identityFail('STATE_CONFLICT', 'credential revocation is reentrant');
    this.#revoking.add(id);
    try {
      const result = audit(Object.freeze({ credentialClass: record?.credentialClass ?? 'unknown' }));
      if (result && typeof result.then === 'function') throw new TypeError('asynchronous audit callback is unsupported');
    } catch (error) {
      identityFail('POLICY_UNAVAILABLE', 'credential revocation audit failed closed', { cause: error });
    } finally { this.#revoking.delete(id); }
    if (record === null) return true;
    this.#put(validateCredentialRecord({ ...record, state: 'revoked' }, this.#pathOptions));
    return true;
  }

  #record(id) {
    let source;
    try { source = this.#store.get(id); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'credential store read failed closed', { cause: error }); }
    if (source === null) return null;
    try { return validateCredentialRecord(source, this.#pathOptions); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'credential store record is invalid', { cause: error }); }
  }

  #nextGeneration(subject, credentialClass) {
    try { return this.#store.nextGeneration(subject, credentialClass); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
  }

  #put(record) {
    try { this.#store.put(record); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
  }

  #now() {
    let value;
    try { value = this.#clock(); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
    if (!Number.isSafeInteger(value) || value < 0) identityFail('POLICY_UNAVAILABLE', 'clock failed closed');
    return value;
  }
}
