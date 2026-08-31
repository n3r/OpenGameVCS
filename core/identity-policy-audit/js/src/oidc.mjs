import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
} from 'node:crypto';

import { asIdentityError, identityFail } from './errors.mjs';
import { RUNTIME_LIMITS, cloneBounded, deepFreeze } from './validate.mjs';

const ID = /^[a-z][a-z0-9.-]{0,127}$/u;
const OPAQUE = /^[A-Za-z0-9._:-]{1,256}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const DOMAIN = Object.freeze({
  state: Buffer.from('OGVCS-OIDC-STATE-V1\0', 'ascii'),
  nonce: Buffer.from('OGVCS-OIDC-NONCE-V1\0', 'ascii'),
  verifier: Buffer.from('OGVCS-OIDC-VERIFIER-V1\0', 'ascii'),
  device: Buffer.from('OGVCS-OIDC-DEVICE-CODE-V1\0', 'ascii'),
  handle: Buffer.from('OGVCS-OIDC-HANDLE-V1\0', 'ascii'),
});

function sha(domain, value) {
  return createHash('sha256').update(domain).update(value, 'utf8').digest('hex');
}

function equalHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string'
      || !/^[0-9a-f]{64}$/u.test(left) || !/^[0-9a-f]{64}$/u.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function nowFrom(clock) {
  let now;
  try { now = clock(); }
  catch (error) { identityFail('POLICY_UNAVAILABLE', 'OIDC clock failed closed', { cause: error }); }
  if (!Number.isSafeInteger(now) || now < 0) identityFail('POLICY_UNAVAILABLE', 'OIDC clock is invalid');
  return now;
}

function randomSecret(source, label) {
  let value;
  try { value = source(label); }
  catch (error) { identityFail('POLICY_UNAVAILABLE', 'OIDC secret source failed closed', { cause: error }); }
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) {
    identityFail('POLICY_UNAVAILABLE', 'OIDC secret source returned an invalid secret');
  }
  return Buffer.from(value).toString('base64url');
}

function exactHttps(value, label) {
  let url;
  try { url = new URL(value); }
  catch (error) { identityFail('INPUT_INVALID', `${label} is invalid`, { cause: error }); }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.hash !== '') {
    identityFail('INPUT_INVALID', `${label} must be an exact HTTPS endpoint`);
  }
  return url.toString();
}

function operationSignal(callerSignal, timeoutMilliseconds) {
  const timeout = AbortSignal.timeout(timeoutMilliseconds);
  return callerSignal === undefined ? timeout : AbortSignal.any([callerSignal, timeout]);
}

export function validateOidcProvider(input) {
  const provider = cloneBounded(input, { maxBytes: 32 * 1024, maxDepth: 8, maxNodes: 256, maxStringBytes: 2_048 });
  const keys = Object.keys(provider).sort();
  const expected = [
    'schemaVersion', 'id', 'issuer', 'authorizationEndpoint', 'tokenEndpoint',
    'deviceAuthorizationEndpoint', 'jwksUri', 'clientId', 'redirectUri', 'scopes',
    'signingAlgorithms', 'subjectClaim', 'groupClaim',
  ].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
      || provider.schemaVersion !== 'ogvcs.identity-policy/oidc-provider/v1'
      || !ID.test(provider.id) || !OPAQUE.test(provider.clientId)
      || provider.subjectClaim !== 'sub'
      || !(provider.groupClaim === null || ID.test(provider.groupClaim ?? ''))
      || !Array.isArray(provider.scopes) || provider.scopes.length < 1 || provider.scopes.length > 32
      || provider.scopes.some((value) => typeof value !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/u.test(value))
      || new Set(provider.scopes).size !== provider.scopes.length
      || !provider.scopes.includes('openid')
      || !Array.isArray(provider.signingAlgorithms) || provider.signingAlgorithms.length < 1
      || provider.signingAlgorithms.length > 2
      || provider.signingAlgorithms.some((value) => !['RS256', 'ES256'].includes(value))
      || new Set(provider.signingAlgorithms).size !== provider.signingAlgorithms.length) {
    identityFail('INPUT_INVALID', 'OIDC provider configuration is invalid');
  }
  provider.issuer = exactHttps(provider.issuer, 'OIDC issuer');
  provider.authorizationEndpoint = exactHttps(provider.authorizationEndpoint, 'OIDC authorization endpoint');
  provider.tokenEndpoint = exactHttps(provider.tokenEndpoint, 'OIDC token endpoint');
  provider.deviceAuthorizationEndpoint = provider.deviceAuthorizationEndpoint === null
    ? null : exactHttps(provider.deviceAuthorizationEndpoint, 'OIDC device endpoint');
  provider.jwksUri = exactHttps(provider.jwksUri, 'OIDC JWKS endpoint');
  provider.redirectUri = exactHttps(provider.redirectUri, 'OIDC redirect URI');
  return deepFreeze(provider);
}

function validateRecord(record) {
  const value = cloneBounded(record, { maxBytes: 8 * 1024, maxDepth: 6, maxNodes: 64, maxStringBytes: 256 });
  const expected = [
    'schemaVersion', 'id', 'providerId', 'flow', 'stateDigest', 'nonceDigest',
    'verifierDigest', 'deviceCodeDigest', 'createdAt', 'expiresAt', 'nextPollAt', 'state',
  ].sort();
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
      || value.schemaVersion !== 'ogvcs.identity-policy/authentication-transaction/v1'
      || !ID.test(value.id) || !ID.test(value.providerId)
      || !['authorization-code-pkce', 'device-code'].includes(value.flow)
      || !/^[0-9a-f]{64}$/u.test(value.stateDigest) || !/^[0-9a-f]{64}$/u.test(value.nonceDigest)
      || !(value.verifierDigest === null || /^[0-9a-f]{64}$/u.test(value.verifierDigest))
      || !(value.deviceCodeDigest === null || /^[0-9a-f]{64}$/u.test(value.deviceCodeDigest))
      || !Number.isSafeInteger(value.createdAt) || value.createdAt < 0
      || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= value.createdAt
      || !(value.nextPollAt === null || (Number.isSafeInteger(value.nextPollAt) && value.nextPollAt >= value.createdAt))
      || !['pending', 'claimed', 'complete', 'failed'].includes(value.state)) {
    identityFail('POLICY_UNAVAILABLE', 'OIDC transaction record is invalid');
  }
  return deepFreeze(value);
}

function form(values) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== null && value !== undefined) body.set(key, String(value));
  }
  return body.toString();
}

async function readBoundedBody(response, maximum, signal) {
  const declared = response.headers?.get?.('content-length');
  if (declared !== null && declared !== undefined
      && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    identityFail('POLICY_UNAVAILABLE', 'OIDC response exceeds its bound');
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > maximum) identityFail('POLICY_UNAVAILABLE', 'OIDC response exceeds its bound');
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks = []; let total = 0;
  try {
    while (true) {
      if (signal?.aborted) identityFail('POLICY_UNAVAILABLE', 'OIDC request was cancelled');
      const { done, value } = await readStreamChunk(reader, signal);
      if (done) break;
      if (!(value instanceof Uint8Array)) identityFail('POLICY_UNAVAILABLE', 'OIDC response stream is invalid');
      total += value.byteLength;
      if (total > maximum) identityFail('POLICY_UNAVAILABLE', 'OIDC response exceeds its bound');
      chunks.push(Buffer.from(value));
    }
  } finally {
    try { reader.releaseLock?.(); }
    catch { /* An aborted implementation may retain its pending read lock. */ }
  }
  return Buffer.concat(chunks, total);
}

async function readStreamChunk(reader, signal) {
  if (signal === undefined) {
    try { return await reader.read(); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
  }
  if (signal.aborted) identityFail('POLICY_UNAVAILABLE', 'OIDC request was cancelled');
  let abort;
  const aborted = new Promise((resolvePromise, reject) => {
    abort = () => {
      Promise.resolve(reader.cancel?.(signal.reason)).catch(() => {});
      reject(asIdentityError(signal.reason ?? new Error('OIDC request was cancelled'), 'POLICY_UNAVAILABLE'));
    };
    signal.addEventListener('abort', abort, { once: true });
  });
  try { return await Promise.race([Promise.resolve().then(() => reader.read()), aborted]); }
  catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
  finally { signal.removeEventListener('abort', abort); }
}

async function fetchJson(fetchImplementation, endpoint, init, options) {
  let response;
  try {
    response = await fetchImplementation(endpoint, { ...init, redirect: 'error', signal: options.signal });
  } catch (error) {
    identityFail('POLICY_UNAVAILABLE', 'OIDC dependency is unavailable', { cause: error });
  }
  if (!response || typeof response.status !== 'number') identityFail('POLICY_UNAVAILABLE', 'OIDC response is invalid');
  if (response.url && new URL(response.url).toString() !== new URL(endpoint).toString()) {
    identityFail('POLICY_UNAVAILABLE', 'OIDC endpoint redirected');
  }
  const bytes = await readBoundedBody(response, options.maximum, options.signal);
  let body;
  try { body = JSON.parse(bytes.toString('utf8')); }
  catch (error) { identityFail('POLICY_UNAVAILABLE', 'OIDC response JSON is invalid', { cause: error }); }
  return { response, body: cloneBounded(body, { maxBytes: options.maximum, maxDepth: 12, maxNodes: 10_000, maxStringBytes: 16_384 }) };
}

function decodeSegment(segment, label, maximum) {
  if (typeof segment !== 'string' || segment.length < 1 || segment.length > maximum || !BASE64URL.test(segment)) {
    identityFail('AUTHENTICATION_DENIED', `${label} is invalid`);
  }
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) identityFail('AUTHENTICATION_DENIED', `${label} is non-canonical`);
  try { return cloneBounded(JSON.parse(bytes.toString('utf8')), { maxBytes: maximum, maxDepth: 8, maxNodes: 1_000, maxStringBytes: 16_384 }); }
  catch (error) { identityFail('AUTHENTICATION_DENIED', `${label} JSON is invalid`, { cause: error }); }
}

function stringAudience(aud, clientId) {
  if (typeof aud === 'string') return aud === clientId;
  return Array.isArray(aud) && aud.length >= 1 && aud.length <= 16
    && aud.every((item) => typeof item === 'string' && item.length <= 256)
    && aud.includes(clientId);
}

function canonicalJwkBytes(value, expectedBytes) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.byteLength === expectedBytes && bytes.toString('base64url') === value ? bytes : null;
}

function acceptedSigningJwk(jwk, algorithm) {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) return false;
  if (algorithm === 'ES256') {
    return jwk.kty === 'EC' && jwk.crv === 'P-256'
      && canonicalJwkBytes(jwk.x, 32) !== null && canonicalJwkBytes(jwk.y, 32) !== null;
  }
  if (algorithm === 'RS256') {
    if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string'
        || !BASE64URL.test(jwk.n) || !BASE64URL.test(jwk.e)) return false;
    const modulus = Buffer.from(jwk.n, 'base64url'); const exponent = Buffer.from(jwk.e, 'base64url');
    return modulus.byteLength >= 256 && modulus.toString('base64url') === jwk.n
      && exponent.byteLength >= 1 && exponent.byteLength <= 8 && exponent.toString('base64url') === jwk.e;
  }
  return false;
}

export function verifyOidcIdToken(token, { provider: providerInput, jwks, nonce, now }) {
  const provider = validateOidcProvider(providerInput);
  if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > 131_072) identityFail('AUTHENTICATION_DENIED');
  const segments = token.split('.');
  if (segments.length !== 3) identityFail('AUTHENTICATION_DENIED');
  const header = decodeSegment(segments[0], 'OIDC JOSE header', 8_192);
  const claims = decodeSegment(segments[1], 'OIDC claims', 65_536);
  if (!header || typeof header !== 'object' || Array.isArray(header)
      || !provider.signingAlgorithms.includes(header.alg)
      || typeof header.kid !== 'string' || header.kid.length < 1 || header.kid.length > 256
      || header.crit !== undefined || (header.typ !== undefined && header.typ !== 'JWT')) {
    identityFail('AUTHENTICATION_DENIED', 'OIDC JOSE header is not accepted');
  }
  if (!jwks || typeof jwks !== 'object' || !Array.isArray(jwks.keys) || jwks.keys.length > 64) {
    identityFail('POLICY_UNAVAILABLE', 'OIDC key set is invalid');
  }
  const matches = jwks.keys.filter((key) => key && typeof key === 'object'
    && key.kid === header.kid && (key.alg === undefined || key.alg === header.alg)
    && (key.use === undefined || key.use === 'sig') && acceptedSigningJwk(key, header.alg));
  if (matches.length !== 1) identityFail('AUTHENTICATION_DENIED', 'OIDC signing key is unavailable or ambiguous');
  let key;
  try { key = createPublicKey({ key: matches[0], format: 'jwk' }); }
  catch (error) { identityFail('POLICY_UNAVAILABLE', 'OIDC signing key is invalid', { cause: error }); }
  const signature = Buffer.from(segments[2], 'base64url');
  if (signature.toString('base64url') !== segments[2]) identityFail('AUTHENTICATION_DENIED');
  if (header.alg === 'ES256' && signature.byteLength !== 64) identityFail('AUTHENTICATION_DENIED');
  const signingInput = Buffer.from(`${segments[0]}.${segments[1]}`, 'ascii');
  const algorithm = header.alg === 'RS256' ? 'RSA-SHA256' : 'sha256';
  const keyOptions = header.alg === 'ES256' ? { key, dsaEncoding: 'ieee-p1363' } : key;
  let valid;
  try { valid = verifySignature(algorithm, signingInput, keyOptions, signature); }
  catch (error) { identityFail('AUTHENTICATION_DENIED', 'OIDC signature verification failed', { cause: error }); }
  if (!valid) identityFail('AUTHENTICATION_DENIED', 'OIDC signature is invalid');
  const skew = RUNTIME_LIMITS.oidcClockSkewSeconds;
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)
      || claims.iss !== provider.issuer || !stringAudience(claims.aud, provider.clientId)
      || (Array.isArray(claims.aud) && claims.aud.length > 1 && claims.azp !== provider.clientId)
      || typeof claims.sub !== 'string' || claims.sub.length < 1 || Buffer.byteLength(claims.sub, 'utf8') > 256
      || !Number.isSafeInteger(claims.exp) || claims.exp < now - skew
      || !Number.isSafeInteger(claims.iat) || claims.iat > now + skew
      || (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > now + skew))
      || claims.iat > claims.exp
      || claims.nonce !== nonce) {
    identityFail('AUTHENTICATION_DENIED', 'OIDC claims are invalid');
  }
  let groups = [];
  if (provider.groupClaim !== null && claims[provider.groupClaim] !== undefined) {
    const source = claims[provider.groupClaim];
    if (!Array.isArray(source) || source.length > RUNTIME_LIMITS.maxOidcGroups
        || source.some((group) => typeof group !== 'string' || !ID.test(group))
        || new Set(source).size !== source.length) identityFail('AUTHENTICATION_DENIED', 'OIDC group claims are invalid');
    groups = [...source].sort();
  }
  return deepFreeze({ subject: claims.sub, groups, issuer: claims.iss, issuedAt: claims.iat, expiresAt: claims.exp });
}

export class OidcAuthenticationAdapter {
  #clock;
  #fetch;
  #provider;
  #source;
  #store;
  #subjectMapper;
  #timeout;

  constructor({
    provider, transactionStore, secretSource,
    fetch: fetchImplementation = globalThis.fetch,
    clock = () => Math.floor(Date.now() / 1000),
    networkTimeoutMilliseconds = RUNTIME_LIMITS.oidcNetworkTimeoutMilliseconds,
    subjectMapper = ({ issuer, subject }) => `oidc.${createHash('sha256').update(issuer).update('\0').update(subject).digest('hex').slice(0, 24)}`,
  }) {
    this.#provider = validateOidcProvider(provider);
    if (!transactionStore || typeof transactionStore.create !== 'function'
        || typeof transactionStore.claim !== 'function' || typeof transactionStore.release !== 'function'
        || typeof transactionStore.finish !== 'function'
        || typeof secretSource !== 'function' || typeof fetchImplementation !== 'function' || typeof clock !== 'function'
        || typeof subjectMapper !== 'function' || !Number.isSafeInteger(networkTimeoutMilliseconds)
        || networkTimeoutMilliseconds < 1 || networkTimeoutMilliseconds > RUNTIME_LIMITS.oidcNetworkTimeoutMilliseconds) {
      identityFail('INPUT_INVALID', 'OIDC adapter dependencies are invalid');
    }
    this.#store = transactionStore; this.#source = secretSource;
    this.#fetch = fetchImplementation; this.#clock = clock; this.#subjectMapper = subjectMapper;
    this.#timeout = networkTimeoutMilliseconds;
  }

  get id() { return this.#provider.id; }
  get flows() { return Object.freeze(this.#provider.deviceAuthorizationEndpoint === null
    ? ['authorization-code-pkce'] : ['authorization-code-pkce', 'device-code']); }

  async begin(flow, input = {}, options = {}) {
    if (flow === 'authorization-code-pkce') return this.#beginCode(input, options);
    if (flow === 'device-code') return this.#beginDevice(input, options);
    identityFail('AUTHENTICATION_DENIED');
  }

  async complete(flow, input, options = {}) {
    if (flow === 'authorization-code-pkce') return this.#completeCode(input, options);
    if (flow === 'device-code') return this.#pollDevice(input, options);
    identityFail('AUTHENTICATION_DENIED');
  }

  async #beginCode(input, _options) {
    if (input === null || typeof input !== 'object' || Array.isArray(input)
        || Object.keys(input).some((key) => key !== 'loginHint')
        || (input.loginHint !== undefined && (typeof input.loginHint !== 'string' || Buffer.byteLength(input.loginHint, 'utf8') > 256))) {
      identityFail('INPUT_INVALID', 'OIDC authorization input is invalid');
    }
    const now = nowFrom(this.#clock);
    const state = randomSecret(this.#source, 'oidc-state');
    const nonce = randomSecret(this.#source, 'oidc-nonce');
    const verifier = randomSecret(this.#source, 'oidc-verifier');
    const handleSecret = randomSecret(this.#source, 'oidc-handle');
    const id = `auth.${sha(DOMAIN.handle, handleSecret).slice(0, 24)}`;
    const record = validateRecord({
      schemaVersion: 'ogvcs.identity-policy/authentication-transaction/v1', id,
      providerId: this.#provider.id, flow: 'authorization-code-pkce',
      stateDigest: sha(DOMAIN.state, state), nonceDigest: sha(DOMAIN.nonce, nonce),
      verifierDigest: sha(DOMAIN.verifier, verifier), deviceCodeDigest: null,
      createdAt: now, expiresAt: now + RUNTIME_LIMITS.authorizationCodeTtlSeconds,
      nextPollAt: null, state: 'pending',
    });
    try {
      this.#store.create(record, { state, nonce, verifier });
    } catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
    const url = new URL(this.#provider.authorizationEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.#provider.clientId);
    url.searchParams.set('redirect_uri', this.#provider.redirectUri);
    url.searchParams.set('scope', this.#provider.scopes.join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', createHash('sha256').update(verifier, 'ascii').digest('base64url'));
    url.searchParams.set('code_challenge_method', 'S256');
    if (input.loginHint !== undefined) url.searchParams.set('login_hint', input.loginHint);
    return deepFreeze({ flow: 'authorization-code-pkce', handle: id, authorizationUrl: url.toString(), expiresAt: record.expiresAt });
  }

  async #completeCode(input, options) {
    if (!input || typeof input !== 'object' || Array.isArray(input)
        || Object.keys(input).sort().join('\0') !== ['code', 'handle', 'state'].sort().join('\0')
        || !ID.test(input.handle ?? '') || typeof input.code !== 'string' || !OPAQUE.test(input.code)
        || typeof input.state !== 'string' || !BASE64URL.test(input.state) || input.state.length !== 43) {
      identityFail('AUTHENTICATION_DENIED');
    }
    const now = nowFrom(this.#clock);
    const claimed = this.#claim(input.handle, sha(DOMAIN.state, input.state), now);
    const { record, secrets } = claimed;
    if (record.flow !== 'authorization-code-pkce') return this.#fail(record.id, 'AUTHENTICATION_DENIED');
    if (!equalHex(record.verifierDigest, sha(DOMAIN.verifier, secrets.verifier))
        || !equalHex(record.nonceDigest, sha(DOMAIN.nonce, secrets.nonce))
        || !equalHex(record.stateDigest, sha(DOMAIN.state, secrets.state))) return this.#fail(record.id, 'POLICY_UNAVAILABLE');
    try {
      const token = await this.#token({
        grant_type: 'authorization_code', code: input.code, redirect_uri: this.#provider.redirectUri,
        client_id: this.#provider.clientId, code_verifier: secrets.verifier,
      }, options);
      const identity = await this.#identity(token, secrets.nonce, now, options);
      this.#store.finish(record.id, 'complete');
      return deepFreeze({ ...identity, authenticationMethod: 'oidc-authorization-code-pkce', providerId: this.#provider.id });
    } catch (error) {
      this.#fail(record.id, error?.code === 'POLICY_UNAVAILABLE' ? 'POLICY_UNAVAILABLE' : 'AUTHENTICATION_DENIED', error);
    }
  }

  async #beginDevice(input, options) {
    if (this.#provider.deviceAuthorizationEndpoint === null || (input && Object.keys(input).length !== 0)) identityFail('AUTHENTICATION_DENIED');
    const now = nowFrom(this.#clock);
    const nonce = randomSecret(this.#source, 'oidc-device-nonce');
    const result = await fetchJson(this.#fetch, this.#provider.deviceAuthorizationEndpoint, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: form({ client_id: this.#provider.clientId, scope: this.#provider.scopes.join(' '), nonce }),
    }, { maximum: RUNTIME_LIMITS.maxOidcResponseBytes, signal: operationSignal(options.signal, this.#timeout) });
    const body = result.body;
    if (!result.response.ok || typeof body.device_code !== 'string' || body.device_code.length < 1 || body.device_code.length > 4_096
        || typeof body.user_code !== 'string' || body.user_code.length < 1 || body.user_code.length > 256
        || typeof body.verification_uri !== 'string' || exactHttps(body.verification_uri, 'OIDC verification URI') !== body.verification_uri
        || !Number.isSafeInteger(body.expires_in) || body.expires_in < 1 || body.expires_in > RUNTIME_LIMITS.deviceCodeTtlSeconds
        || !Number.isSafeInteger(body.interval ?? 5) || (body.interval ?? 5) < 1 || (body.interval ?? 5) > 60) {
      identityFail('AUTHENTICATION_DENIED', 'OIDC device authorization response is invalid');
    }
    const handleSecret = randomSecret(this.#source, 'oidc-device-handle');
    const state = randomSecret(this.#source, 'oidc-device-state');
    const id = `auth.${sha(DOMAIN.handle, handleSecret).slice(0, 24)}`;
    const interval = body.interval ?? 5;
    const record = validateRecord({
      schemaVersion: 'ogvcs.identity-policy/authentication-transaction/v1', id,
      providerId: this.#provider.id, flow: 'device-code', stateDigest: sha(DOMAIN.state, state),
      nonceDigest: sha(DOMAIN.nonce, nonce), verifierDigest: null,
      deviceCodeDigest: sha(DOMAIN.device, body.device_code), createdAt: now,
      expiresAt: now + body.expires_in, nextPollAt: now + interval, state: 'pending',
    });
    try { this.#store.create(record, { deviceCode: body.device_code, nonce, interval }); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
    return deepFreeze({
      flow: 'device-code', handle: id, userCode: body.user_code,
      verificationUri: body.verification_uri,
      verificationUriComplete: typeof body.verification_uri_complete === 'string' ? exactHttps(body.verification_uri_complete, 'OIDC complete verification URI') : null,
      expiresAt: record.expiresAt, intervalSeconds: interval,
    });
  }

  async #pollDevice(input, options) {
    if (!input || typeof input !== 'object' || Array.isArray(input)
        || Object.keys(input).join('\0') !== 'handle' || !ID.test(input.handle ?? '')) identityFail('AUTHENTICATION_DENIED');
    const now = nowFrom(this.#clock); const claimed = this.#claim(input.handle, null, now);
    const { record, secrets } = claimed;
    if (record.flow !== 'device-code' || (record.nextPollAt !== null && now < record.nextPollAt)) {
      if (record.flow === 'device-code') this.#release(record.id, record.nextPollAt, secrets);
      identityFail('AUTHENTICATION_DENIED');
    }
    if (!equalHex(record.deviceCodeDigest, sha(DOMAIN.device, secrets.deviceCode))
        || !equalHex(record.nonceDigest, sha(DOMAIN.nonce, secrets.nonce))) return this.#fail(record.id, 'POLICY_UNAVAILABLE');
    let result;
    try {
      result = await fetchJson(this.#fetch, this.#provider.tokenEndpoint, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: form({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: secrets.deviceCode, client_id: this.#provider.clientId }),
      }, { maximum: RUNTIME_LIMITS.maxOidcResponseBytes, signal: operationSignal(options.signal, this.#timeout) });
    } catch (error) {
      const retryAt = now + secrets.interval;
      if (retryAt >= record.expiresAt) return this.#fail(record.id, 'AUTHENTICATION_DENIED', error);
      this.#release(record.id, retryAt, secrets);
      throw asIdentityError(error, 'POLICY_UNAVAILABLE');
    }
    if (!result.response.ok) {
      const code = result.body?.error;
      if (code === 'authorization_pending' || code === 'slow_down') {
        const interval = secrets.interval + (code === 'slow_down' ? 5 : 0);
        secrets.interval = interval; this.#release(record.id, now + interval, secrets);
        return deepFreeze({ status: 'pending', retryAfterSeconds: interval });
      }
      return this.#fail(record.id, 'AUTHENTICATION_DENIED');
    }
    try {
      const identity = await this.#identity(result.body, secrets.nonce, now, options);
      this.#store.finish(record.id, 'complete');
      return deepFreeze({ ...identity, authenticationMethod: 'oidc-device-code', providerId: this.#provider.id });
    } catch (error) { this.#fail(record.id, error?.code === 'POLICY_UNAVAILABLE' ? 'POLICY_UNAVAILABLE' : 'AUTHENTICATION_DENIED', error); }
  }

  #claim(id, stateDigest, now) {
    try {
      const claimed = this.#store.claim(id, stateDigest, now);
      if (!claimed || typeof claimed !== 'object' || !claimed.secrets || typeof claimed.secrets !== 'object') {
        throw new TypeError('OIDC transaction claim is invalid');
      }
      return { record: validateRecord(claimed.record), secrets: cloneBounded(claimed.secrets, { maxBytes: 16_384, maxDepth: 4, maxNodes: 32, maxStringBytes: 4_096 }) };
    }
    catch (error) { throw asIdentityError(error, 'AUTHENTICATION_DENIED'); }
  }

  #release(id, nextPollAt, secrets) {
    try { this.#store.release(id, nextPollAt, secrets); }
    catch (error) { throw asIdentityError(error, 'POLICY_UNAVAILABLE'); }
  }

  #fail(id, code, cause) {
    try { this.#store.finish(id, 'failed'); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'OIDC failure state could not be persisted', { cause: error }); }
    identityFail(code, code, cause === undefined ? undefined : { cause });
  }

  async #token(parameters, options) {
    const result = await fetchJson(this.#fetch, this.#provider.tokenEndpoint, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: form(parameters),
    }, { maximum: RUNTIME_LIMITS.maxOidcResponseBytes, signal: operationSignal(options.signal, this.#timeout) });
    if (!result.response.ok) identityFail('AUTHENTICATION_DENIED', 'OIDC token exchange was denied');
    return result.body;
  }

  async #identity(tokenBody, nonce, now, options) {
    if (!tokenBody || typeof tokenBody.id_token !== 'string') identityFail('AUTHENTICATION_DENIED', 'OIDC token response omits an ID token');
    const result = await fetchJson(this.#fetch, this.#provider.jwksUri, { method: 'GET', headers: { accept: 'application/json' } }, {
      maximum: RUNTIME_LIMITS.maxOidcResponseBytes, signal: operationSignal(options.signal, this.#timeout),
    });
    if (!result.response.ok) identityFail('POLICY_UNAVAILABLE', 'OIDC key retrieval failed');
    const identity = verifyOidcIdToken(tokenBody.id_token, { provider: this.#provider, jwks: result.body, nonce, now });
    let subject;
    try { subject = this.#subjectMapper(identity); }
    catch (error) { identityFail('AUTHENTICATION_DENIED', 'OIDC subject mapping failed closed', { cause: error }); }
    if (typeof subject !== 'string' || !ID.test(subject)) identityFail('AUTHENTICATION_DENIED', 'OIDC subject mapping is invalid');
    return deepFreeze({ ...identity, subject });
  }
}
