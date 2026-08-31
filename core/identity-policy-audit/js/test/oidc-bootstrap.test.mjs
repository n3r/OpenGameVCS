import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';

import {
  BootstrapAuthority,
  IdentityProviderBroker,
  OidcAuthenticationAdapter,
  verifyOidcIdToken,
} from '../src/index.mjs';
import {
  MemoryAuthenticationTransactionStore,
  MemoryBootstrapStore,
  deterministicSecretSource,
} from '../src/testing.mjs';

const provider = Object.freeze({
  schemaVersion: 'ogvcs.identity-policy/oidc-provider/v1',
  id: 'studio-oidc',
  issuer: 'https://id.example.test/',
  authorizationEndpoint: 'https://id.example.test/authorize',
  tokenEndpoint: 'https://id.example.test/token',
  deviceAuthorizationEndpoint: 'https://id.example.test/device',
  jwksUri: 'https://id.example.test/jwks',
  clientId: 'ogvcs-client',
  redirectUri: 'https://vcs.example.test/oidc/callback',
  scopes: Object.freeze(['openid', 'profile', 'groups']),
  signingAlgorithms: Object.freeze(['RS256']),
  subjectClaim: 'sub',
  groupClaim: 'groups',
});

const keys = generateKeyPairSync('rsa', { modulusLength: 2_048 });
const jwk = Object.freeze({ ...keys.publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' });

function idToken({
  nonce, now = 1_800_000_000, subject = 'external-user-123', privateKey = keys.privateKey,
  alg = 'RS256', kid = 'test-key', extraClaims = {},
} = {}) {
  const header = Buffer.from(JSON.stringify({ alg, kid, typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: 'https://id.example.test/', aud: 'ogvcs-client', sub: subject,
    iat: now - 1, exp: now + 300, nonce, groups: ['artists', 'project-a'], ...extraClaims,
  })).toString('base64url');
  const key = alg === 'ES256' ? { key: privateKey, dsaEncoding: 'ieee-p1363' } : privateKey;
  const signature = sign(alg === 'ES256' ? 'sha256' : 'RSA-SHA256', Buffer.from(`${header}.${payload}`, 'ascii'), key).toString('base64url');
  return `${header}.${payload}.${signature}`;
}

function response(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function adapterFixture({ fetch: fetchImplementation, clock = () => 1_800_000_000 } = {}) {
  return new OidcAuthenticationAdapter({
    provider,
    transactionStore: new MemoryAuthenticationTransactionStore(),
    secretSource: deterministicSecretSource('oidc-test'),
    fetch: fetchImplementation,
    clock,
  });
}

test('authorization code flow uses PKCE S256 and one-use state before issuing an identity', async () => {
  let expectedNonce;
  const adapter = adapterFixture({
    fetch: async (url, options) => {
      if (url === provider.tokenEndpoint) {
        const body = new URLSearchParams(options.body);
        assert.equal(body.get('grant_type'), 'authorization_code');
        assert.equal(body.get('code'), 'code.once');
        assert.match(body.get('code_verifier'), /^[A-Za-z0-9_-]{43}$/u);
        return response({ id_token: idToken({ nonce: expectedNonce }) });
      }
      if (url === provider.jwksUri) return response({ keys: [jwk] });
      throw new Error(`unexpected URL ${url}`);
    },
  });
  const broker = new IdentityProviderBroker([adapter]);
  const begun = await broker.begin('studio-oidc', 'authorization-code-pkce', {});
  const authorization = new URL(begun.authorizationUrl);
  expectedNonce = authorization.searchParams.get('nonce');
  assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.match(authorization.searchParams.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(authorization.searchParams.has('code_verifier'), false);
  const completed = await broker.complete('studio-oidc', 'authorization-code-pkce', {
    handle: begun.handle, state: authorization.searchParams.get('state'), code: 'code.once',
  });
  assert.match(completed.subject, /^oidc\.[0-9a-f]{24}$/u);
  assert.deepEqual(completed.groups, ['artists', 'project-a']);
  assert.equal(completed.authenticationMethod, 'oidc-authorization-code-pkce');
  await assert.rejects(
    broker.complete('studio-oidc', 'authorization-code-pkce', {
      handle: begun.handle, state: authorization.searchParams.get('state'), code: 'code.once',
    }),
    ({ code }) => code === 'AUTHENTICATION_DENIED',
  );
});

test('authorization code state replay is independently denied after completion', async () => {
  let expectedNonce;
  const adapter = adapterFixture({
    fetch: async (url) => {
      if (url === provider.tokenEndpoint) return response({ id_token: idToken({ nonce: expectedNonce }) });
      if (url === provider.jwksUri) return response({ keys: [jwk] });
      throw new Error(`unexpected URL ${url}`);
    },
  });
  const begun = await adapter.begin('authorization-code-pkce', {});
  const authorization = new URL(begun.authorizationUrl); expectedNonce = authorization.searchParams.get('nonce');
  const input = { handle: begun.handle, state: authorization.searchParams.get('state'), code: 'code.once' };
  await adapter.complete('authorization-code-pkce', input);
  await assert.rejects(() => adapter.complete('authorization-code-pkce', input), ({ code }) => code === 'AUTHENTICATION_DENIED');
});

test('signed ID-token validation rejects signature, audience, nonce, and clock substitution', () => {
  const now = 1_800_000_000; const nonce = 'nonce-value';
  const valid = idToken({ nonce, now });
  assert.equal(verifyOidcIdToken(valid, { provider, jwks: { keys: [jwk] }, nonce, now }).subject, 'external-user-123');
  const hostileKeys = generateKeyPairSync('rsa', { modulusLength: 2_048 });
  assert.throws(
    () => verifyOidcIdToken(idToken({ nonce, now, privateKey: hostileKeys.privateKey }), { provider, jwks: { keys: [jwk] }, nonce, now }),
    ({ code }) => code === 'AUTHENTICATION_DENIED',
  );
  assert.throws(() => verifyOidcIdToken(valid, { provider, jwks: { keys: [jwk] }, nonce: 'other', now }), ({ code }) => code === 'AUTHENTICATION_DENIED');
  assert.throws(() => verifyOidcIdToken(valid, { provider, jwks: { keys: [jwk] }, nonce, now: now + 1_000 }), ({ code }) => code === 'AUTHENTICATION_DENIED');
  assert.throws(
    () => verifyOidcIdToken(idToken({ nonce, now, extraClaims: { nbf: now + 1_000 } }), { provider, jwks: { keys: [jwk] }, nonce, now }),
    ({ code }) => code === 'AUTHENTICATION_DENIED',
  );
  assert.throws(
    () => verifyOidcIdToken(idToken({ nonce, now, extraClaims: { nbf: 'future' } }), { provider, jwks: { keys: [jwk] }, nonce, now }),
    ({ code }) => code === 'AUTHENTICATION_DENIED',
  );
  const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  const p384Jwk = { ...p384.publicKey.export({ format: 'jwk' }), kid: 'p384', alg: 'ES256', use: 'sig' };
  assert.throws(() => verifyOidcIdToken(
    idToken({ nonce, now, subject: 'attacker', privateKey: p384.privateKey, alg: 'ES256', kid: 'p384' }),
    { provider: { ...provider, signingAlgorithms: ['ES256'] }, jwks: { keys: [p384Jwk] }, nonce, now },
  ), ({ code }) => code === 'AUTHENTICATION_DENIED');
  const p256 = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const p256Jwk = { ...p256.publicKey.export({ format: 'jwk' }), kid: 'p256', alg: 'ES256', use: 'sig' };
  assert.equal(verifyOidcIdToken(
    idToken({ nonce, now, privateKey: p256.privateKey, alg: 'ES256', kid: 'p256' }),
    { provider: { ...provider, signingAlgorithms: ['ES256'] }, jwks: { keys: [p256Jwk] }, nonce, now },
  ).subject, 'external-user-123');
});

test('device flow retains pending and slow-down state without consuming the transaction', async () => {
  let tokenPolls = 0;
  const clockState = { now: 1_800_000_000 };
  const adapter = adapterFixture({
    clock: () => clockState.now,
    fetch: async (url) => {
      if (url === provider.deviceAuthorizationEndpoint) return response({
        device_code: 'device-secret', user_code: 'ABCD-EFGH', verification_uri: 'https://id.example.test/device-ui',
        expires_in: 300, interval: 5,
      });
      if (url === provider.tokenEndpoint) {
        tokenPolls += 1;
        return response({ error: tokenPolls === 1 ? 'authorization_pending' : 'slow_down' }, 400);
      }
      throw new Error(`unexpected URL ${url}`);
    },
  });
  const begun = await adapter.begin('device-code', {});
  clockState.now += 5;
  assert.deepEqual(await adapter.complete('device-code', { handle: begun.handle }), { status: 'pending', retryAfterSeconds: 5 });
  clockState.now += 5;
  assert.deepEqual(await adapter.complete('device-code', { handle: begun.handle }), { status: 'pending', retryAfterSeconds: 10 });
});

test('OIDC outage fails closed and never invokes a local bootstrap path', async () => {
  let providerCalls = 0;
  const adapter = adapterFixture({ fetch: async () => { providerCalls += 1; throw new Error('provider offline'); } });
  const broker = new IdentityProviderBroker([adapter]);
  const begun = await broker.begin('studio-oidc', 'authorization-code-pkce', {});
  const authorization = new URL(begun.authorizationUrl);
  await assert.rejects(
    broker.complete('studio-oidc', 'authorization-code-pkce', {
      handle: begun.handle, state: authorization.searchParams.get('state'), code: 'code.once',
    }),
    ({ code }) => code === 'AUTHENTICATION_DENIED',
  );
  assert.equal(providerCalls, 1);
});

test('bootstrap recovery rotates one-use material and local login disables only after independent recovery', () => {
  const authority = new BootstrapAuthority({
    store: new MemoryBootstrapStore(), secretSource: deterministicSecretSource('bootstrap-test'),
    rateLimiter: { consume: () => ({ allowed: true }) },
    rateSource: () => 'test-source',
  });
  const initialized = authority.initialize({ administratorSubject: 'admin.bootstrap', authorityEpoch: 1 });
  assert.equal(Object.hasOwn(initialized.state, 'recoveryDigest'), false);
  let recovered = authority.recover(initialized.recoveryCode, { mode: 'login' });
  assert.throws(() => authority.disableLocalLogin(recovered.principal), ({ code }) => code === 'STATE_CONFLICT');
  const configured = authority.configureExternalRecovery(recovered.principal);
  const disabled = authority.disableLocalLogin(configured.principal);
  assert.equal(disabled.state.localLoginEnabled, false);
  assert.throws(() => authority.recover(initialized.recoveryCode), ({ code }) => code === 'AUTHENTICATION_DENIED');
  recovered = authority.recover(recovered.replacementRecoveryCode, { mode: 'recovery' });
  assert.equal(recovered.principal.actorClass, 'administrator');
  assert.throws(() => authority.recover(recovered.replacementRecoveryCode, { mode: 'login' }), ({ code }) => code === 'AUTHENTICATION_DENIED');
});

test('device provider outages release the claimed transaction for a bounded retry', async () => {
  let tokenPolls = 0;
  const clockState = { now: 1_800_000_000 };
  const adapter = adapterFixture({
    clock: () => clockState.now,
    fetch: async (url) => {
      if (url === provider.deviceAuthorizationEndpoint) return response({
        device_code: 'retry-device-secret', user_code: 'RETRY-01', verification_uri: 'https://id.example.test/device-ui',
        expires_in: 300, interval: 5,
      });
      if (url === provider.tokenEndpoint) {
        tokenPolls += 1;
        if (tokenPolls === 1) throw new Error('temporary provider outage');
        return response({ error: 'authorization_pending' }, 400);
      }
      throw new Error(`unexpected URL ${url}`);
    },
  });
  const begun = await adapter.begin('device-code', {}); clockState.now += 5;
  await assert.rejects(() => adapter.complete('device-code', { handle: begun.handle }), ({ code }) => code === 'POLICY_UNAVAILABLE');
  clockState.now += 5;
  assert.deepEqual(await adapter.complete('device-code', { handle: begun.handle }), { status: 'pending', retryAfterSeconds: 5 });
});

test('OIDC response-body deadlines interrupt a stalled stream after headers', async () => {
  const stalled = new Promise(() => {});
  const adapter = adapterFixture({
    fetch: async () => ({
      status: 200, ok: true, url: provider.deviceAuthorizationEndpoint,
      headers: { get: () => null },
      body: { getReader: () => ({ read: () => stalled, cancel: async () => {}, releaseLock() {} }) },
    }),
  });
  let guard;
  try {
    await assert.rejects(Promise.race([
      adapter.begin('device-code', {}, { signal: AbortSignal.timeout(1) }),
      new Promise((resolvePromise, reject) => { guard = setTimeout(() => reject(new Error('OIDC deadline did not settle')), 500); }),
    ]), ({ code }) => code === 'POLICY_UNAVAILABLE');
  } finally { clearTimeout(guard); }
});
