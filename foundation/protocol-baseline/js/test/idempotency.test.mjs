import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { loadAuthority } from '../../adapters/js-independent/src/core.mjs';
import { evaluateIndependentCase } from '../../adapters/js-independent/src/engine.mjs';
import { executeReferenceProtocolCase } from '../src/evaluator.mjs';
import { IdempotencyReplayStore, loadProtocolContract, semanticIdempotencyFingerprint } from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

const scope = { subject: 'alice', tenant: 'studio', repository: 'game', operation: 'mutate' };
const AT = 1_000;
const allowReplay = async () => ({ result: 'allow', code: 'ALLOW_EXPLICIT' });
function key(label, issuedAt = AT, expiresAt = AT + 1_000) {
  const seed = [...label].reduce((sum, character) => sum + character.charCodeAt(0), 0) % 251;
  return `ik1.${issuedAt}.${expiresAt}.${Buffer.alloc(16, seed).toString('base64url')}`;
}
function store(options = {}) {
  return new IdempotencyReplayStore({ now: () => AT, ...options });
}

test('semantic fingerprint is JCS-based, domain separated, and insensitive to member order', () => {
  const left = semanticIdempotencyFingerprint({ operation: 'rename', input: { from: 'a', to: 'b' } });
  const right = semanticIdempotencyFingerprint({ input: { to: 'b', from: 'a' }, operation: 'rename' });
  const different = semanticIdempotencyFingerprint({ operation: 'rename', input: { from: 'a', to: 'c' } });
  assert.equal(left, right);
  assert.notEqual(left, different);
});

test('same key and fingerprint replays one committed mutation while changed input conflicts', async () => {
  const replayStore = store({ maxEntries: 4, maxBytes: 512 * 1024, maxOutcomeBytes: 1024 });
  const fingerprint = semanticIdempotencyFingerprint({ operation: 'create', value: 1 });
  let mutations = 0;
  const identity = { scope, key: key('one'), fingerprint };
  const first = await replayStore.execute(identity, async () => {
    mutations += 1;
    return { ok: true, generation: 2 };
  });
  const replay = await replayStore.execute(identity, async () => {
    mutations += 1;
    return { ok: false };
  }, { authorizeReplay: allowReplay });
  assert.equal(first.kind, 'committed');
  assert.equal(replay.kind, 'replay');
  assert.equal(replay.outcome.generation, 2);
  assert.equal(mutations, 1);
  assert.throws(() => replayStore.begin({ ...identity, fingerprint: semanticIdempotencyFingerprint({ operation: 'create', value: 2 }) }), (error) => error.code === 'IDEMPOTENCY_KEY_REUSE');
});

test('concurrent identical callers await the pending result without a second mutation', async () => {
  const replayStore = store({ maxEntries: 4, maxBytes: 512 * 1024, maxOutcomeBytes: 1024 });
  const fingerprint = semanticIdempotencyFingerprint({ operation: 'create', value: 1 });
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let mutations = 0;
  const identity = { scope, key: key('two'), fingerprint };
  const first = replayStore.execute(identity, async () => {
    mutations += 1;
    await gate;
    return { ok: true };
  });
  await new Promise((resolve) => setImmediate(resolve));
  const second = replayStore.execute(identity, async () => {
    mutations += 1;
    return { ok: false };
  }, { authorizeReplay: allowReplay });
  release();
  const [committed, replay] = await Promise.all([first, second]);
  assert.equal(committed.kind, 'committed');
  assert.equal(replay.kind, 'replay');
  assert.equal(mutations, 1);
});

test('committed result survives a lost response and preflight limits prevent mutation', async () => {
  const replayStore = store({ maxEntries: 1, maxBytes: 4096, maxOutcomeBytes: 512 });
  const fingerprint = semanticIdempotencyFingerprint({ operation: 'create', value: 1 });
  let mutations = 0;
  const identity = { scope, key: key('three'), fingerprint };
  await assert.rejects(() => replayStore.execute(identity, async () => {
    mutations += 1;
    return { ok: true };
  }, { afterCommit: () => { throw new Error('connection lost'); } }), /connection lost/u);
  const replay = await replayStore.execute(identity, async () => { mutations += 1; }, { authorizeReplay: allowReplay });
  assert.equal(replay.kind, 'replay');
  assert.equal(mutations, 1);
  assert.throws(() => replayStore.begin({ scope, key: key('other'), fingerprint }), (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED');
  assert.equal(mutations, 1);
});

test('callback rejection after invocation retains an indeterminate reservation', async () => {
  const replayStore = store({ maxEntries: 1, maxBytes: 4096, maxOutcomeBytes: 512 });
  const fingerprint = semanticIdempotencyFingerprint({ operation: 'create', value: 1 });
  let mutations = 0;
  const identity = { scope, key: key('four'), fingerprint };
  await assert.rejects(() => replayStore.execute(identity, async () => { mutations += 1; throw new Error('settlement unknown'); }), /settlement unknown/u);
  assert.equal(replayStore.summary().entries, 1);
  await assert.rejects(() => replayStore.execute(identity, async () => { mutations += 1; }, { authorizeReplay: allowReplay }), /indeterminate/u);
  assert.equal(mutations, 1);
});

test('invalid or oversized callback outcomes retain the key as indeterminate', async () => {
  for (const [label, outcome] of [
    ['idempotency-invalid-outcome', undefined],
    ['idempotency-oversized-outcome', { value: 'x'.repeat(1024) }],
  ]) {
    const replayStore = store({ maxEntries: 1, maxBytes: 4096, maxOutcomeBytes: 64 });
    const fingerprint = semanticIdempotencyFingerprint({ operation: label });
    let mutations = 0;
    const identity = { scope, key: key(label), fingerprint };
    await assert.rejects(() => replayStore.execute(identity, async () => { mutations += 1; return outcome; }));
    await assert.rejects(() => replayStore.execute(identity, async () => { mutations += 1; }, { authorizeReplay: allowReplay }), /indeterminate/u);
    assert.equal(mutations, 1);
  }
});

test('expired outcomes become tombstones and cannot silently execute again', async () => {
  let now = 0;
  const replayStore = new IdempotencyReplayStore({ now: () => now, tombstoneTtlMs: 20 });
  const input = { scope, key: key('tombstone', 0, 10), fingerprint: semanticIdempotencyFingerprint({ operation: 'mutate', value: 1 }) };
  await replayStore.execute(input, async () => ({ result: 'ok' }));
  now = 11;
  await assert.rejects(() => replayStore.execute(input, async () => ({ result: 'wrong' }), { authorizeReplay: allowReplay }), (error) => error.code === 'IDEMPOTENCY_KEY_REQUIRED');
  now = 31;
  await assert.rejects(() => replayStore.execute(input, async () => ({ result: 'still-wrong' }), { authorizeReplay: allowReplay }), (error) => error.code === 'IDEMPOTENCY_KEY_REQUIRED');
});

test('replay authorization runs before a stored result is disclosed', async () => {
  const replayStore = store();
  const input = { scope, key: key('reauthorize'), fingerprint: semanticIdempotencyFingerprint({ operation: 'mutate', value: 2 }) };
  await replayStore.execute(input, async () => ({ protected: 'value' }));
  let authorized = 0;
  const replay = await replayStore.execute(input, async () => assert.fail('must not mutate'), {
    authorizeReplay: async (binding) => {
      authorized += 1;
      assert.equal(binding.key, input.key);
      return { result: 'allow', code: 'ALLOW_EXPLICIT' };
    },
  });
  assert.equal(authorized, 1);
  assert.equal(replay.kind, 'replay');
  const publicReplay = await replayStore.execute(input, async () => assert.fail('must not mutate'), {
    authorizeReplay: async () => ({ result: 'allow', code: 'ALLOW_PUBLIC' }),
  });
  assert.equal(publicReplay.kind, 'replay');
  await assert.rejects(
    () => replayStore.execute(input, async () => assert.fail('must not mutate')),
    (error) => error.code === 'AUTHORIZATION_DENIED',
  );
  await assert.rejects(
    () => replayStore.execute(input, async () => assert.fail('must not mutate'), { authorizeReplay: async () => { throw new Error('revoked'); } }),
    (error) => error.code === 'AUTHORIZATION_DENIED',
  );
});

test('replay authorization fails closed for every non-predecessor allow shape', async () => {
  const replayStore = store();
  const input = { scope, key: key('closed-reauthorize'), fingerprint: semanticIdempotencyFingerprint({ operation: 'mutate', value: 3 }) };
  await replayStore.execute(input, async () => ({ protected: 'must-not-disclose' }));
  for (const decision of [undefined, null, true, false, { allowed: true }, { result: 'allow' }, { result: 'allow', code: 'ALLOW_bad' }, { result: 'allow', code: 'ALLOW_FAKE' }, { result: 'deny', code: 'DENY_POLICY' }, { result: 'allow', code: 'ALLOW_EXPLICIT', extra: true }]) {
    let mutated = false;
    await assert.rejects(
      () => replayStore.execute(input, async () => { mutated = true; }, { authorizeReplay: async () => decision }),
      (error) => error.code === 'AUTHORIZATION_DENIED' && !JSON.stringify(error).includes('must-not-disclose'),
    );
    assert.equal(mutated, false);
  }
});

test('timeout after mutation start retains the reservation and retry replays one settled mutation', async () => {
  const replayStore = store({ maxEntries: 4, maxBytes: 64 * 1024, maxOutcomeBytes: 1024 });
  let mutations = 0;
  const identity = {
    scope,
    key: key('timeout'),
    fingerprint: semanticIdempotencyFingerprint({ operation: 'mutate', body: { value: 1 } }),
  };
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const first = replayStore.execute(identity, async () => {
    mutations += 1;
    await blocked;
    return { committed: true };
  }, { timeoutMs: 5 });
  await assert.rejects(() => first, (error) => error.code === 'PROTOCOL_DEADLINE_EXCEEDED' && error.preMutation === false);
  assert.equal(replayStore.summary().pending, 1);
  release();
  await new Promise((resolve) => setImmediate(resolve));
  const replay = await replayStore.execute(identity, async () => { mutations += 1; return { committed: false }; }, { authorizeReplay: allowReplay });
  assert.equal(replay.kind, 'replay');
  assert.deepEqual({ ...replay.outcome }, { committed: true });
  assert.equal(mutations, 1);
});

test('retry-only with an unused valid self-dating key performs exactly one first execution in both engines', async () => {
  const input = {
    algorithm: 'OGVCS-SEMANTIC-JCS-SHA-256',
    atUnixMs: AT,
    attemptAuthorizationDecisions: ['allow'],
    attemptProjectionIndexes: [0],
    attemptSchedule: ['retry'],
    idempotencyExpiresAtUnixMs: AT + 86_400_000,
    idempotencyIssuedAtUnixMs: AT,
    idempotencyKey: `ik1.${AT}.${AT + 86_400_000}.AAAAAAAAAAAAAAAAAAAAAA`,
    projections: [{
      body: { value: 1 },
      extensions: {},
      operation: 'repository.example/mutate@1',
      schemaVersion: 'ogvcs.protocol/request-envelope/v1',
    }],
    rawInputs: [],
    retryableMutation: true,
    route: 'idempotency',
    tombstoneRetentionMs: 0,
  };
  const runnerCase = {
    schemaVersion: 'ogvcs.protocol/runner-case/v1',
    id: `case-${'a'.repeat(32)}`,
    operation: 'fingerprint',
    inputKind: 'semantic-value',
    input,
    control: { cancellation: 'none', clockSamplesUnixMs: [AT] },
  };
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const [reference, independent] = await Promise.all([
    executeReferenceProtocolCase(runnerCase, { contract }),
    evaluateIndependentCase(authority, runnerCase),
  ]);
  for (const result of [reference, independent]) {
    assert.equal(result.result, 'accept');
    assert.equal(result.code, 'NONE');
    assert.equal(result.preMutation, false);
    assert.equal(result.mutationCount, 1);
    assert.deepEqual(result.trace.semanticOutput, { firstExecution: true, replay: false });
  }
});
