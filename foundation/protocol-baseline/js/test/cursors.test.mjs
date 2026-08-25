import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { loadAuthority } from '../../adapters/js-independent/src/core.mjs';
import { evaluateIndependentCase } from '../../adapters/js-independent/src/engine.mjs';
import {
  CursorStore, executeReferenceProtocolCase, HARD_LIMITS, loadProtocolContract,
} from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

const scope = Object.freeze({
  subject: 'subject-1',
  tenant: 'tenant-1',
  repository: 'repository-1',
  operation: 'PagedProbe',
  queryDigest: 'ab'.repeat(32),
});

test('cursor lifetime is capped by the registered one-day authority', () => {
  assert.doesNotThrow(() => new CursorStore({ ttlMs: HARD_LIMITS.cursorLifetimeMs }));
  assert.throws(() => new CursorStore({ ttlMs: 0 }), /supported range/u);
  assert.throws(() => new CursorStore({ ttlMs: HARD_LIMITS.cursorLifetimeMs + 1 }), /supported range/u);
});

test('zero cursor lifetime is malformed before token lifecycle in both engines', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const scenario = contract.vectors.cursors.cases.find(({ id }) => id === 'cursor-expired');
  assert.ok(scenario);
  const runnerCase = {
    schemaVersion: 'ogvcs.protocol/runner-case/v1',
    id: `case-${'c'.repeat(32)}`,
    operation: scenario.operation,
    inputKind: scenario.inputKind,
    input: { ...scenario.input, ttlMs: 0 },
    control: scenario.control,
  };
  const [reference, independent] = await Promise.all([
    executeReferenceProtocolCase(runnerCase, { contract }),
    evaluateIndependentCase(authority, runnerCase),
  ]);
  assert.equal(reference.code, 'PROTOCOL_MALFORMED');
  assert.equal(independent.code, 'PROTOCOL_MALFORMED');
});

test('cursor expiry arithmetic overflow is malformed in both engines', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const scenario = contract.vectors.cursors.cases.find(({ id }) => id === 'cursor-expired');
  assert.ok(scenario);
  const runnerCase = {
    schemaVersion: 'ogvcs.protocol/runner-case/v1',
    id: `case-${'e'.repeat(32)}`,
    operation: scenario.operation,
    inputKind: scenario.inputKind,
    input: {
      ...scenario.input,
      issuedAtUnixMs: Number.MAX_SAFE_INTEGER,
      readAtUnixMs: Number.MAX_SAFE_INTEGER,
    },
    control: scenario.control,
  };
  const [reference, independent] = await Promise.all([
    executeReferenceProtocolCase(runnerCase, { contract }),
    evaluateIndependentCase(authority, runnerCase),
  ]);
  assert.equal(reference.code, 'PROTOCOL_MALFORMED');
  assert.equal(independent.code, 'PROTOCOL_MALFORMED');
});

function deterministicRandom() {
  let next = 1;
  return () => Buffer.alloc(32, next++);
}

test('cursor handles are opaque, scoped, expiring, and single-use on advance', () => {
  let now = 100;
  const store = new CursorStore({ now: () => now, randomBytes: deterministicRandom(), ttlMs: 50 });
  const issued = store.issue({ scope, generation: 7, position: 3 });
  assert.match(issued.token, /^c1\.[A-Za-z0-9_-]{43}$/u);
  assert.deepEqual({ ...store.read(issued.token, scope) }, { generation: 7, position: 3, issuedAt: 100, expiresAt: 150 });

  assert.throws(
    () => store.read(issued.token, { ...scope, subject: 'subject-2' }),
    (error) => error.code === 'CURSOR_SCOPE_MISMATCH',
  );
  const advanced = store.advance(issued.token, scope, { position: 4 });
  assert.throws(
    () => store.read(issued.token, scope),
    (error) => error.code === 'CURSOR_INVALID',
  );
  assert.equal(store.read(advanced.token, scope).position, 4);

  now = 151;
  assert.throws(
    () => store.read(advanced.token, scope),
    (error) => error.code === 'CURSOR_EXPIRED',
  );
  assert.equal(store.summary().entries, 1, 'expired tokens remain stable bounded tombstones');
});

test('cursor generation, backwards movement, tamper, and retention gap fail closed', () => {
  const store = new CursorStore({ now: () => 1, randomBytes: deterministicRandom() });
  const issued = store.issue({ scope, generation: 8, position: 5 });
  assert.throws(
    () => store.read(issued.token, scope, { generation: 7 }),
    (error) => error.code === 'CURSOR_GAP',
  );
  assert.throws(
    () => store.advance(issued.token, scope, { position: 4 }),
    (error) => error.code === 'CURSOR_INVALID',
  );
  assert.throws(
    () => store.read(`${issued.token.slice(0, -1)}A`, scope),
    (error) => ['CURSOR_INVALID', 'PROTOCOL_INPUT_INVALID'].includes(error.code),
  );

  store.markGap(issued.token, 'retention-window');
  assert.throws(
    () => store.read(issued.token, scope),
    (error) => error.code === 'CURSOR_GAP',
  );
});

test('cursor resource checks happen before publication and gap reservation is stable', () => {
  const random = deterministicRandom();
  const probe = new CursorStore({ now: () => 1, randomBytes: random, maxEntries: 1 });
  const first = probe.issue({ scope, generation: 1, position: 0 });
  const beforeGap = probe.summary();
  probe.markGap(first.token, 'x'.repeat(128));
  assert.deepEqual(probe.summary(), beforeGap);
  assert.throws(() => probe.issue({ scope, generation: 1, position: 1 }), /ceiling/u);
  assert.equal(probe.summary().entries, 1);
});

test('cursor validates the complete closed scope before state access', () => {
  const store = new CursorStore({ now: () => 1, randomBytes: deterministicRandom() });
  const issued = store.issue({ scope, generation: 1, position: 0 });
  assert.throws(() => store.read(issued.token, { ...scope, extra: true }), /scope fields/u);
  assert.throws(() => store.read('c1.bad', { ...scope, extra: true }), /scope fields/u);
  const { operation: _operation, ...missingOperation } = scope;
  assert.throws(() => store.read('c1.bad', missingOperation), /scope fields/u);
  assert.throws(() => store.read('c1.bad', scope), /wrong length|malformed|not canonical/u);
  assert.equal(store.summary().entries, 1);

  let traps = 0;
  const hostileScope = new Proxy({}, {
    ownKeys() { traps += 1; throw new Error('must not execute'); },
  });
  assert.throws(() => store.read(issued.token, hostileScope), (error) => error.code === 'PROTOCOL_INPUT_INVALID');
  assert.equal(traps, 0);

  const hostileIssue = {};
  Object.defineProperty(hostileIssue, 'scope', {
    enumerable: true,
    get() { traps += 1; throw new Error('must not execute'); },
  });
  assert.throws(() => store.issue(hostileIssue), (error) => error.code === 'PROTOCOL_INPUT_INVALID');
  const hostileAdvance = new Proxy({}, {
    ownKeys() { traps += 1; throw new Error('must not execute'); },
  });
  assert.throws(() => store.advance(issued.token, scope, hostileAdvance), (error) => error.code === 'PROTOCOL_INPUT_INVALID');
  assert.equal(traps, 0);
});

test('unrelated issuance cannot change an expired cursor into invalid during tombstone retention', () => {
  let now = 100;
  const store = new CursorStore({ now: () => now, randomBytes: deterministicRandom(), ttlMs: 10, tombstoneRetentionMs: 20 });
  const first = store.issue({ scope, generation: 1, position: 0 });
  now = 111;
  store.issue({ scope, generation: 1, position: 1 });
  assert.throws(() => store.read(first.token, scope), (error) => error.code === 'CURSOR_EXPIRED');
  now = 131;
  store.issue({ scope, generation: 1, position: 2 });
  assert.throws(() => store.read(first.token, scope), (error) => error.code === 'CURSOR_INVALID');
});
