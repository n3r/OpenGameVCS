import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  atomicJsonWrite,
  directorySyncUnsupported,
  pinPlainDirectory,
  readJson,
  withRecoverableDirectoryLock,
} from '../src/fs-util.mjs';

const lockName = '7'.repeat(64);
const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const deferred = () => {
  let resolve;
  const promise = new Promise((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
};

test('a live slow lock renews its lease and cannot be taken over', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-renewed-lock-'));
  const rootPin = await pinPlainDirectory(root);
  const entered = deferred();
  const held = withRecoverableDirectoryLock({
    rootPin,
    name: lockName,
    now: () => Date.now(),
    attempts: 1,
    leaseMilliseconds: 1_000,
    operation: async (lockGuard) => {
      entered.resolve();
      await wait(1_150);
      await lockGuard.assertOwned();
      return 'owner-completed';
    },
  });
  await entered.promise;
  await wait(1_050);
  await assert.rejects(() => withRecoverableDirectoryLock({
    rootPin,
    name: lockName,
    now: () => Date.now(),
    attempts: 1,
    leaseMilliseconds: 1_000,
    operation: async () => 'must-not-run',
  }), { code: 'TRANSFER_SESSION_STATE' });
  assert.equal(await held, 'owner-completed');
});

test('a stale fencing token cannot commit after an expired-lock takeover', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-fenced-lock-'));
  const rootPin = await pinPlainDirectory(root);
  const statePin = await pinPlainDirectory(join(root, 'state'), { parentPin: rootPin });
  const statePath = join(statePin.path, 'record.json');
  let now = 1_000;
  const entered = deferred();
  const release = deferred();
  const stale = withRecoverableDirectoryLock({
    rootPin,
    name: lockName,
    now: () => now,
    attempts: 1,
    leaseMilliseconds: 1_000,
    operation: async (lockGuard) => {
      entered.resolve();
      await release.promise;
      await atomicJsonWrite(statePath, { writer: 'stale' }, { directoryPin: statePin, lockGuard });
    },
  });
  await entered.promise;
  now = 2_001;
  await withRecoverableDirectoryLock({
    rootPin,
    name: lockName,
    now: () => now,
    attempts: 2,
    leaseMilliseconds: 1_000,
    operation: async (lockGuard) => atomicJsonWrite(
      statePath,
      { writer: 'winner' },
      { directoryPin: statePin, lockGuard },
    ),
  });
  release.resolve();
  await assert.rejects(stale, { code: 'TRANSFER_SESSION_STATE' });
  assert.equal((await readJson(statePath, 8192, { directoryPin: statePin })).writer, 'winner');
});

test('directory-sync portability suppresses only the exact Windows unsupported result', () => {
  assert.equal(directorySyncUnsupported({ code: 'EPERM' }, 'win32'), true);
  assert.equal(directorySyncUnsupported({ code: 'EACCES' }, 'win32'), false);
  assert.equal(directorySyncUnsupported({ code: 'EPERM' }, 'linux'), false);
  assert.equal(directorySyncUnsupported({ code: 'EINVAL' }, 'darwin'), false);
});
