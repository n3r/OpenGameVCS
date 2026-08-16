import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { PathFilesystemError } from '../src/errors.mjs';
import { applyWatcherEvent, initialWatcherState, loadWatcherState, openWorkspaceWatcher, persistWatcherState, transitionWatcher } from '../src/watcher.mjs';
import { openWorkspaceRoot } from '../src/workspace.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-watcher-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, workspace: await openWorkspaceRoot(root) };
}

test('overflow and gaps persist reconciliation-required state before rejecting', async t => {
  const { workspace } = await fixture(t);
  let state = initialWatcherState();
  state = await applyWatcherEvent(workspace, state, { type: 'reconcile', cursor: 'c0', generation: 1 });
  state = await applyWatcherEvent(workspace, state, { type: 'start', session: 's1' });
  await assert.rejects(applyWatcherEvent(workspace, state, { type: 'batch', session: 's1', fromCursor: 'wrong', toCursor: 'c1' }), error => error instanceof PathFilesystemError && error.code === 'WATCH_GAP');
  const durable = await loadWatcherState(workspace);
  assert.equal(durable.authoritativeClean, false);
  assert.equal(durable.reconciliationRequired, true);
  assert.equal(durable.reason, 'cursor-gap');
});

test('unclean restart cannot report a clean workspace', async () => {
  let state = transitionWatcher(initialWatcherState(), { type: 'reconcile', cursor: 'c0', generation: 1 });
  state = transitionWatcher(state, { type: 'start', session: 's1' });
  assert.throws(() => transitionWatcher(state, { type: 'restart' }), error => error instanceof PathFilesystemError && error.code === 'WATCH_UNCLEAN_SHUTDOWN' && error.cause.reconciliationRequired === true && error.cause.authoritativeClean === false);
});

test('corrupt durable watcher state becomes dirty rather than trusted', async t => {
  const { workspace } = await fixture(t);
  await writeFile(join(workspace.control, 'watcher-state.json'), '{"authoritativeClean":true}\n');
  const state = await loadWatcherState(workspace);
  assert.equal(state.authoritativeClean, false);
  assert.equal(state.reconciliationRequired, true);
  assert.equal(state.reason, 'state-corrupt');
  await assert.rejects(loadWatcherState(workspace, { failOnCorrupt: true }), error => error.code === 'WATCH_STATE_INVALID');
});

test('state persistence rejects impossible clean/reconciliation combinations', async t => {
  const { workspace } = await fixture(t);
  const invalid = { ...initialWatcherState(), authoritativeClean: true };
  await assert.rejects(persistWatcherState(workspace, invalid), error => error.code === 'WATCH_STATE_INVALID');
  await assert.rejects(persistWatcherState(workspace, { ...initialWatcherState(), reason: 'anything' }), error => error.code === 'WATCH_STATE_INVALID');
});

test('watcher persistence rejects forged workspace handles', async t => {
  const { workspace } = await fixture(t);
  await assert.rejects(persistWatcherState(Object.freeze({ ...workspace }), initialWatcherState()), error => error.code === 'UNSAFE_TARGET');
});

test('portable watcher filters control events and persists an indexed cursor before clean stop', async t => {
  const { workspace } = await fixture(t);
  let state = await applyWatcherEvent(workspace, initialWatcherState('node-fs-watch-v1'), { type: 'reconcile', cursor: 'c0', generation: 1 });
  const values = [
    { eventType: 'change', filename: '.ogvcs/watcher-state.json' },
    { eventType: 'rename', filename: 'Game/Hero.uasset' },
  ];
  let offset = 0;
  const watcher = await openWorkspaceWatcher(workspace, state, {
    session: 'session-1',
    iteratorFactory: () => ({
      next: async () => ({ done: false, value: values[offset++] }),
      return: async () => ({ done: true }),
    }),
  });
  const seen = [];
  const batch = await watcher.nextBatch(async (events, signal) => { assert.equal(signal.aborted, false); seen.push(...events); return true; });
  assert.deepEqual(seen, [{ type: 'rename', path: 'Game/Hero.uasset' }]);
  assert.equal(batch.state.authoritativeClean, true);
  state = await watcher.close();
  assert.equal(state.session, null);
  assert.equal((await loadWatcherState(workspace)).cursor, '1:1');
});

test('portable watcher overflow durably requires reconciliation', async t => {
  const { workspace } = await fixture(t);
  const state = await applyWatcherEvent(workspace, initialWatcherState('node-fs-watch-v1'), { type: 'reconcile', cursor: 'c0', generation: 1 });
  const watcher = await openWorkspaceWatcher(workspace, state, {
    session: 'session-2',
    iteratorFactory: () => ({ next: async () => { const error = new Error('overflow'); error.code = 'ERR_FS_WATCHER_QUEUE_OVERFLOW'; throw error; } }),
  });
  await assert.rejects(watcher.nextBatch(async () => true), error => error.code === 'WATCH_OVERFLOW');
  const durable = await loadWatcherState(workspace);
  assert.equal(durable.reconciliationRequired, true);
  assert.equal(durable.reason, 'overflow');
});
