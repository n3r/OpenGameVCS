import assert from 'node:assert/strict';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
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

test('only explicitly resumable adapters remain clean after a normal stop', () => {
  let live = transitionWatcher(initialWatcherState(), { type: 'reconcile', cursor: 'c0', generation: 1 });
  live = transitionWatcher(live, { type: 'start', session: 's1' });
  live = transitionWatcher(live, { type: 'batch', session: 's1', fromCursor: 'c0', toCursor: 'c1', overflow: false, indexUpdated: true });

  const resumable = transitionWatcher(live, { type: 'stop', session: 's1', resumeSupported: true });
  assert.equal(resumable.authoritativeClean, true);
  assert.equal(resumable.reconciliationRequired, false);
  assert.equal(resumable.session, null);

  const nonresumable = transitionWatcher(live, { type: 'stop', session: 's1' });
  assert.equal(nonresumable.authoritativeClean, false);
  assert.equal(nonresumable.reconciliationRequired, true);
  assert.equal(nonresumable.reason, 'unsupported-resume');
  assert.equal(nonresumable.session, null);
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

test('portable watcher filters control events without promoting a partial native queue to clean', async t => {
  const { workspace } = await fixture(t);
  let state = await applyWatcherEvent(workspace, initialWatcherState('node-fs-watch-v1'), { type: 'reconcile', cursor: 'c0', generation: 1 });
  const values = [
    { eventType: 'change', filename: '.ogvcs/watcher-state.json' },
    { eventType: 'change', filename: '.OGVCS/other-control-state' },
    { eventType: 'rename', filename: 'Game/Hero.uasset' },
  ];
  let offset = 0;
  const watcher = await openWorkspaceWatcher(workspace, state, {
    session: 'session-1',
    iteratorFactory: () => ({
      next: async () => ({ done: false, value: values[offset++] }),
      return: async () => ({ done: true }),
    }),
    reconcile: async () => true,
  });
  const seen = [];
  const batch = await watcher.nextBatch(async (events, signal) => { assert.equal(signal.aborted, false); seen.push(...events); return true; });
  assert.deepEqual(seen, [{ type: 'rename', path: 'Game/Hero.uasset' }]);
  assert.equal(batch.state.authoritativeClean, false);
  assert.equal(batch.state.reconciliationRequired, false);
  const cursor = batch.state.cursor;
  state = await watcher.close();
  assert.equal(state.session, null);
  assert.equal(state.authoritativeClean, false);
  assert.equal(state.reconciliationRequired, true);
  assert.equal(state.reason, 'unsupported-resume');
  const durable = await loadWatcherState(workspace);
  assert.equal(durable.cursor, cursor);
  assert.equal(durable.reason, 'unsupported-resume');
});

test('offline mutation after stop cannot be hidden by a clean reopen or reused cursor', async t => {
  const { root, workspace } = await fixture(t);
  let state = await applyWatcherEvent(workspace, initialWatcherState('node-fs-watch-v1'), { type: 'reconcile', cursor: 'c0', generation: 1 });
  const iterator = (filename) => ({
    next: async () => ({ done: false, value: { eventType: 'change', filename } }),
    return: async () => ({ done: true }),
  });
  const first = await openWorkspaceWatcher(workspace, state, {
    session: 'session-before-stop', iteratorFactory: () => iterator('observed-before-stop'),
    reconcile: async () => true,
  });
  const firstBatch = await first.nextBatch(async () => true);
  const firstCursor = firstBatch.cursor;
  state = await first.close();

  await writeFile(join(root, 'missed-while-stopped'), 'offline mutation');
  let factoryCalled = false;
  await assert.rejects(openWorkspaceWatcher(workspace, state, {
    session: 'forbidden-reopen',
    iteratorFactory: () => { factoryCalled = true; return iterator('observed-after-reopen'); },
  }), error => error.code === 'RECONCILIATION_REQUIRED');
  assert.equal(factoryCalled, false);
  assert.equal((await loadWatcherState(workspace)).reason, 'unsupported-resume');

  const second = await openWorkspaceWatcher(workspace, state, {
    session: 'session-after-reconcile', iteratorFactory: () => iterator('observed-after-reconcile'),
    reconcile: async () => true,
  });
  const secondBatch = await second.nextBatch(async () => true);
  assert.notEqual(secondBatch.cursor, firstCursor);
  assert.equal(secondBatch.cursor, '3:1');
  await second.close();
});

test('portable watcher subscribes before the reconciliation that grants clean authority', async t => {
  const { root, workspace } = await fixture(t);
  const previouslyClean = await applyWatcherEvent(
    workspace, initialWatcherState('node-fs-watch-v1'),
    { type: 'reconcile', cursor: 'external-before-open', generation: 1 },
  );
  let injected = false;
  let subscribed = false;
  let reconciledNames;
  const watcher = await openWorkspaceWatcher(workspace, previouslyClean, {
    session: 'subscribe-before-reconcile',
    hooks: {
      boundary: async (name) => {
        if (name === 'before-watcher-state-write' && !injected) {
          injected = true;
          await writeFile(join(root, 'missed-before-subscribe'), 'created in the old gap');
        }
      },
    },
    iteratorFactory: () => {
      subscribed = true;
      return {
        next: async () => ({ done: false, value: { eventType: 'change', filename: 'later-visible' } }),
        return: async () => ({ done: true }),
      };
    },
    reconcile: async ({ generation, cursor }) => {
      assert.equal(subscribed, true);
      assert.equal(generation, 2);
      assert.equal(cursor, '2:0');
      reconciledNames = (await readdir(root)).sort();
      return true;
    },
  });
  assert.equal(reconciledNames.includes('missed-before-subscribe'), true);
  const batch = await watcher.nextBatch(async () => true);
  assert.equal(batch.cursor, '2:1');
  assert.equal(batch.state.authoritativeClean, false);
  await watcher.close();
});

test('portable watcher never reports clean while a second native event remains queued', async t => {
  const { workspace } = await fixture(t);
  const queued = [
    { eventType: 'change', filename: 'first' },
    { eventType: 'change', filename: 'second' },
  ];
  const watcher = await openWorkspaceWatcher(workspace, initialWatcherState('node-fs-watch-v1'), {
    session: 'queued-native-events', reconcile: async () => true,
    iteratorFactory: () => ({
      next: async () => ({ done: false, value: queued.shift() }),
      return: async () => ({ done: true }),
    }),
  });
  const seen = [];
  const first = await watcher.nextBatch(async (events) => { seen.push(...events); return true; });
  assert.deepEqual(seen, [{ type: 'change', path: 'first' }]);
  assert.equal(queued.length, 1);
  assert.equal(first.state.authoritativeClean, false);
  assert.equal(first.state.reconciliationRequired, false);
  const second = await watcher.nextBatch(async (events) => { seen.push(...events); return true; });
  assert.deepEqual(seen, [{ type: 'change', path: 'first' }, { type: 'change', path: 'second' }]);
  assert.equal(second.state.authoritativeClean, false);
  await watcher.close();
});

test('portable watcher overflow durably requires reconciliation', async t => {
  const { workspace } = await fixture(t);
  const state = await applyWatcherEvent(workspace, initialWatcherState('node-fs-watch-v1'), { type: 'reconcile', cursor: 'c0', generation: 1 });
  const watcher = await openWorkspaceWatcher(workspace, state, {
    session: 'session-2',
    iteratorFactory: () => ({ next: async () => { const error = new Error('overflow'); error.code = 'ERR_FS_WATCHER_QUEUE_OVERFLOW'; throw error; } }),
    reconcile: async () => true,
  });
  await assert.rejects(watcher.nextBatch(async () => true), error => error.code === 'WATCH_OVERFLOW');
  const durable = await loadWatcherState(workspace);
  assert.equal(durable.reconciliationRequired, true);
  assert.equal(durable.reason, 'overflow');
});
