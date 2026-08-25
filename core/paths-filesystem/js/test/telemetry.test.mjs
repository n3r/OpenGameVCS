import assert from 'node:assert/strict';
import { mkdtemp, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { probeFilesystemCapabilities } from '../src/capabilities.mjs';
import { createPathTelemetry, snapshotPathTelemetry } from '../src/telemetry.mjs';
import { preflightWorkspaceMaterialization } from '../src/preflight.mjs';
import { initialWatcherState, openWorkspaceWatcher } from '../src/watcher.mjs';
import { atomicWriteFile, openWorkspaceRoot, rollbackCrashRemnant, inspectCrashRemnants } from '../src/workspace.mjs';

async function plan(workspace, capabilities, entries, telemetry) {
  return preflightWorkspaceMaterialization(workspace, {
    schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: workspace.caseMode,
    profile: workspace.profile, platform: capabilities.platform,
    capabilities: { atomicReplace: capabilities.atomicReplace, executableBit: capabilities.executableBit, symlink: capabilities.symlink },
    entries,
  }, { telemetry });
}

test('privacy-safe telemetry exposes operational counters without caller callbacks', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-path-telemetry-'));
  const outside = await mkdtemp(join(tmpdir(), 'ogvcs-path-telemetry-outside-'));
  t.after(() => Promise.all([
    rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 }),
    rm(outside, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 }),
  ]));
  const telemetry = createPathTelemetry();
  const workspace = await openWorkspaceRoot(root, { telemetry });
  const capabilities = await probeFilesystemCapabilities(root);

  await assert.rejects(plan(workspace, capabilities, [
    { id: 'left', path: 'same', kind: 'regular', mode: 'regular-file' },
    { id: 'right', path: 'same', kind: 'regular', mode: 'regular-file' },
  ], telemetry), error => error.code === 'PATH_COLLISION');

  const writePlan = await plan(workspace, capabilities, [
    { id: 'game', path: 'Game', kind: 'directory', mode: 'directory' },
    { id: 'file', path: 'Game/file', kind: 'regular', mode: 'regular-file' },
  ], telemetry);
  let busy = true;
  await atomicWriteFile(workspace, 'Game/file', Buffer.from('telemetry'), {
    createParents: true, maxRetries: 1, plan: writePlan, telemetry,
    hooks: { boundary: (name) => {
      if (name === 'before-publish-attempt' && busy) {
        busy = false; const error = new Error('busy'); error.code = 'EBUSY'; throw error;
      }
    } },
  });

  const unsafePlan = await plan(workspace, capabilities, [
    { id: 'escape', path: 'escape', kind: 'directory', mode: 'directory' },
    { id: 'denied', path: 'escape/denied', kind: 'regular', mode: 'regular-file' },
  ], telemetry);
  await symlink(outside, join(root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(atomicWriteFile(workspace, 'escape/denied', Buffer.from('no'), {
    createParents: true, plan: unsafePlan, telemetry,
  }), error => error.code === 'UNSAFE_TARGET');

  const watcher = await openWorkspaceWatcher(workspace, initialWatcherState('node-fs-watch-v1'), {
    session: 'telemetry-watch', telemetry, reconcile: async () => true,
    iteratorFactory: () => ({
      next: async () => { const error = new Error('overflow'); error.code = 'ERR_FS_WATCHER_QUEUE_OVERFLOW'; throw error; },
      return: async () => ({ done: true }),
    }),
  });
  await assert.rejects(watcher.nextBatch(async () => true), error => error.code === 'WATCH_OVERFLOW');

  const snapshot = snapshotPathTelemetry(telemetry);
  assert.deepEqual(snapshot.profiles, ['path.opengamevcs/portable@1']);
  assert.deepEqual(snapshot.preflightFailures, { PATH_COLLISION: 1 });
  assert.equal(snapshot.busyRetries, 1);
  assert.equal(snapshot.unsafePathDenials, 1);
  assert.equal(snapshot.reconciliations, 1);
  assert.equal(snapshot.watcherGaps, 1);
  assert.equal(snapshot.atomicFallbackRefusals, 0);
  assert.equal(JSON.stringify(snapshot).includes(root), false);
  assert.equal(JSON.stringify(snapshot).includes(outside), false);
  for (const remnant of await inspectCrashRemnants(workspace)) await rollbackCrashRemnant(workspace, remnant.id);
});

test('telemetry rejects forged collectors', () => {
  assert.throws(() => snapshotPathTelemetry(Object.freeze({ schemaVersion: 'ogvcs.path/telemetry/v1' })), error => error.code === 'PATH_INPUT_INVALID');
});
