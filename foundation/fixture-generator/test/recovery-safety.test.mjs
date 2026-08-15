import assert from 'node:assert/strict';
import {
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rmdir,
  symlink,
  truncate,
  unlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';

import {
  canonicalDigest,
  createRequest,
  generateFixture,
  planFixture,
  verifyFixture,
} from '../src/index.mjs';
import {
  deriveWorkspacePaths,
  OWNER_FILENAME,
  prepareWorkspace,
  publishWorkspace,
} from '../src/safety.mjs';
import {
  jsonError,
  jsonOutput,
  progressEvents,
  readJson,
  runCli,
  smallCliArguments,
  temporaryDirectory,
} from './test-helpers.mjs';

async function onlyStage(cwd) {
  const entries = await readdir(cwd);
  const matches = entries.filter((name) => name.endsWith('.stage'));
  assert.equal(matches.length, 1, `expected one stage, found ${matches.join(', ')}`);
  return path.join(cwd, matches[0]);
}

async function onlyLock(cwd) {
  const entries = await readdir(cwd);
  const matches = entries.filter((name) => name.endsWith('.ogvcs-fixture.lock'));
  assert.equal(matches.length, 1, `expected one lock, found ${matches.join(', ')}`);
  return path.join(cwd, matches[0]);
}

async function baselineManifest(t, arguments_) {
  const cwd = await temporaryDirectory(t, 'ogvcs-fixture-baseline-');
  const generated = await runCli(cwd, ['generate', ...arguments_]);
  assert.equal(generated.code, 0, generated.stderr);
  const destination = arguments_[arguments_.indexOf('--destination') + 1];
  return readJson(path.join(cwd, destination, 'manifest.json'));
}

async function waitFor(check, message, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await delay(20);
  }
  assert.fail(message);
}

test('forced checkpoint exit refuses a concurrent owner, then resumes to the uninterrupted manifest', async (t) => {
  const cwd = await temporaryDirectory(t);
  const destination = 'fixture';
  const arguments_ = smallCliArguments('code-heavy', destination, {
    checkpointEvery: 4,
    historyOperationCount: 9,
    largeFileBytes: 0,
    pathCount: 13,
  });
  const expected = await baselineManifest(t, arguments_);

  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  assert.equal(interrupted.signal, null);
  const stage = await onlyStage(cwd);
  assert.rejects(readFile(path.join(stage, 'manifest.json')), { code: 'ENOENT' });
  const lock = await onlyLock(cwd);
  const staleLock = await readJson(lock);

  await writeFile(lock, `${JSON.stringify({ ...staleLock, pid: process.pid })}\n`);
  const concurrent = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(concurrent.code, 5);
  assert.equal(jsonError(concurrent).error.type, 'conflict');

  await writeFile(lock, `${JSON.stringify(staleLock)}\n`);
  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal(jsonOutput(resumed).result.resumed, true);
  assert.ok(progressEvents(resumed).some(({ type }) => type === 'resumed'));
  assert.deepEqual(await readJson(path.join(cwd, destination, 'manifest.json')), expected);
});

test('resume recovers an atomic lock candidate interrupted before final lock publication', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-lock-initialization-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_LOCK_CANDIDATE_CREATE: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const interruptedEntries = await readdir(cwd);
  assert.ok(interruptedEntries.some((name) => name.includes('.lock.candidate-')));
  assert.ok(!interruptedEntries.some((name) => name.endsWith('.ogvcs-fixture.lock')));

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
  assert.ok(!(await readdir(cwd)).some((name) => name.includes('.lock.candidate-')));
});

test('resume removes dead guard-recovery epochs after interruption', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-guard-epoch-interruption-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const first = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(first.code, 99, first.stderr);
  const staleLockPath = await onlyLock(cwd);
  const staleLock = await readJson(staleLockPath);
  await writeFile(`${staleLockPath}.guard`, `${JSON.stringify({
    kind: 'opengamevcs-fixture-generator-lock-guard/v1',
    pid: 2_147_483_647,
    requestDigest: staleLock.requestDigest,
    tool: 'ogvcs-fixture',
  })}\n`);

  const interruptedRecovery = await runCli(cwd, ['generate', ...arguments_, '--resume'], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_GUARD_RECOVERY_EPOCH: '1' },
  });
  assert.equal(interruptedRecovery.code, 99, interruptedRecovery.stderr);
  assert.ok((await readdir(cwd)).some((name) => name.includes('.guard.recovery-')));

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
  assert.ok(!(await readdir(cwd)).some((name) => (
    name.includes('.guard.recovery-') || name.includes('.guard.candidate-')
  )));
});

test('fresh guard installation removes an orphaned epoch left after stale-guard unlink', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-guard-handoff-interruption-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const first = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(first.code, 99, first.stderr);
  const staleLockPath = await onlyLock(cwd);
  const staleLock = await readJson(staleLockPath);
  const guardPath = `${staleLockPath}.guard`;
  await writeFile(guardPath, `${JSON.stringify({
    kind: 'opengamevcs-fixture-generator-lock-guard/v1',
    pid: 2_147_483_647,
    requestDigest: staleLock.requestDigest,
    tool: 'ogvcs-fixture',
  })}\n`);

  const interruptedRecovery = await runCli(cwd, ['generate', ...arguments_, '--resume'], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_STALE_GUARD_UNLINK: '1' },
  });
  assert.equal(interruptedRecovery.code, 99, interruptedRecovery.stderr);
  await assert.rejects(lstat(guardPath), { code: 'ENOENT' });
  assert.ok((await readdir(cwd)).some((name) => name.includes('.guard.recovery-')));

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
  assert.ok(!(await readdir(cwd)).some((name) => name.includes('.guard.recovery-')));
});

test('resume claims only a receipted empty initialization stage left under its compatible lock', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-stage-initialization-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_STAGE_CREATE: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  assert.deepEqual(await readdir(stage), []);
  assert.ok((await readdir(cwd)).some((name) => name.endsWith('.stage-initializing')));

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
  assert.ok(!(await readdir(cwd)).some((name) => name.endsWith('.stage-initializing')));
});

test('resume removes only a receipted empty publication reservation left before owner linkage', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-publication-initialization-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_DESTINATION_CREATE: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  assert.deepEqual(await readdir(path.join(cwd, 'fixture')), []);
  assert.ok(await onlyStage(cwd));
  assert.ok((await readdir(cwd)).some((name) => name.endsWith('.publishing')));

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
  assert.ok(!(await readdir(cwd)).some((name) => name.endsWith('.publishing')));
});

test('resume never adopts an unreceipted ownerless stage or empty destination', async (t) => {
  const cwd = await realpath(await temporaryDirectory(t, 'ogvcs-unreceipted-control-'));
  const destination = path.join(cwd, 'fixture');
  const requestDigest = canonicalDigest({ test: 'unreceipted-control' });
  const paths = deriveWorkspacePaths(destination, requestDigest);

  await mkdir(paths.stage);
  await assert.rejects(
    prepareWorkspace(destination, requestDigest, { resume: true }),
    (error) => error?.type === 'unsafe-destination' && /ownership marker/iu.test(error.message),
  );
  assert.deepEqual(await readdir(paths.stage), []);
  await rmdir(paths.stage);

  const initialized = await prepareWorkspace(destination, requestDigest);
  await initialized.releaseLock();
  await mkdir(destination);
  await assert.rejects(
    prepareWorkspace(destination, requestDigest, { resume: true }),
    (error) => error?.type === 'unsafe-destination' && /reservation proof/iu.test(error.message),
  );
  assert.deepEqual(await readdir(destination), []);
});

test('lossy destination display names never share live or stale workspace locks', async (t) => {
  const liveCwd = await temporaryDirectory(t, 'ogvcs-lock-name-live-');
  const firstDestination = 'Café-live';
  const secondDestination = 'Caf_-live';
  const firstPaths = deriveWorkspacePaths(
    path.join(liveCwd, firstDestination),
    canonicalDigest({ destination: firstDestination }),
  );
  const secondPaths = deriveWorkspacePaths(
    path.join(liveCwd, secondDestination),
    canonicalDigest({ destination: secondDestination }),
  );
  assert.notEqual(firstPaths.lock, secondPaths.lock);
  assert.notEqual(firstPaths.stage, secondPaths.stage);

  const firstArguments = smallCliArguments('code-heavy', firstDestination, {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const secondArguments = smallCliArguments('code-heavy', secondDestination, {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const first = runCli(liveCwd, ['generate', ...firstArguments], {
    env: {
      OGVCS_FIXTURE_TEST_PAUSE_AT_CHECKPOINT: '1',
      OGVCS_FIXTURE_TEST_PAUSE_MILLISECONDS: '600',
    },
  });
  await waitFor(async () => (await readdir(liveCwd)).some((name) => name.endsWith('.ogvcs-fixture.lock')),
    'first colliding-name process never acquired its lock');
  const second = await runCli(liveCwd, ['generate', ...secondArguments]);
  assert.equal(second.code, 0, second.stderr);
  const firstResult = await first;
  assert.equal(firstResult.code, 0, firstResult.stderr);

  const staleCwd = await temporaryDirectory(t, 'ogvcs-lock-name-stale-');
  const staleArguments = smallCliArguments('code-heavy', 'Café', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const independentArguments = smallCliArguments('code-heavy', 'Caf_', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const interrupted = await runCli(staleCwd, ['generate', ...staleArguments], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const independent = await runCli(staleCwd, ['generate', ...independentArguments]);
  assert.equal(independent.code, 0, independent.stderr);
  assert.equal((await runCli(staleCwd, ['verify', 'Caf_', '--deep'])).code, 0);
});

test('corrupt checkpoint is detected and deterministically regenerated', async (t) => {
  const cwd = await temporaryDirectory(t);
  const destination = 'fixture';
  const arguments_ = smallCliArguments('unity-like', destination, {
    checkpointEvery: 3,
    historyOperationCount: 7,
    largeFileBytes: 0,
    pathCount: 11,
  });
  const expected = await baselineManifest(t, arguments_);
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  await writeFile(path.join(stage, 'checkpoint.json'), '{ definitely-not-json');

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
  assert.equal(resumed.code, 0, resumed.stderr);
  const restarted = progressEvents(resumed).find(({ type }) => type === 'restarted');
  assert.ok(restarted);
  assert.match(restarted.reason, /checkpoint is malformed/i);
  assert.deepEqual(await readJson(path.join(cwd, destination, 'manifest.json')), expected);
});

test('oversized recovery checkpoint and NDJSON records fail within fixed parser bounds', async (t) => {
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 5,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const cases = [
    {
      artifact: 'checkpoint.json',
      content: ' '.repeat(2 * 1024 * 1024 + 1),
      reason: /safe byte bound/iu,
    },
    {
      artifact: 'inventory.ndjson',
      content: `${JSON.stringify({ padding: 'x'.repeat(64 * 1024) })}\n`,
      reason: /safe line bound/iu,
    },
  ];
  for (const [index, testCase] of cases.entries()) {
    const cwd = await temporaryDirectory(t, `ogvcs-bounded-recovery-${index}-`);
    const interrupted = await runCli(cwd, ['generate', ...arguments_], {
      env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
    });
    assert.equal(interrupted.code, 99, interrupted.stderr);
    const stage = await onlyStage(cwd);
    await writeFile(path.join(stage, testCase.artifact), testCase.content);

    const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
    assert.equal(resumed.code, 0, resumed.stderr);
    const restarted = progressEvents(resumed).find(({ type }) => type === 'restarted');
    assert.ok(restarted);
    assert.match(restarted.reason, testCase.reason);
    assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
  }
});

test('oversized recovery large-file descriptor is rejected before JSON parsing', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('large-binary', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 4096,
    pathCount: 3,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '3' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  await truncate(path.join(stage, 'large-file.json'), 2 * 1024 * 1024 + 1);

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
  assert.equal(resumed.code, 0, resumed.stderr);
  const restarted = progressEvents(resumed).find(({ type }) => type === 'restarted');
  assert.ok(restarted);
  assert.match(restarted.reason, /safe byte bound/iu);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('corrupt materialized item is detected at resume and regenerated', async (t) => {
  const cwd = await temporaryDirectory(t);
  const destination = 'fixture';
  const arguments_ = smallCliArguments('unreal-like', destination, {
    checkpointEvery: 4,
    historyOperationCount: 7,
    largeFileBytes: 0,
    pathCount: 12,
  });
  const expected = await baselineManifest(t, arguments_);
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const firstRecord = JSON.parse((await readFile(path.join(stage, 'inventory.ndjson'), 'utf8')).split('\n')[0]);
  await writeFile(path.join(stage, 'files', ...firstRecord.logicalPath.split('/')), 'corrupt-item');

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.ok(progressEvents(resumed).some(({ type }) => type === 'reconciled-path-materialization'));
  assert.ok(!progressEvents(resumed).some(({ type }) => type === 'restarted'));
  assert.deepEqual(await readJson(path.join(cwd, destination, 'manifest.json')), expected);
});

test('resume removes only positively identified atomic-write temporaries', async (t) => {
  const cwd = await temporaryDirectory(t);
  const destination = 'fixture';
  const arguments_ = smallCliArguments('code-heavy', destination, {
    checkpointEvery: 3,
    historyOperationCount: 4,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const ownedTemporary = path.join(stage, 'checkpoint.json.tmp-999999-42');
  await writeFile(ownedTemporary, 'torn atomic checkpoint bytes');

  const cleanupFault = await runCli(cwd, ['generate', ...arguments_, '--resume'], {
    env: { OGVCS_FIXTURE_TEST_FAIL_AT_PERSISTENCE: 'atomic-temporary-cleanup-sync' },
  });
  assert.equal(cleanupFault.code, 7, cleanupFault.stderr);
  await assert.rejects(readFile(ownedTemporary), { code: 'ENOENT' });
  await assert.rejects(readFile(path.join(cwd, destination, 'manifest.json')), { code: 'ENOENT' });

  await writeFile(ownedTemporary, 'second torn atomic checkpoint bytes');
  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
  assert.equal(resumed.code, 0, resumed.stderr);
  const cleanup = progressEvents(resumed).find(({ type }) => type === 'removed-owned-atomic-temporaries');
  assert.deepEqual(cleanup.artifacts, ['checkpoint.json.tmp-999999-42']);
  assert.equal((await runCli(cwd, ['verify', destination, '--deep'])).code, 0);
});

test('resource failure during owner initialization removes the unowned empty stage', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('global-studio', 'fixture', {
    checkpointEvery: 3,
    historyOperationCount: 6,
    largeFileBytes: 0,
    pathCount: 9,
  });
  const failed = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_FAIL_AFTER_BYTES: '1' },
  });
  assert.equal(failed.code, 7, failed.stderr);
  assert.equal(jsonError(failed).error.type, 'resource-limit');
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });
  assert.ok(!(await readdir(cwd)).some((name) => name.endsWith('.stage')));
  assert.ok(!(await readdir(cwd, { recursive: true })).some((name) => /\.tmp-[0-9]+-[0-9]+$/.test(name)));
});

test('injected later write failure never publishes a manifest and a compatible resume is safe', async (t) => {
  const cwd = await temporaryDirectory(t);
  const destination = 'fixture';
  const arguments_ = smallCliArguments('global-studio', destination, {
    checkpointEvery: 3,
    historyOperationCount: 6,
    largeFileBytes: 0,
    pathCount: 9,
  });
  const failed = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_FAIL_AFTER_BYTES: '4096' },
  });
  assert.equal(failed.code, 7);
  assert.equal(jsonError(failed).error.type, 'resource-limit');
  await assert.rejects(readFile(path.join(cwd, destination, 'manifest.json')), { code: 'ENOENT' });
  const stage = await onlyStage(cwd);
  await assert.rejects(readFile(path.join(stage, 'manifest.json')), { code: 'ENOENT' });

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.ok(progressEvents(resumed).some(({ type }) => type === 'restarted'));
  assert.equal((await readJson(path.join(cwd, destination, 'manifest.json'))).schemaVersion, 'ogvcs.fixture/manifest/v1');
});

test('a real competing process cannot enter a live generator workspace', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 5,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const firstPromise = runCli(cwd, ['generate', ...arguments_], {
    env: {
      OGVCS_FIXTURE_TEST_PAUSE_AT_CHECKPOINT: '1',
      OGVCS_FIXTURE_TEST_PAUSE_MILLISECONDS: '600',
    },
  });
  await waitFor(async () => {
    const entries = await readdir(cwd);
    return entries.some((name) => name.endsWith('.ogvcs-fixture.lock'));
  }, 'first process never acquired its lock');

  const competing = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(competing.code, 5, competing.stderr);
  assert.equal(jsonError(competing).error.type, 'conflict');
  const first = await firstPromise;
  assert.equal(first.code, 0, first.stderr);
  assert.equal((await readJson(path.join(cwd, 'fixture', 'manifest.json'))).manifestDigest, jsonOutput(first).result.manifestDigest);
});

test('two simultaneous stale-lock resumptions are atomically arbitrated', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 5,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const staleLockPath = await onlyLock(cwd);
  const staleLock = await readJson(staleLockPath);
  await writeFile(`${staleLockPath}.guard`, `${JSON.stringify({
    kind: 'opengamevcs-fixture-generator-lock-guard/v1',
    pid: 2_147_483_647,
    requestDigest: staleLock.requestDigest,
    tool: 'ogvcs-fixture',
  })}\n`);

  const environment = {
    OGVCS_FIXTURE_TEST_PAUSE_AT_CHECKPOINT: '2',
    OGVCS_FIXTURE_TEST_PAUSE_MILLISECONDS: '600',
  };
  const results = await Promise.all([
    runCli(cwd, ['generate', ...arguments_, '--resume'], { env: environment }),
    runCli(cwd, ['generate', ...arguments_, '--resume'], { env: environment }),
  ]);
  assert.deepEqual(results.map(({ code }) => code).sort((a, b) => a - b), [0, 5]);
  assert.equal(jsonError(results.find(({ code }) => code === 5)).error.type, 'conflict');
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('a later contender cannot enter after stale-guard recovery admission closes', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 5,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const staleLockPath = await onlyLock(cwd);
  const staleLock = await readJson(staleLockPath);
  await writeFile(`${staleLockPath}.guard`, `${JSON.stringify({
    kind: 'opengamevcs-fixture-generator-lock-guard/v1',
    pid: 2_147_483_647,
    requestDigest: staleLock.requestDigest,
    tool: 'ogvcs-fixture',
  })}\n`);

  const admitted = runCli(cwd, ['generate', ...arguments_, '--resume'], {
    env: { OGVCS_FIXTURE_TEST_PAUSE_AFTER_GUARD_RECOVERY_EPOCH_MS: '750' },
  });
  await waitFor(async () => {
    const entries = await readdir(cwd);
    return entries.some((name) => name.includes('.guard.recovery-') && /^[0-9]+$/u.test(name.split('-').at(-1)));
  }, 'first resume never installed its recovery epoch');

  const later = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(later.code, 5, later.stderr);
  assert.equal(jsonError(later).error.type, 'conflict');
  const completed = await admitted;
  assert.equal(completed.code, 0, completed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
  assert.ok(!(await readdir(cwd)).some((name) => name.includes('.guard.recovery-')));
});

test('resource failure during valid checkpoint recovery preserves the resumable stage', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 5,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const checkpointBefore = await readFile(path.join(stage, 'checkpoint.json'));
  const inventoryBefore = await readFile(path.join(stage, 'inventory.ndjson'));

  const limited = await runCli(cwd, ['generate', ...arguments_, '--resume'], {
    env: { OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE: 'recovery-inventory-record' },
  });
  assert.equal(limited.code, 7, limited.stderr);
  assert.equal(jsonError(limited).error.type, 'resource-limit');
  assert.deepEqual(await readFile(path.join(stage, 'checkpoint.json')), checkpointBefore);
  assert.deepEqual(await readFile(path.join(stage, 'inventory.ndjson')), inventoryBefore);
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('resource failure while replaying operations preserves the durable operation checkpoint', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 5,
    largeFileBytes: 0,
    pathCount: 3,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '4' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const checkpointBefore = await readFile(path.join(stage, 'checkpoint.json'));
  const operationsBefore = await readFile(path.join(stage, 'operations.ndjson'));

  const limited = await runCli(cwd, ['generate', ...arguments_, '--resume'], {
    env: { OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE: 'recovery-operation-record' },
  });
  assert.equal(limited.code, 7, limited.stderr);
  assert.deepEqual(await readFile(path.join(stage, 'checkpoint.json')), checkpointBefore);
  assert.deepEqual(await readFile(path.join(stage, 'operations.ndjson')), operationsBefore);

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('resume removes materialized files ahead of the durable path checkpoint', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 5,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_MATERIALIZED_PATH: '3' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  assert.equal((await readFile(path.join(stage, 'inventory.ndjson'), 'utf8')).trim().split('\n').length, 2);

  const rebuildLimited = await runCli(cwd, ['generate', ...arguments_, '--resume'], {
    env: { OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE: 'recovery-materialization-rebuild' },
  });
  assert.equal(rebuildLimited.code, 7, rebuildLimited.stderr);
  assert.ok((await readFile(path.join(stage, 'checkpoint.json'))).length > 0);

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('path reconciliation preserves and rejects unknown nested materialized content', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-nested-unknown-reconcile-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_MATERIALIZED_PATH: '3' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const unknown = path.join(stage, 'files', 'user-data', 'preserve.txt');
  await mkdir(path.dirname(unknown), { recursive: true });
  await writeFile(unknown, 'preserve-me');

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 4, resumed.stderr);
  assert.equal(jsonError(resumed).error.type, 'unsafe-destination');
  assert.equal(await readFile(unknown, 'utf8'), 'preserve-me');
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });
});

test('corruption restart preserves and rejects unknown nested materialized content', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-nested-unknown-restart-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '7' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const unknown = path.join(stage, 'files', 'user-data', 'preserve.txt');
  await mkdir(path.dirname(unknown), { recursive: true });
  await writeFile(unknown, 'preserve-me');
  await writeFile(path.join(stage, 'checkpoint.json'), '{corrupt');

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 4, resumed.stderr);
  assert.equal(jsonError(resumed).error.type, 'unsafe-destination');
  assert.equal(await readFile(unknown, 'utf8'), 'preserve-me');
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });
});

test('index-only full and sparse large files resume after a partial pre-checkpoint write', async (t) => {
  for (const largeFileMode of ['full', 'sparse']) {
    const cwd = await temporaryDirectory(t, `ogvcs-large-recovery-${largeFileMode}-`);
    const arguments_ = smallCliArguments('large-binary', 'fixture', {
      checkpointEvery: 1,
      historyOperationCount: 1,
      largeFileBytes: 4 * 1024 * 1024,
      largeFileMode,
      materialization: 'index-only',
      pathCount: 1,
    });
    const failed = await runCli(cwd, ['generate', ...arguments_], {
      env: { OGVCS_FIXTURE_TEST_FAIL_AFTER_BYTES: '1700000' },
    });
    assert.equal(failed.code, 7, `${largeFileMode}: ${failed.stderr}`);
    assert.equal(jsonError(failed).error.type, 'resource-limit');
    const stage = await onlyStage(cwd);
    const checkpoint = await readJson(path.join(stage, 'checkpoint.json'));
    assert.equal(checkpoint.extensions['generation.phase'], 'paths');
    const [inventoryLine] = (await readFile(path.join(stage, 'inventory.ndjson'), 'utf8'))
      .trim()
      .split('\n');
    const record = JSON.parse(inventoryLine);
    const partialPath = path.join(stage, 'files', ...record.logicalPath.split('/'));
    const partialMetadata = await lstat(partialPath);
    assert.ok(partialMetadata.isFile());
    if (largeFileMode === 'full') {
      assert.ok(partialMetadata.size > 0 && partialMetadata.size < 4 * 1024 * 1024);
    } else {
      assert.equal(partialMetadata.size, 4 * 1024 * 1024);
    }

    const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
    assert.equal(resumed.code, 0, `${largeFileMode}: ${resumed.stderr}`);
    const verified = await runCli(cwd, ['verify', 'fixture', '--deep']);
    assert.equal(verified.code, 0, `${largeFileMode}: ${verified.stderr}`);
  }
});

test('sparse recovery restarts a coherently relocated request-inconsistent extent', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-sparse-relocation-recovery-');
  const arguments_ = smallCliArguments('large-binary', 'fixture', {
    checkpointEvery: 1,
    historyOperationCount: 1,
    largeFileBytes: 4 * 1024 * 1024,
    largeFileMode: 'sparse',
    materialization: 'index-only',
    pathCount: 1,
  });
  const expected = await baselineManifest(t, arguments_);
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '2' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const checkpoint = await readJson(path.join(stage, 'checkpoint.json'));
  assert.equal(checkpoint.extensions['generation.phase'], 'operations');
  const descriptorPath = path.join(stage, 'large-file.json');
  const descriptor = await readJson(descriptorPath);
  const [first, second] = descriptor.physical.extents;
  const relocatedOffset = Math.floor((second.offset - first.length) / 2);
  assert.ok(relocatedOffset > first.offset);
  const largePath = path.join(stage, 'files', ...descriptor.logicalPath.split('/'));
  const handle = await open(largePath, 'r+');
  try {
    const bytes = Buffer.alloc(first.length);
    const read = await handle.read(bytes, 0, bytes.length, first.offset);
    assert.equal(read.bytesRead, bytes.length);
    await handle.write(bytes, 0, bytes.length, relocatedOffset);
    await handle.sync();
  } finally {
    await handle.close();
  }
  first.offset = relocatedOffset;
  const { descriptorDigest: ignoredDescriptorDigest, ...descriptorBody } = descriptor;
  void ignoredDescriptorDigest;
  descriptor.descriptorDigest = canonicalDigest(
    descriptorBody,
    'ogvcs.fixture/large-file-descriptor/v2',
  );
  await writeFile(descriptorPath, JSON.stringify(descriptor));

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.ok(progressEvents(resumed).some(({ type }) => type === 'restarted'));
  assert.deepEqual(await readJson(path.join(cwd, 'fixture', 'manifest.json')), expected);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('path materialization rebuild stays within the request physical ledger', async (t) => {
  const cwd = await temporaryDirectory(t);
  const base = createRequest({
    destination: 'fixture',
    extensions: {
      'generation.checkpoint-every': 2,
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'full',
    },
    profile: { id: 'code-heavy', version: '2.0.0' },
    scale: { historyOperationCount: 5, largeFileBytes: 0, maxDepth: 6, pathCount: 7 },
    seed: 'recovery-physical-ledger',
  });
  const request = createRequest({
    ...base,
    resourceLimits: {
      maximumDurationSeconds: planFixture(base).estimates.durationSeconds,
      maximumPhysicalBytes: Number(planFixture(base).estimates.physicalBytes),
    },
  });
  await writeFile(path.join(cwd, 'request.json'), JSON.stringify(request));
  const interrupted = await runCli(cwd, ['generate', '--request', 'request.json'], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);

  const resumed = await runCli(cwd, ['generate', '--request', 'request.json', '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('every durable checkpoint sequence resumes to the uninterrupted manifest', async (t) => {
  const arguments_ = smallCliArguments('large-binary', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 4096,
    pathCount: 5,
  });
  const expected = await baselineManifest(t, arguments_);

  // Sequences 1-3 are path checkpoints, 4 is the large-file handoff,
  // 5-6 are operation checkpoints, and 7 is the finalize checkpoint.
  for (let checkpoint = 1; checkpoint <= 7; checkpoint += 1) {
    const cwd = await temporaryDirectory(t, `ogvcs-checkpoint-${checkpoint}-`);
    const interrupted = await runCli(cwd, ['generate', ...arguments_], {
      env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: String(checkpoint) },
    });
    assert.equal(interrupted.code, 99, `checkpoint ${checkpoint}: ${interrupted.stderr}`);
    const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
    assert.equal(resumed.code, 0, `checkpoint ${checkpoint}: ${resumed.stderr}`);
    assert.deepEqual(await readJson(path.join(cwd, 'fixture', 'manifest.json')), expected, `checkpoint ${checkpoint}`);
  }
});

test('zero-operation finalize recovery regenerates a missing empty operation stream', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-zero-operation-recovery-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 1,
    historyOperationCount: 0,
    largeFileBytes: 0,
    pathCount: 1,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '3' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  assert.equal(
    (await readJson(path.join(stage, 'checkpoint.json'))).extensions['generation.phase'],
    'finalize',
  );
  await unlink(path.join(stage, 'operations.ndjson'));

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.ok(progressEvents(resumed).some(({ type }) => type === 'restarted'));
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('finalize recovery restarts damaged request, profile, and materialized modes', async (t) => {
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const cases = [
    {
      name: 'stored-request',
      mutate: async (stage) => {
        const requestPath = path.join(stage, 'fixture-request.json');
        const request = await readJson(requestPath);
        request.seed = `${request.seed}-mutated`;
        await writeFile(requestPath, JSON.stringify(request));
      },
    },
    {
      name: 'stored-profile',
      mutate: async (stage) => unlink(path.join(stage, 'workload-profile.json')),
    },
    ...(process.platform === 'win32' ? [] : [{
      name: 'executable-mode',
      mutate: async (stage) => {
        const records = (await readFile(path.join(stage, 'inventory.ndjson'), 'utf8'))
          .trim()
          .split('\n')
          .map((line) => JSON.parse(line));
        const executable = records.find(({ mode }) => mode === '100755');
        assert.ok(executable, 'fixture must contain an executable record');
        await chmod(path.join(stage, 'files', ...executable.logicalPath.split('/')), 0o644);
      },
    }]),
  ];

  for (const scenario of cases) {
    const cwd = await temporaryDirectory(t, `ogvcs-finalize-control-${scenario.name}-`);
    const interrupted = await runCli(cwd, ['generate', ...arguments_], {
      env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '7' },
    });
    assert.equal(interrupted.code, 99, `${scenario.name}: ${interrupted.stderr}`);
    const stage = await onlyStage(cwd);
    assert.equal(
      (await readJson(path.join(stage, 'checkpoint.json'))).extensions['generation.phase'],
      'finalize',
    );
    await scenario.mutate(stage);

    const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
    assert.equal(resumed.code, 0, `${scenario.name}: ${resumed.stderr}`);
    assert.ok(progressEvents(resumed).some(({ type }) => type === 'restarted'), scenario.name);
    assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
  }
});

test('torn checkpoints and corrupted inventory, operation, and large-file artifacts restart safely', async (t) => {
  const arguments_ = smallCliArguments('large-binary', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 4096,
    pathCount: 5,
  });
  const expected = await baselineManifest(t, arguments_);
  const cases = [
    {
      name: 'torn-checkpoint',
      checkpoint: 1,
      mutate: async (stage) => writeFile(path.join(stage, 'checkpoint.json'), '{"schemaVersion"'),
    },
    {
      name: 'checkpoint-digest',
      checkpoint: 1,
      mutate: async (stage) => {
        const checkpoint = await readJson(path.join(stage, 'checkpoint.json'));
        checkpoint.nextItemIndex += 1;
        await writeFile(path.join(stage, 'checkpoint.json'), JSON.stringify(checkpoint));
      },
    },
    {
      name: 'checkpoint-schema',
      checkpoint: 1,
      mutate: async (stage) => {
        const checkpointPath = path.join(stage, 'checkpoint.json');
        const checkpoint = await readJson(checkpointPath);
        checkpoint.state = 'not-a-checkpoint-state';
        const { checkpointDigest: ignored, ...body } = checkpoint;
        void ignored;
        checkpoint.checkpointDigest = canonicalDigest(body, 'ogvcs.fixture/checkpoint/v1');
        await writeFile(checkpointPath, JSON.stringify(checkpoint));
      },
    },
    {
      name: 'torn-inventory',
      checkpoint: 2,
      mutate: async (stage) => {
        const inventoryPath = path.join(stage, 'inventory.ndjson');
        const bytes = await readFile(inventoryPath);
        await writeFile(inventoryPath, bytes.subarray(0, bytes.length - 7));
      },
    },
    {
      name: 'operation-record',
      checkpoint: 5,
      mutate: async (stage) => {
        const operationsPath = path.join(stage, 'operations.ndjson');
        const lines = (await readFile(operationsPath, 'utf8')).trim().split('\n');
        const operation = JSON.parse(lines[0]);
        operation.sequence += 1;
        lines[0] = JSON.stringify(operation);
        await writeFile(operationsPath, `${lines.join('\n')}\n`);
      },
    },
    {
      name: 'large-file-descriptor',
      checkpoint: 5,
      mutate: async (stage) => {
        const descriptorPath = path.join(stage, 'large-file.json');
        const descriptor = await readJson(descriptorPath);
        descriptor.logicalBytes += 1;
        await writeFile(descriptorPath, JSON.stringify(descriptor));
      },
    },
  ];

  for (const scenario of cases) {
    const cwd = await temporaryDirectory(t, `ogvcs-corrupt-${scenario.name}-`);
    const interrupted = await runCli(cwd, ['generate', ...arguments_], {
      env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: String(scenario.checkpoint) },
    });
    assert.equal(interrupted.code, 99, scenario.name);
    await scenario.mutate(await onlyStage(cwd));
    const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume', '--progress']);
    assert.equal(resumed.code, 0, `${scenario.name}: ${resumed.stderr}`);
    assert.ok(progressEvents(resumed).some(({ type }) => type === 'restarted'), scenario.name);
    assert.deepEqual(await readJson(path.join(cwd, 'fixture', 'manifest.json')), expected, scenario.name);
  }
});

test('unknown stage artifacts are rejected and never removed by recovery', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const unrelated = path.join(stage, 'unrelated-user-data.txt');
  await writeFile(unrelated, 'preserve-me');

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 4, resumed.stderr);
  assert.equal(jsonError(resumed).error.type, 'unsafe-destination');
  assert.equal(await readFile(unrelated, 'utf8'), 'preserve-me');
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });
});

test('oversized pre-ownership owner, lock, and guard documents fail within 64 KiB', async (t) => {
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  for (const control of ['owner', 'lock', 'guard']) {
    const cwd = await temporaryDirectory(t, `ogvcs-oversized-${control}-`);
    const interrupted = await runCli(cwd, ['generate', ...arguments_], {
      env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
    });
    assert.equal(interrupted.code, 99, interrupted.stderr);
    const lockPath = await onlyLock(cwd);
    const target = control === 'owner'
      ? path.join(await onlyStage(cwd), OWNER_FILENAME)
      : control === 'guard'
        ? `${lockPath}.guard`
        : lockPath;
    if (control === 'guard') await writeFile(target, '');
    await truncate(target, 64 * 1024 + 1);

    const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
    assert.equal(resumed.code, control === 'owner' ? 4 : 5, resumed.stderr);
    assert.match(jsonError(resumed).error.message, /ownership marker|lock guard|generator lock/iu);
    assert.match(JSON.stringify(jsonError(resumed)), /65536-byte safe bound/iu);
    assert.ok((await readdir(cwd)).some((name) => name.endsWith('.stage')));
  }
});

test('completed resume performs deterministic deep verification before reuse', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const generated = await runCli(cwd, ['generate', ...arguments_]);
  assert.equal(generated.code, 0, generated.stderr);
  const firstRecord = JSON.parse((await readFile(path.join(cwd, 'fixture', 'inventory.ndjson'), 'utf8')).split('\n')[0]);
  await writeFile(path.join(cwd, 'fixture', 'files', ...firstRecord.logicalPath.split('/')), 'corrupt');

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 6, resumed.stderr);
  assert.equal(jsonError(resumed).error.type, 'integrity-failure');
});

test('stage path replacement by a symlink cannot redirect an active generator', async (t) => {
  if (process.platform === 'win32') {
    t.skip('requires unprivileged POSIX symlink creation');
    return;
  }
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 7,
  });
  const generation = runCli(cwd, ['generate', ...arguments_], {
    env: {
      OGVCS_FIXTURE_TEST_PAUSE_AT_CHECKPOINT: '1',
      OGVCS_FIXTURE_TEST_PAUSE_MILLISECONDS: '600',
    },
  });
  await waitFor(async () => {
    const entries = await readdir(cwd);
    const stageName = entries.find((name) => name.endsWith('.stage'));
    if (!stageName) return false;
    return readFile(path.join(cwd, stageName, 'checkpoint.json')).then(() => true, () => false);
  }, 'generator did not reach its paused checkpoint');
  const stage = await onlyStage(cwd);
  const moved = `${stage}.moved`;
  await rename(stage, moved);
  await symlink(moved, stage, 'dir');

  const result = await generation;
  assert.equal(result.code, 4, result.stderr);
  assert.equal(jsonError(result).error.type, 'unsafe-destination');
  assert.equal((await readJson(path.join(moved, '.ogvcs-fixture-owner.json'))).tool, 'ogvcs-fixture');
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });
});

test('prepublication deep-verification failure preserves only the owned stage', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const generation = runCli(cwd, ['generate', ...arguments_], {
    env: {
      OGVCS_FIXTURE_TEST_PAUSE_AT_CHECKPOINT: '7',
      OGVCS_FIXTURE_TEST_PAUSE_MILLISECONDS: '600',
    },
  });
  let stage;
  await waitFor(async () => {
    const stageName = (await readdir(cwd)).find((name) => name.endsWith('.stage'));
    if (!stageName) return false;
    stage = path.join(cwd, stageName);
    const checkpoint = await readJson(path.join(stage, 'checkpoint.json')).catch(() => null);
    return checkpoint?.checkpointSequence === 7;
  }, 'generator did not reach its finalize checkpoint');

  const inventoryPath = path.join(stage, 'inventory.ndjson');
  const lines = (await readFile(inventoryPath, 'utf8')).trim().split('\n');
  const record = JSON.parse(lines[0]);
  record.role = 'adversarial-replacement';
  lines[0] = JSON.stringify(record);
  await writeFile(inventoryPath, `${lines.join('\n')}\n`);

  const result = await generation;
  assert.equal(result.code, 6, result.stderr);
  assert.equal(jsonError(result).error.type, 'integrity-failure');
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });
  assert.equal((await readJson(path.join(stage, '.ogvcs-fixture-owner.json'))).tool, 'ogvcs-fixture');
  assert.equal((await readJson(path.join(stage, 'manifest.json'))).schemaVersion, 'ogvcs.fixture/manifest/v1');
  assert.ok(!(await readdir(cwd)).some((name) => name.endsWith('.ogvcs-fixture.lock')));
});

test('prefinalize allowlist rejects even reserved artifacts appearing in the wrong phase', async (t) => {
  const cwd = await temporaryDirectory(t);
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const generation = runCli(cwd, ['generate', ...arguments_], {
    env: {
      OGVCS_FIXTURE_TEST_PAUSE_AT_CHECKPOINT: '7',
      OGVCS_FIXTURE_TEST_PAUSE_MILLISECONDS: '600',
    },
  });
  let stage;
  await waitFor(async () => {
    const stageName = (await readdir(cwd)).find((name) => name.endsWith('.stage'));
    if (!stageName) return false;
    stage = path.join(cwd, stageName);
    const checkpoint = await readJson(path.join(stage, 'checkpoint.json')).catch(() => null);
    return checkpoint?.checkpointSequence === 7;
  }, 'generator did not reach its finalize checkpoint');
  const premature = path.join(stage, 'groups.json');
  await writeFile(premature, 'reserved-name-but-not-tool-owned-at-this-phase');

  const result = await generation;
  assert.equal(result.code, 4, result.stderr);
  assert.equal(jsonError(result).error.type, 'unsafe-destination');
  assert.equal(await readFile(premature, 'utf8'), 'reserved-name-but-not-tool-owned-at-this-phase');
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });
});

test('destination reservation is an atomic no-replace operation', async (t) => {
  const cwd = await realpath(await temporaryDirectory(t, 'ogvcs-publication-race-'));
  const destination = path.join(cwd, 'fixture');
  const requestDigest = canonicalDigest({ test: 'destination-reservation' });
  const workspace = await prepareWorkspace(destination, requestDigest);
  t.after(workspace.releaseLock);
  await writeFile(path.join(workspace.stage, 'manifest.json'), '{"complete":true}\n');

  await assert.rejects(
    publishWorkspace(workspace.stage, destination, requestDigest, {
      ...workspace,
      beforeDestinationReservation: async () => {
        await mkdir(destination);
        await writeFile(path.join(destination, 'competing-owner.txt'), 'preserve-me');
      },
      expectedArtifacts: [OWNER_FILENAME, 'manifest.json'],
    }),
    (error) => error?.type === 'unsafe-destination' && /appeared/i.test(error.message),
  );

  assert.equal(await readFile(path.join(destination, 'competing-owner.txt'), 'utf8'), 'preserve-me');
  assert.equal(await readFile(path.join(workspace.stage, 'manifest.json'), 'utf8'), '{"complete":true}\n');
});

test('destination lock precedes every incomplete-publication recovery mutation', async (t) => {
  const cwd = await realpath(await temporaryDirectory(t, 'ogvcs-recovery-lock-order-'));
  const destination = path.join(cwd, 'fixture');
  const requestDigest = canonicalDigest({ test: 'recovery-lock-order' });
  const publisher = await prepareWorkspace(destination, requestDigest);
  t.after(publisher.releaseLock);
  await mkdir(destination);
  await link(
    path.join(publisher.stage, OWNER_FILENAME),
    path.join(destination, OWNER_FILENAME),
  );

  await assert.rejects(
    prepareWorkspace(destination, requestDigest, { resume: true }),
    (error) => error?.type === 'conflict' && /already owns/i.test(error.message),
  );

  assert.equal(
    (await readJson(path.join(destination, OWNER_FILENAME))).requestDigest,
    requestDigest,
  );
  assert.equal(
    (await readJson(path.join(publisher.stage, OWNER_FILENAME))).requestDigest,
    requestDigest,
  );
});

test('resume recovers only a positively linked, manifest-free publication reservation', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-incomplete-publication-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const expected = await baselineManifest(t, arguments_);
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const destination = path.join(cwd, 'fixture');
  await mkdir(destination);
  await link(path.join(stage, OWNER_FILENAME), path.join(destination, OWNER_FILENAME));

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.deepEqual(await readJson(path.join(destination, 'manifest.json')), expected);
});

test('resume preserves and rejects an incomplete publication containing unrelated data', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-incomplete-publication-unknown-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const interrupted = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT: '1' },
  });
  assert.equal(interrupted.code, 99, interrupted.stderr);
  const stage = await onlyStage(cwd);
  const destination = path.join(cwd, 'fixture');
  await mkdir(destination);
  await link(path.join(stage, OWNER_FILENAME), path.join(destination, OWNER_FILENAME));
  await writeFile(path.join(destination, 'unrelated.txt'), 'preserve-me');

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 4, resumed.stderr);
  assert.equal(jsonError(resumed).error.type, 'unsafe-destination');
  assert.equal(await readFile(path.join(destination, 'unrelated.txt'), 'utf8'), 'preserve-me');
  await assert.rejects(readFile(path.join(destination, 'manifest.json')), { code: 'ENOENT' });
});

test('ENOSPC-like failures at persistence boundaries never expose a partial completed fixture', async (t) => {
  const boundaries = [
    'atomic-open:.ogvcs-fixture-owner.json',
    'atomic-write:.ogvcs-fixture-owner.json',
    'atomic-sync:.ogvcs-fixture-owner.json',
    'atomic-rename:.ogvcs-fixture-owner.json',
    'atomic-parent-sync:.ogvcs-fixture-owner.json',
    'atomic-open:fixture-request.json',
    'atomic-write:fixture-request.json',
    'atomic-sync:checkpoint.json',
    'atomic-rename:groups.json',
    'atomic-parent-sync:manifest.json',
    'stream-open:inventory.ndjson',
    'stream-write:inventory.ndjson',
    'stream-sync:operations.ndjson',
    'stream-close:scenario.json',
    'stream-parent-sync:scenario.json',
    'checkpoint-removal-sync',
    'stage-sync',
    'stage-create-parent-sync',
    'publish-mkdir:fixture',
    'publish-owner-link:.ogvcs-fixture-owner.json',
    'publish-tree-link',
    'publish-tree-sync',
    'publish-artifact-link:fixture-request.json',
    'publish-precommit-sync:fixture',
    'publish-parent-sync',
    'publish-manifest-link:manifest.json',
    'publish-commit-sync:fixture',
    'lock-guard-open',
    'lock-guard-write',
    'lock-guard-sync',
    'lock-guard-parent-sync',
    'lock-open',
    'lock-write',
    'lock-sync',
    'lock-parent-sync',
  ];
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });

  for (const boundary of boundaries) {
    const cwd = await temporaryDirectory(t, 'ogvcs-persistence-fault-');
    const result = await runCli(cwd, ['generate', ...arguments_], {
      env: { OGVCS_FIXTURE_TEST_FAIL_AT_PERSISTENCE: boundary },
    });
    assert.equal(result.code, 7, `${boundary}: ${result.stderr}`);
    assert.equal(jsonError(result).error.type, 'resource-limit', boundary);
    const destinationManifest = path.join(cwd, 'fixture', 'manifest.json');
    await assert.rejects(readFile(destinationManifest), { code: 'ENOENT' }, boundary);
    const entries = await readdir(cwd, { recursive: true });
    assert.ok(!entries.some((name) => /\.tmp-[0-9]+-[0-9]+$/.test(name)), `${boundary}: leaked atomic temp`);
    assert.ok(!entries.some((name) => name.endsWith('.ogvcs-fixture.lock')), `${boundary}: leaked lock`);
    assert.ok(!entries.some((name) => name.endsWith('.ogvcs-fixture.lock.guard')), `${boundary}: leaked guard`);
  }
});

test('commit-sync failure rolls back the manifest and resumes to the uninterrupted result', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-commit-sync-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const expected = await baselineManifest(t, arguments_);
  const failed = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_FAIL_AT_PERSISTENCE: 'publish-commit-sync:fixture' },
  });
  assert.equal(failed.code, 7, failed.stderr);
  await assert.rejects(readFile(path.join(cwd, 'fixture', 'manifest.json')), { code: 'ENOENT' });
  const stage = await onlyStage(cwd);
  assert.equal((await readJson(path.join(stage, 'manifest.json'))).schemaVersion, 'ogvcs.fixture/manifest/v1');

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.deepEqual(await readJson(path.join(cwd, 'fixture', 'manifest.json')), expected);
});

test('post-commit stage cleanup failure cannot turn a published fixture into an error', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-post-commit-cleanup-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const generated = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_FAIL_AT_PERSISTENCE: 'publish-stage-cleanup-sync' },
  });
  assert.equal(generated.code, 0, generated.stderr);
  assert.deepEqual(jsonOutput(generated).result.postCommitWarnings, [
    { code: 'ENOSPC', phase: 'stage-cleanup' },
  ]);
  const verified = await runCli(cwd, ['verify', 'fixture', '--deep']);
  assert.equal(verified.code, 0, verified.stderr);
});

test('compatible resume safely reconciles an owned stage left by post-commit cleanup failure', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-post-commit-reconcile-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const generated = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_FAIL_AT_PERSISTENCE: 'publish-stage-cleanup-remove' },
  });
  assert.equal(generated.code, 0, generated.stderr);
  assert.deepEqual(jsonOutput(generated).result.postCommitWarnings, [
    { code: 'ENOSPC', phase: 'stage-cleanup' },
  ]);
  const stage = await onlyStage(cwd);

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal(jsonOutput(resumed).result.resumed, true);
  assert.equal(jsonOutput(resumed).result.postCommitWarnings, undefined);
  await assert.rejects(lstat(stage), { code: 'ENOENT' });
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);
});

test('a published progress callback failure is returned as a warning after durable success', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-post-commit-progress-');
  const request = createRequest({
    destination: 'fixture',
    extensions: {
      'generation.checkpoint-every': 2,
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'index-only',
    },
    profile: { id: 'code-heavy', version: '2.0.0' },
    scale: { historyOperationCount: 3, largeFileBytes: 0, maxDepth: 4, pathCount: 5 },
    seed: 'post-commit-progress-v1',
  });
  const generated = await generateFixture(request, {
    cwd,
    onProgress(event) {
      if (event.phase === 'published') throw new Error('consumer progress sink failed');
    },
  });

  assert.deepEqual(generated.postCommitWarnings, [
    { code: 'POST_COMMIT_ERROR', phase: 'progress-callback' },
  ]);
  assert.equal((await verifyFixture('fixture', { cwd, deep: true })).verified, true);
});

test('a lock-release failure cannot reject a durable fixture and stale cleanup remains resumable', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-post-commit-lock-');
  const arguments_ = smallCliArguments('code-heavy', 'fixture', {
    checkpointEvery: 2,
    historyOperationCount: 3,
    largeFileBytes: 0,
    pathCount: 5,
  });
  const generated = await runCli(cwd, ['generate', ...arguments_], {
    env: { OGVCS_FIXTURE_TEST_FAIL_AT_PERSISTENCE: 'lock-release' },
  });
  assert.equal(generated.code, 0, generated.stderr);
  assert.deepEqual(jsonOutput(generated).result.postCommitWarnings, [
    { code: 'ENOSPC', phase: 'lock-release' },
  ]);
  assert.equal((await runCli(cwd, ['verify', 'fixture', '--deep'])).code, 0);

  const resumed = await runCli(cwd, ['generate', ...arguments_, '--resume']);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal(jsonOutput(resumed).result.resumed, true);
});

test('unsafe destination, traversal, symlink, malformed input, overflow, and depth have typed failures', async (t) => {
  const cwd = await temporaryDirectory(t);
  const existing = path.join(cwd, 'existing');
  await mkdir(existing);
  await writeFile(path.join(existing, 'unrelated.txt'), 'must-survive');
  const unsafe = await runCli(cwd, [
    'generate',
    ...smallCliArguments('code-heavy', 'existing', { largeFileBytes: 0 }),
  ]);
  assert.equal(unsafe.code, 4);
  assert.equal(jsonError(unsafe).error.type, 'unsafe-destination');
  assert.equal(await readFile(path.join(existing, 'unrelated.txt'), 'utf8'), 'must-survive');

  const traversal = await runCli(cwd, [
    'generate',
    ...smallCliArguments('code-heavy', '../escape', { largeFileBytes: 0 }),
  ]);
  assert.equal(traversal.code, 3);
  assert.equal(jsonError(traversal).error.type, 'invalid-request');

  const target = path.join(cwd, 'symlink-target');
  await mkdir(target);
  const link = path.join(cwd, 'link');
  let symlinkCreated = true;
  try {
    await symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) {
    if (process.platform !== 'win32' || !['EPERM', 'EACCES'].includes(error.code)) throw error;
    symlinkCreated = false;
  }
  if (symlinkCreated) {
    const linked = await runCli(cwd, [
      'generate',
      ...smallCliArguments('code-heavy', 'link/fixture', { largeFileBytes: 0 }),
    ]);
    assert.equal(linked.code, 4);
    assert.equal(jsonError(linked).error.type, 'unsafe-destination');
    assert.deepEqual(await readdir(target), []);
  }

  await writeFile(path.join(cwd, 'malformed.json'), '{');
  const malformed = await runCli(cwd, ['generate', '--request', 'malformed.json']);
  assert.equal(malformed.code, 2);
  assert.equal(jsonError(malformed).error.type, 'usage');

  await writeFile(path.join(cwd, 'oversized-request.json'), ' '.repeat(2 * 1024 * 1024 + 1));
  const oversizedRequest = await runCli(cwd, ['plan', '--request', 'oversized-request.json']);
  assert.equal(oversizedRequest.code, 2);
  assert.equal(jsonError(oversizedRequest).error.type, 'usage');
  assert.match(jsonError(oversizedRequest).error.message, /exceeds 2097152 bytes/iu);

  const invalidRequest = { ...createRequest({ destination: 'invalid' }), scale: {
    ...createRequest({ destination: 'invalid' }).scale,
    pathCount: 0,
  } };
  await writeFile(path.join(cwd, 'invalid.json'), JSON.stringify(invalidRequest));
  const invalid = await runCli(cwd, ['generate', '--request', 'invalid.json']);
  assert.equal(invalid.code, 3);
  assert.equal(jsonError(invalid).error.type, 'invalid-request');

  const overflow = await runCli(cwd, ['plan', '--path-count', '9007199254740992']);
  assert.equal(overflow.code, 2);
  assert.equal(jsonError(overflow).error.type, 'usage');

  const depth = await runCli(cwd, ['plan', '--max-depth', '65']);
  assert.equal(depth.code, 3);
  assert.equal(jsonError(depth).error.type, 'invalid-request');
  const rootlessDepth = await runCli(cwd, ['plan', '--max-depth', '1']);
  assert.equal(rootlessDepth.code, 3);
  assert.equal(jsonError(rootlessDepth).error.type, 'invalid-request');

  const constrained = createRequest({
    destination: 'resource-limited',
    extensions: {
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'index-only',
    },
    resourceLimits: { maximumPhysicalBytes: 0 },
    scale: { historyOperationCount: 1, largeFileBytes: 0, maxDepth: 2, pathCount: 1 },
  });
  await writeFile(path.join(cwd, 'constrained.json'), JSON.stringify(constrained));
  const resource = await runCli(cwd, ['generate', '--request', 'constrained.json']);
  assert.equal(resource.code, 7);
  assert.equal(jsonError(resource).error.type, 'resource-limit');
  await assert.rejects(readFile(path.join(cwd, 'resource-limited', 'manifest.json')), { code: 'ENOENT' });
});
