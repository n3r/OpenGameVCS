import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, open, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { hostPlatform, probeFilesystemCapabilities } from './capabilities.mjs';
import { loadContractJson, pathContract } from './contract.mjs';
import { PathFilesystemError } from './errors.mjs';
import { caseFold, evaluateCollisions, evaluatePath } from './path.mjs';
import { evaluatePreflight, preflightWorkspaceMaterialization } from './preflight.mjs';
import { evaluateRenames, planRenames } from './rename.mjs';
import { applyWatcherEvent, evaluateWatcherCase, initialWatcherState, loadWatcherState, openWorkspaceWatcher } from './watcher.mjs';
import {
  applyReadOnlyHint, atomicWriteFile as rawAtomicWriteFile, atomicWriteStream as rawAtomicWriteStream,
  executeRenamePlan as rawExecuteRenamePlan,
  inspectCrashRemnants, materializeSymlink as rawMaterializeSymlink, openWorkspaceRoot,
  replaceWorkspaceEntry as rawReplaceWorkspaceEntry, rollbackCrashRemnant,
} from './workspace.mjs';

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const resultHash = (value) => sha256(Buffer.from(canonicalJson(value), 'utf8'));

function row(id, category, expected, actual) {
  return Object.freeze({ id, category, passed: canonicalJson(expected) === canonicalJson(actual), expectedSha256: resultHash(expected), actualSha256: resultHash(actual) });
}

function plannedEntries(targets) {
  const entries = new Map(); let nextId = 0;
  const add = (path, value) => {
    if (!entries.has(path)) { entries.set(path, { id: `entry-${nextId}`, path, ...value }); nextId += 1; }
    else if (value.kind !== 'directory') entries.set(path, { id: entries.get(path).id, path, ...value });
  };
  for (const target of targets) {
    const segments = target.path.split('/');
    for (let index = 1; index < segments.length; index += 1) add(segments.slice(0, index).join('/'), { kind: 'directory', mode: 'directory' });
    add(target.path, {
      kind: target.kind,
      mode: { directory: 'directory', regular: 'regular-file', executable: 'executable-file', symlink: 'symlink' }[target.kind],
      ...(target.symlinkTarget === undefined ? {} : { symlinkTarget: target.symlinkTarget }),
    });
  }
  return [...entries.values()].sort((left, right) => left.path.split('/').length - right.path.split('/').length || Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
}

async function workspacePlan(workspace, targets, capabilities) {
  return preflightWorkspaceMaterialization(workspace, {
    schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: workspace.caseMode,
    profile: workspace.profile, platform: capabilities.platform,
    capabilities: { atomicReplace: capabilities.atomicReplace, executableBit: capabilities.executableBit, symlink: capabilities.symlink },
    entries: plannedEntries(targets),
  });
}

async function atomicWriteFile(workspace, path, content, capabilities, options = {}) {
  const plan = options.plan ?? await workspacePlan(workspace, [{ path, kind: options.executable === true ? 'executable' : 'regular' }], capabilities);
  return rawAtomicWriteFile(workspace, path, content, { ...options, plan });
}

async function replaceWorkspaceEntry(workspace, path, replacement, capabilities, options = {}) {
  const kind = replacement.kind === 'regular' && replacement.executable === true ? 'executable' : replacement.kind;
  const plan = options.plan ?? await workspacePlan(workspace, [{ path, kind }], capabilities);
  return rawReplaceWorkspaceEntry(workspace, path, replacement, { ...options, plan });
}

async function materializeSymlink(workspace, path, target, capabilities, options = {}) {
  const plan = options.plan ?? await workspacePlan(workspace, [{ path, kind: 'symlink', symlinkTarget: target }], capabilities);
  return rawMaterializeSymlink(workspace, path, target, { ...options, plan });
}

async function executeRenamePlan(workspace, renamePlan, capabilities, options = {}) {
  const targets = renamePlan.steps.filter(({ phase }) => phase === 'publish').map(({ to }) => ({ path: to, kind: 'regular' }));
  const materializationPlan = options.materializationPlan ?? await workspacePlan(workspace, targets, capabilities);
  return rawExecuteRenamePlan(workspace, renamePlan, { ...options, materializationPlan });
}

async function pureRows() {
  const rows = [];
  for (const testCase of loadContractJson('vectors/path-cases.json').cases) rows.push(row(`path:${testCase.id}`, 'path', testCase.expected, evaluatePath(testCase.input, { caseMode: testCase.caseMode, profile: testCase.profile })));
  for (const testCase of loadContractJson('vectors/fold-cases.json').cases) rows.push(row(`fold:${testCase.id}`, 'fold', testCase.expected, caseFold(testCase.input)));
  for (const testCase of loadContractJson('vectors/collision-cases.json').cases) rows.push(row(`collision:${testCase.id}`, 'collision', testCase.expected, evaluateCollisions(testCase.paths.map((path, index) => ({ id: String(index), path })), { caseMode: testCase.caseMode, profile: testCase.profile })));
  for (const testCase of loadContractJson('vectors/preflight-cases.json').cases) {
    const { id, expected, ...request } = testCase;
    rows.push(row(`preflight:${id}`, 'preflight', expected, evaluatePreflight(request)));
  }
  for (const testCase of loadContractJson('vectors/rename-cases.json').cases) rows.push(row(`rename:${testCase.id}`, 'rename', testCase.expected, evaluateRenames(testCase)));
  for (const testCase of loadContractJson('vectors/watcher-cases.json').cases) rows.push(row(`watcher:${testCase.id}`, 'watcher', testCase.expected, evaluateWatcherCase(testCase)));
  return rows;
}

async function nativeCheck(id, action) {
  try { await action(); return row(`native:${id}`, 'native-filesystem', 'passed', 'passed'); }
  catch { return row(`native:${id}`, 'native-filesystem', 'passed', 'failed'); }
}

async function nativeValue(id, expected, action) {
  try { return row(`native:${id}`, 'native-filesystem', expected, await action()); }
  catch { return row(`native:${id}`, 'native-filesystem', expected, 'failed'); }
}

async function materializeFixture(workspace, capabilities, files) {
  const targets = files.map(({ path, executable = false }) => ({ path, kind: executable ? 'executable' : 'regular' }));
  const plan = await workspacePlan(workspace, targets, capabilities);
  for (const file of files) {
    await rawAtomicWriteFile(workspace, file.path, Buffer.from(file.content, 'utf8'), {
      createParents: true, executable: file.executable === true, plan,
    });
  }
  const inventory = [];
  for (const file of [...files].sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))) {
    const absolute = join(workspace.root, ...file.path.split('/'));
    const info = await lstat(absolute);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error('fixture entry is not a regular file');
    const bytes = await readFile(absolute);
    inventory.push({ path: file.path, bytes: bytes.length, sha256: sha256(bytes), executable: file.executable === true });
  }
  return Object.freeze({ entries: inventory.length, inventorySha256: resultHash(inventory) });
}

async function nativeRows(root, capabilities) {
  const rows = [];
  const workspace = await openWorkspaceRoot(root, { profile: 'path.opengamevcs/portable@1' });
  rows.push(await nativeCheck('atomic-replace', async () => {
    if (!capabilities.atomicReplace) throw new Error('atomic replacement unavailable');
    await atomicWriteFile(workspace, 'Game/data.bin', Buffer.from('first'), capabilities, { createParents: true });
    await atomicWriteFile(workspace, 'Game/data.bin', Buffer.from('second'), capabilities);
    assert.equal(await readFile(join(root, 'Game/data.bin'), 'utf8'), 'second');
  }));
  rows.push(await nativeCheck('bounded-staged-stream-publication', async () => {
    if (!capabilities.atomicReplace || !capabilities.hardlink) throw new Error('stream replacement capabilities unavailable');
    const path = 'Game/stream-publication.bin';
    await atomicWriteFile(workspace, path, Buffer.from('prior'), capabilities, { createParents: true });
    const publication = Buffer.from('bounded staged stream publication');
    const plan = await workspacePlan(workspace, [{ path, kind: 'regular' }], capabilities);
    async function *chunks() {
      yield publication.subarray(0, 8);
      yield publication.subarray(8, 22);
      yield publication.subarray(22);
    }
    const published = await rawAtomicWriteStream(workspace, path, chunks(), {
      plan, maxBytes: publication.length, maxScratchBytes: publication.length, maxChunkBytes: 16,
      expectedBytes: publication.length, expectedSha256: sha256(publication),
    });
    assert.equal(published.bytes, publication.length);
    assert.equal(published.sha256, sha256(publication));
    assert.deepEqual(await readFile(join(root, 'Game/stream-publication.bin')), publication);

    const prior = await lstat(join(root, 'Game/stream-publication.bin'));
    const refused = Buffer.from('must roll back');
    let code;
    try {
      await rawAtomicWriteStream(workspace, path, (async function *source() { yield refused; }()), {
        plan, maxBytes: refused.length, maxScratchBytes: refused.length,
        expectedBytes: refused.length, expectedSha256: sha256(refused),
        hooks: { boundary: (name) => {
          if (name === 'before-parent-sync') { const error = new Error('simulated directory sync fault'); error.code = 'EIO'; throw error; }
        } },
      });
    } catch (error) { code = error?.code; }
    assert.equal(code, 'ATOMIC_REPLACE_FAILED');
    assert.equal((await lstat(join(root, 'Game/stream-publication.bin'))).ino, prior.ino);
    assert.deepEqual(await readFile(join(root, 'Game/stream-publication.bin')), publication);
    assert.equal((await inspectCrashRemnants(workspace)).length, 0);
  }));
  rows.push(await nativeCheck('target-race-denied', async () => {
    let code;
    try {
      await atomicWriteFile(workspace, 'Game/data.bin', Buffer.from('trusted'), capabilities, {
        hooks: { boundary: async (name) => { if (name === 'before-publish') await writeFile(join(root, 'Game/data.bin'), 'racer'); } },
      });
    } catch (error) { code = error?.code; }
    assert.equal(code, 'TARGET_CHANGED');
    assert.equal(await readFile(join(root, 'Game/data.bin'), 'utf8'), 'racer');
    for (const remnant of await inspectCrashRemnants(workspace)) await rollbackCrashRemnant(workspace, remnant.id);
  }));
  rows.push(await nativeCheck('symlink-ancestor-denied', async () => {
    const outside = await mkdtemp(join(tmpdir(), 'ogvcs-path-outside-'));
    try {
      let linked = false;
      try { await symlink(outside, join(root, 'escape'), process.platform === 'win32' ? 'junction' : 'dir'); linked = true; } catch {}
      if (!linked) {
        if (process.platform === 'win32') throw new Error('Windows junction fixture unavailable');
        return;
      }
      let code;
      try { await atomicWriteFile(workspace, 'escape/pwned', Buffer.from('no'), capabilities, { createParents: true }); } catch (error) { code = error?.code; }
      assert.equal(code, 'UNSAFE_TARGET');
      await assert.rejects(readFile(join(outside, 'pwned')));
    } finally { await rm(outside, { recursive: true, force: true }); }
  }));
  rows.push(await nativeCheck('crash-remnant-recovery', async () => {
    let failed = false;
    try { await atomicWriteFile(workspace, 'Game/crash.bin', Buffer.from('staged'), capabilities, { hooks: { boundary: (name) => { if (name === 'after-record') throw new Error('simulated power loss'); } } }); }
    catch { failed = true; }
    assert.equal(failed, true);
    const remnants = await inspectCrashRemnants(workspace);
    assert.equal(remnants.length, 1);
    await rollbackCrashRemnant(workspace, remnants[0].id);
    assert.equal((await inspectCrashRemnants(workspace)).length, 0);
  }));
  rows.push(await nativeCheck('read-only-is-hint', async () => {
    await atomicWriteFile(workspace, 'Game/locked.asset', Buffer.from('lock'), capabilities);
    const result = await applyReadOnlyHint(workspace, 'Game/locked.asset', true);
    assert.equal(result.authoritative, false);
    await applyReadOnlyHint(workspace, 'Game/locked.asset', false);
  }));
  rows.push(await nativeCheck('directory-file-replacement', async () => {
    await atomicWriteFile(workspace, 'Game/kind/child', Buffer.from('old'), capabilities, { createParents: true });
    await replaceWorkspaceEntry(workspace, 'Game/kind', { kind: 'regular', content: Buffer.from('file') }, capabilities);
    assert.equal(await readFile(join(root, 'Game/kind'), 'utf8'), 'file');
    await replaceWorkspaceEntry(workspace, 'Game/kind', { kind: 'directory' }, capabilities);
  }));
  rows.push(await nativeCheck('rename-cycle', async () => {
    await atomicWriteFile(workspace, 'Game/left', Buffer.from('left'), capabilities);
    await atomicWriteFile(workspace, 'Game/right', Buffer.from('right'), capabilities);
    const plan = planRenames({ caseMode: 'case-sensitive', profile: workspace.profile, renames: [
      { from: 'Game/left', to: 'Game/right', fileId: '11'.repeat(16) },
      { from: 'Game/right', to: 'Game/left', fileId: '22'.repeat(16) },
    ] });
    await executeRenamePlan(workspace, plan, capabilities);
    assert.equal(await readFile(join(root, 'Game/left'), 'utf8'), 'right');
    assert.equal(await readFile(join(root, 'Game/right'), 'utf8'), 'left');
  }));
  rows.push(await nativeCheck('symlink-materialization', async () => {
    await atomicWriteFile(workspace, 'Game/link-target', Buffer.from('target'), capabilities);
    if (capabilities.symlink) {
      await materializeSymlink(workspace, 'Game/current', 'link-target', capabilities);
    } else {
      let code;
      try { await materializeSymlink(workspace, 'Game/current', 'link-target', capabilities); } catch (error) { code = error?.code; }
      assert.equal(code, 'CAPABILITY_UNAVAILABLE');
    }
  }));
  rows.push(await nativeCheck('watcher-state-durable', async () => {
    let state = initialWatcherState();
    state = await applyWatcherEvent(workspace, state, { type: 'reconcile', cursor: 'native-c0', generation: 1 });
    state = await applyWatcherEvent(workspace, state, { type: 'start', session: 'native-s1' });
    let code;
    try { await applyWatcherEvent(workspace, state, { type: 'batch', session: 'native-s1', fromCursor: 'wrong', toCursor: 'native-c1' }); } catch (error) { code = error?.code; }
    assert.equal(code, 'WATCH_GAP');
    const durable = await loadWatcherState(workspace);
    assert.equal(durable.reconciliationRequired, true);
    assert.equal(durable.authoritativeClean, false);
  }));
  rows.push(await nativeCheck('watcher-subscribe-before-reconcile', async () => {
    let state = await applyWatcherEvent(workspace, initialWatcherState('node-fs-watch-v1'), {
      type: 'reconcile', cursor: 'before-open', generation: 1,
    });
    let injected = false; let subscribed = false; let included = false;
    const watcher = await openWorkspaceWatcher(workspace, state, {
      session: 'native-open-gap',
      hooks: { boundary: async (name) => {
        if (name === 'before-watcher-state-write' && !injected) {
          injected = true;
          await writeFile(join(root, 'missed-before-subscribe'), 'covered by reconciliation');
        }
      } },
      iteratorFactory: () => {
        subscribed = true;
        return {
          next: async () => ({ done: false, value: { eventType: 'change', filename: 'later-visible' } }),
          return: async () => ({ done: true }),
        };
      },
      reconcile: async () => {
        assert.equal(subscribed, true);
        included = (await readdir(root)).includes('missed-before-subscribe');
        return included;
      },
    });
    const batch = await watcher.nextBatch(async () => true);
    assert.equal(included, true);
    assert.equal(batch.state.authoritativeClean, false);
    state = await watcher.close();
    assert.equal(state.reason, 'unsupported-resume');
  }));
  rows.push(await nativeCheck('sparse-logical-bytes-authoritative', async () => {
    const sourceRoot = await mkdtemp(join(tmpdir(), 'ogvcs-path-sparse-'));
    try {
      const source = join(sourceRoot, 'sparse.bin');
      const handle = await open(source, 'w', 0o600);
      try {
        await handle.write(Buffer.from([0x7f]), 0, 1, (1024 * 1024) - 1);
        await handle.sync();
      } finally { await handle.close(); }
      const logical = await readFile(source);
      assert.equal(logical.length, 1024 * 1024);
      const result = await atomicWriteFile(workspace, 'Game/sparse.bin', logical, capabilities);
      const materialized = await readFile(join(root, 'Game/sparse.bin'));
      assert.equal(result.sha256, sha256(logical));
      assert.equal(sha256(materialized), sha256(logical));
    } finally { await rm(sourceRoot, { recursive: true, force: true }); }
  }));
  rows.push(await nativeCheck('busy-interference-bounded', async () => {
    let attempts = 0; let code;
    try {
      await atomicWriteFile(workspace, 'Game/busy.bin', Buffer.from('never publish'), capabilities, {
        maxRetries: 2,
        hooks: { boundary: (name) => {
          if (name === 'before-publish-attempt') {
            attempts += 1;
            const error = new Error('simulated locked-file or scanner interference');
            error.code = 'EBUSY';
            throw error;
          }
        } },
      });
    } catch (error) { code = error?.code; }
    assert.equal(code, 'TARGET_BUSY');
    assert.equal(attempts, 3);
    await assert.rejects(readFile(join(root, 'Game/busy.bin')));
    for (const remnant of await inspectCrashRemnants(workspace)) await rollbackCrashRemnant(workspace, remnant.id);
  }));
  rows.push(await nativeValue('unreal-materialization', {
    entries: 4, inventorySha256: '745d74b9e539640deefb654a52dc3de0ab4c95f70fd8238e53832541c0f17e0e',
  }, () => materializeFixture(workspace, capabilities, [
    { path: 'Fixtures/Unreal/Config/DefaultGame.ini', content: '[/Script/EngineSettings.GameMapsSettings]\nGameDefaultMap=/Game/Maps/Main\n' },
    { path: 'Fixtures/Unreal/Content/Characters/Hero/Hero.uasset', content: 'ogvcs-unreal-uasset-v1\n' },
    { path: 'Fixtures/Unreal/Content/Characters/Hero/Hero.uexp', content: 'ogvcs-unreal-uexp-v1\n' },
    { path: 'Fixtures/Unreal/Source/Game/Build.sh', content: '#!/bin/sh\necho build\n', executable: true },
  ])));
  rows.push(await nativeValue('unity-materialization', {
    entries: 5, inventorySha256: 'c9b1b054b916d64769aff96059be6f3c25fa0da909fac82ab444b2d05e93d81d',
  }, () => materializeFixture(workspace, capabilities, [
    { path: 'Fixtures/Unity/Assets/Prefabs/Hero.prefab', content: '%YAML 1.1\n--- !u!1 &1001\nGameObject:\n  m_Name: Hero\n' },
    { path: 'Fixtures/Unity/Assets/Prefabs/Hero.prefab.meta', content: 'fileFormatVersion: 2\nguid: 11111111111111111111111111111111\n' },
    { path: 'Fixtures/Unity/Assets/Scenes/Main.unity', content: '%YAML 1.1\n--- !u!1045 &1\nEditorBuildSettings:\n' },
    { path: 'Fixtures/Unity/Assets/Scenes/Main.unity.meta', content: 'fileFormatVersion: 2\nguid: 22222222222222222222222222222222\n' },
    { path: 'Fixtures/Unity/ProjectSettings/ProjectVersion.txt', content: 'm_EditorVersion: 6000.0.0f1\n' },
  ])));
  rows.push(await nativeValue('engine-fixture-depth-limit', {
    accepted: false, error: 'PATH_LIMIT_EXCEEDED', detail: { resource: 'depth' },
  }, async () => {
    const entries = []; let parent = '';
    for (let index = 0; index < 257; index += 1) {
      parent = parent === '' ? `Segment${String(index).padStart(3, '0')}` : `${parent}/Segment${String(index).padStart(3, '0')}`;
      entries.push({ id: `d${index}`, path: parent, kind: 'directory', mode: 'directory' });
    }
    return evaluatePreflight({
      schemaVersion: 'ogvcs.path/preflight-request/v1',
      caseMode: 'case-folded',
      profile: 'path.opengamevcs/portable@1',
      platform: hostPlatform(),
      capabilities: {
        atomicReplace: capabilities.atomicReplace,
        executableBit: capabilities.executableBit,
        symlink: capabilities.symlink,
      },
      entries,
    });
  }));
  return rows;
}

export async function buildConformanceReport(options = {}) {
  const scratch = options.root === undefined ? await mkdtemp(join(tmpdir(), 'ogvcs-path-report-')) : null;
  const root = resolve(options.root ?? scratch);
  try {
    await mkdir(root, { recursive: true });
    const capabilities = await probeFilesystemCapabilities(root, options);
    const results = [...await pureRows(), ...await nativeRows(root, capabilities)];
    const passed = results.filter((item) => item.passed).length;
    const report = {
      schemaVersion: 'ogvcs.path/conformance-report/v1', contractVersion: pathContract.contractVersion,
      implementation: { name: '@opengamevcs/path-filesystem', version: '1.1.0', runtime: `${process.release.name} ${process.version}` },
      platform: hostPlatform(),
      capabilities: {
        atomicReplace: capabilities.atomicReplace, casePreserving: capabilities.casePreserving,
        caseSensitive: capabilities.caseSensitive, directorySync: capabilities.directorySync,
        executableBit: capabilities.executableBit, hardlink: capabilities.hardlink,
        normalizationSensitive: capabilities.normalizationSensitive, symlink: capabilities.symlink,
      },
      manifestSha256: pathContract.manifestSha256, registrySetSha256: pathContract.registrySetSha256,
      unicodeCaseFoldingSha256: pathContract.unicodeCaseFoldingSha256,
      resultsSha256: sha256(Buffer.from(canonicalJson(results), 'utf8')),
      total: results.length, passed, failed: results.length - passed, results,
    };
    return Object.freeze(report);
  } finally { if (scratch !== null) await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }); }
}

export async function writeConformanceReport(path, options = {}) {
  const report = await buildConformanceReport(options);
  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(resolve(path), `${canonicalJson(report)}\n`, 'utf8');
  return report;
}
