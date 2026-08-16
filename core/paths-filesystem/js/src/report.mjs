import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { hostPlatform, probeFilesystemCapabilities } from './capabilities.mjs';
import { loadContractJson, pathContract } from './contract.mjs';
import { PathFilesystemError } from './errors.mjs';
import { caseFold, evaluateCollisions, evaluatePath } from './path.mjs';
import { evaluatePreflight } from './preflight.mjs';
import { evaluateRenames, planRenames } from './rename.mjs';
import { applyWatcherEvent, evaluateWatcherCase, initialWatcherState, loadWatcherState } from './watcher.mjs';
import { applyReadOnlyHint, atomicWriteFile, executeRenamePlan, inspectCrashRemnants, materializeSymlink, openWorkspaceRoot, replaceWorkspaceEntry, rollbackCrashRemnant } from './workspace.mjs';

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

async function nativeRows(root, capabilities) {
  const rows = [];
  const workspace = await openWorkspaceRoot(root, { profile: 'path.opengamevcs/portable@1' });
  rows.push(await nativeCheck('atomic-replace', async () => {
    if (!capabilities.atomicReplace) throw new Error('atomic replacement unavailable');
    await atomicWriteFile(workspace, 'Game/data.bin', Buffer.from('first'), { createParents: true });
    await atomicWriteFile(workspace, 'Game/data.bin', Buffer.from('second'));
    assert.equal(await readFile(join(root, 'Game/data.bin'), 'utf8'), 'second');
  }));
  rows.push(await nativeCheck('target-race-denied', async () => {
    let code;
    try {
      await atomicWriteFile(workspace, 'Game/data.bin', Buffer.from('trusted'), {
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
      if (!linked) return;
      let code;
      try { await atomicWriteFile(workspace, 'escape/pwned', Buffer.from('no'), { createParents: true }); } catch (error) { code = error?.code; }
      assert.equal(code, 'UNSAFE_TARGET');
      await assert.rejects(readFile(join(outside, 'pwned')));
    } finally { await rm(outside, { recursive: true, force: true }); }
  }));
  rows.push(await nativeCheck('crash-remnant-recovery', async () => {
    let failed = false;
    try { await atomicWriteFile(workspace, 'Game/crash.bin', Buffer.from('staged'), { hooks: { boundary: (name) => { if (name === 'after-record') throw new Error('simulated power loss'); } } }); }
    catch { failed = true; }
    assert.equal(failed, true);
    const remnants = await inspectCrashRemnants(workspace);
    assert.equal(remnants.length, 1);
    await rollbackCrashRemnant(workspace, remnants[0].id);
    assert.equal((await inspectCrashRemnants(workspace)).length, 0);
  }));
  rows.push(await nativeCheck('read-only-is-hint', async () => {
    await atomicWriteFile(workspace, 'Game/locked.asset', Buffer.from('lock'));
    const result = await applyReadOnlyHint(workspace, 'Game/locked.asset', true);
    assert.equal(result.authoritative, false);
    await applyReadOnlyHint(workspace, 'Game/locked.asset', false);
  }));
  rows.push(await nativeCheck('directory-file-replacement', async () => {
    await atomicWriteFile(workspace, 'Game/kind/child', Buffer.from('old'), { createParents: true });
    await replaceWorkspaceEntry(workspace, 'Game/kind', { kind: 'regular', content: Buffer.from('file') });
    assert.equal(await readFile(join(root, 'Game/kind'), 'utf8'), 'file');
    await replaceWorkspaceEntry(workspace, 'Game/kind', { kind: 'directory' });
  }));
  rows.push(await nativeCheck('rename-cycle', async () => {
    await atomicWriteFile(workspace, 'Game/left', Buffer.from('left'));
    await atomicWriteFile(workspace, 'Game/right', Buffer.from('right'));
    const plan = planRenames({ caseMode: 'case-sensitive', profile: workspace.profile, renames: [
      { from: 'Game/left', to: 'Game/right', fileId: '11'.repeat(16) },
      { from: 'Game/right', to: 'Game/left', fileId: '22'.repeat(16) },
    ] });
    await executeRenamePlan(workspace, plan);
    assert.equal(await readFile(join(root, 'Game/left'), 'utf8'), 'right');
    assert.equal(await readFile(join(root, 'Game/right'), 'utf8'), 'left');
  }));
  rows.push(await nativeCheck('symlink-materialization', async () => {
    await atomicWriteFile(workspace, 'Game/link-target', Buffer.from('target'));
    if (capabilities.symlink) {
      await materializeSymlink(workspace, 'Game/current', 'link-target', { capabilities });
    } else {
      let code;
      try { await materializeSymlink(workspace, 'Game/current', 'link-target', { capabilities }); } catch (error) { code = error?.code; }
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
  rows.push(await nativeCheck('unreal-unity-bounded-preflight', async () => {
    const entries = [{ id: 'root', path: 'Content', kind: 'directory', mode: 'directory' }];
    let parent = 'Content';
    for (let index = 0; index < 80; index += 1) {
      parent = `${parent}/Segment${String(index).padStart(3, '0')}`;
      entries.push({ id: `d${index}`, path: parent, kind: 'directory', mode: 'directory' });
    }
    entries.push({ id: 'asset', path: `${parent}/VeryLongGeneratedAssetName.uasset`, kind: 'regular', mode: 'regular-file' });
    const result = evaluatePreflight({
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
    assert.equal(result.accepted, true);
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
      implementation: { name: '@opengamevcs/path-filesystem', version: '1.0.0', runtime: `${process.release.name} ${process.version}` },
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
