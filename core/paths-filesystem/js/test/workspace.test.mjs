import assert from 'node:assert/strict';
import { lstat, mkdtemp, readFile, readdir, rm, stat, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { probeFilesystemCapabilities } from '../src/capabilities.mjs';
import { PathFilesystemError } from '../src/errors.mjs';
import { planRenames } from '../src/rename.mjs';
import {
  applyReadOnlyHint, atomicWriteFile, executeRenamePlan, inspectCrashRemnants,
  materializeSymlink, openWorkspaceRoot, replaceWorkspaceEntry, resumeRenamePlan, rollbackCrashRemnant,
} from '../src/workspace.mjs';

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-workspace-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 }));
  return { root, workspace: await openWorkspaceRoot(root) };
}
const code = (expected) => (error) => error instanceof PathFilesystemError && error.code === expected;

test('capability probe is bounded and leaves no probe artifacts', async t => {
  const { root } = await workspace(t);
  const capabilities = await probeFilesystemCapabilities(root);
  assert.equal(capabilities.schemaVersion, 'ogvcs.path/filesystem-capabilities/v1');
  assert.equal(capabilities.atomicReplace, true);
  assert.equal(typeof capabilities.caseSensitive, 'boolean');
  assert.deepEqual((await readdir(root)).sort(), ['.ogvcs']);
});

test('exclusive stage and atomic publication replace exact regular files', async t => {
  const { root, workspace: handle } = await workspace(t);
  const first = await atomicWriteFile(handle, 'Content/Hero.uasset', Buffer.from('one'), { createParents: true });
  const second = await atomicWriteFile(handle, 'Content/Hero.uasset', Buffer.from('two'));
  assert.notEqual(first.transaction, second.transaction);
  assert.equal(await readFile(join(root, 'Content/Hero.uasset'), 'utf8'), 'two');
  assert.deepEqual(await inspectCrashRemnants(handle), []);
});

test('workspace mutation rejects structurally convincing forged handles', async t => {
  const { workspace: handle } = await workspace(t);
  await assert.rejects(atomicWriteFile(Object.freeze({ ...handle }), 'forged', Buffer.from('no')), code('UNSAFE_TARGET'));
});

test('write byte ceilings reject before staging or caller-byte copying', async t => {
  const { workspace: handle } = await workspace(t);
  await assert.rejects(atomicWriteFile(handle, 'oversized', new Uint8Array(1024), { maxBytes: 8 }), code('LIMIT_EXCEEDED'));
  await assert.rejects(atomicWriteFile(handle, 'invalid', { byteLength: 1 }, { maxBytes: 8 }), code('PATH_INPUT_INVALID'));
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('failure after staging leaves an owner-bound recoverable plan record', async t => {
  const { workspace: handle } = await workspace(t);
  await assert.rejects(atomicWriteFile(handle, 'interrupted', Buffer.from('bytes'), {
    hooks: { boundary: (name) => { if (name === 'after-stage') throw new Error('stop-before-record'); } },
  }), code('ATOMIC_REPLACE_FAILED'));
  const [remnant] = await inspectCrashRemnants(handle);
  assert.deepEqual({ state: remnant.state, stagePresent: remnant.stagePresent }, { state: 'planned', stagePresent: true });
  await rollbackCrashRemnant(handle, remnant.id);
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('unowned transaction artifacts are reported instead of recursively cleaned', async t => {
  const { workspace: handle } = await workspace(t);
  await writeFile(join(handle.transactions, `${'aa'.repeat(16)}.stage`), 'unknown');
  await assert.rejects(inspectCrashRemnants(handle), code('CRASH_REMNANT'));
});

test('pre-existing symlink or junction ancestor cannot redirect a write', async t => {
  const { root, workspace: handle } = await workspace(t);
  const outside = await mkdtemp(join(tmpdir(), 'ogvcs-outside-'));
  t.after(() => rm(outside, { recursive: true, force: true }));
  try { await symlink(outside, join(root, 'Content'), process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (process.platform === 'win32' && ['EPERM', 'EACCES'].includes(error?.code)) return; throw error; }
  await assert.rejects(atomicWriteFile(handle, 'Content/pwned', Buffer.from('bad')), code('UNSAFE_TARGET'));
  await assert.rejects(readFile(join(outside, 'pwned')));
});

test('identity change at the publication boundary fails closed and remains recoverable', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Content/Asset.bin', Buffer.from('base'), { createParents: true });
  await assert.rejects(atomicWriteFile(handle, 'Content/Asset.bin', Buffer.from('new'), {
    hooks: { boundary: async (name) => { if (name === 'before-publish') await writeFile(join(root, 'Content/Asset.bin'), 'racer'); } },
  }), code('TARGET_CHANGED'));
  assert.equal(await readFile(join(root, 'Content/Asset.bin'), 'utf8'), 'racer');
  const remnants = await inspectCrashRemnants(handle);
  assert.equal(remnants.length, 1);
  await rollbackCrashRemnant(handle, remnants[0].id);
  assert.deepEqual(await inspectCrashRemnants(handle), []);
});

test('same-size in-place target rewrite is detected even when timestamps are restored', async t => {
  const { root, workspace: handle } = await workspace(t);
  const target = join(root, 'Asset.bin');
  await atomicWriteFile(handle, 'Asset.bin', Buffer.from('base'));
  const prior = await stat(target);
  await assert.rejects(atomicWriteFile(handle, 'Asset.bin', Buffer.from('next'), {
    hooks: { boundary: async (name) => {
      if (name === 'before-publish') {
        await writeFile(target, 'race');
        await utimes(target, prior.atime, prior.mtime);
      }
    } },
  }), code('TARGET_CHANGED'));
  const [remnant] = await inspectCrashRemnants(handle);
  await rollbackCrashRemnant(handle, remnant.id);
});

test('a published file with a staged record is finalized only after exact digest recovery', async t => {
  const { root, workspace: handle } = await workspace(t);
  await assert.rejects(atomicWriteFile(handle, 'published.bin', Buffer.from('durable'), {
    hooks: { boundary: (name) => { if (name === 'after-publish') throw new Error('lost-after-rename'); } },
  }), code('ATOMIC_REPLACE_FAILED'));
  const [remnant] = await inspectCrashRemnants(handle);
  assert.equal(remnant.stagePresent, false);
  const recovered = await rollbackCrashRemnant(handle, remnant.id);
  assert.equal(recovered.action, 'finalized');
  assert.equal(await readFile(join(root, 'published.bin'), 'utf8'), 'durable');
});

test('fault after durable transaction record produces an exact removable remnant', async t => {
  const { workspace: handle } = await workspace(t);
  await assert.rejects(atomicWriteFile(handle, 'Content/Interrupted.bin', Buffer.from('staged'), {
    createParents: true, hooks: { boundary: (name) => { if (name === 'after-record') throw new Error('power loss'); } },
  }), code('ATOMIC_REPLACE_FAILED'));
  const [remnant] = await inspectCrashRemnants(handle);
  assert.equal(remnant.operation, 'write-file');
  assert.equal(remnant.state, 'staged');
  await rollbackCrashRemnant(handle, remnant.id);
  assert.deepEqual(await inspectCrashRemnants(handle), []);
});

test('case-only and cyclic renames preserve the declared FileIDs', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Game/Hero', Buffer.from('hero'), { createParents: true });
  const casePlan = planRenames({ caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1', renames: [{ from: 'Game/Hero', to: 'Game/hero', fileId: '11'.repeat(16) }] });
  const caseResult = await executeRenamePlan(handle, casePlan);
  assert.deepEqual(caseResult.fileIds, ['11'.repeat(16)]);
  assert.equal(await readFile(join(root, 'Game/hero'), 'utf8'), 'hero');

  await atomicWriteFile(handle, 'A', Buffer.from('left'));
  await atomicWriteFile(handle, 'B', Buffer.from('right'));
  const cycle = planRenames({ caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', renames: [
    { from: 'A', to: 'B', fileId: '22'.repeat(16) }, { from: 'B', to: 'A', fileId: '33'.repeat(16) },
  ] });
  const cycleHandle = await openWorkspaceRoot(root, { profile: 'path.opengamevcs/linux@1' });
  const result = await executeRenamePlan(cycleHandle, cycle);
  assert.deepEqual([...result.fileIds].sort(), ['22'.repeat(16), '33'.repeat(16)].sort());
  assert.equal(await readFile(join(root, 'A'), 'utf8'), 'right');
  assert.equal(await readFile(join(root, 'B'), 'utf8'), 'left');
});

test('durable rename records resume after publication precedes record advancement', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'A', Buffer.from('left'));
  await atomicWriteFile(handle, 'B', Buffer.from('right'));
  const plan = planRenames({ caseMode: 'case-sensitive', profile: 'path.opengamevcs/portable@1', renames: [
    { from: 'A', to: 'B', fileId: '44'.repeat(16) }, { from: 'B', to: 'A', fileId: '55'.repeat(16) },
  ] });
  await assert.rejects(executeRenamePlan(handle, plan, {
    hooks: { boundary: (name, context) => { if (name === 'after-stage' && context.step === 0) throw new Error('rename-power-loss'); } },
  }), code('ATOMIC_REPLACE_FAILED'));
  const [remnant] = await inspectCrashRemnants(handle);
  assert.deepEqual({ operation: remnant.operation, completed: remnant.completed, stepPending: remnant.stepPending }, { operation: 'rename', completed: 0, stepPending: true });
  const result = await resumeRenamePlan(handle, plan);
  assert.equal(result.steps, 4);
  assert.equal(await readFile(join(root, 'A'), 'utf8'), 'right');
  assert.equal(await readFile(join(root, 'B'), 'utf8'), 'left');
  assert.deepEqual(await inspectCrashRemnants(handle), []);
});

test('directory and file kind replacement is staged, durable, and recoverable', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Kind/child', Buffer.from('old'), { createParents: true });
  const toFile = await replaceWorkspaceEntry(handle, 'Kind', { kind: 'regular', content: Buffer.from('new') });
  assert.deepEqual({ priorKind: toFile.priorKind, kind: toFile.kind }, { priorKind: 'directory', kind: 'regular' });
  assert.equal(await readFile(join(root, 'Kind'), 'utf8'), 'new');
  await replaceWorkspaceEntry(handle, 'Kind', { kind: 'directory' });
  assert.equal((await lstat(join(root, 'Kind'))).isDirectory(), true);
  assert.deepEqual(await readdir(join(root, 'Kind')), []);

  await assert.rejects(replaceWorkspaceEntry(handle, 'Kind', { kind: 'regular', content: Buffer.from('planned') }, {
    hooks: { boundary: (name) => { if (name === 'after-stage') throw new Error('before-stage-record'); } },
  }), code('ATOMIC_REPLACE_FAILED'));
  const [planned] = await inspectCrashRemnants(handle);
  assert.equal(planned.state, 'planned');
  await rollbackCrashRemnant(handle, planned.id);

  await atomicWriteFile(handle, 'Kind/child', Buffer.from('restorable'));
  await assert.rejects(replaceWorkspaceEntry(handle, 'Kind', { kind: 'regular', content: Buffer.from('interrupted') }, {
    hooks: { boundary: (name) => { if (name === 'after-remove') throw new Error('power-loss'); } },
  }), code('ATOMIC_REPLACE_FAILED'));
  const [remnant] = await inspectCrashRemnants(handle);
  assert.deepEqual({ operation: remnant.operation, state: remnant.state, stagePresent: remnant.stagePresent, backupPresent: remnant.backupPresent }, { operation: 'replace-kind', state: 'old-moved', stagePresent: true, backupPresent: true });
  const recovered = await rollbackCrashRemnant(handle, remnant.id);
  assert.equal(recovered.action, 'rolled-back');
  assert.equal(await readFile(join(root, 'Kind/child'), 'utf8'), 'restorable');
});

test('symlink materialization is explicit and read-only state remains nonauthoritative', async t => {
  const { root, workspace: handle } = await workspace(t);
  const capabilities = await probeFilesystemCapabilities(root);
  await atomicWriteFile(handle, 'Content/target', Buffer.from('target'), { createParents: true });
  await assert.rejects(
    materializeSymlink(handle, 'Content/junction', 'target', { capabilities: { ...capabilities, symlink: true }, type: 'junction' }),
    code('SYMLINK_FORBIDDEN'),
  );
  await assert.rejects(
    materializeSymlink(handle, 'Content/non-scalar', '\ud800', { capabilities: { ...capabilities, symlink: true } }),
    code('SYMLINK_FORBIDDEN'),
  );
  if (capabilities.symlink) {
    await materializeSymlink(handle, 'Content/current', 'target', { capabilities });
    assert.equal((await lstat(join(root, 'Content/current'))).isSymbolicLink(), true);
  } else {
    await assert.rejects(materializeSymlink(handle, 'Content/current', 'target', { capabilities }), code('CAPABILITY_UNAVAILABLE'));
  }
  const hint = await applyReadOnlyHint(handle, 'Content/target', true);
  assert.equal(hint.authoritative, false);
  await applyReadOnlyHint(handle, 'Content/target', false);
});
