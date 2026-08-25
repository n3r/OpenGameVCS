import assert from 'node:assert/strict';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { probeFilesystemCapabilities } from '../src/capabilities.mjs';
import { PathFilesystemError } from '../src/errors.mjs';
import { preflightWorkspaceMaterialization } from '../src/preflight.mjs';
import { planRenames } from '../src/rename.mjs';
import {
  applyReadOnlyHint, atomicWriteFile as rawAtomicWriteFile, executeRenamePlan as rawExecuteRenamePlan,
  inspectCrashRemnants, materializeSymlink as rawMaterializeSymlink, openWorkspaceRoot,
  replaceWorkspaceEntry as rawReplaceWorkspaceEntry, resumeRenamePlan as rawResumeRenamePlan, rollbackCrashRemnant,
} from '../src/workspace.mjs';

async function workspace(t, options) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-workspace-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 }));
  return { root, workspace: await openWorkspaceRoot(root, options) };
}
const code = (expected) => (error) => error instanceof PathFilesystemError && error.code === expected;

function plannedEntries(targets) {
  const entries = new Map(); let nextId = 0;
  const add = (path, value) => {
    if (!entries.has(path)) { entries.set(path, { id: `entry-${nextId}`, path, ...value }); nextId += 1; }
    else if (value.kind !== 'directory') entries.set(path, { id: entries.get(path).id, path, ...value });
  };
  for (const target of targets) {
    const segments = target.path.split('/');
    for (let index = 1; index < segments.length; index += 1) {
      const path = segments.slice(0, index).join('/');
      add(path, { kind: 'directory', mode: 'directory' });
    }
    const mode = { directory: 'directory', regular: 'regular-file', executable: 'executable-file', symlink: 'symlink' }[target.kind];
    add(target.path, {
      kind: target.kind, mode,
      ...(target.symlinkTarget === undefined ? {} : { symlinkTarget: target.symlinkTarget }),
    });
  }
  return [...entries.values()].sort((left, right) => left.path.split('/').length - right.path.split('/').length || left.path.localeCompare(right.path));
}

async function workspacePlan(handle, targets, options = {}) {
  const capabilityProbe = options.capabilityProbe ?? probeFilesystemCapabilities;
  const measured = options.capabilities ?? await capabilityProbe(handle.root);
  return preflightWorkspaceMaterialization(handle, {
    schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: handle.caseMode,
    profile: handle.profile, platform: measured.platform,
    capabilities: { atomicReplace: measured.atomicReplace, executableBit: measured.executableBit, symlink: measured.symlink },
    entries: plannedEntries(targets),
  }, { capabilityProbe });
}

async function atomicWriteFile(handle, path, content, options = {}) {
  const plan = options.plan ?? await workspacePlan(handle, [{ path, kind: options.executable === true ? 'executable' : 'regular' }]);
  return rawAtomicWriteFile(handle, path, content, { ...options, plan });
}

async function replaceWorkspaceEntry(handle, path, replacement, options = {}) {
  const kind = replacement?.kind === 'regular' && replacement.executable === true ? 'executable' : replacement?.kind;
  const plan = options.plan ?? await workspacePlan(handle, [{ path, kind }]);
  return rawReplaceWorkspaceEntry(handle, path, replacement, { ...options, plan });
}

async function materializeSymlink(handle, path, target, options = {}) {
  const plan = options.plan ?? await workspacePlan(handle, [{ path, kind: 'symlink', symlinkTarget: target }], options);
  return rawMaterializeSymlink(handle, path, target, { ...options, plan });
}

async function executeRenamePlan(handle, renamePlan, options = {}) {
  const targets = renamePlan.steps.filter(({ phase }) => phase === 'publish').map(({ to }) => ({ path: to, kind: 'regular' }));
  const materializationPlan = options.materializationPlan ?? await workspacePlan(handle, targets);
  return rawExecuteRenamePlan(handle, renamePlan, { ...options, materializationPlan });
}

async function resumeRenamePlan(handle, renamePlan, options = {}) {
  const targets = renamePlan.steps.filter(({ phase }) => phase === 'publish').map(({ to }) => ({ path: to, kind: 'regular' }));
  const materializationPlan = options.materializationPlan ?? await workspacePlan(handle, targets);
  return rawResumeRenamePlan(handle, renamePlan, { ...options, materializationPlan });
}

test('capability probe is bounded and leaves no probe artifacts', async t => {
  const { root } = await workspace(t);
  const capabilities = await probeFilesystemCapabilities(root);
  assert.equal(capabilities.schemaVersion, 'ogvcs.path/filesystem-capabilities/v1');
  assert.equal(capabilities.atomicReplace, true);
  assert.equal(typeof capabilities.caseSensitive, 'boolean');
  assert.deepEqual((await readdir(root)).sort(), ['.ogvcs']);
});

test('POSIX workspace roots must enforce the documented private-authority boundary', { skip: process.platform === 'win32' }, async t => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-workspace-public-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await chmod(root, 0o755);
  await assert.rejects(openWorkspaceRoot(root), code('UNSAFE_TARGET'));
});

test('workspace configuration is rejected before creating control state', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-workspace-config-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await assert.rejects(openWorkspaceRoot(root, { profile: 'path.opengamevcs/unknown@1' }), code('PATH_PROFILE_UNKNOWN'));
  await assert.rejects(openWorkspaceRoot(root, { caseMode: 'host-default' }), code('CASE_MODE_INVALID'));
  assert.deepEqual(await readdir(root), []);
});

test('exclusive stage and atomic publication replace exact regular files', async t => {
  const { root, workspace: handle } = await workspace(t);
  const first = await atomicWriteFile(handle, 'Content/Hero.uasset', Buffer.from('one'), { createParents: true });
  const second = await atomicWriteFile(handle, 'Content/Hero.uasset', Buffer.from('two'));
  assert.notEqual(first.transaction, second.transaction);
  assert.equal(await readFile(join(root, 'Content/Hero.uasset'), 'utf8'), 'two');
  assert.deepEqual(await inspectCrashRemnants(handle), []);
});

test('locked-file and scanner interference retries are bounded and never copy-fallback', async t => {
  const { root, workspace: handle } = await workspace(t);
  let transientAttempts = 0;
  await atomicWriteFile(handle, 'Game/retry.bin', Buffer.from('published after retry'), {
    createParents: true, maxRetries: 2,
    hooks: { boundary: (name) => {
      if (name === 'before-publish-attempt' && transientAttempts < 2) {
        transientAttempts += 1;
        const error = new Error('transient scanner lock'); error.code = 'EACCES'; throw error;
      }
    } },
  });
  assert.equal(transientAttempts, 2);
  assert.equal(await readFile(join(root, 'Game/retry.bin'), 'utf8'), 'published after retry');

  let terminalAttempts = 0;
  await assert.rejects(atomicWriteFile(handle, 'Game/busy.bin', Buffer.from('not published'), {
    maxRetries: 1,
    hooks: { boundary: (name) => {
      if (name === 'before-publish-attempt') {
        terminalAttempts += 1;
        const error = new Error('locked target'); error.code = 'EBUSY'; throw error;
      }
    } },
  }), code('TARGET_BUSY'));
  assert.equal(terminalAttempts, 2);
  await assert.rejects(readFile(join(root, 'Game/busy.bin')));
  for (const remnant of await inspectCrashRemnants(handle)) await rollbackCrashRemnant(handle, remnant.id);
});

test('workspace mutation rejects structurally convincing forged handles', async t => {
  const { workspace: handle } = await workspace(t);
  await assert.rejects(atomicWriteFile(Object.freeze({ ...handle }), 'forged', Buffer.from('no')), code('UNSAFE_TARGET'));
});

test('workspace mutation requires an owner-bound complete preflight plan', async t => {
  const { workspace: first } = await workspace(t);
  const { workspace: second } = await workspace(t);
  await assert.rejects(rawAtomicWriteFile(first, 'file', Buffer.from('no')), code('CAPABILITY_UNAVAILABLE'));
  const plan = await workspacePlan(first, [{ path: 'file', kind: 'regular' }]);
  await assert.rejects(rawAtomicWriteFile(first, 'other', Buffer.from('no'), { plan }), code('ENTRY_INVALID'));
  await assert.rejects(rawAtomicWriteFile(second, 'file', Buffer.from('no'), { plan }), code('CAPABILITY_UNAVAILABLE'));
  assert.deepEqual(await readdir(first.transactions), []);
  assert.deepEqual(await readdir(second.transactions), []);
});

test('measured capability drift invalidates a bound plan before staging', async t => {
  const { workspace: handle } = await workspace(t);
  const base = await probeFilesystemCapabilities(handle.root);
  let probes = 0;
  const capabilityProbe = async () => {
    probes += 1;
    return probes === 1 ? base : Object.freeze({ ...base, executableBit: !base.executableBit });
  };
  const plan = await workspacePlan(handle, [{ path: 'file', kind: 'regular' }], { capabilities: base, capabilityProbe });
  await assert.rejects(rawAtomicWriteFile(handle, 'file', Buffer.from('no'), { plan }), code('CAPABILITY_UNAVAILABLE'));
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('workspace mutation rejects replaced owner-bound control directories', async t => {
  const { workspace: handle } = await workspace(t);
  const displaced = `${handle.transactions}-displaced`;
  await rename(handle.transactions, displaced);
  await mkdir(handle.transactions, { mode: 0o700 });
  await assert.rejects(atomicWriteFile(handle, 'file', Buffer.from('no')), code('TARGET_CHANGED'));
  assert.deepEqual(await readdir(handle.transactions), []);
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

test('ancestor replacement at the publication boundary fails closed', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Content/Asset.bin', Buffer.from('base'), { createParents: true });
  await assert.rejects(atomicWriteFile(handle, 'Content/Asset.bin', Buffer.from('next'), {
    hooks: { boundary: async (name) => {
      if (name === 'before-publish') {
        await rename(join(root, 'Content'), join(root, 'Content-displaced'));
        await mkdir(join(root, 'Content'));
      }
    } },
  }), code('TARGET_CHANGED'));
  await assert.rejects(readFile(join(root, 'Content/Asset.bin')));
  assert.equal(await readFile(join(root, 'Content-displaced/Asset.bin'), 'utf8'), 'base');
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

test('stage mutation is rejected before publication preserves the prior target', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Asset.bin', Buffer.from('base'));
  await assert.rejects(atomicWriteFile(handle, 'Asset.bin', Buffer.from('next'), {
    hooks: { boundary: async (name) => {
      if (name === 'before-publish') {
        const stage = (await readdir(handle.transactions)).find((entry) => entry.endsWith('.stage'));
        assert.equal(typeof stage, 'string');
        await writeFile(join(handle.transactions, stage), 'evil');
      }
    } },
  }), code('TARGET_CHANGED'));
  assert.equal(await readFile(join(root, 'Asset.bin'), 'utf8'), 'base');
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
  const { root, workspace: handle } = await workspace(t, { caseMode: 'case-folded' });
  await atomicWriteFile(handle, 'Game/Hero', Buffer.from('hero'), { createParents: true });
  const casePlan = planRenames({ caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1', renames: [{ from: 'Game/Hero', to: 'Game/hero', fileId: '11'.repeat(16) }] });
  const caseResult = await executeRenamePlan(handle, casePlan);
  assert.deepEqual(caseResult.fileIds, ['11'.repeat(16)]);
  assert.equal(await readFile(join(root, 'Game/hero'), 'utf8'), 'hero');

  await atomicWriteFile(handle, 'A', Buffer.from('left'));
  await atomicWriteFile(handle, 'B', Buffer.from('right'));
  const cycle = planRenames({ caseMode: 'case-sensitive', profile: 'path.opengamevcs/portable@1', renames: [
    { from: 'A', to: 'B', fileId: '22'.repeat(16) }, { from: 'B', to: 'A', fileId: '33'.repeat(16) },
  ] });
  const cycleHandle = await openWorkspaceRoot(root, { profile: 'path.opengamevcs/portable@1' });
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

test('directory rename preserves the complete bounded subtree', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Old/Nested/asset', Buffer.from('directory-state'), { createParents: true });
  const renamePlan = planRenames({
    caseMode: handle.caseMode, profile: handle.profile,
    renames: [{ from: 'Old', to: 'New', fileId: '66'.repeat(16) }],
  });
  const materializationPlan = await workspacePlan(handle, [{ path: 'New', kind: 'directory' }]);
  const result = await rawExecuteRenamePlan(handle, renamePlan, { materializationPlan });
  assert.deepEqual(result.fileIds, ['66'.repeat(16)]);
  assert.equal(await readFile(join(root, 'New/Nested/asset'), 'utf8'), 'directory-state');
  await assert.rejects(lstat(join(root, 'Old')));
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

test('directory replacement detects a descendant delete-modify race', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Kind/child', Buffer.from('base'), { createParents: true });
  await assert.rejects(replaceWorkspaceEntry(handle, 'Kind', { kind: 'regular', content: Buffer.from('new') }, {
    hooks: { boundary: async (name) => {
      if (name === 'before-remove') await writeFile(join(root, 'Kind/child'), 'race');
    } },
  }), code('TARGET_CHANGED'));
  assert.equal(await readFile(join(root, 'Kind/child'), 'utf8'), 'race');
});

test('directory replacement traversal obeys configured entry bounds', async t => {
  const { workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Kind/one', Buffer.from('1'), { createParents: true });
  await atomicWriteFile(handle, 'Kind/two', Buffer.from('2'));
  await assert.rejects(
    replaceWorkspaceEntry(handle, 'Kind', { kind: 'regular', content: Buffer.from('new') }, { maxDirectoryEntries: 1 }),
    code('LIMIT_EXCEEDED'),
  );
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('symlink materialization is explicit and read-only state remains nonauthoritative', async t => {
  const { root, workspace: handle } = await workspace(t);
  const capabilities = await probeFilesystemCapabilities(root);
  await atomicWriteFile(handle, 'Content/target', Buffer.from('target'), { createParents: true });
  await assert.rejects(
    rawMaterializeSymlink(handle, 'Content/junction', 'target', { type: 'junction' }),
    code('SYMLINK_FORBIDDEN'),
  );
  await assert.rejects(
    rawMaterializeSymlink(handle, 'Content/non-scalar', '\ud800'),
    code('SYMLINK_FORBIDDEN'),
  );
  if (capabilities.symlink) {
    await materializeSymlink(handle, 'Content/current', 'target');
    assert.equal((await lstat(join(root, 'Content/current'))).isSymbolicLink(), true);
  } else {
    await assert.rejects(materializeSymlink(handle, 'Content/current', 'target'), code('CAPABILITY_UNAVAILABLE'));
  }
  const hint = await applyReadOnlyHint(handle, 'Content/target', true);
  assert.equal(hint.authoritative, false);
  await applyReadOnlyHint(handle, 'Content/target', false);
});

test('read-only hints reject multiply linked inodes', async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'target', Buffer.from('bytes'));
  await link(join(root, 'target'), join(root, 'alias'));
  await assert.rejects(atomicWriteFile(handle, 'target', Buffer.from('new')), code('UNSAFE_TARGET'));
  await assert.rejects(applyReadOnlyHint(handle, 'target', true), code('UNSAFE_TARGET'));
});

test('public filesystem failures are normalized to stable path errors', async t => {
  const { workspace: handle } = await workspace(t);
  await assert.rejects(
    replaceWorkspaceEntry(handle, 'missing/target', { kind: 'directory' }),
    error => error instanceof PathFilesystemError && typeof error.code === 'string',
  );
  await assert.rejects(
    applyReadOnlyHint(handle, 'missing/target'),
    error => error instanceof PathFilesystemError && typeof error.code === 'string',
  );
});

test('directory sync permission failures are not reported as durable success', { skip: process.platform === 'win32' }, async t => {
  const { root, workspace: handle } = await workspace(t);
  await atomicWriteFile(handle, 'Content/target', Buffer.from('old'), { createParents: true });
  const parent = join(root, 'Content');
  await chmod(parent, 0o300);
  try {
    await assert.rejects(
      atomicWriteFile(handle, 'Content/target', Buffer.from('new')),
      error => error instanceof PathFilesystemError,
    );
  } finally {
    await chmod(parent, 0o700);
  }
});
