import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { link, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';

import { probeFilesystemCapabilities } from '../src/capabilities.mjs';
import { PathFilesystemError } from '../src/errors.mjs';
import { preflightWorkspaceMaterialization } from '../src/preflight.mjs';
import { atomicWriteFile, atomicWriteStream, inspectCrashRemnants, openWorkspaceRoot, rollbackCrashRemnant } from '../src/workspace.mjs';

const code = (expected) => (error) => error instanceof PathFilesystemError && error.code === expected;

async function createWorkspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-stream-publication-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 }));
  return { root, handle: await openWorkspaceRoot(root) };
}

function plannedEntries(path, kind = 'regular') {
  const segments = path.split('/');
  const entries = [];
  for (let index = 1; index < segments.length; index += 1) {
    entries.push({ id: `parent-${index}`, path: segments.slice(0, index).join('/'), kind: 'directory', mode: 'directory' });
  }
  entries.push({ id: 'target', path, kind, mode: kind === 'executable' ? 'executable-file' : 'regular-file' });
  return entries;
}

async function plan(handle, path, options = {}) {
  const capabilityProbe = options.capabilityProbe ?? probeFilesystemCapabilities;
  const measured = options.capabilities ?? await capabilityProbe(handle.root);
  return preflightWorkspaceMaterialization(handle, {
    schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: handle.caseMode,
    profile: handle.profile, platform: measured.platform,
    capabilities: { atomicReplace: measured.atomicReplace, executableBit: measured.executableBit, symlink: measured.symlink },
    entries: plannedEntries(path, options.kind),
  }, { capabilityProbe });
}

async function publish(handle, path, source, options = {}) {
  const bound = options.plan ?? await plan(handle, path, options);
  const expected = options.expected ?? Buffer.from('new');
  const { expected: ignored, ...publicationOptions } = options;
  return atomicWriteStream(handle, path, source, {
    maxBytes: 1024 * 1024, maxScratchBytes: 1024 * 1024,
    expectedBytes: expected.length, expectedSha256: createHash('sha256').update(expected).digest('hex'),
    ...publicationOptions, plan: bound,
  });
}

async function seed(handle, path, bytes) {
  const bound = await plan(handle, path);
  return atomicWriteFile(handle, path, bytes, { createParents: true, plan: bound });
}

async function *chunks(values) {
  for (const value of values) yield Buffer.from(value);
}

function runCrashChild(root, boundary) {
  const workspaceUrl = pathToFileURL(join(import.meta.dirname, '../src/workspace.mjs')).href;
  const preflightUrl = pathToFileURL(join(import.meta.dirname, '../src/preflight.mjs')).href;
  const capabilitiesUrl = pathToFileURL(join(import.meta.dirname, '../src/capabilities.mjs')).href;
  const script = `
    import { createHash } from 'node:crypto';
    import { atomicWriteStream, openWorkspaceRoot } from ${JSON.stringify(workspaceUrl)};
    import { preflightWorkspaceMaterialization } from ${JSON.stringify(preflightUrl)};
    import { probeFilesystemCapabilities } from ${JSON.stringify(capabilitiesUrl)};
    const [root, boundary] = process.argv.slice(1);
    const workspace = await openWorkspaceRoot(root);
    const capabilities = await probeFilesystemCapabilities(root);
    const plan = await preflightWorkspaceMaterialization(workspace, {
      schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: workspace.caseMode,
      profile: workspace.profile, platform: capabilities.platform,
      capabilities: { atomicReplace: capabilities.atomicReplace, executableBit: capabilities.executableBit, symlink: capabilities.symlink },
      entries: [{ id: 'target', path: 'asset.bin', kind: 'regular', mode: 'regular-file' }],
    });
    async function *source() {
      yield Buffer.from('ne');
      if (boundary === 'during-source') process.exit(71);
      yield Buffer.from('w');
    }
    await atomicWriteStream(workspace, 'asset.bin', source(), {
      maxBytes: 3, maxScratchBytes: 3, expectedBytes: 3,
      expectedSha256: createHash('sha256').update('new').digest('hex'), plan,
      hooks: { boundary: (name) => { if (name === boundary) process.exit(71); } },
    });
  `;
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', script, root, boundary], {
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    const stderr = [];
    child.stderr.on('data', (value) => stderr.push(value));
    child.once('error', reject);
    child.once('close', (status) => resolvePromise({ status, stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

test('streams multiple chunks into an atomic replacement without retaining source bytes', async t => {
  const { root, handle } = await createWorkspace(t);
  await seed(handle, 'Content/asset.bin', Buffer.from('old'));
  const prior = await lstat(join(root, 'Content/asset.bin'));
  let live = 0; let peak = 0;
  async function *source() {
    for (let index = 0; index < 256; index += 1) {
      const chunk = Buffer.alloc(4096, index);
      live += chunk.length; peak = Math.max(peak, live);
      yield chunk;
      live -= chunk.length;
    }
  }
  const expectedHash = createHash('sha256');
  for (let index = 0; index < 256; index += 1) expectedHash.update(Buffer.alloc(4096, index));
  const bound = await plan(handle, 'Content/asset.bin');
  const result = await atomicWriteStream(handle, 'Content/asset.bin', source(), {
    maxBytes: 1024 * 1024, maxScratchBytes: 1024 * 1024,
    expectedBytes: 1024 * 1024, expectedSha256: expectedHash.digest('hex'), plan: bound,
  });
  const bytes = await readFile(join(root, 'Content/asset.bin'));
  assert.equal(result.bytes, 1024 * 1024);
  assert.equal(bytes.length, 1024 * 1024);
  assert.equal(bytes[0], 0); assert.equal(bytes[4096], 1); assert.equal(bytes.at(-1), 255);
  assert.equal(peak, 4096);
  assert.notEqual((await lstat(join(root, 'Content/asset.bin'))).ino, prior.ino);
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('accepts a web ReadableStream and publishes executable intent', async t => {
  const { root, handle } = await createWorkspace(t);
  const source = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array([1, 2])); controller.enqueue(new Uint8Array([3, 4])); controller.close(); },
  });
  const bound = await plan(handle, 'Tools/run.bin', { kind: 'executable' });
  await atomicWriteStream(handle, 'Tools/run.bin', source, {
    createParents: true, executable: true, maxBytes: 4, maxScratchBytes: 4,
    expectedBytes: 4, expectedSha256: createHash('sha256').update(Buffer.from([1, 2, 3, 4])).digest('hex'), plan: bound,
  });
  assert.deepEqual(await readFile(join(root, 'Tools/run.bin')), Buffer.from([1, 2, 3, 4]));
  if (process.platform !== 'win32') assert.notEqual((await lstat(join(root, 'Tools/run.bin'))).mode & 0o100, 0);
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('portable executable intent does not require an unsupported native mode bit', async t => {
  const { root, handle } = await createWorkspace(t);
  const measured = await probeFilesystemCapabilities(root);
  const withoutExecutableBit = Object.freeze({ ...measured, executableBit: false });
  const capabilityProbe = async () => withoutExecutableBit;
  const bound = await plan(handle, 'Tools/portable.bin', {
    kind: 'executable', capabilities: withoutExecutableBit, capabilityProbe,
  });
  const bytes = Buffer.from([5, 6, 7, 8]);
  await atomicWriteStream(handle, 'Tools/portable.bin', chunks([bytes]), {
    createParents: true, executable: true, maxBytes: bytes.length, maxScratchBytes: bytes.length,
    expectedBytes: bytes.length, expectedSha256: createHash('sha256').update(bytes).digest('hex'), plan: bound,
  });
  assert.deepEqual(await readFile(join(root, 'Tools/portable.bin')), bytes);
  assert.equal((await lstat(join(root, 'Tools/portable.bin'))).mode & 0o100, 0);
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('requires the exact branded workspace and closed owner-bound preflight plan', async t => {
  const { handle } = await createWorkspace(t);
  const { handle: other } = await createWorkspace(t);
  const bound = await plan(handle, 'asset.bin');
  const integrity = { maxBytes: 1, maxScratchBytes: 1, expectedBytes: 1, expectedSha256: createHash('sha256').update('x').digest('hex') };
  await assert.rejects(atomicWriteStream(handle, 'asset.bin', chunks(['x']), integrity), code('CAPABILITY_UNAVAILABLE'));
  await assert.rejects(atomicWriteStream(Object.freeze({ ...handle }), 'asset.bin', chunks(['x']), { ...integrity, plan: bound }), code('UNSAFE_TARGET'));
  await assert.rejects(atomicWriteStream(other, 'asset.bin', chunks(['x']), { ...integrity, plan: bound }), code('CAPABILITY_UNAVAILABLE'));
  await assert.rejects(atomicWriteStream(handle, 'other.bin', chunks(['x']), { ...integrity, plan: bound }), code('ENTRY_INVALID'));
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('capability drift fails before stage creation and is rechecked after source consumption', async t => {
  const { root, handle } = await createWorkspace(t);
  const measured = await probeFilesystemCapabilities(root);
  let probes = 0;
  const earlyProbe = async () => {
    probes += 1;
    return probes === 1 ? measured : Object.freeze({ ...measured, atomicReplace: false });
  };
  const earlyPlan = await plan(handle, 'early.bin', { capabilities: measured, capabilityProbe: earlyProbe });
  const integrity = { maxBytes: 4, maxScratchBytes: 4, expectedBytes: 4, expectedSha256: createHash('sha256').update('late').digest('hex') };
  await assert.rejects(atomicWriteStream(handle, 'early.bin', chunks(['late']), { ...integrity, plan: earlyPlan }), code('CAPABILITY_UNAVAILABLE'));
  assert.deepEqual(await readdir(handle.transactions), []);

  probes = 0;
  const lateProbe = async () => {
    probes += 1;
    return probes < 4 ? measured : Object.freeze({ ...measured, atomicReplace: false });
  };
  const latePlan = await plan(handle, 'late.bin', { capabilities: measured, capabilityProbe: lateProbe });
  await assert.rejects(atomicWriteStream(handle, 'late.bin', chunks(['late']), { ...integrity, plan: latePlan }), code('CAPABILITY_UNAVAILABLE'));
  await assert.rejects(readFile(join(root, 'late.bin')));
  assert.deepEqual(await readdir(handle.transactions), []);

  await seed(handle, 'replace.bin', Buffer.from('old'));
  const noHardlink = Object.freeze({ ...measured, hardlink: false });
  const noHardlinkPlan = await plan(handle, 'replace.bin', { capabilities: noHardlink, capabilityProbe: async () => noHardlink });
  await assert.rejects(publish(handle, 'replace.bin', chunks(['new']), {
    plan: noHardlinkPlan, expected: Buffer.from('new'),
  }), code('CAPABILITY_UNAVAILABLE'));
  assert.equal(await readFile(join(root, 'replace.bin'), 'utf8'), 'old');
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('byte, scratch, chunk, operation, and time bounds fail typed and preserve the target', async t => {
  const { root, handle } = await createWorkspace(t);
  await seed(handle, 'asset.bin', Buffer.from('old'));
  for (const options of [
    { maxBytes: 3, maxScratchBytes: 8 },
    { maxBytes: 8, maxScratchBytes: 3 },
    { maxBytes: 8, maxScratchBytes: 8, maxChunkBytes: 3 },
    { maxBytes: 8, maxScratchBytes: 8, maxOperations: 2 },
  ]) {
    await assert.rejects(publish(handle, 'asset.bin', chunks(['four']), { ...options, expected: Buffer.from('four') }), code('LIMIT_EXCEEDED'));
    assert.equal(await readFile(join(root, 'asset.bin'), 'utf8'), 'old');
    assert.deepEqual(await readdir(handle.transactions), []);
  }
  const hanging = { [Symbol.asyncIterator]() { return { next: () => new Promise(() => {}), return: async () => ({ done: true }) }; } };
  await assert.rejects(publish(handle, 'asset.bin', hanging, { maxTimeMs: 10, expected: Buffer.alloc(0) }), code('LIMIT_EXCEEDED'));
  assert.equal(await readFile(join(root, 'asset.bin'), 'utf8'), 'old');
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('source errors and caller cancellation close the source and clean the private stage', async t => {
  const { root, handle } = await createWorkspace(t);
  await seed(handle, 'asset.bin', Buffer.from('old'));
  let finalized = false;
  async function *broken() {
    try { yield Buffer.from('part'); throw new Error('source failed'); }
    finally { finalized = true; }
  }
  await assert.rejects(publish(handle, 'asset.bin', broken(), { expected: Buffer.from('part') }), code('IO_ERROR'));
  assert.equal(finalized, true);

  const controller = new AbortController();
  async function *cancelled() { yield Buffer.from('part'); controller.abort(); yield Buffer.from('never'); }
  await assert.rejects(publish(handle, 'asset.bin', cancelled(), { signal: controller.signal, expected: Buffer.from('partnever') }), code('IO_ERROR'));
  await assert.rejects(publish(handle, 'asset.bin', chunks(['bad']), { expected: Buffer.from('new') }), code('TARGET_CHANGED'));
  await assert.rejects(publish(handle, 'asset.bin', chunks(['ne']), { expected: Buffer.from('new') }), code('TARGET_CHANGED'));
  assert.equal(await readFile(join(root, 'asset.bin'), 'utf8'), 'old');
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('stage, target, ancestor, sync, and rename faults never publish over the prior target', async t => {
  const { root, handle } = await createWorkspace(t);
  await seed(handle, 'Content/asset.bin', Buffer.from('old'));
  const target = join(root, 'Content/asset.bin');

  await assert.rejects(publish(handle, 'Content/asset.bin', chunks(['new']), {
    hooks: { boundary: async (name) => {
      if (name === 'after-stage') {
        const stage = (await readdir(handle.transactions)).find((entry) => entry.endsWith('.stage'));
        await writeFile(join(handle.transactions, stage), 'tampered');
      }
    } },
  }), code('TARGET_CHANGED'));
  assert.equal(await readFile(target, 'utf8'), 'old');
  assert.deepEqual(await readdir(handle.transactions), []);

  await assert.rejects(publish(handle, 'Content/asset.bin', chunks(['new']), {
    hooks: { boundary: async (name) => {
      if (name === 'before-publish') {
        await rename(target, join(root, 'Content/asset-displaced.bin'));
        await writeFile(target, 'racer');
      }
    } },
  }), code('ATOMIC_REPLACE_FAILED'));
  assert.equal(await readFile(join(root, 'Content/asset-displaced.bin'), 'utf8'), 'old');
  assert.equal(await readFile(target, 'utf8'), 'racer');
  await rm(target);
  await rename(join(root, 'Content/asset-displaced.bin'), target);
  const [targetRemnant] = await inspectCrashRemnants(handle);
  assert.equal((await rollbackCrashRemnant(handle, targetRemnant.id)).action, 'rolled-back');
  assert.deepEqual(await readdir(handle.transactions), []);

  await assert.rejects(publish(handle, 'Content/asset.bin', chunks(['new']), {
    hooks: { boundary: async (name) => {
      if (name === 'before-publish') {
        await rename(join(root, 'Content'), join(root, 'Content-displaced'));
        await mkdir(join(root, 'Content'), { mode: 0o700 });
      }
    } },
  }), code('ATOMIC_REPLACE_FAILED'));
  assert.equal(await readFile(join(root, 'Content-displaced/asset.bin'), 'utf8'), 'old');
  await rm(join(root, 'Content'), { recursive: true });
  await rename(join(root, 'Content-displaced'), join(root, 'Content'));
  const [ancestorRemnant] = await inspectCrashRemnants(handle);
  assert.equal(ancestorRemnant.operation, 'write-stream');
  assert.equal((await rollbackCrashRemnant(handle, ancestorRemnant.id)).action, 'rolled-back');
  assert.deepEqual(await readdir(handle.transactions), []);

  for (const boundary of ['before-parent-sync', 'after-publish']) {
    const prior = await lstat(target);
    await assert.rejects(publish(handle, 'Content/asset.bin', chunks(['new']), {
      hooks: { boundary: (name) => { if (name === boundary) { const error = new Error('fault'); error.code = 'EIO'; throw error; } } },
    }), code('ATOMIC_REPLACE_FAILED'));
    assert.equal(await readFile(target, 'utf8'), 'old');
    assert.equal((await lstat(target)).ino, prior.ino);
    assert.deepEqual(await readdir(handle.transactions), []);
  }

  await assert.rejects(publish(handle, 'Content/asset.bin', chunks(['new']), {
    maxRetries: 0,
    hooks: { boundary: (name) => { if (name === 'before-publish-attempt') { const error = new Error('busy'); error.code = 'EBUSY'; throw error; } } },
  }), code('TARGET_BUSY'));
  assert.equal(await readFile(target, 'utf8'), 'old');
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('no-follow component checks reject a symlink or junction ancestor', async t => {
  const { root, handle } = await createWorkspace(t);
  const outside = await mkdtemp(join(tmpdir(), 'ogvcs-stream-outside-'));
  t.after(() => rm(outside, { recursive: true, force: true }));
  try { await symlink(outside, join(root, 'Content'), process.platform === 'win32' ? 'junction' : 'dir'); }
  catch (error) { if (process.platform === 'win32' && ['EPERM', 'EACCES'].includes(error?.code)) return; throw error; }
  const bound = await plan(handle, 'Content/asset.bin');
  await assert.rejects(atomicWriteStream(handle, 'Content/asset.bin', chunks(['no']), {
    maxBytes: 2, maxScratchBytes: 2, expectedBytes: 2,
    expectedSha256: createHash('sha256').update('no').digest('hex'), plan: bound,
  }), code('UNSAFE_TARGET'));
  await assert.rejects(readFile(join(outside, 'asset.bin')));
  assert.deepEqual(await readdir(handle.transactions), []);

  if ((await probeFilesystemCapabilities(root)).hardlink) {
    await seed(handle, 'linked.bin', Buffer.from('old'));
    await link(join(root, 'linked.bin'), join(root, 'linked-alias.bin'));
    const linkedPlan = await plan(handle, 'linked.bin');
    await assert.rejects(atomicWriteStream(handle, 'linked.bin', chunks(['no']), {
      maxBytes: 2, maxScratchBytes: 2, expectedBytes: 2,
      expectedSha256: createHash('sha256').update('no').digest('hex'), plan: linkedPlan,
    }), code('UNSAFE_TARGET'));
    assert.equal(await readFile(join(root, 'linked-alias.bin'), 'utf8'), 'old');
    assert.deepEqual(await readdir(handle.transactions), []);
  }
});

test('restart recovery owns every partial-stream, rollback-link, publication, and commit boundary', async t => {
  for (const boundary of ['after-plan', 'during-source', 'after-backup-link', 'after-record', 'after-publish', 'after-commit']) {
    const { root, handle } = await createWorkspace(t);
    await seed(handle, 'asset.bin', Buffer.from('old'));
    const crashed = await runCrashChild(root, boundary);
    assert.equal(crashed.status, 71, `${boundary}: ${crashed.stderr}`);
    const [remnant] = await inspectCrashRemnants(handle);
    assert.equal(remnant.operation, 'write-stream', boundary);
    const recovery = await rollbackCrashRemnant(handle, remnant.id);
    if (boundary === 'after-commit') {
      assert.equal(recovery.action, 'finalized');
      assert.equal(await readFile(join(root, 'asset.bin'), 'utf8'), 'new');
    } else {
      assert.equal(recovery.action, 'rolled-back');
      assert.equal(await readFile(join(root, 'asset.bin'), 'utf8'), 'old');
    }
    assert.deepEqual(await readdir(handle.transactions), []);
  }

  const { root, handle } = await createWorkspace(t);
  const crashed = await runCrashChild(root, 'after-publish');
  assert.equal(crashed.status, 71, crashed.stderr);
  const [remnant] = await inspectCrashRemnants(handle);
  assert.equal((await rollbackCrashRemnant(handle, remnant.id)).action, 'rolled-back');
  await assert.rejects(readFile(join(root, 'asset.bin')));
  assert.deepEqual(await readdir(handle.transactions), []);
});

test('post-commit observer failure preserves durable success and a recoverable committed record', async t => {
  const { root, handle } = await createWorkspace(t);
  await seed(handle, 'asset.bin', Buffer.from('old'));
  const expected = Buffer.from('new');
  const result = await publish(handle, 'asset.bin', chunks([expected]), {
    expected,
    hooks: { boundary(name) {
      if (name === 'after-commit') throw new Error('post-commit observer failed');
    } },
  });
  assert.equal(result.bytes, expected.length);
  assert.equal(result.sha256, createHash('sha256').update(expected).digest('hex'));
  assert.deepEqual(await readFile(join(root, 'asset.bin')), expected);

  const [remnant] = await inspectCrashRemnants(handle);
  assert.equal(remnant.operation, 'write-stream');
  assert.equal(remnant.state, 'committed');
  assert.equal((await rollbackCrashRemnant(handle, remnant.id)).action, 'finalized');
  assert.deepEqual(await readdir(handle.transactions), []);
});
