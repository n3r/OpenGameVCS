import { constants } from 'node:fs';
import { chmod, link, lstat, mkdir, mkdtemp, open, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { basename, isAbsolute, join, resolve } from 'node:path';

import { asPathError, pathFail } from './errors.mjs';
import { OperationGuard } from './resource.mjs';

export function hostPlatform(nodePlatform = process.platform) {
  if (nodePlatform === 'win32') return 'windows';
  if (nodePlatform === 'darwin') return 'macos';
  if (nodePlatform === 'linux') return 'linux';
  pathFail('CAPABILITY_UNAVAILABLE', undefined, { capability: 'supported-platform' });
}

async function directorySync(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY);
    await handle.sync();
    return true;
  } catch { return false; }
  finally { await handle?.close().catch(() => {}); }
}

export async function probeFilesystemCapabilities(root, options = {}) {
  const guard = new OperationGuard({ maxTimeMs: options.maxTimeMs ?? 15_000, maxOperations: 256 });
  if (typeof root !== 'string' || root.length === 0 || !isAbsolute(root)) pathFail('PATH_INPUT_INVALID');
  const absolute = resolve(root);
  let rootInfo;
  try { rootInfo = await lstat(absolute); } catch (error) { throw asPathError(error); }
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) pathFail('UNSAFE_TARGET');
  const probe = await mkdtemp(join(absolute, '.ogvcs-capability-'));
  try {
    const recheckedRoot = await lstat(absolute);
    if (!recheckedRoot.isDirectory() || recheckedRoot.isSymbolicLink() || String(recheckedRoot.dev) !== String(rootInfo.dev) || String(recheckedRoot.ino) !== String(rootInfo.ino)) pathFail('TARGET_CHANGED');
    await chmod(probe, 0o700).catch(() => {});
    guard.checkpoint();

    const caseName = join(probe, 'CaseProbe');
    await writeFile(caseName, 'case', { flag: 'wx' });
    const caseAlias = await lstat(join(probe, 'caseprobe')).then(() => true, () => false);

    const composed = join(probe, 'é');
    const decomposed = join(probe, 'é');
    await writeFile(composed, 'normalization', { flag: 'wx' });
    const normalizationAlias = await lstat(decomposed).then(() => true, () => false);

    const atomicFrom = join(probe, 'atomic.from');
    const atomicTo = join(probe, 'atomic.to');
    await writeFile(atomicFrom, 'new', { flag: 'wx' });
    await writeFile(atomicTo, 'old', { flag: 'wx' });
    let atomicReplace = false;
    try { await rename(atomicFrom, atomicTo); atomicReplace = (await readFile(atomicTo, 'utf8')) === 'new'; } catch { atomicReplace = false; }

    const executablePath = join(probe, 'executable');
    await writeFile(executablePath, '#!/bin/sh\n', { flag: 'wx', mode: 0o600 });
    let executableBit = false;
    try { await chmod(executablePath, 0o700); executableBit = ((await stat(executablePath)).mode & 0o100) !== 0; } catch { executableBit = false; }

    const hardlinkSource = join(probe, 'hardlink.source');
    const hardlinkTarget = join(probe, 'hardlink.target');
    await writeFile(hardlinkSource, 'hardlink', { flag: 'wx' });
    let hardlinkCapability = false;
    try { await link(hardlinkSource, hardlinkTarget); hardlinkCapability = (await stat(hardlinkSource)).ino === (await stat(hardlinkTarget)).ino; } catch { hardlinkCapability = false; }

    const symlinkSource = join(probe, 'symlink.source');
    const symlinkTarget = join(probe, 'symlink.target');
    await writeFile(symlinkSource, 'symlink', { flag: 'wx' });
    let symlinkCapability = false;
    try {
      await symlink(basename(symlinkSource), symlinkTarget, 'file');
      const info = await lstat(symlinkTarget);
      symlinkCapability = info.isSymbolicLink();
    } catch { symlinkCapability = false; }

    guard.checkpoint();
    return Object.freeze({
      schemaVersion: 'ogvcs.path/filesystem-capabilities/v1',
      platform: hostPlatform(), caseSensitive: !caseAlias,
      normalizationSensitive: !normalizationAlias, casePreserving: true,
      atomicReplace, directorySync: await directorySync(probe),
      executableBit, hardlink: hardlinkCapability, symlink: symlinkCapability,
    });
  } catch (error) { throw asPathError(error); }
  finally { await rm(probe, { recursive: true, force: true, maxRetries: 4, retryDelay: 25 }).catch(() => {}); }
}
