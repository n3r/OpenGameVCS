import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, open, opendir, readdir, readlink, realpath, rename, rm } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

import { asPathError, PathFilesystemError, pathFail } from './errors.mjs';
import { authorizeWorkspaceMutation, authorizeWorkspaceMutations } from './materialization-plan.mjs';
import { isUnicodeScalarString, validateRepositoryPath } from './path.mjs';
import { planRenames } from './rename.mjs';
import { boundedBytes, OperationGuard } from './resource.mjs';
import { assertPathTelemetry, recordPathTelemetry } from './telemetry.mjs';

const RECORD_VERSION = 'ogvcs.path/workspace-transaction/v1';
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_STREAM_CHUNK_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_REMNANTS = 1024;
const DEFAULT_MAX_DIRECTORY_ENTRIES = 100_000;
const DEFAULT_MAX_DIRECTORY_DEPTH = 256;
const WORKSPACE_HANDLES = new WeakSet();
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const DIRECTORY_ONLY = constants.O_DIRECTORY ?? 0;

function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
function recordBytes(value) { return Buffer.from(`${canonicalJson(value)}\n`, 'utf8'); }
function identity(info) { return Object.freeze({ dev: String(info.dev), ino: String(info.ino), mode: info.mode, size: info.size, mtimeMs: Math.trunc(info.mtimeMs) }); }
function sameIdentity(left, right) { return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode && left.size === right.size && left.mtimeMs === right.mtimeMs; }
function sameNode(left, right) { return left.dev === right.dev && left.ino === right.ino && (left.mode & constants.S_IFMT) === (right.mode & constants.S_IFMT); }
function sameBoundDirectory(left, right) { return sameNode(left, right) && (left.mode & 0o7777) === (right.mode & 0o7777); }
function privateDirectory(info) { return process.platform === 'win32' || (info.mode & 0o077) === 0; }
function transactionId(value) { return typeof value === 'string' && /^[0-9a-f]{32}$/u.test(value); }
function renameTransactionId(value) { return typeof value === 'string' && /^[0-9a-f]{24}$/u.test(value); }

export function assertWorkspaceHandle(workspace) {
  if (workspace === null || typeof workspace !== 'object' || !WORKSPACE_HANDLES.has(workspace)) pathFail('UNSAFE_TARGET');
  return workspace;
}

async function syncFile(handle) { await handle.sync(); }
async function syncDirectory(path) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW | DIRECTORY_ONLY);
    if (!(await handle.stat()).isDirectory()) pathFail('UNSAFE_TARGET');
    try { await handle.sync(); }
    catch (error) {
      // Windows exposes directory handles but does not implement fsync for
      // them. Keep that measured capability distinction without treating a
      // real path-open/ACL denial as a successful durability barrier.
      if (process.platform === 'win32' && error?.code === 'EPERM') return;
      throw error;
    }
  }
  catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR', 'EBADF'].includes(error?.code)) throw error;
  } finally { await handle?.close().catch(() => {}); }
}

async function exclusiveFile(path, bytes, mode = 0o600) {
  const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, mode);
  try { await handle.writeFile(bytes); await syncFile(handle); }
  finally { await handle.close(); }
}

function abortError() {
  return new PathFilesystemError('IO_ERROR', 'stream publication was cancelled', { details: { resource: 'cancellation' } });
}

function deadlineError() {
  return new PathFilesystemError('LIMIT_EXCEEDED', 'stream publication exceeded its deadline', { details: { resource: 'time' } });
}

function assertAbortSignal(signal) {
  if (signal === undefined) return;
  if (signal === null || typeof signal !== 'object' || typeof signal.aborted !== 'boolean'
    || typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function') pathFail('PATH_INPUT_INVALID');
}

function checkpoint(guard, signal) {
  if (signal?.aborted) throw abortError();
  guard.checkpoint();
}

function raceSignals(promise, deadlineSignal, callerSignal) {
  return new Promise((resolvePromise, reject) => {
    let settled = false;
    const finish = (action, value) => {
      if (settled) return;
      settled = true;
      deadlineSignal?.removeEventListener('abort', onDeadline);
      callerSignal?.removeEventListener('abort', onCaller);
      action(value);
    };
    const onDeadline = () => finish(reject, deadlineError());
    const onCaller = () => finish(reject, abortError());
    if (deadlineSignal?.aborted) { onDeadline(); return; }
    if (callerSignal?.aborted) { onCaller(); return; }
    deadlineSignal?.addEventListener('abort', onDeadline, { once: true });
    callerSignal?.addEventListener('abort', onCaller, { once: true });
    Promise.resolve(promise).then(
      (value) => finish(resolvePromise, value),
      (error) => finish(reject, error),
    );
  });
}

async function guardedBoundary(guard, signal, action) {
  checkpoint(guard, signal);
  return guard.boundary((deadlineSignal) => raceSignals(Promise.resolve().then(action), deadlineSignal, signal), true);
}

async function settledBoundary(guard, signal, action) {
  checkpoint(guard, signal);
  const result = await action();
  checkpoint(guard, signal);
  return result;
}

function streamingLimits(options) {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxScratchBytes = options.maxScratchBytes ?? maxBytes;
  const maxChunkBytes = options.maxChunkBytes ?? Math.min(maxBytes, DEFAULT_MAX_STREAM_CHUNK_BYTES);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0
    || !Number.isSafeInteger(maxScratchBytes) || maxScratchBytes < 0
    || !Number.isSafeInteger(maxChunkBytes) || maxChunkBytes < 0) {
    pathFail('LIMIT_EXCEEDED', undefined, { resource: 'configuration' });
  }
  return Object.freeze({ maxBytes, maxScratchBytes, maxChunkBytes });
}

function streamChunk(value, maximum) {
  let view;
  if (value instanceof ArrayBuffer) view = new Uint8Array(value);
  else if (ArrayBuffer.isView(value)) view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  else pathFail('PATH_INPUT_INVALID');
  if (view.byteLength > maximum) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'chunkBytes' });
  return Buffer.from(view);
}

function byteSource(source) {
  let getReader;
  try { getReader = source !== null && typeof source === 'object' ? source.getReader : undefined; }
  catch (error) { throw asPathError(error, 'IO_ERROR', 'stream source could not be opened'); }
  if (typeof getReader === 'function') {
    let reader;
    try { reader = getReader.call(source); } catch (error) { throw asPathError(error, 'IO_ERROR', 'stream source could not be opened'); }
    return Object.freeze({
      next: () => reader.read(),
      close: (error) => error === undefined ? Promise.resolve(reader.releaseLock()) : reader.cancel(error).finally(() => reader.releaseLock()),
    });
  }
  let factory;
  try { factory = source?.[Symbol.asyncIterator]; }
  catch (error) { throw asPathError(error, 'IO_ERROR', 'stream source could not be opened'); }
  if (typeof factory !== 'function') pathFail('PATH_INPUT_INVALID');
  let iterator;
  try { iterator = factory.call(source); } catch (error) { throw asPathError(error, 'IO_ERROR', 'stream source could not be opened'); }
  if (iterator === null || typeof iterator !== 'object' || typeof iterator.next !== 'function') pathFail('PATH_INPUT_INVALID');
  return Object.freeze({
    next: () => iterator.next(),
    close: (error) => error === undefined || typeof iterator.return !== 'function' ? Promise.resolve() : Promise.resolve(iterator.return()),
  });
}

async function streamToExclusiveFile(path, source, limits, mode, guard, signal) {
  const adapter = byteSource(source);
  let handle; let sourceFailure; let closeFailure; let result; let bytes = 0;
  const hasher = createHash('sha256');
  try {
    handle = await settledBoundary(guard, signal, () => open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | NO_FOLLOW, mode));
    const opened = await settledBoundary(guard, signal, () => handle.stat());
    if (!opened.isFile() || opened.nlink !== 1) pathFail('UNSAFE_TARGET');
    for (;;) {
      let item;
      try { item = await guardedBoundary(guard, signal, () => adapter.next()); }
      catch (error) {
        if (error instanceof PathFilesystemError) throw error;
        throw asPathError(error, 'IO_ERROR', 'stream source failed');
      }
      if (item === null || typeof item !== 'object' || typeof item.done !== 'boolean') pathFail('PATH_INPUT_INVALID');
      if (item.done) break;
      const chunk = streamChunk(item.value, limits.maxChunkBytes);
      if (bytes > limits.maxBytes - chunk.length) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'bytes' });
      if (bytes > limits.maxScratchBytes - chunk.length) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'scratchBytes' });
      let offset = 0;
      while (offset < chunk.length) {
        const result = await settledBoundary(guard, signal, () => handle.write(chunk, offset, chunk.length - offset, null));
        if (!Number.isSafeInteger(result?.bytesWritten) || result.bytesWritten <= 0) pathFail('IO_ERROR');
        offset += result.bytesWritten;
      }
      hasher.update(chunk);
      bytes += chunk.length;
    }
    await settledBoundary(guard, signal, () => handle.sync());
    const after = await settledBoundary(guard, signal, () => handle.stat());
    if (!after.isFile() || after.nlink !== 1 || after.size !== bytes || !sameNode(identity(opened), identity(after))) pathFail('TARGET_CHANGED');
    result = Object.freeze({ bytes, sha256: hasher.digest('hex') });
  } catch (error) {
    sourceFailure = error;
  } finally {
    await handle?.close().catch(() => {});
    try {
      const closeGuard = new OperationGuard({ maxTimeMs: 1000, maxOperations: 4 });
      await closeGuard.boundary(
        (deadlineSignal) => raceSignals(Promise.resolve().then(() => adapter.close(sourceFailure)), deadlineSignal), true,
      );
    } catch (error) { closeFailure = error; }
  }
  if (sourceFailure !== undefined) throw sourceFailure;
  if (closeFailure !== undefined) throw asPathError(closeFailure, 'IO_ERROR', 'stream source could not be closed');
  return result;
}

async function removeIfPresent(path) {
  await rm(path).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
}

async function ensurePrivateDirectory(path) {
  await mkdir(path, { recursive: false, mode: 0o700 }).catch((error) => { if (error?.code !== 'EEXIST') throw error; });
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) pathFail('UNSAFE_TARGET');
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW | DIRECTORY_ONLY);
    const opened = await handle.stat();
    if (!opened.isDirectory() || !sameNode(identity(info), identity(opened))) pathFail('UNSAFE_TARGET');
    if (process.platform !== 'win32') await handle.chmod(0o700);
    const secured = await handle.stat();
    if (!secured.isDirectory() || !privateDirectory(secured)) pathFail('UNSAFE_TARGET');
    return identity(secured);
  } finally { await handle?.close().catch(() => {}); }
}

function confined(root, candidate) {
  const rel = relative(root, candidate);
  return rel !== '' && !rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel);
}

async function openWorkspaceRootInternal(root, options = {}) {
  if (typeof root !== 'string' || root.length === 0 || !isAbsolute(root)) pathFail('PATH_INPUT_INVALID');
  const caseMode = options.caseMode ?? 'case-sensitive';
  if (!['case-sensitive', 'case-folded'].includes(caseMode)) pathFail('CASE_MODE_INVALID');
  const profile = options.profile ?? 'path.opengamevcs/portable@1';
  validateRepositoryPath('workspace-profile-check', { profile });
  const absolute = resolve(root);
  let info;
  try { info = await lstat(absolute); } catch (error) { throw asPathError(error); }
  if (!info.isDirectory() || info.isSymbolicLink()) pathFail('UNSAFE_TARGET');
  const canonicalRoot = await realpath(absolute);
  const rootInfo = await lstat(canonicalRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || !privateDirectory(rootInfo)) pathFail('UNSAFE_TARGET');
  const control = join(canonicalRoot, '.ogvcs');
  const transactions = join(control, 'transactions');
  const renameRoot = join(control, 'rename');
  try {
    const controlIdentity = await ensurePrivateDirectory(control);
    const transactionsIdentity = await ensurePrivateDirectory(transactions);
    const renameIdentity = await ensurePrivateDirectory(renameRoot);
    const workspace = {
      schemaVersion: 'ogvcs.path/workspace-root/v1', root: canonicalRoot, control,
      transactions, renameRoot, identity: identity(await lstat(canonicalRoot)),
      controlIdentity, transactionsIdentity, renameIdentity,
      profile, caseMode,
    };
    WORKSPACE_HANDLES.add(workspace);
    return Object.freeze(workspace);
  } catch (error) { throw asPathError(error, 'UNSAFE_TARGET'); }
}

async function assertBoundDirectory(path, expected) {
  let pathInfo;
  try { pathInfo = await lstat(path); }
  catch (error) { if (['ENOENT', 'ENOTDIR'].includes(error?.code)) pathFail('TARGET_CHANGED'); throw error; }
  if (!pathInfo.isDirectory() || pathInfo.isSymbolicLink() || !sameBoundDirectory(expected, identity(pathInfo))) pathFail('TARGET_CHANGED');
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW | DIRECTORY_ONLY);
    const opened = await handle.stat();
    if (!opened.isDirectory() || !sameBoundDirectory(expected, identity(opened)) || !sameBoundDirectory(identity(pathInfo), identity(opened))) pathFail('TARGET_CHANGED');
  } finally { await handle?.close().catch(() => {}); }
}

async function assertWorkspaceDirectories(workspace) {
  assertWorkspaceHandle(workspace);
  await assertBoundDirectory(workspace.root, workspace.identity);
  await assertBoundDirectory(workspace.control, workspace.controlIdentity);
  await assertBoundDirectory(workspace.transactions, workspace.transactionsIdentity);
  await assertBoundDirectory(workspace.renameRoot, workspace.renameIdentity);
}

export async function assertWorkspaceAuthority(workspace) {
  await assertWorkspaceDirectories(workspace);
  return workspace;
}

async function bindComponents(workspace, canonicalPath, options = {}) {
  const segments = canonicalPath.split('/');
  let current = workspace.root; const ancestors = [];
  for (let index = 0; index < segments.length - (options.includeTarget ? 0 : 1); index += 1) {
    current = join(current, segments[index]);
    let info;
    try { info = await lstat(current); }
    catch (error) {
      if (error?.code === 'ENOENT' && options.createParents && index < segments.length - 1) {
        await mkdir(current, { mode: 0o700 });
        info = await lstat(current);
      } else throw error;
    }
    if (!info.isDirectory() || info.isSymbolicLink()) pathFail('UNSAFE_TARGET');
    ancestors.push(Object.freeze({ path: current, identity: identity(info) }));
  }
  return Object.freeze({ target: join(workspace.root, ...segments), ancestors: Object.freeze(ancestors) });
}

async function inspectComponents(workspace, canonicalPath, options = {}) {
  return (await bindComponents(workspace, canonicalPath, options)).target;
}

async function assertComponentBindings(binding) {
  for (const ancestor of binding.ancestors) await assertBoundDirectory(ancestor.path, ancestor.identity);
}

async function targetIdentity(path) {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) pathFail('UNSAFE_TARGET');
    return identity(info);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

async function regularTargetState(path, options = {}) {
  let pathInfo;
  try { pathInfo = await lstat(path); }
  catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
  const expectedLinks = options.expectedLinks ?? 1;
  if (!Number.isSafeInteger(expectedLinks) || expectedLinks < 1) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'configuration' });
  if (!pathInfo.isFile() || pathInfo.isSymbolicLink() || pathInfo.nlink !== expectedLinks) pathFail('UNSAFE_TARGET');
  const handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== expectedLinks || !sameNode(identity(pathInfo), identity(before))) pathFail('TARGET_CHANGED');
    const maximum = options.maxBytes ?? DEFAULT_MAX_BYTES;
    if (!Number.isSafeInteger(maximum) || maximum < 0 || before.size > maximum) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'observedBytes' });
    const hasher = createHash('sha256');
    const buffer = Buffer.allocUnsafe(Math.max(1, Math.min(64 * 1024, before.size)));
    let offset = 0;
    while (offset < before.size) {
      options.guard?.checkpoint();
      const length = Math.min(buffer.length, before.size - offset);
      const { bytesRead } = await handle.read(buffer, 0, length, offset);
      if (bytesRead <= 0) pathFail('TARGET_CHANGED');
      hasher.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (after.nlink !== expectedLinks || !sameIdentity(identity(before), identity(after)) || offset !== before.size) pathFail('TARGET_CHANGED');
    return Object.freeze({ identity: identity(after), sha256: hasher.digest('hex'), bytes: offset });
  } finally { await handle.close(); }
}

function directoryLimits(options) {
  const maxEntries = options.maxDirectoryEntries ?? DEFAULT_MAX_DIRECTORY_ENTRIES;
  const maxDepth = options.maxDirectoryDepth ?? DEFAULT_MAX_DIRECTORY_DEPTH;
  const maxBytes = options.maxDirectoryBytes ?? options.maxBytes ?? DEFAULT_MAX_BYTES;
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 0 || maxEntries > DEFAULT_MAX_DIRECTORY_ENTRIES
    || !Number.isSafeInteger(maxDepth) || maxDepth < 0 || maxDepth > DEFAULT_MAX_DIRECTORY_DEPTH
    || !Number.isSafeInteger(maxBytes) || maxBytes < 0) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'configuration' });
  return { maxEntries, maxDepth, maxBytes };
}

async function exactSymlinkState(path, maximumBytes) {
  const beforeInfo = await lstat(path);
  if (!beforeInfo.isSymbolicLink()) pathFail('UNSAFE_TARGET');
  const target = await readlink(path);
  const bytes = Buffer.byteLength(target, 'utf8');
  if (bytes > maximumBytes) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'observedBytes' });
  const afterInfo = await lstat(path);
  const before = identity(beforeInfo); const after = identity(afterInfo);
  if (!afterInfo.isSymbolicLink() || !sameIdentity(before, after)) pathFail('TARGET_CHANGED');
  return Object.freeze({ identity: after, target, bytes });
}

async function directoryTargetState(path, options = {}) {
  const limits = directoryLimits(options);
  const hasher = createHash('sha256');
  let entries = 0; let bytes = 0;

  const walk = async (current, relativePath, depth) => {
    options.guard?.checkpoint();
    if (depth > limits.maxDepth) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'directoryDepth' });
    const beforeInfo = await lstat(current);
    if (!beforeInfo.isDirectory() || beforeInfo.isSymbolicLink()) pathFail('UNSAFE_TARGET');
    const before = identity(beforeInfo);
    const names = [];
    const directory = await opendir(current);
    try {
      for await (const item of directory) {
        options.guard?.checkpoint();
        entries += 1;
        if (entries > limits.maxEntries) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'directoryEntries' });
        names.push(item.name);
      }
    } finally { await directory.close().catch((error) => { if (error?.code !== 'ERR_DIR_CLOSED') throw error; }); }
    names.sort((left, right) => Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')));
    for (const name of names) {
      options.guard?.checkpoint();
      const child = join(current, name);
      const childRelative = relativePath === '' ? name : `${relativePath}/${name}`;
      const info = await lstat(child);
      if (info.isSymbolicLink()) {
        const state = await exactSymlinkState(child, limits.maxBytes - bytes);
        bytes += state.bytes;
        hasher.update(recordBytes({ path: childRelative, kind: 'symlink', identity: state.identity, target: state.target }));
      } else if (info.isFile()) {
        const state = await regularTargetState(child, { ...options, maxBytes: limits.maxBytes - bytes });
        bytes += state.bytes;
        hasher.update(recordBytes({ path: childRelative, kind: 'regular', state }));
      } else if (info.isDirectory()) {
        const childIdentity = await walk(child, childRelative, depth + 1);
        hasher.update(recordBytes({ path: childRelative, kind: 'directory', identity: childIdentity }));
      } else {
        pathFail('UNSAFE_TARGET');
      }
    }
    const afterInfo = await lstat(current);
    const after = identity(afterInfo);
    if (!afterInfo.isDirectory() || afterInfo.isSymbolicLink() || !sameIdentity(before, after)) pathFail('TARGET_CHANGED');
    return after;
  };

  const rootIdentity = await walk(path, '', 0);
  return Object.freeze({ identity: rootIdentity, treeSha256: hasher.digest('hex'), entries, bytes });
}

async function boundedRegularBytes(path, maximum) {
  const pathInfo = await lstat(path);
  if (!pathInfo.isFile() || pathInfo.isSymbolicLink() || pathInfo.nlink !== 1 || pathInfo.size > maximum) pathFail('CRASH_REMNANT');
  const handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size > maximum || !sameNode(identity(pathInfo), identity(before))) pathFail('CRASH_REMNANT');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.nlink !== 1 || !sameIdentity(identity(before), identity(after)) || bytes.length !== before.size) pathFail('CRASH_REMNANT');
    return bytes;
  } finally { await handle.close(); }
}

function sameRegularState(left, right) {
  return left !== null && right !== null && sameIdentity(left.identity, right.identity) && left.sha256 === right.sha256 && left.bytes === right.bytes;
}

async function exactRegularTarget(path, expected, options = {}) {
  const current = await regularTargetState(path, options);
  if ((expected === null) !== (current === null) || (expected !== null && !sameRegularState(expected, current))) pathFail('TARGET_CHANGED');
  return current;
}

async function entryState(path, options = {}) {
  const info = await lstat(path).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
  if (info === null) return null;
  if (info.isSymbolicLink()) pathFail('UNSAFE_TARGET');
  if (info.isFile()) {
    const state = await regularTargetState(path, options);
    return Object.freeze({ kind: 'regular', state });
  }
  if (info.isDirectory()) {
    try { return Object.freeze({ kind: 'directory', state: await directoryTargetState(path, options) }); }
    catch (error) {
      if (['ENOENT', 'ENOTDIR'].includes(error?.code)) pathFail('TARGET_CHANGED');
      throw error;
    }
  }
  pathFail('UNSAFE_TARGET');
}

function sameEntryState(left, right) {
  if (left === null || right === null || left.kind !== right.kind) return false;
  return left.kind === 'regular'
    ? sameRegularState(left.state, right.state)
    : sameIdentity(left.state.identity, right.state.identity) && left.state.treeSha256 === right.state.treeSha256
      && left.state.entries === right.state.entries && left.state.bytes === right.state.bytes;
}

async function exactEntryState(path, expected, options = {}) {
  const current = await entryState(path, options);
  if ((expected === null) !== (current === null) || (expected !== null && !sameEntryState(expected, current))) pathFail('TARGET_CHANGED');
  return current;
}

async function exactTarget(path, expected) {
  const current = await targetIdentity(path);
  if ((expected === null) !== (current === null) || (expected !== null && !sameIdentity(expected, current))) pathFail('TARGET_CHANGED');
}

async function writeRecord(path, value) {
  const temporary = `${path}.${randomUUID().replaceAll('-', '')}.tmp`;
  try {
    await exclusiveFile(temporary, recordBytes(value));
    await rename(temporary, path);
    await syncDirectory(dirname(path));
  } catch (error) {
    await removeIfPresent(temporary).catch(() => {});
    throw error;
  }
}

async function publishWithRetry(stage, target, options, guard) {
  const retries = options.maxRetries ?? 8;
  if (!Number.isSafeInteger(retries) || retries < 0 || retries > 1000) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'retries' });
  for (let attempt = 0; ; attempt += 1) {
    guard.checkpoint();
    try {
      await guard.hook(options.hooks, 'before-publish-attempt', Object.freeze({ attempt }));
      await rename(stage, target);
      return;
    }
    catch (error) {
      if (!['EACCES', 'EBUSY', 'EPERM', 'ETXTBSY'].includes(error?.code) || attempt >= retries) {
        recordPathTelemetry(options.telemetry, 'atomic-fallback-refused');
        if (['EACCES', 'EBUSY', 'EPERM', 'ETXTBSY'].includes(error?.code)) pathFail('TARGET_BUSY', undefined, { attempts: attempt + 1 });
        throw error;
      }
      recordPathTelemetry(options.telemetry, 'busy-retry');
      await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.min(250, 5 * (2 ** attempt))));
    }
  }
}

async function atomicWriteFileInternal(workspace, repositoryPath, content, options = {}) {
  assertWorkspaceHandle(workspace);
  const guard = new OperationGuard(options);
  const bytes = boundedBytes(content, options.maxBytes ?? DEFAULT_MAX_BYTES, 'bytes');
  const canonical = validateRepositoryPath(repositoryPath, { profile: workspace.profile }).canonical;
  await authorizeWorkspaceMutation(options.plan, workspace, {
    path: canonical, kinds: [options.executable === true ? 'executable' : 'regular'],
  });
  await assertWorkspaceDirectories(workspace);
  let binding;
  try { binding = await bindComponents(workspace, canonical, { createParents: options.createParents === true }); }
  catch (error) { throw asPathError(error, 'UNSAFE_TARGET'); }
  const { target } = binding;
  if (!confined(workspace.root, target)) pathFail('UNSAFE_TARGET');
  const observed = {
    guard, maxBytes: options.maxObservedBytes ?? options.maxBytes ?? DEFAULT_MAX_BYTES,
    maxDirectoryBytes: options.maxDirectoryBytes, maxDirectoryEntries: options.maxDirectoryEntries,
    maxDirectoryDepth: options.maxDirectoryDepth,
  };
  const before = await regularTargetState(target, observed);
  const id = randomUUID().replaceAll('-', '');
  const stage = join(workspace.transactions, `${id}.stage`);
  const recordPath = join(workspace.transactions, `${id}.json`);
  const planned = {
    schemaVersion: RECORD_VERSION, id, operation: 'write-file', path: canonical,
    stage: basename(stage), sha256: digest(bytes), bytes: bytes.length,
    prior: before, state: 'planned',
  };
  let recordDurable = false;
  try {
    await writeRecord(recordPath, planned);
    recordDurable = true;
    await guard.hook(options.hooks, 'after-plan', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await exclusiveFile(stage, bytes, options.executable === true ? 0o700 : 0o600);
    await guard.hook(options.hooks, 'after-stage', Object.freeze({ bytes: bytes.length }));
    await assertWorkspaceDirectories(workspace);
    const staged = await regularTargetState(stage, observed);
    if (staged === null || staged.bytes !== bytes.length || staged.sha256 !== planned.sha256) pathFail('TARGET_CHANGED');
    const record = { ...planned, staged, state: 'staged' };
    await writeRecord(recordPath, record);
    await guard.hook(options.hooks, 'after-record', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await assertComponentBindings(binding);
    await inspectComponents(workspace, canonical);
    await exactRegularTarget(target, before, observed);
    await guard.hook(options.hooks, 'before-publish', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await assertComponentBindings(binding);
    await inspectComponents(workspace, canonical);
    await exactRegularTarget(target, before, observed);
    await exactRegularTarget(stage, staged, observed);
    await publishWithRetry(stage, target, options, guard);
    await syncDirectory(dirname(target));
    const published = await regularTargetState(target, observed);
    if (!sameRegularState(staged, published) || published.bytes !== bytes.length || published.sha256 !== record.sha256) pathFail('ATOMIC_REPLACE_FAILED');
    await guard.hook(options.hooks, 'after-publish', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await writeRecord(recordPath, { ...record, state: 'committed', published: published });
    await guard.hook(options.hooks, 'after-commit', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await rm(recordPath);
    await syncDirectory(workspace.transactions);
    return Object.freeze({ path: canonical, bytes: bytes.length, sha256: record.sha256, transaction: id });
  } catch (error) {
    if (!recordDurable) {
      const recordExists = await lstat(recordPath).then(() => true, (failure) => failure?.code === 'ENOENT' ? false : Promise.reject(failure)).catch(() => true);
      if (!recordExists) await removeIfPresent(stage).catch(() => {});
    }
    if (error instanceof PathFilesystemError) throw error;
    throw asPathError(error, 'ATOMIC_REPLACE_FAILED');
  }
}

async function guardedHook(guard, signal, hooks, name, context = Object.freeze({})) {
  checkpoint(guard, signal);
  await guard.hook(hooks, name, context);
  checkpoint(guard, signal);
}

async function removeStreamingArtifact(path) {
  const info = await lstat(path).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
  if (info === null) return;
  if (!info.isFile() || info.isSymbolicLink()) pathFail('TARGET_CHANGED');
  await rm(path);
}

async function assertOwnedPartialStage(path) {
  const pathInfo = await lstat(path);
  if (!pathInfo.isFile() || pathInfo.isSymbolicLink() || pathInfo.nlink !== 1) pathFail('CRASH_REMNANT');
  const handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || !sameNode(identity(pathInfo), identity(opened))) pathFail('CRASH_REMNANT');
  } finally { await handle.close(); }
}

async function createRollbackLink(target, backup, prior, observed, guard, signal) {
  await settledBoundary(guard, signal, () => link(target, backup));
  const linkedObserved = { ...observed, expectedLinks: 2 };
  const current = await settledBoundary(guard, signal, () => regularTargetState(target, linkedObserved));
  const backupState = await settledBoundary(guard, signal, () => regularTargetState(backup, linkedObserved));
  if (!sameRegularState(prior, current) || !sameRegularState(prior, backupState)
    || !sameNode(current.identity, backupState.identity)) pathFail('TARGET_CHANGED');
  return backupState;
}

function streamExpectation(options, limits) {
  const expectedBytes = options.expectedBytes;
  const expectedSha256 = options.expectedSha256;
  if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 0
    || typeof expectedSha256 !== 'string' || !/^[0-9a-f]{64}$/u.test(expectedSha256)) pathFail('PATH_INPUT_INVALID');
  if (expectedBytes > limits.maxBytes) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'bytes' });
  if (expectedBytes > limits.maxScratchBytes) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'scratchBytes' });
  return Object.freeze({ bytes: expectedBytes, sha256: expectedSha256, executable: options.executable === true });
}

async function recoverWriteStreamRecord(workspace, recordPath, record, observed = {}) {
  const canonical = validateRepositoryPath(record.path, { profile: workspace.profile }).canonical;
  const binding = await bindComponents(workspace, canonical);
  const target = binding.target;
  const stage = join(workspace.transactions, record.stage);
  const backup = join(workspace.transactions, record.backup);
  if (!confined(workspace.root, target) || !confined(workspace.transactions, stage) || !confined(workspace.transactions, backup)) pathFail('CRASH_REMNANT');
  await assertWorkspaceDirectories(workspace);
  await assertComponentBindings(binding);
  const stageInfo = await lstat(stage).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
  const backupInfo = await lstat(backup).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
  if (record.state === 'planned') {
    if (stageInfo !== null) await assertOwnedPartialStage(stage);
    if (backupInfo === null) {
      await exactRegularTarget(target, record.prior, observed);
    } else {
      if (record.prior === null) pathFail('CRASH_REMNANT');
      const linked = { ...observed, expectedLinks: 2 };
      const current = await regularTargetState(target, linked);
      const backupState = await regularTargetState(backup, linked);
      if (!sameRegularState(record.prior, current) || !sameRegularState(record.prior, backupState)
        || !sameNode(current.identity, backupState.identity)) pathFail('CRASH_REMNANT');
      await rm(backup);
    }
    if (stageInfo !== null) await rm(stage);
    await rm(recordPath); await syncDirectory(workspace.transactions);
    return Object.freeze({ id: record.id, action: 'rolled-back' });
  }
  if (record.state === 'committed') {
    if (stageInfo !== null) pathFail('CRASH_REMNANT');
    const current = await regularTargetState(target, observed);
    if (!sameRegularState(record.published, current) || !sameRegularState(record.staged, current)) pathFail('CRASH_REMNANT');
    if (record.prior === null) {
      if (backupInfo !== null) pathFail('CRASH_REMNANT');
    } else if (backupInfo !== null) {
      const backupState = await regularTargetState(backup, observed);
      if (!sameRegularState(record.prior, backupState) || !sameNode(record.prior.identity, backupState.identity)) pathFail('CRASH_REMNANT');
      await rm(backup);
    }
    await rm(recordPath); await syncDirectory(workspace.transactions);
    return Object.freeze({ id: record.id, action: 'finalized' });
  }
  if (stageInfo !== null) {
    const staged = await regularTargetState(stage, observed);
    if (!sameRegularState(record.staged, staged)) pathFail('CRASH_REMNANT');
    if (record.prior === null) {
      if (backupInfo !== null) pathFail('CRASH_REMNANT');
      await exactRegularTarget(target, null, observed);
    } else {
      if (backupInfo === null) pathFail('CRASH_REMNANT');
      const linked = { ...observed, expectedLinks: 2 };
      const current = await regularTargetState(target, linked);
      const backupState = await regularTargetState(backup, linked);
      if (!sameRegularState(record.prior, current) || !sameRegularState(record.prior, backupState)
        || !sameNode(current.identity, backupState.identity)) pathFail('CRASH_REMNANT');
      await rm(backup);
    }
    await rm(stage);
  } else {
    const current = await regularTargetState(target, observed);
    if (!sameRegularState(record.staged, current)) pathFail('CRASH_REMNANT');
    if (record.prior === null) {
      if (backupInfo !== null) pathFail('CRASH_REMNANT');
      await rm(target);
    } else {
      if (backupInfo === null) pathFail('CRASH_REMNANT');
      const backupState = await regularTargetState(backup, observed);
      if (!sameRegularState(record.prior, backupState) || !sameNode(record.prior.identity, backupState.identity)) pathFail('CRASH_REMNANT');
      await rename(backup, target);
    }
    await syncDirectory(dirname(target));
  }
  await rm(recordPath); await syncDirectory(workspace.transactions);
  return Object.freeze({ id: record.id, action: 'rolled-back' });
}

async function atomicWriteStreamInternal(workspace, repositoryPath, source, options = {}) {
  assertWorkspaceHandle(workspace);
  assertAbortSignal(options.signal);
  const guard = new OperationGuard(options);
  const limits = streamingLimits(options);
  const portableExpected = streamExpectation(options, limits);
  const canonical = validateRepositoryPath(repositoryPath, { profile: workspace.profile }).canonical;
  const request = {
    path: canonical, kinds: [options.executable === true ? 'executable' : 'regular'], capabilities: ['atomicReplace'],
  };
  await settledBoundary(guard, options.signal, () => authorizeWorkspaceMutation(options.plan, workspace, request));
  const expected = Object.freeze({
    ...portableExpected,
    nativeExecutable: portableExpected.executable
      && options.plan.request.capabilities.executableBit === true,
  });
  await settledBoundary(guard, options.signal, () => assertWorkspaceDirectories(workspace));
  let binding;
  try {
    binding = await settledBoundary(guard, options.signal, () => bindComponents(workspace, canonical, { createParents: options.createParents === true }));
  } catch (error) { throw asPathError(error, 'UNSAFE_TARGET'); }
  const { target } = binding;
  if (!confined(workspace.root, target)) pathFail('UNSAFE_TARGET');
  const observed = {
    guard, maxBytes: options.maxObservedBytes ?? DEFAULT_MAX_BYTES,
    maxDirectoryBytes: options.maxDirectoryBytes, maxDirectoryEntries: options.maxDirectoryEntries,
    maxDirectoryDepth: options.maxDirectoryDepth,
  };
  const before = await settledBoundary(guard, options.signal, () => regularTargetState(target, observed));
  const id = randomUUID().replaceAll('-', '');
  const stage = join(workspace.transactions, `${id}.stage`);
  const backup = join(workspace.transactions, `${id}.backup`);
  const recordPath = join(workspace.transactions, `${id}.json`);
  const planned = Object.freeze({
    schemaVersion: RECORD_VERSION, id, operation: 'write-stream', path: canonical,
    stage: basename(stage), backup: basename(backup), prior: before, expected, state: 'planned',
  });
  let durableRecord = null;
  try {
    // Reprobe immediately before creating the stage, which is the first
    // destructive boundary when no output parent was requested.
    await settledBoundary(guard, options.signal, () => authorizeWorkspaceMutation(options.plan, workspace, {
      ...request, capabilities: before === null ? ['atomicReplace'] : ['atomicReplace', 'hardlink'],
    }));
    await settledBoundary(guard, options.signal, () => assertWorkspaceDirectories(workspace));
    await settledBoundary(guard, options.signal, () => assertComponentBindings(binding));
    await settledBoundary(guard, options.signal, () => exactRegularTarget(target, before, observed));
    await settledBoundary(guard, options.signal, () => writeRecord(recordPath, planned));
    durableRecord = planned;
    await guardedHook(guard, options.signal, options.hooks, 'after-plan', Object.freeze({}));
    const streamed = await streamToExclusiveFile(
      stage, source, limits, expected.nativeExecutable ? 0o700 : 0o600, guard, options.signal,
    );
    if (streamed.bytes !== expected.bytes || streamed.sha256 !== expected.sha256) pathFail('TARGET_CHANGED');
    await guardedHook(guard, options.signal, options.hooks, 'after-stage', Object.freeze({ bytes: streamed.bytes }));
    await settledBoundary(guard, options.signal, () => assertWorkspaceDirectories(workspace));
    const staged = await settledBoundary(guard, options.signal, () => regularTargetState(stage, observed));
    if (staged === null || staged.bytes !== streamed.bytes || staged.sha256 !== streamed.sha256
      || ((staged.identity.mode & 0o100) !== 0) !== expected.nativeExecutable) pathFail('TARGET_CHANGED');
    if (before !== null) {
      await settledBoundary(guard, options.signal, () => authorizeWorkspaceMutation(options.plan, workspace, { ...request, capabilities: ['atomicReplace', 'hardlink'] }));
      await createRollbackLink(target, backup, before, observed, guard, options.signal);
    }
    await settledBoundary(guard, options.signal, () => syncDirectory(workspace.transactions));
    await guardedHook(guard, options.signal, options.hooks, 'after-backup-link', Object.freeze({ present: before !== null }));
    const stagedRecord = Object.freeze({ ...planned, staged, state: 'staged' });
    await settledBoundary(guard, options.signal, () => writeRecord(recordPath, stagedRecord));
    durableRecord = stagedRecord;
    await guardedHook(guard, options.signal, options.hooks, 'after-record', Object.freeze({}));
    await guardedHook(guard, options.signal, options.hooks, 'after-backup', Object.freeze({ present: before !== null }));

    // The source can run for a long time, so bind the original closed plan to
    // a fresh capability measurement again immediately before publication.
    await settledBoundary(guard, options.signal, () => authorizeWorkspaceMutation(options.plan, workspace, {
      ...request, capabilities: before === null ? ['atomicReplace'] : ['atomicReplace', 'hardlink'],
    }));
    await settledBoundary(guard, options.signal, () => assertWorkspaceDirectories(workspace));
    await settledBoundary(guard, options.signal, () => assertComponentBindings(binding));
    await settledBoundary(guard, options.signal, () => inspectComponents(workspace, canonical));
    await settledBoundary(guard, options.signal, () => exactRegularTarget(stage, staged, observed));
    await settledBoundary(guard, options.signal, () => exactRegularTarget(target, before, { ...observed, expectedLinks: before === null ? 1 : 2 }));
    if (before !== null) {
      const backupState = await settledBoundary(guard, options.signal, () => regularTargetState(backup, { ...observed, expectedLinks: 2 }));
      if (!sameRegularState(before, backupState) || !sameNode(before.identity, backupState.identity)) pathFail('TARGET_CHANGED');
    }
    await guardedHook(guard, options.signal, options.hooks, 'before-publish', Object.freeze({}));
    await settledBoundary(guard, options.signal, () => assertWorkspaceDirectories(workspace));
    await settledBoundary(guard, options.signal, () => assertComponentBindings(binding));
    await settledBoundary(guard, options.signal, () => exactRegularTarget(stage, staged, observed));
    await settledBoundary(guard, options.signal, () => exactRegularTarget(target, before, { ...observed, expectedLinks: before === null ? 1 : 2 }));
    await publishWithRetry(stage, target, options, guard);
    await guardedHook(guard, options.signal, options.hooks, 'before-parent-sync', Object.freeze({}));
    await settledBoundary(guard, options.signal, () => syncDirectory(dirname(target)));
    await settledBoundary(guard, options.signal, () => syncDirectory(workspace.transactions));
    const current = await settledBoundary(guard, options.signal, () => regularTargetState(target, observed));
    if (!sameRegularState(staged, current)) pathFail('ATOMIC_REPLACE_FAILED');
    const publishedRecord = Object.freeze({ ...stagedRecord, published: current, state: 'published' });
    await settledBoundary(guard, options.signal, () => writeRecord(recordPath, publishedRecord));
    durableRecord = publishedRecord;
    await guardedHook(guard, options.signal, options.hooks, 'after-publish', Object.freeze({ bytes: staged.bytes }));
    const committedRecord = Object.freeze({ ...publishedRecord, state: 'committed' });
    await settledBoundary(guard, options.signal, () => writeRecord(recordPath, committedRecord));
    durableRecord = committedRecord;
    await guard.hook(options.hooks, 'after-commit', Object.freeze({ bytes: staged.bytes }));
    if (before !== null) {
      const backupState = await regularTargetState(backup, observed);
      if (!sameRegularState(before, backupState) || !sameNode(before.identity, backupState.identity)) pathFail('TARGET_CHANGED');
      await rm(backup);
      // Make the rollback-link removal durable while the committed journal is
      // still present. A crash can then expose either a recoverable committed
      // record or no rollback link, never an unowned rollback artifact.
      await syncDirectory(workspace.transactions);
    }
    await rm(recordPath);
    await syncDirectory(workspace.transactions);
    return Object.freeze({ path: canonical, bytes: staged.bytes, sha256: staged.sha256, transaction: id });
  } catch (error) {
    if (durableRecord?.state === 'committed') {
      // The target and committed record have crossed every durability
      // barrier. Cleanup or a post-commit observer cannot turn that durable
      // publication into an ambiguous failure; retained state is finalized by
      // the normal crash-remnant recovery path.
      return Object.freeze({
        path: canonical,
        bytes: durableRecord.published.bytes,
        sha256: durableRecord.published.sha256,
        transaction: id,
      });
    }
    let cleanupError;
    try {
      if (durableRecord === null) {
        await removeStreamingArtifact(backup); await removeStreamingArtifact(stage); await removeIfPresent(recordPath);
      } else {
        await recoverWriteStreamRecord(workspace, recordPath, durableRecord, { maxBytes: observed.maxBytes });
      }
    } catch (failure) { cleanupError = failure; }
    if (cleanupError !== undefined) {
      throw new PathFilesystemError('ATOMIC_REPLACE_FAILED', 'stream publication rollback failed', {
        cause: new AggregateError([error, cleanupError], 'publication and rollback failed'),
      });
    }
    if (error instanceof PathFilesystemError) throw error;
    throw asPathError(error, 'ATOMIC_REPLACE_FAILED');
  }
}

async function removeExactEntry(path, expected, options = {}) {
  await exactEntryState(path, expected, options);
  await rm(path, { recursive: expected.kind === 'directory' });
}

async function replaceWorkspaceEntryInternal(workspace, repositoryPath, replacement, options = {}) {
  assertWorkspaceHandle(workspace);
  const guard = new OperationGuard(options);
  if (replacement === null || typeof replacement !== 'object' || Array.isArray(replacement)
    || !['regular', 'directory'].includes(replacement.kind)) pathFail('ENTRY_INVALID');
  const replacementKeys = Object.keys(replacement).sort();
  const allowed = replacement.kind === 'regular' ? ['content', 'executable', 'kind'] : ['kind'];
  if (replacementKeys.some((key) => !allowed.includes(key)) || replacement.kind === 'regular' && (!Object.hasOwn(replacement, 'content') || replacement.executable !== undefined && typeof replacement.executable !== 'boolean')) pathFail('ENTRY_INVALID');
  const bytes = replacement.kind === 'regular' ? boundedBytes(replacement.content, options.maxBytes ?? DEFAULT_MAX_BYTES, 'bytes') : null;
  const canonical = validateRepositoryPath(repositoryPath, { profile: workspace.profile }).canonical;
  await authorizeWorkspaceMutation(options.plan, workspace, {
    path: canonical,
    kinds: replacement.kind === 'directory' ? ['directory'] : [replacement.executable === true ? 'executable' : 'regular'],
  });
  await assertWorkspaceDirectories(workspace);
  const binding = await bindComponents(workspace, canonical);
  const { target } = binding;
  if (!confined(workspace.root, target)) pathFail('UNSAFE_TARGET');
  const observed = {
    guard, maxBytes: options.maxObservedBytes ?? DEFAULT_MAX_BYTES,
    maxDirectoryBytes: options.maxDirectoryBytes, maxDirectoryEntries: options.maxDirectoryEntries,
    maxDirectoryDepth: options.maxDirectoryDepth,
  };
  const prior = await entryState(target, observed);
  if (prior === null || prior.kind === replacement.kind) pathFail('ENTRY_INVALID');
  const id = randomUUID().replaceAll('-', '');
  const stage = join(workspace.transactions, replacement.kind === 'regular' ? `${id}.stage` : `${id}.dir`);
  const backup = join(workspace.transactions, `${id}.backup`);
  const recordPath = join(workspace.transactions, `${id}.json`);
  let recordDurable = false;
  try {
    const intent = replacement.kind === 'regular'
      ? { kind: 'regular', sha256: digest(bytes), bytes: bytes.length, executable: replacement.executable === true }
      : { kind: 'directory' };
    const planned = {
      schemaVersion: RECORD_VERSION, id, operation: 'replace-kind', path: canonical,
      stage: basename(stage), backup: basename(backup), prior, replacement: intent,
      state: 'planned',
    };
    await writeRecord(recordPath, planned); recordDurable = true;
    await guard.hook(options.hooks, 'after-plan', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    if (replacement.kind === 'regular') await exclusiveFile(stage, bytes, replacement.executable === true ? 0o700 : 0o600);
    else { await mkdir(stage, { mode: 0o700 }); await syncDirectory(stage); }
    const newState = await entryState(stage, observed);
    if (newState === null || newState.kind !== replacement.kind) pathFail('ATOMIC_REPLACE_FAILED');
    const record = { ...planned, replacement: newState, state: 'staged' };
    await guard.hook(options.hooks, 'after-stage', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await writeRecord(recordPath, record);
    await guard.hook(options.hooks, 'after-record', Object.freeze({}));
    await assertWorkspaceDirectories(workspace); await assertComponentBindings(binding); await inspectComponents(workspace, canonical);
    await exactEntryState(target, prior, observed); await exactEntryState(backup, null, observed);
    await guard.hook(options.hooks, 'before-remove', Object.freeze({}));
    await assertWorkspaceDirectories(workspace); await assertComponentBindings(binding); await inspectComponents(workspace, canonical);
    await exactEntryState(target, prior, observed); await exactEntryState(backup, null, observed);
    await rename(target, backup); await syncDirectory(dirname(target)); await syncDirectory(workspace.transactions);
    await exactEntryState(backup, prior, observed);
    const moved = { ...record, state: 'old-moved' };
    await writeRecord(recordPath, moved);
    await guard.hook(options.hooks, 'after-remove', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await exactEntryState(target, null, observed); await exactEntryState(stage, newState, observed);
    await rename(stage, target); await syncDirectory(dirname(target)); await syncDirectory(workspace.transactions);
    await exactEntryState(target, newState, observed);
    await guard.hook(options.hooks, 'after-publish', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await writeRecord(recordPath, { ...record, state: 'committed' });
    await guard.hook(options.hooks, 'after-commit', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await removeExactEntry(backup, prior, observed);
    await rm(recordPath); await syncDirectory(workspace.transactions);
    return Object.freeze({ path: canonical, priorKind: prior.kind, kind: replacement.kind, transaction: id });
  } catch (error) {
    if (!recordDurable) {
      const recordExists = await lstat(recordPath).then(() => true, (failure) => failure?.code === 'ENOENT' ? false : Promise.reject(failure)).catch(() => true);
      if (!recordExists) await rm(stage, { recursive: true, force: true }).catch(() => {});
    }
    if (error instanceof PathFilesystemError) throw error;
    throw asPathError(error, 'ATOMIC_REPLACE_FAILED');
  }
}

function safeLinkTarget(value, linkPath) {
  if (!isUnicodeScalarString(value) || value.length === 0 || value.startsWith('/') || /^[A-Za-z]:/u.test(value) || value.includes('\\') || value.includes('\0') || value.normalize('NFC') !== value || Buffer.byteLength(value, 'utf8') > 4096) return false;
  let depth = linkPath.split('/').length - 1;
  for (const segment of value.split('/')) {
    if (segment === '' || segment === '.') return false;
    if (segment === '..') { depth -= 1; if (depth < 0) return false; } else depth += 1;
  }
  return true;
}

async function exactSymlink(path, expectedTarget) {
  const before = await lstat(path).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
  if (before === null || !before.isSymbolicLink()) pathFail('TARGET_CHANGED');
  const actualTarget = await readlink(path);
  const after = await lstat(path);
  if (!sameIdentity(identity(before), identity(after)) || actualTarget !== expectedTarget) pathFail('TARGET_CHANGED');
  return identity(after);
}

async function materializeSymlinkInternal(workspace, repositoryPath, linkTarget, options = {}) {
  assertWorkspaceHandle(workspace);
  const guard = new OperationGuard(options);
  const symlinkType = options.type ?? 'file';
  if (!['file', 'dir'].includes(symlinkType)) pathFail('SYMLINK_FORBIDDEN');
  const canonical = validateRepositoryPath(repositoryPath, { profile: workspace.profile }).canonical;
  if (!safeLinkTarget(linkTarget, canonical)) pathFail('SYMLINK_FORBIDDEN');
  await authorizeWorkspaceMutation(options.plan, workspace, {
    path: canonical, kinds: ['symlink'], symlinkTarget: linkTarget,
  });
  await assertWorkspaceDirectories(workspace);
  const binding = await bindComponents(workspace, canonical, { createParents: options.createParents === true });
  const { target } = binding;
  if (!confined(workspace.root, target)) pathFail('UNSAFE_TARGET');
  const before = await targetIdentity(target);
  if (before !== null) pathFail('UNSAFE_TARGET');
  const id = randomUUID().replaceAll('-', '');
  const stage = join(workspace.transactions, `${id}.link`);
  const recordPath = join(workspace.transactions, `${id}.json`);
  const planned = { schemaVersion: RECORD_VERSION, id, operation: 'symlink', path: canonical, stage: basename(stage), linkTarget, prior: null, state: 'planned' };
  const record = { ...planned, state: 'staged' };
  let recordDurable = false;
  try {
    const { symlink } = await import('node:fs/promises');
    await writeRecord(recordPath, planned);
    recordDurable = true;
    await guard.hook(options.hooks, 'after-plan', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await symlink(linkTarget, stage, symlinkType);
    await guard.hook(options.hooks, 'after-stage', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await writeRecord(recordPath, record);
    await guard.hook(options.hooks, 'after-record', Object.freeze({}));
    await assertWorkspaceDirectories(workspace); await assertComponentBindings(binding); await inspectComponents(workspace, canonical); await exactTarget(target, null);
    await guard.hook(options.hooks, 'before-publish', Object.freeze({}));
    await assertWorkspaceDirectories(workspace); await assertComponentBindings(binding); await inspectComponents(workspace, canonical); await exactTarget(target, null);
    await publishWithRetry(stage, target, options, guard); await syncDirectory(dirname(target));
    const published = await exactSymlink(target, linkTarget);
    await guard.hook(options.hooks, 'after-publish', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await writeRecord(recordPath, { ...record, state: 'committed', published });
    await guard.hook(options.hooks, 'after-commit', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    await rm(recordPath); await syncDirectory(workspace.transactions);
    return Object.freeze({ path: canonical, linkTarget, transaction: id });
  } catch (error) {
    if (!recordDurable) {
      const recordExists = await lstat(recordPath).then(() => true, (failure) => failure?.code === 'ENOENT' ? false : Promise.reject(failure)).catch(() => true);
      if (!recordExists) await removeIfPresent(stage).catch(() => {});
    }
    if (error instanceof PathFilesystemError) throw error;
    throw asPathError(error, 'ATOMIC_REPLACE_FAILED');
  }
}

function validateRenamePlan(workspace, plan, maximum) {
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 100_000
    || !exactKeys(plan, ['caseMode', 'profile', 'transaction', 'steps'])
    || !['case-sensitive', 'case-folded'].includes(plan.caseMode)
    || plan.profile !== workspace.profile || !renameTransactionId(plan.transaction)
    || !Array.isArray(plan.steps) || plan.steps.length === 0 || plan.steps.length > maximum * 2 || plan.steps.length % 2 !== 0) pathFail('RENAME_CONFLICT');
  const stage = []; const publishByTemporary = new Map(); let publishStarted = false;
  for (let index = 0; index < plan.steps.length; index += 1) {
    const step = plan.steps[index];
    if (!exactKeys(step, ['from', 'to', 'fileId', 'phase']) || !['stage', 'publish'].includes(step.phase)
      || typeof step.fileId !== 'string' || !/^[0-9a-f]{32}$/u.test(step.fileId)) pathFail('RENAME_CONFLICT', undefined, { step: index });
    if (step.phase === 'stage') {
      if (publishStarted) pathFail('RENAME_CONFLICT', undefined, { step: index });
      validateRepositoryPath(step.from, { profile: workspace.profile });
      const temporary = basename(step.to);
      if (step.to !== `.ogvcs/rename/${temporary}` || !/^[0-9a-f]{24}-[0-9]{6}$/u.test(temporary) || !temporary.startsWith(`${plan.transaction}-`)) pathFail('RENAME_CONFLICT', undefined, { step: index });
      stage.push(step);
    } else {
      publishStarted = true;
      validateRepositoryPath(step.to, { profile: workspace.profile });
      const temporary = basename(step.from);
      if (step.from !== `.ogvcs/rename/${temporary}` || !/^[0-9a-f]{24}-[0-9]{6}$/u.test(temporary) || !temporary.startsWith(`${plan.transaction}-`) || publishByTemporary.has(step.from)) pathFail('RENAME_CONFLICT', undefined, { step: index });
      publishByTemporary.set(step.from, step);
    }
  }
  if (stage.length === 0 || stage.length !== publishByTemporary.size) pathFail('RENAME_CONFLICT');
  const renames = stage.map((step, index) => {
    const publish = publishByTemporary.get(step.to);
    if (publish === undefined || publish.fileId !== step.fileId) pathFail('RENAME_CONFLICT', undefined, { step: index });
    return { from: step.from, to: publish.to, fileId: step.fileId };
  });
  let expected;
  try { expected = planRenames({ caseMode: plan.caseMode, profile: plan.profile, renames }, { maxRenames: maximum }); }
  catch (error) { if (error instanceof PathFilesystemError) pathFail('RENAME_CONFLICT'); throw error; }
  if (expected.transaction !== plan.transaction || canonicalJson(expected.steps) !== canonicalJson(plan.steps)) pathFail('RENAME_CONFLICT');
  return Object.freeze({ renames: Object.freeze(renames), planSha256: digest(recordBytes(plan)) });
}

async function renameStepPaths(workspace, step, options) {
  if (step.phase === 'stage') {
    return Object.freeze({ from: await inspectComponents(workspace, step.from), to: join(workspace.renameRoot, basename(step.to)) });
  }
  return Object.freeze({ from: join(workspace.renameRoot, basename(step.from)), to: await inspectComponents(workspace, step.to, { createParents: options.createParents === true }) });
}

async function advanceRenameRecord(workspace, plan, recordPath, record, guard, options) {
  const observed = {
    guard, maxBytes: options.maxObservedBytes ?? DEFAULT_MAX_BYTES,
    maxDirectoryBytes: options.maxDirectoryBytes, maxDirectoryEntries: options.maxDirectoryEntries,
    maxDirectoryDepth: options.maxDirectoryDepth,
  };
  let current = record;
  await assertWorkspaceDirectories(workspace);
  if (current.next !== null) {
    const step = plan.steps[current.next.index];
    const paths = await renameStepPaths(workspace, step, options);
    const source = await entryState(paths.from, observed);
    const destination = await entryState(paths.to, observed);
    if (source !== null && sameEntryState(source, current.next.source) && destination === null) {
      await assertWorkspaceDirectories(workspace);
      await rename(paths.from, paths.to);
      await syncDirectory(dirname(paths.from)); await syncDirectory(dirname(paths.to));
    } else if (!(source === null && destination !== null && sameEntryState(destination, current.next.source))) {
      pathFail('CRASH_REMNANT');
    }
    current = { ...current, completed: current.next.index + 1, next: null };
    await writeRecord(recordPath, current);
  }
  for (let index = current.completed; index < plan.steps.length; index += 1) {
    guard.checkpoint();
    const step = plan.steps[index];
    const paths = await renameStepPaths(workspace, step, options);
    const source = await entryState(paths.from, observed);
    if (source === null) pathFail('TARGET_CHANGED');
    if (await entryState(paths.to, observed) !== null) pathFail('TARGET_CHANGED');
    current = { ...current, next: { index, from: step.from, to: step.to, source } };
    await writeRecord(recordPath, current);
    await guard.hook(options.hooks, `before-${step.phase}`, Object.freeze({ step: index }));
    await assertWorkspaceDirectories(workspace);
    const checked = await renameStepPaths(workspace, step, options);
    await exactEntryState(checked.from, source, observed);
    await exactEntryState(checked.to, null, observed);
    try { await rename(checked.from, checked.to); }
    catch (error) { throw asPathError(error, 'ATOMIC_REPLACE_FAILED'); }
    await syncDirectory(dirname(checked.from)); await syncDirectory(dirname(checked.to));
    await guard.hook(options.hooks, `after-${step.phase}`, Object.freeze({ step: index }));
    await assertWorkspaceDirectories(workspace);
    await exactEntryState(checked.to, source, observed);
    current = { ...current, completed: index + 1, next: null };
    await writeRecord(recordPath, current);
  }
  await rm(recordPath); await syncDirectory(workspace.transactions); await syncDirectory(workspace.renameRoot);
  return Object.freeze({ transaction: plan.transaction, steps: plan.steps.length, fileIds: Object.freeze(plan.steps.filter(({ phase }) => phase === 'publish').map(({ fileId }) => fileId)) });
}

async function executeRenamePlanInternal(workspace, plan, options = {}) {
  assertWorkspaceHandle(workspace);
  const guard = new OperationGuard(options);
  const maximum = options.maxRenames ?? 100_000;
  const validated = validateRenamePlan(workspace, plan, maximum);
  if (plan.caseMode !== workspace.caseMode) pathFail('RENAME_CONFLICT');
  await authorizeWorkspaceMutations(options.materializationPlan, workspace, validated.renames.map(({ to }) => ({
    path: to, kinds: ['regular', 'executable', 'directory'],
  })));
  await assertWorkspaceDirectories(workspace);
  const observed = {
    guard, maxBytes: options.maxObservedBytes ?? DEFAULT_MAX_BYTES,
    maxDirectoryBytes: options.maxDirectoryBytes, maxDirectoryEntries: options.maxDirectoryEntries,
    maxDirectoryDepth: options.maxDirectoryDepth,
  };
  const sourceStates = [];
  for (const renameItem of validated.renames) {
    const source = await entryState(await inspectComponents(workspace, renameItem.from), observed);
    if (source === null) pathFail('TARGET_CHANGED');
    sourceStates.push(source);
  }
  for (const renameItem of validated.renames) {
    const destination = await entryState(await inspectComponents(workspace, renameItem.to, { createParents: options.createParents === true }), observed);
    if (destination !== null && !sourceStates.some((source) => sameEntryState(source, destination))) pathFail('RENAME_CONFLICT');
  }
  for (const step of plan.steps.filter(({ phase }) => phase === 'stage')) {
    if (await targetIdentity(join(workspace.renameRoot, basename(step.to))) !== null) pathFail('CRASH_REMNANT');
  }
  const id = `${plan.transaction}00000000`;
  const recordPath = join(workspace.transactions, `${id}.json`);
  if (await targetIdentity(recordPath) !== null) pathFail('CRASH_REMNANT');
  const record = { schemaVersion: RECORD_VERSION, id, operation: 'rename', transaction: plan.transaction, planSha256: validated.planSha256, state: 'staged', completed: 0, next: null };
  try {
    await writeRecord(recordPath, record);
    await guard.hook(options.hooks, 'after-rename-record', Object.freeze({}));
    await assertWorkspaceDirectories(workspace);
    return await advanceRenameRecord(workspace, plan, recordPath, record, guard, options);
  } catch (error) {
    if (error instanceof PathFilesystemError) throw error;
    throw asPathError(error, 'ATOMIC_REPLACE_FAILED');
  }
}

async function resumeRenamePlanInternal(workspace, plan, options = {}) {
  assertWorkspaceHandle(workspace);
  const guard = new OperationGuard(options);
  const validated = validateRenamePlan(workspace, plan, options.maxRenames ?? 100_000);
  if (plan.caseMode !== workspace.caseMode) pathFail('RENAME_CONFLICT');
  await authorizeWorkspaceMutations(options.materializationPlan, workspace, validated.renames.map(({ to }) => ({
    path: to, kinds: ['regular', 'executable', 'directory'],
  })));
  await assertWorkspaceDirectories(workspace);
  const id = `${plan.transaction}00000000`;
  const recordPath = join(workspace.transactions, `${id}.json`);
  let bytes; let record;
  try { bytes = await boundedRegularBytes(recordPath, 64 * 1024); record = JSON.parse(bytes); }
  catch (error) { if (error instanceof PathFilesystemError) throw error; throw asPathError(error, 'CRASH_REMNANT'); }
  if (!validRecord(record) || record.operation !== 'rename' || !bytes.equals(recordBytes(record)) || record.planSha256 !== validated.planSha256) pathFail('CRASH_REMNANT');
  return advanceRenameRecord(workspace, plan, recordPath, record, guard, options);
}

function exactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function validIdentity(value) {
  return exactKeys(value, ['dev', 'ino', 'mode', 'size', 'mtimeMs'])
    && typeof value.dev === 'string' && /^\d+$/u.test(value.dev)
    && typeof value.ino === 'string' && /^\d+$/u.test(value.ino)
    && Number.isSafeInteger(value.mode) && value.mode >= 0
    && Number.isSafeInteger(value.size) && value.size >= 0
    && Number.isSafeInteger(value.mtimeMs) && value.mtimeMs >= 0;
}

function validRegularState(value) {
  return exactKeys(value, ['identity', 'sha256', 'bytes']) && validIdentity(value.identity)
    && typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/u.test(value.sha256)
    && Number.isSafeInteger(value.bytes) && value.bytes >= 0 && value.bytes === value.identity.size;
}

function validEntryState(value) {
  return value?.kind === 'regular'
    ? exactKeys(value, ['kind', 'state']) && validRegularState(value.state)
    : value?.kind === 'directory' && exactKeys(value, ['kind', 'state'])
      && exactKeys(value.state, ['identity', 'treeSha256', 'entries', 'bytes']) && validIdentity(value.state.identity)
      && typeof value.state.treeSha256 === 'string' && /^[0-9a-f]{64}$/u.test(value.state.treeSha256)
      && Number.isSafeInteger(value.state.entries) && value.state.entries >= 0
      && Number.isSafeInteger(value.state.bytes) && value.state.bytes >= 0;
}

function validReplacementIntent(value) {
  return value?.kind === 'regular'
    ? exactKeys(value, ['kind', 'sha256', 'bytes', 'executable']) && typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/u.test(value.sha256)
      && Number.isSafeInteger(value.bytes) && value.bytes >= 0 && typeof value.executable === 'boolean'
    : value?.kind === 'directory' && exactKeys(value, ['kind']);
}

function validStreamExpectation(value) {
  return exactKeys(value, ['bytes', 'sha256', 'executable', 'nativeExecutable'])
    && Number.isSafeInteger(value.bytes) && value.bytes >= 0
    && typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/u.test(value.sha256)
    && typeof value.executable === 'boolean' && typeof value.nativeExecutable === 'boolean'
    && (!value.nativeExecutable || value.executable);
}

function validRenameNext(value, completed) {
  return value === null || (exactKeys(value, ['index', 'from', 'to', 'source'])
    && Number.isSafeInteger(value.index) && value.index === completed && value.index >= 0
    && typeof value.from === 'string' && value.from.length > 0 && value.from.length <= 4096
    && typeof value.to === 'string' && value.to.length > 0 && value.to.length <= 4096
    && validEntryState(value.source));
}

function validRecord(record) {
  if (record?.schemaVersion !== RECORD_VERSION || !transactionId(record.id) || !['write-file', 'write-stream', 'symlink', 'rename', 'replace-kind'].includes(record.operation)) return false;
  if (record.operation === 'rename') {
    return record.state === 'staged' && exactKeys(record, ['schemaVersion', 'id', 'operation', 'transaction', 'planSha256', 'state', 'completed', 'next'])
      && renameTransactionId(record.transaction) && record.id === `${record.transaction}00000000`
      && typeof record.planSha256 === 'string' && /^[0-9a-f]{64}$/u.test(record.planSha256)
      && Number.isSafeInteger(record.completed) && record.completed >= 0 && validRenameNext(record.next, record.completed);
  }
  if (record.operation === 'replace-kind') {
    return ['planned', 'staged', 'old-moved', 'committed'].includes(record.state)
      && exactKeys(record, ['schemaVersion', 'id', 'operation', 'path', 'stage', 'backup', 'prior', 'replacement', 'state'])
      && typeof record.path === 'string' && record.path.length > 0 && record.path.length <= 4096
      && record.stage === (record.replacement?.kind === 'regular' ? `${record.id}.stage` : `${record.id}.dir`)
      && record.backup === `${record.id}.backup` && validEntryState(record.prior)
      && (record.state === 'planned' ? validReplacementIntent(record.replacement) : validEntryState(record.replacement))
      && record.prior.kind !== record.replacement.kind;
  }
  if (record.operation === 'write-stream') {
    if (!['planned', 'staged', 'published', 'committed'].includes(record.state)) return false;
    const hasStaged = record.state !== 'planned';
    const hasPublished = ['published', 'committed'].includes(record.state);
    const keys = ['schemaVersion', 'id', 'operation', 'path', 'stage', 'backup', 'prior', 'expected', 'state',
      ...(hasStaged ? ['staged'] : []), ...(hasPublished ? ['published'] : [])];
    return exactKeys(record, keys)
      && typeof record.path === 'string' && record.path.length > 0 && record.path.length <= 4096
      && record.stage === `${record.id}.stage` && record.backup === `${record.id}.backup`
      && (record.prior === null || validRegularState(record.prior)) && validStreamExpectation(record.expected)
      && (!hasStaged || validRegularState(record.staged)
        && record.staged.bytes === record.expected.bytes && record.staged.sha256 === record.expected.sha256
        && (((record.staged.identity.mode & 0o100) !== 0) === record.expected.nativeExecutable))
      && (!hasPublished || validRegularState(record.published)
        && sameRegularState(record.staged, record.published));
  }
  if (!['planned', 'staged', 'committed'].includes(record.state)) return false;
  if (typeof record.path !== 'string' || typeof record.stage !== 'string' || record.stage.includes('/')) return false;
  if (record.operation === 'write-file') {
    const hasStaged = Object.hasOwn(record, 'staged');
    const keys = ['schemaVersion', 'id', 'operation', 'path', 'stage', 'sha256', 'bytes', 'prior', 'state',
      ...(record.state === 'planned' || !hasStaged ? [] : ['staged']), ...(record.state === 'committed' ? ['published'] : [])];
    return exactKeys(record, keys) && record.stage === `${record.id}.stage` && /^[0-9a-f]{64}$/u.test(record.sha256)
      && Number.isSafeInteger(record.bytes) && record.bytes >= 0 && (record.prior === null || validRegularState(record.prior))
      && (record.state === 'planned' || !hasStaged || validRegularState(record.staged))
      && (record.state !== 'committed' || validRegularState(record.published));
  }
  const keys = ['schemaVersion', 'id', 'operation', 'path', 'stage', 'linkTarget', 'prior', 'state', ...(record.state === 'committed' ? ['published'] : [])];
  return exactKeys(record, keys) && record.stage === `${record.id}.link` && record.prior === null
    && safeLinkTarget(record.linkTarget, record.path)
    && (record.state !== 'committed' || validIdentity(record.published));
}

async function inspectCrashRemnantsInternal(workspace, options = {}) {
  assertWorkspaceHandle(workspace);
  await assertWorkspaceDirectories(workspace);
  const maximum = options.maxRemnants ?? DEFAULT_MAX_REMNANTS;
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 100_000) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'remnants' });
  const directoryNames = (await readdir(workspace.transactions)).sort();
  if (directoryNames.length > maximum * 4 + 16) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'remnants' });
  const names = directoryNames.filter((name) => name.endsWith('.json'));
  if (names.length > maximum) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'remnants' });
  const remnants = []; const allowedNames = new Set(names); const renameTransactions = new Set();
  for (const name of names) {
    const bytes = await boundedRegularBytes(join(workspace.transactions, name), 64 * 1024);
    let record;
    try { record = JSON.parse(bytes); } catch { pathFail('CRASH_REMNANT'); }
    if (!validRecord(record) || name !== `${record.id}.json` || !bytes.equals(recordBytes(record))) pathFail('CRASH_REMNANT');
    if (record.operation === 'rename') {
      renameTransactions.add(record.transaction);
      remnants.push(Object.freeze({ id: record.id, operation: record.operation, transaction: record.transaction, state: record.state, completed: record.completed, stepPending: record.next !== null }));
    } else {
      allowedNames.add(record.stage);
      const stage = join(workspace.transactions, record.stage);
      const stageInfo = await lstat(stage).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
      if (record.operation === 'replace-kind') {
        allowedNames.add(record.backup);
        const backupInfo = await lstat(join(workspace.transactions, record.backup)).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
        remnants.push(Object.freeze({ id: record.id, operation: record.operation, path: record.path, state: record.state, stagePresent: stageInfo !== null, backupPresent: backupInfo !== null }));
      } else if (record.operation === 'write-stream') {
        allowedNames.add(record.backup);
        const backupInfo = await lstat(join(workspace.transactions, record.backup)).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
        remnants.push(Object.freeze({ id: record.id, operation: record.operation, path: record.path, state: record.state, stagePresent: stageInfo !== null, backupPresent: backupInfo !== null }));
      } else {
        remnants.push(Object.freeze({ id: record.id, operation: record.operation, path: record.path, state: record.state, stagePresent: stageInfo !== null }));
      }
    }
  }
  if (directoryNames.some((name) => !allowedNames.has(name))) pathFail('CRASH_REMNANT');
  const renameNames = (await readdir(workspace.renameRoot)).sort();
  if (renameNames.length > maximum * 2 + 16) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'remnants' });
  for (const name of renameNames) {
    const match = /^([0-9a-f]{24})-[0-9]{6}$/u.exec(name);
    if (match === null || !renameTransactions.has(match[1])) pathFail('CRASH_REMNANT');
    const info = await lstat(join(workspace.renameRoot, name));
    if (!info.isFile() || info.isSymbolicLink()) pathFail('CRASH_REMNANT');
  }
  return Object.freeze(remnants);
}

async function rollbackCrashRemnantInternal(workspace, id, options = {}) {
  assertWorkspaceHandle(workspace);
  const guard = new OperationGuard(options);
  await assertWorkspaceDirectories(workspace);
  if (!transactionId(id)) pathFail('CRASH_REMNANT');
  const recordPath = join(workspace.transactions, `${id}.json`);
  const bytes = await boundedRegularBytes(recordPath, 64 * 1024).catch((error) => { throw asPathError(error, 'CRASH_REMNANT'); });
  let record;
  try { record = JSON.parse(bytes); } catch { pathFail('CRASH_REMNANT'); }
  if (!validRecord(record) || !bytes.equals(recordBytes(record))) pathFail('CRASH_REMNANT');
  if (record.operation === 'rename') pathFail('CRASH_REMNANT');
  if (record.operation === 'write-stream') {
    return recoverWriteStreamRecord(workspace, recordPath, record, {
      guard, maxBytes: options.maxBytes ?? DEFAULT_MAX_BYTES,
    });
  }
  if (record.operation === 'replace-kind') {
    const canonical = validateRepositoryPath(record.path, { profile: workspace.profile }).canonical;
    const target = await inspectComponents(workspace, canonical);
    const stage = join(workspace.transactions, record.stage);
    const backup = join(workspace.transactions, record.backup);
    if (!confined(workspace.root, target) || !confined(workspace.transactions, stage) || !confined(workspace.transactions, backup)) pathFail('CRASH_REMNANT');
    const observed = { maxBytes: DEFAULT_MAX_BYTES };
    const stageState = await entryState(stage, observed);
    const backupState = await entryState(backup, observed);
    if (record.state === 'planned') {
      if (backupState !== null) pathFail('CRASH_REMNANT');
      if (stageState !== null) {
        const matches = record.replacement.kind === 'regular'
          ? stageState.kind === 'regular' && stageState.state.sha256 === record.replacement.sha256
            && stageState.state.bytes === record.replacement.bytes
            && ((stageState.state.identity.mode & 0o100) !== 0) === record.replacement.executable
          : stageState.kind === 'directory' && (await readdir(stage)).length === 0;
        if (!matches) pathFail('CRASH_REMNANT');
        await rm(stage, { recursive: true });
      }
      await rm(recordPath); await syncDirectory(workspace.transactions);
      return Object.freeze({ id, action: 'rolled-back' });
    }
    const targetState = await entryState(target, observed);
    const staged = stageState !== null && sameEntryState(stageState, record.replacement);
    const backedUp = backupState !== null && sameEntryState(backupState, record.prior);
    const priorTarget = targetState !== null && sameEntryState(targetState, record.prior);
    const replacementTarget = targetState !== null && sameEntryState(targetState, record.replacement);
    let action;
    if (record.state === 'staged' && staged && priorTarget && backupState === null) {
      await removeExactEntry(stage, record.replacement, observed); action = 'rolled-back';
    } else if (['staged', 'old-moved'].includes(record.state) && staged && targetState === null && backedUp) {
      await rename(backup, target); await syncDirectory(dirname(target));
      await removeExactEntry(stage, record.replacement, observed); action = 'rolled-back';
    } else if (['staged', 'old-moved', 'committed'].includes(record.state) && stageState === null && replacementTarget && (backedUp || backupState === null)) {
      if (backedUp) await removeExactEntry(backup, record.prior, observed);
      action = 'finalized';
    } else {
      pathFail('CRASH_REMNANT');
    }
    await rm(recordPath); await syncDirectory(workspace.transactions);
    return Object.freeze({ id, action });
  }
  const stage = join(workspace.transactions, record.stage);
  if (!confined(workspace.transactions, stage)) pathFail('CRASH_REMNANT');
  if (record.state === 'planned') {
    const info = await lstat(stage).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
    if (info !== null) {
      if (record.operation === 'write-file') {
        const staged = await regularTargetState(stage);
        if (staged === null || staged.bytes !== record.bytes || staged.sha256 !== record.sha256) pathFail('CRASH_REMNANT');
      } else {
        await exactSymlink(stage, record.linkTarget);
      }
      await rm(stage);
    }
    await rm(recordPath); await syncDirectory(workspace.transactions);
    return Object.freeze({ id, action: 'rolled-back' });
  }
  const canonical = validateRepositoryPath(record.path, { profile: workspace.profile }).canonical;
  const target = await inspectComponents(workspace, canonical);
  if (!confined(workspace.root, target)) pathFail('CRASH_REMNANT');
  let action = 'rolled-back';
  if (record.state === 'staged') {
    const info = await lstat(stage).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
    if (info !== null) {
      if (record.operation === 'write-file') {
        const staged = await regularTargetState(stage);
        if ((record.staged !== undefined && !sameRegularState(staged, record.staged))
          || staged === null || staged.bytes !== record.bytes || staged.sha256 !== record.sha256) pathFail('CRASH_REMNANT');
      } else {
        await exactSymlink(stage, record.linkTarget);
      }
      await rm(stage);
    } else {
      if (record.operation === 'write-file') {
        const published = await regularTargetState(target);
        if ((record.staged !== undefined && !sameRegularState(published, record.staged))
          || published === null || published.bytes !== record.bytes || published.sha256 !== record.sha256) pathFail('CRASH_REMNANT');
      } else {
        await exactSymlink(target, record.linkTarget);
      }
      action = 'finalized';
    }
  } else if (record.operation === 'write-file') {
    const published = await regularTargetState(target);
    if (!sameRegularState(record.published, published) || published.sha256 !== record.sha256 || published.bytes !== record.bytes) pathFail('CRASH_REMNANT');
    action = 'finalized';
  } else {
    const published = await exactSymlink(target, record.linkTarget);
    if (!sameIdentity(record.published, published)) pathFail('CRASH_REMNANT');
    action = 'finalized';
  }
  await rm(recordPath); await syncDirectory(workspace.transactions);
  return Object.freeze({ id, action });
}

async function applyReadOnlyHintInternal(workspace, repositoryPath, readOnly = true) {
  assertWorkspaceHandle(workspace);
  const canonical = validateRepositoryPath(repositoryPath, { profile: workspace.profile }).canonical;
  await assertWorkspaceDirectories(workspace);
  const path = await inspectComponents(workspace, canonical);
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink()) pathFail('UNSAFE_TARGET');
  const mode = readOnly ? info.mode & ~0o222 : info.mode | 0o200;
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
    const opened = await handle.stat();
    if (!opened.isFile() || !sameNode(identity(info), identity(opened))) pathFail('TARGET_CHANGED');
    if (opened.nlink !== 1) pathFail('UNSAFE_TARGET');
    await handle.chmod(mode);
    const after = await handle.stat();
    if (!sameNode(identity(opened), identity(after))) pathFail('TARGET_CHANGED');
  } catch (error) {
    if (error instanceof PathFilesystemError) throw error;
    throw asPathError(error);
  } finally { await handle?.close().catch(() => {}); }
  return Object.freeze({ path: canonical, readOnly, authoritative: false });
}

async function publicFilesystemOperation(action, fallback = 'IO_ERROR', telemetry) {
  const sink = assertPathTelemetry(telemetry);
  try { return await action(); }
  catch (error) {
    const normalized = error instanceof PathFilesystemError ? error : asPathError(error, fallback);
    if (['UNSAFE_TARGET', 'TARGET_CHANGED', 'SYMLINK_FORBIDDEN'].includes(normalized.code)) recordPathTelemetry(sink, 'unsafe-path-denial');
    throw normalized;
  }
}

export const openWorkspaceRoot = (root, options) => publicFilesystemOperation(() => openWorkspaceRootInternal(root, options), 'UNSAFE_TARGET', options?.telemetry);
export const atomicWriteFile = (workspace, repositoryPath, content, options) => publicFilesystemOperation(
  () => atomicWriteFileInternal(workspace, repositoryPath, content, options), 'ATOMIC_REPLACE_FAILED', options?.telemetry,
);
export const atomicWriteStream = (workspace, repositoryPath, source, options) => publicFilesystemOperation(
  () => atomicWriteStreamInternal(workspace, repositoryPath, source, options), 'ATOMIC_REPLACE_FAILED', options?.telemetry,
);
export const replaceWorkspaceEntry = (workspace, repositoryPath, replacement, options) => publicFilesystemOperation(
  () => replaceWorkspaceEntryInternal(workspace, repositoryPath, replacement, options), 'ATOMIC_REPLACE_FAILED', options?.telemetry,
);
export const materializeSymlink = (workspace, repositoryPath, linkTarget, options) => publicFilesystemOperation(
  () => materializeSymlinkInternal(workspace, repositoryPath, linkTarget, options), 'ATOMIC_REPLACE_FAILED', options?.telemetry,
);
export const executeRenamePlan = (workspace, plan, options) => publicFilesystemOperation(
  () => executeRenamePlanInternal(workspace, plan, options), 'ATOMIC_REPLACE_FAILED', options?.telemetry,
);
export const resumeRenamePlan = (workspace, plan, options) => publicFilesystemOperation(
  () => resumeRenamePlanInternal(workspace, plan, options), 'ATOMIC_REPLACE_FAILED', options?.telemetry,
);
export const inspectCrashRemnants = (workspace, options) => publicFilesystemOperation(
  () => inspectCrashRemnantsInternal(workspace, options), 'CRASH_REMNANT', options?.telemetry,
);
export const rollbackCrashRemnant = (workspace, id, options) => publicFilesystemOperation(
  () => rollbackCrashRemnantInternal(workspace, id, options), 'CRASH_REMNANT', options?.telemetry,
);
export const applyReadOnlyHint = (workspace, repositoryPath, readOnly) => publicFilesystemOperation(
  () => applyReadOnlyHintInternal(workspace, repositoryPath, readOnly),
);
