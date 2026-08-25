import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, rename, rm, watch as watchFilesystem } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { asPathError, PathFilesystemError, errorDecision, pathFail } from './errors.mjs';
import { caseFold, validateRepositoryPath } from './path.mjs';
import { OperationGuard } from './resource.mjs';
import { assertPathTelemetry, recordPathTelemetry } from './telemetry.mjs';
import { assertWorkspaceAuthority, assertWorkspaceHandle } from './workspace.mjs';

const WATCH_STATE_KEYS = Object.freeze(['schemaVersion', 'adapter', 'cursor', 'generation', 'session', 'authoritativeClean', 'reconciliationRequired', 'reason']);
const WATCH_REASONS = new Set(['initial-scan', 'overflow', 'cursor-gap', 'unclean-shutdown', 'unsupported-resume', 'adapter-error', 'state-corrupt']);
const SAFE_TOKEN = /^[A-Za-z0-9._:-]+$/u;
const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const DIRECTORY_ONLY = constants.O_DIRECTORY ?? 0;

function exactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

export function initialWatcherState(adapter = 'portable-sequence') {
  if (typeof adapter !== 'string' || adapter.length === 0 || adapter.length > 128 || !SAFE_TOKEN.test(adapter)) pathFail('WATCH_STATE_INVALID');
  return Object.freeze({
    schemaVersion: 'ogvcs.path/watcher-state/v1', adapter, cursor: null,
    generation: 0, session: null, authoritativeClean: false,
    reconciliationRequired: true, reason: 'initial-scan',
  });
}

function validState(state) {
  return exactKeys(state, WATCH_STATE_KEYS) && state.schemaVersion === 'ogvcs.path/watcher-state/v1'
    && typeof state.adapter === 'string' && state.adapter.length > 0 && state.adapter.length <= 128 && SAFE_TOKEN.test(state.adapter)
    && (state.cursor === null || (typeof state.cursor === 'string' && state.cursor.length > 0 && state.cursor.length <= 4096))
    && Number.isSafeInteger(state.generation) && state.generation >= 0
    && (state.session === null || (typeof state.session === 'string' && state.session.length > 0 && state.session.length <= 256))
    && typeof state.authoritativeClean === 'boolean' && typeof state.reconciliationRequired === 'boolean'
    && (state.reason === null || WATCH_REASONS.has(state.reason));
}

export function validateWatcherState(state) {
  if (!validState(state)) pathFail('WATCH_STATE_INVALID');
  if (state.reconciliationRequired === false && state.reason !== null) pathFail('WATCH_STATE_INVALID');
  if (state.reconciliationRequired === true && state.reason === null) pathFail('WATCH_STATE_INVALID');
  if (state.authoritativeClean && (state.reconciliationRequired || state.reason !== null)) pathFail('WATCH_STATE_INVALID');
  return Object.freeze({ ...state });
}

export function transitionWatcher(state, event) {
  if (!validState(state) || event === null || typeof event !== 'object' || Array.isArray(event)) pathFail('WATCH_STATE_INVALID');
  const next = { ...state };
  if (event.type === 'reconcile') {
    if (typeof event.cursor !== 'string' || event.cursor.length === 0 || event.cursor.length > 4096 || !Number.isSafeInteger(event.generation) || event.generation !== state.generation + 1) pathFail('WATCH_STATE_INVALID');
    Object.assign(next, { cursor: event.cursor, generation: event.generation, session: null, authoritativeClean: true, reconciliationRequired: false, reason: null });
    return Object.freeze(next);
  }
  if (event.type === 'start') {
    if (typeof event.session !== 'string' || event.session.length === 0 || event.session.length > 256 || state.session !== null) pathFail('WATCH_STATE_INVALID');
    next.session = event.session; next.authoritativeClean = false;
    return Object.freeze(next);
  }
  if (event.type === 'batch') {
    if (state.session === null || event.session !== state.session) pathFail('WATCH_STATE_INVALID');
    if (event.overflow === true) {
      Object.assign(next, { authoritativeClean: false, reconciliationRequired: true, reason: 'overflow' });
      throw new PathFilesystemError('WATCH_OVERFLOW', 'watcher overflow requires reconciliation', { cause: Object.freeze(next) });
    }
    if (event.fromCursor !== state.cursor) {
      Object.assign(next, { authoritativeClean: false, reconciliationRequired: true, reason: 'cursor-gap' });
      throw new PathFilesystemError('WATCH_GAP', 'watcher cursor gap requires reconciliation', { cause: Object.freeze(next) });
    }
    if (typeof event.toCursor !== 'string' || event.toCursor.length === 0 || event.toCursor.length > 4096) pathFail('WATCH_STATE_INVALID');
    next.cursor = event.toCursor;
    if (event.indexUpdated !== true) {
      Object.assign(next, { authoritativeClean: false, reconciliationRequired: true, reason: 'adapter-error' });
    } else {
      next.authoritativeClean = event.authoritativeComplete !== false && !state.reconciliationRequired;
    }
    return Object.freeze(next);
  }
  if (event.type === 'stop') {
    if (state.session === null || event.session !== state.session || state.authoritativeClean !== true || state.reconciliationRequired) pathFail('RECONCILIATION_REQUIRED');
    next.session = null;
    if (event.resumeSupported !== true) {
      Object.assign(next, { authoritativeClean: false, reconciliationRequired: true, reason: 'unsupported-resume' });
    }
    return Object.freeze(next);
  }
  if (event.type === 'restart') {
    if (state.session !== null) {
      Object.assign(next, { session: null, authoritativeClean: false, reconciliationRequired: true, reason: 'unclean-shutdown' });
      throw new PathFilesystemError('WATCH_UNCLEAN_SHUTDOWN', 'unclean watcher session requires reconciliation', { cause: Object.freeze(next) });
    }
    return Object.freeze(next);
  }
  pathFail('WATCH_STATE_INVALID');
}

export const completeReconciliation = (state, cursor, generation = state?.generation + 1) => transitionWatcher(state, { type: 'reconcile', cursor, generation });
export const beginWatcherSession = (state, session) => transitionWatcher(state, { type: 'start', session });
export const applyWatcherBatch = (state, batch) => transitionWatcher(state, { type: 'batch', ...batch });
export const stopWatcherSession = (state, session, resumeSupported = false) => transitionWatcher(state, { type: 'stop', session, resumeSupported });
export const markWatcherRestart = (state) => transitionWatcher(state, { type: 'restart' });

export function evaluateWatcherCase(testCase) {
  let state = initialWatcherState(); const outcomes = [];
  for (const event of testCase.events) {
    try {
      state = transitionWatcher(state, event);
      outcomes.push(Object.freeze({ accepted: true, state }));
    } catch (error) {
      if (!(error instanceof PathFilesystemError)) throw error;
      const failedState = validState(error.cause) ? error.cause : state;
      state = failedState;
      outcomes.push(Object.freeze({ ...errorDecision(error), state }));
      break;
    }
  }
  return Object.freeze({ outcomes: Object.freeze(outcomes), state });
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

async function writeStateFile(path, state, verifyAuthority) {
  const temporary = `${path}.${randomUUID().replaceAll('-', '')}.tmp`;
  try {
    const handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    try { await handle.writeFile(`${canonicalJson(state)}\n`, 'utf8'); await handle.sync(); }
    finally { await handle.close(); }
    await verifyAuthority();
    await rename(temporary, path);
    await verifyAuthority();
    let directory;
    try {
      directory = await open(dirname(path), constants.O_RDONLY | NO_FOLLOW | DIRECTORY_ONLY);
      if (!(await directory.stat()).isDirectory()) pathFail('UNSAFE_TARGET');
      try { await directory.sync(); }
      catch (error) {
        // Directory fsync is unsupported by Windows even after a successful
        // no-follow open. Do not suppress permission failures from the open
        // itself, or from platforms that promise directory durability.
        if (process.platform !== 'win32' || error?.code !== 'EPERM') throw error;
      }
    } catch (error) {
      if (!['EINVAL', 'ENOTSUP', 'EISDIR', 'EBADF'].includes(error?.code)) throw error;
    } finally { await directory?.close().catch(() => {}); }
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

async function readStateFile(path) {
  const pathInfo = await lstat(path);
  if (!pathInfo.isFile() || pathInfo.isSymbolicLink() || pathInfo.nlink !== 1 || pathInfo.size > 64 * 1024) pathFail('WATCH_STATE_INVALID');
  const handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size > 64 * 1024 || String(before.dev) !== String(pathInfo.dev) || String(before.ino) !== String(pathInfo.ino)) pathFail('WATCH_STATE_INVALID');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (after.nlink !== 1 || String(after.dev) !== String(before.dev) || String(after.ino) !== String(before.ino) || after.size !== before.size || Math.trunc(after.mtimeMs) !== Math.trunc(before.mtimeMs) || bytes.length !== before.size) pathFail('WATCH_STATE_INVALID');
    return bytes;
  } finally { await handle.close(); }
}

export async function persistWatcherState(workspace, state, options = {}) {
  assertWorkspaceHandle(workspace);
  await assertWorkspaceAuthority(workspace);
  const guard = new OperationGuard({ maxTimeMs: options.maxTimeMs ?? 5_000, maxOperations: 64 });
  const validated = validateWatcherState(state);
  const path = join(workspace.control, 'watcher-state.json');
  try {
    const existing = await lstat(path).catch((error) => error?.code === 'ENOENT' ? null : Promise.reject(error));
    if (existing?.isSymbolicLink() || (existing !== null && !existing.isFile())) pathFail('UNSAFE_TARGET');
    await guard.hook(options.hooks, 'before-watcher-state-write', Object.freeze({ generation: validated.generation }));
    await assertWorkspaceAuthority(workspace);
    await writeStateFile(path, validated, () => assertWorkspaceAuthority(workspace));
    await assertWorkspaceAuthority(workspace);
    guard.checkpoint();
    return validated;
  } catch (error) { if (error instanceof PathFilesystemError) throw error; throw asPathError(error); }
}

export async function loadWatcherState(workspace, options = {}) {
  assertWorkspaceHandle(workspace);
  await assertWorkspaceAuthority(workspace);
  const path = join(workspace.control, 'watcher-state.json');
  let bytes;
  try {
    bytes = await readStateFile(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return initialWatcherState(options.adapter);
    if (error instanceof PathFilesystemError && options.failOnCorrupt === true) throw error;
    if (error instanceof PathFilesystemError) return Object.freeze({ ...initialWatcherState(options.adapter), reason: 'state-corrupt' });
    throw asPathError(error);
  }
  await assertWorkspaceAuthority(workspace);
  try {
    const value = JSON.parse(bytes);
    if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`, 'utf8'))) pathFail('WATCH_STATE_INVALID');
    return validateWatcherState(value);
  } catch (error) {
    if (options.failOnCorrupt === true) {
      if (error instanceof PathFilesystemError) throw error;
      pathFail('WATCH_STATE_INVALID');
    }
    return Object.freeze({ ...initialWatcherState(options.adapter), reason: 'state-corrupt' });
  }
}

export async function applyWatcherEvent(workspace, state, event, options = {}) {
  assertWorkspaceHandle(workspace);
  try {
    const next = transitionWatcher(state, event);
    return persistWatcherState(workspace, next, options);
  } catch (error) {
    if (!(error instanceof PathFilesystemError)) throw error;
    if (validState(error.cause)) await persistWatcherState(workspace, error.cause, options);
    throw error;
  }
}

export async function openWorkspaceWatcher(workspace, state, options = {}) {
  assertWorkspaceHandle(workspace);
  const telemetry = assertPathTelemetry(options.telemetry);
  recordPathTelemetry(telemetry, 'profile', workspace.profile);
  let current = validateWatcherState(state);
  if (current.session !== null) pathFail('RECONCILIATION_REQUIRED');
  const session = options.session ?? randomUUID().replaceAll('-', '');
  if (typeof session !== 'string' || session.length === 0 || session.length > 256 || !SAFE_TOKEN.test(session)) pathFail('WATCH_STATE_INVALID');
  const maxNativeEvents = options.maxNativeEvents ?? 1024;
  const maxQueue = options.maxQueue ?? 4096;
  if (!Number.isSafeInteger(maxNativeEvents) || maxNativeEvents < 1 || maxNativeEvents > 100_000
    || !Number.isSafeInteger(maxQueue) || maxQueue < 1 || maxQueue > 100_000) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'configuration' });
  const controller = new AbortController();
  const createGuard = new OperationGuard({ maxTimeMs: options.maxTimeMs ?? 30_000, maxOperations: 64 });
  const factory = options.iteratorFactory ?? ((root, nativeOptions) => watchFilesystem(root, nativeOptions));
  const reconcile = options.reconcile;
  if (typeof factory !== 'function' || typeof reconcile !== 'function') pathFail('RECONCILIATION_REQUIRED');

  // fs.watch has no portable resumable cursor. Persist a dirty boundary before
  // subscribing, then perform the authoritative scan only after the native
  // subscription exists. Events produced during that scan remain queued by the
  // iterator and are applied from the newly installed generation.
  if (!current.reconciliationRequired || current.authoritativeClean) {
    current = await persistWatcherState(workspace, {
      ...current, session: null, authoritativeClean: false,
      reconciliationRequired: true, reason: 'unsupported-resume',
    }, options);
  }
  let iterator;
  try {
    const value = await createGuard.boundary((deadlineSignal) => factory(workspace.root, {
      recursive: options.recursive ?? true,
      encoding: 'utf8', maxQueue, overflow: 'throw',
      signal: AbortSignal.any([controller.signal, deadlineSignal]),
    }), true);
    iterator = typeof value?.next === 'function' ? value : value?.[Symbol.asyncIterator]?.();
    if (typeof iterator?.next !== 'function') pathFail('WATCH_STATE_INVALID');

    const generation = current.generation + 1;
    const cursor = `${generation}:0`;
    const reconcileStarted = process.hrtime.bigint();
    const reconciled = await createGuard.boundary((signal) => reconcile(Object.freeze({
      generation, cursor, previousCursor: current.cursor,
    }), signal), true);
    if (reconciled !== true) pathFail('RECONCILIATION_REQUIRED');
    const reconcileElapsed = Number((process.hrtime.bigint() - reconcileStarted) / 1_000_000n);
    recordPathTelemetry(telemetry, 'reconciliation', reconcileElapsed);
    current = await applyWatcherEvent(workspace, current, { type: 'reconcile', cursor, generation }, options);
    current = await applyWatcherEvent(workspace, current, { type: 'start', session }, options);
  } catch (error) {
    recordPathTelemetry(telemetry, 'watcher-gap');
    controller.abort();
    if (typeof iterator?.return === 'function') await Promise.resolve(iterator.return()).catch(() => {});
    const dirty = {
      ...current, session: null, authoritativeClean: false,
      reconciliationRequired: true, reason: 'adapter-error',
    };
    await persistWatcherState(workspace, dirty, options).then((value) => { current = value; }).catch(() => {});
    if (error instanceof PathFilesystemError) throw error;
    throw asPathError(error, 'WATCH_UNCLEAN_SHUTDOWN');
  }
  let sequence = 0;
  let closed = false;

  const dirty = async (reason = 'adapter-error') => {
    recordPathTelemetry(telemetry, 'watcher-gap');
    current = await persistWatcherState(workspace, { ...current, authoritativeClean: false, reconciliationRequired: true, reason }, options);
    return current;
  };

  const nextNative = async (guard) => guard.boundary((deadlineSignal) => {
    const abort = () => controller.abort();
    deadlineSignal.addEventListener('abort', abort, { once: true });
    return Promise.resolve(iterator.next()).finally(() => deadlineSignal.removeEventListener('abort', abort));
  }, true);

  return Object.freeze({
    get state() { return current; },
    async nextBatch(apply) {
      if (closed || typeof apply !== 'function') pathFail('WATCH_STATE_INVALID');
      const guard = new OperationGuard({ maxTimeMs: options.maxTimeMs ?? 30_000, maxOperations: maxNativeEvents + 64 });
      for (let scanned = 0; scanned < maxNativeEvents; scanned += 1) {
        let result;
        try { result = await nextNative(guard); }
        catch (error) {
          if (error?.code === 'ERR_FS_WATCHER_QUEUE_OVERFLOW') {
            recordPathTelemetry(telemetry, 'watcher-gap');
            try { await applyWatcherEvent(workspace, current, { type: 'batch', session, fromCursor: current.cursor, toCursor: current.cursor ?? 'overflow', overflow: true, indexUpdated: false }, options); }
            catch (watchError) { if (watchError instanceof PathFilesystemError) { if (watchError.cause !== undefined) current = watchError.cause; throw watchError; } throw watchError; }
          }
          await dirty();
          if (error instanceof PathFilesystemError) throw error;
          throw new PathFilesystemError('WATCH_UNCLEAN_SHUTDOWN', 'watch adapter stopped unexpectedly', { cause: current });
        }
        if (result?.done === true) {
          await dirty('unclean-shutdown');
          throw new PathFilesystemError('WATCH_UNCLEAN_SHUTDOWN', 'watch adapter ended before a clean stop', { cause: current });
        }
        const event = result?.value;
        let filename = event?.filename;
        if (Buffer.isBuffer(filename)) filename = filename.toString('utf8');
        if (process.platform === 'win32' && typeof filename === 'string') filename = filename.replaceAll('\\', '/');
        if (typeof filename !== 'string' || filename.length === 0 || filename.length > 4096 || !['rename', 'change'].includes(event?.eventType)) {
          await dirty();
          throw new PathFilesystemError('WATCH_GAP', 'watch adapter produced an ambiguous event', { cause: current });
        }
        if (caseFold(filename.split('/', 1)[0]) === '.ogvcs') continue;
        let canonical;
        try { canonical = validateRepositoryPath(filename, { profile: workspace.profile }).canonical; }
        catch (error) {
          await dirty();
          throw new PathFilesystemError('WATCH_GAP', 'watch adapter produced a noncanonical path', { cause: current });
        }
        const indexed = await guard.boundary((signal) => apply(Object.freeze([{ type: event.eventType, path: canonical }]), signal), true).catch(async (error) => {
          await dirty();
          if (error instanceof PathFilesystemError) throw error;
          throw new PathFilesystemError('WATCH_GAP', 'watch index callback failed', { cause: current });
        });
        sequence += 1;
        const toCursor = `${current.generation}:${sequence}`;
        current = await applyWatcherEvent(workspace, current, {
          type: 'batch', session, fromCursor: current.cursor, toCursor,
          overflow: false, indexUpdated: indexed === true,
          // promises.watch exposes no queue-drained/barrier proof. Advancing its
          // synthetic cursor is useful acceleration, but one delivered event
          // cannot make the index authoritative while more native events may
          // already be queued.
          authoritativeComplete: false,
        }, options);
        if (indexed !== true) pathFail('RECONCILIATION_REQUIRED');
        return Object.freeze({ events: Object.freeze([{ type: event.eventType, path: canonical }]), cursor: toCursor, state: current });
      }
      await dirty();
      pathFail('WATCH_GAP');
    },
    async close() {
      if (closed) return current;
      closed = true;
      controller.abort();
      if (typeof iterator.return === 'function') {
        const guard = new OperationGuard({ maxTimeMs: options.maxTimeMs ?? 30_000, maxOperations: 64 });
        await guard.boundary((signal) => iterator.return(signal), true).catch(() => {});
      }
      current = await persistWatcherState(workspace, {
        ...current, session: null, authoritativeClean: false,
        reconciliationRequired: true,
        reason: current.reconciliationRequired ? current.reason : 'unsupported-resume',
      }, options);
      return current;
    },
  });
}
