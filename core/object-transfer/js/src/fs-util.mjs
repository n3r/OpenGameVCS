import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import {
  lstat,
  mkdir,
  open,
  opendir,
  realpath,
  rename,
  rmdir,
  unlink,
} from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { canonicalBytes, parseCanonicalJson } from '@opengamevcs/protocol-baseline';
import { mapIo, transferError } from './errors.mjs';

const DIRECTORY_MODE = 0o700;
const LOCK_OWNER = 'owner.json';
const LOCK_OWNER_KEYS = [
  'acquiredAtUnixMs',
  'expiresAtUnixMs',
  'pid',
  'schemaVersion',
  'token',
].join('\0');
const LOCK_TOKEN = /^[0-9a-f]{48}$/u;
const MAXIMUM_LOCK_LEASE_MILLISECONDS = 86_400_000;
const LOCK_GUARD = Symbol('ogvcs.object-transfer/lock-guard');
const delay = (milliseconds) => new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));

function sameIdentity(left, right) {
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino);
}

function validatePin(pin) {
  if (!pin || typeof pin !== 'object' || typeof pin.path !== 'string'
      || typeof pin.realpath !== 'string' || typeof pin.dev !== 'string'
      || typeof pin.ino !== 'string' || !('parent' in pin)) {
    transferError('TRANSFER_BACKEND_IO', 'storage directory pin is invalid');
  }
  return pin;
}

function lockTime(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    transferError('TRANSFER_BACKEND_IO', 'storage lock clock is invalid');
  }
  return value;
}

function validLockOwner(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === LOCK_OWNER_KEYS
    && value.schemaVersion === 'ogvcs.object-transfer/lock-owner/v1'
    && LOCK_TOKEN.test(value.token ?? '')
    && Number.isSafeInteger(value.pid) && value.pid >= 1
    && Number.isSafeInteger(value.acquiredAtUnixMs) && value.acquiredAtUnixMs >= 0
    && Number.isSafeInteger(value.expiresAtUnixMs)
    && value.expiresAtUnixMs > value.acquiredAtUnixMs
    && value.expiresAtUnixMs - value.acquiredAtUnixMs <= MAXIMUM_LOCK_LEASE_MILLISECONDS);
}

export async function ensurePlainDirectory(path, { create = true } = {}) {
  if (create) {
    try {
      await mkdir(path, { mode: DIRECTORY_MODE });
    } catch (error) {
      if (error?.code !== 'EEXIST') mapIo(error);
    }
  }
  let stat;
  try { stat = await lstat(path); } catch (error) { mapIo(error); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    transferError('TRANSFER_BACKEND_IO', 'storage component is not a plain directory');
  }
  if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    transferError('TRANSFER_BACKEND_IO', 'storage directory is not private');
  }
  return stat;
}

export async function pinPlainDirectory(path, { create = true, parentPin = null } = {}) {
  const absolute = resolve(path);
  if (parentPin !== null) {
    validatePin(parentPin);
    if (dirname(absolute) !== parentPin.path) {
      transferError('TRANSFER_BACKEND_IO', 'storage directory is not a direct child of its pinned parent');
    }
    await assertPinnedDirectory(parentPin);
  }
  const first = await ensurePlainDirectory(absolute, { create });
  let canonical;
  let second;
  try {
    canonical = await realpath(absolute);
    second = await lstat(absolute);
  } catch (error) { mapIo(error, 'storage directory pin failed'); }
  if (!second.isDirectory() || second.isSymbolicLink() || !sameIdentity(first, second)) {
    transferError('TRANSFER_BACKEND_IO', 'storage directory changed while it was pinned');
  }
  if (parentPin !== null) {
    await assertPinnedDirectory(parentPin);
    if (canonical !== resolve(parentPin.realpath, basename(absolute))) {
      transferError('TRANSFER_BACKEND_IO', 'storage directory escapes its pinned parent');
    }
  }
  if (create) {
    // mkdir durability belongs to the parent directory. Sync on both a fresh
    // create and EEXIST recovery so a prior crash cannot leave an acknowledged
    // but non-durable ancestor entry.
    if (parentPin === null) {
      let parentCanonical;
      try { parentCanonical = await realpath(dirname(absolute)); }
      catch (error) { mapIo(error, 'storage root parent resolution failed'); }
      await syncDirectory(parentCanonical);
    }
    else await syncDirectory(parentPin.path, parentPin);
  }
  return Object.freeze({
    path: absolute,
    realpath: canonical,
    dev: String(second.dev),
    ino: String(second.ino),
    parent: parentPin,
  });
}

export async function pinPlainDirectoryIfExists(path, { parentPin = null } = {}) {
  try { await lstat(path); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    mapIo(error, 'storage directory inspection failed');
  }
  return pinPlainDirectory(path, { create: false, parentPin });
}

export async function assertPinnedDirectory(pinInput) {
  const pin = validatePin(pinInput);
  if (pin.parent !== null) {
    const parent = validatePin(pin.parent);
    if (dirname(pin.path) !== parent.path
        || pin.realpath !== resolve(parent.realpath, basename(pin.path))) {
      transferError('TRANSFER_BACKEND_IO', 'storage directory pin has an invalid parent binding');
    }
    await assertPinnedDirectory(parent);
  }
  let stat;
  let canonical;
  try {
    stat = await lstat(pin.path);
    canonical = await realpath(pin.path);
  } catch (error) { mapIo(error, 'storage directory pin no longer resolves'); }
  if (!stat.isDirectory() || stat.isSymbolicLink()
      || (process.platform !== 'win32' && (stat.mode & 0o077) !== 0)
      || String(stat.dev) !== pin.dev
      || String(stat.ino) !== pin.ino || canonical !== pin.realpath) {
    transferError('TRANSFER_BACKEND_IO', 'storage directory identity changed');
  }
  return pin;
}

export function directorySyncUnsupported(error, platform = process.platform) {
  return platform === 'win32' && error?.code === 'EPERM';
}

export async function syncDirectory(path, pin = undefined) {
  if (pin !== undefined) {
    validatePin(pin);
    if (resolve(path) !== pin.path) transferError('TRANSFER_BACKEND_IO', 'directory sync path differs from its pin');
    await assertPinnedDirectory(pin);
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0));
    if (pin !== undefined) {
      const stat = await handle.stat();
      if (!stat.isDirectory() || String(stat.dev) !== pin.dev || String(stat.ino) !== pin.ino) {
        transferError('TRANSFER_BACKEND_IO', 'opened directory differs from its pin');
      }
    }
    try { await handle.sync(); }
    catch (error) {
      // Windows can open and identity-check a directory handle but does not
      // implement fsync for it. Suppress only that exact capability result;
      // path-open, ACL, identity, and every non-Windows failure still fail
      // closed. Atomic name operations plus synced file handles remain the
      // strongest portable Windows boundary exposed by Node.
      if (!directorySyncUnsupported(error)) throw error;
    }
  } catch (error) { mapIo(error, 'directory durability sync failed'); }
  finally { await handle?.close().catch(() => {}); }
}

async function assertLockGuard(lockGuard) {
  if (lockGuard === undefined) return;
  if (!lockGuard || lockGuard[LOCK_GUARD] !== true || typeof lockGuard.assertOwned !== 'function') {
    transferError('TRANSFER_BACKEND_IO', 'persisted commit lock guard is invalid');
  }
  await lockGuard.assertOwned();
}

export async function writeAll(handle, bytes, position = null) {
  let offset = 0;
  while (offset < bytes.length) {
    const result = await handle.write(bytes, offset, bytes.length - offset, position === null ? null : position + offset);
    if (result.bytesWritten <= 0) transferError('TRANSFER_BACKEND_IO', 'short filesystem write');
    offset += result.bytesWritten;
  }
}

export async function readExact(handle, length, position) {
  const output = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const result = await handle.read(output, offset, length - offset, position + offset);
    if (result.bytesRead === 0) transferError('TRANSFER_BACKEND_CORRUPT', 'stored record is truncated');
    offset += result.bytesRead;
  }
  return output;
}

export async function atomicJsonWrite(path, value, { directoryPin, lockGuard } = {}) {
  const body = canonicalBytes(value);
  const directory = dirname(path);
  const pin = directoryPin ?? await pinPlainDirectory(directory);
  if (pin.path !== resolve(directory)) transferError('TRANSFER_BACKEND_IO', 'state path leaves its pinned directory');
  await assertPinnedDirectory(pin);
  const temporary = `${directory}/.${basename(path)}.${randomBytes(12).toString('hex')}.tmp`;
  let handle;
  try {
    await assertLockGuard(lockGuard);
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
    await assertPinnedDirectory(pin);
    await writeAll(handle, body);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await assertPinnedDirectory(pin);
    await assertLockGuard(lockGuard);
    await rename(temporary, path);
    await syncDirectory(directory, pin);
    await assertLockGuard(lockGuard);
  } catch (error) {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    mapIo(error, 'atomic state write failed');
  }
}

export async function atomicJsonCreate(path, value, { directoryPin, lockGuard } = {}) {
  const body = canonicalBytes(value);
  const directory = dirname(path);
  const pin = directoryPin ?? await pinPlainDirectory(directory);
  if (pin.path !== resolve(directory)) transferError('TRANSFER_BACKEND_IO', 'state path leaves its pinned directory');
  await assertPinnedDirectory(pin);
  let handle;
  try {
    await assertLockGuard(lockGuard);
    handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
    await assertPinnedDirectory(pin);
    await writeAll(handle, body);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await syncDirectory(directory, pin);
    await assertLockGuard(lockGuard);
    return true;
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error?.code === 'EEXIST') {
      // A prior process may have crashed after syncing the file and before
      // syncing its directory entry. A replay denial must remain durable too.
      await syncDirectory(directory, pin);
      return false;
    }
    mapIo(error, 'exclusive state write failed');
  }
}

export async function readJson(path, maximumBytes = 1024 * 1024, { directoryPin } = {}) {
  const directory = dirname(path);
  if (directoryPin !== undefined) {
    if (directoryPin.path !== resolve(directory)) transferError('TRANSFER_BACKEND_IO', 'state path leaves its pinned directory');
    await assertPinnedDirectory(directoryPin);
  }
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    if (directoryPin !== undefined) await assertPinnedDirectory(directoryPin);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size <= 0 || stat.size > maximumBytes) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'state record is not bounded');
    }
    const body = await readExact(handle, stat.size, 0);
    return parseCanonicalJson(body, { maxBytes: maximumBytes, maxWorkingMemoryBytes: maximumBytes * 4 });
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    if (error?.code?.startsWith?.('TRANSFER_')) throw error;
    mapIo(error, 'state record read failed');
  } finally { await handle?.close().catch(() => {}); }
}

async function lockOwner(lockPath, lockPin) {
  try {
    const value = await readJson(`${lockPath}/${LOCK_OWNER}`, 8192, { directoryPin: lockPin });
    return validLockOwner(value) ? value : null;
  }
  catch (error) { if (error?.code === 'TRANSFER_BACKEND_CORRUPT') return null; throw error; }
}

async function removeRenamedLock(path, pin) {
  await assertPinnedDirectory(pin);
  let scanned = 0;
  const directory = await opendir(path);
  try {
    for await (const entry of directory) {
      scanned += 1;
      if (scanned > 8) transferError('TRANSFER_BACKEND_CORRUPT', 'stale lock directory exceeds its bound');
      if (!entry.isFile() || (entry.name !== LOCK_OWNER
          && !/^\.owner\.json\.[0-9a-f]{24}\.tmp$/u.test(entry.name))) {
        transferError('TRANSFER_BACKEND_CORRUPT', 'stale lock directory contains an unexpected entry');
      }
      await assertPinnedDirectory(pin);
      await unlink(`${path}/${entry.name}`);
    }
  } finally { await directory.close().catch(() => {}); }
  await rmdir(path);
}

async function recoverExpiredLock(rootPin, lockPath, nowUnixMs, leaseMilliseconds) {
  let stat;
  try { stat = await lstat(lockPath); } catch (error) { if (error?.code === 'ENOENT') return true; mapIo(error, 'lock inspection failed'); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) transferError('TRANSFER_BACKEND_IO', 'lock path is not a plain directory');
  const lockPin = await pinPlainDirectory(lockPath, { create: false, parentPin: rootPin });
  const owner = await lockOwner(lockPath, lockPin);
  const expired = owner && Number.isSafeInteger(owner.expiresAtUnixMs)
    ? owner.expiresAtUnixMs <= nowUnixMs
    : stat.mtimeMs + leaseMilliseconds <= nowUnixMs;
  if (!expired) return false;
  const stale = `${lockPath}.stale.${randomBytes(12).toString('hex')}`;
  await assertPinnedDirectory(rootPin);
  try { await rename(lockPath, stale); } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'EEXIST') return true;
    mapIo(error, 'expired lock takeover failed');
  }
  const stalePin = await pinPlainDirectory(stale, { create: false, parentPin: rootPin });
  // A renewal can win after the first owner read but before the takeover
  // rename. Once renamed, the directory is stable: re-read the owner there and
  // restore a renewed live lease before allowing any successor to acquire.
  const renamedStat = await lstat(stale);
  const renamedOwner = await lockOwner(stale, stalePin);
  const stillExpired = renamedOwner
    ? renamedOwner.expiresAtUnixMs <= nowUnixMs
    : renamedStat.mtimeMs + leaseMilliseconds <= nowUnixMs;
  if (!stillExpired) {
    await assertPinnedDirectory(rootPin);
    try { await rename(stale, lockPath); }
    catch (error) {
      if (error?.code === 'EEXIST') transferError('TRANSFER_BACKEND_IO', 'renewed lock restoration conflicted');
      mapIo(error, 'renewed lock restoration failed');
    }
    await syncDirectory(rootPin.path, rootPin);
    return false;
  }
  await removeRenamedLock(stale, stalePin);
  await syncDirectory(rootPin.path, rootPin);
  return true;
}

export async function withRecoverableDirectoryLock({
  rootPin,
  name,
  now,
  operation,
  attempts = 200,
  delayMilliseconds = 5,
  leaseMilliseconds = 300_000,
  busyCode = 'TRANSFER_SESSION_STATE',
  busyMessage = 'state is busy',
}) {
  validatePin(rootPin);
  if (typeof name !== 'string' || !/^[0-9a-f]{64}$/u.test(name) || typeof now !== 'function'
      || typeof operation !== 'function' || !Number.isSafeInteger(attempts) || attempts < 1
      || !Number.isSafeInteger(leaseMilliseconds) || leaseMilliseconds < 1_000
      || leaseMilliseconds > MAXIMUM_LOCK_LEASE_MILLISECONDS) {
    transferError('TRANSFER_INPUT_INVALID', 'recoverable lock configuration is invalid');
  }
  const lockPath = `${rootPin.path}/${name}.lock`;
  let lockPin;
  let token;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    await assertPinnedDirectory(rootPin);
    try {
      await mkdir(lockPath, { mode: DIRECTORY_MODE });
      lockPin = await pinPlainDirectory(lockPath, { create: false, parentPin: rootPin });
      token = randomBytes(24).toString('hex');
      const acquiredAtUnixMs = lockTime(now());
      if (acquiredAtUnixMs > Number.MAX_SAFE_INTEGER - leaseMilliseconds) {
        transferError('TRANSFER_BACKEND_IO', 'storage lock clock exceeds its safe range');
      }
      await atomicJsonWrite(`${lockPath}/${LOCK_OWNER}`, {
        schemaVersion: 'ogvcs.object-transfer/lock-owner/v1',
        token,
        pid: process.pid,
        acquiredAtUnixMs,
        expiresAtUnixMs: acquiredAtUnixMs + leaseMilliseconds,
      }, { directoryPin: lockPin });
      await syncDirectory(rootPin.path, rootPin);
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST') {
        if (error?.code?.startsWith?.('TRANSFER_')) throw error;
        mapIo(error, 'state lock acquisition failed');
      }
      await recoverExpiredLock(rootPin, lockPath, lockTime(now()), leaseMilliseconds);
      if (attempt + 1 < attempts) await delay(delayMilliseconds);
    }
  }
  if (!lockPin) transferError(busyCode, busyMessage);
  let stopped = false;
  let renewalFailure;
  let ownerExpiresAtUnixMs;
  let renewal = Promise.resolve();
  const heartbeatMilliseconds = Math.max(100, Math.floor(leaseMilliseconds / 3));
  const guardedOwner = async () => {
    try { return await lockOwner(lockPath, lockPin); }
    catch (error) {
      if (error?.code === 'TRANSFER_BACKEND_IO') {
        transferError(busyCode, 'state lock ownership was lost', { cause: error });
      }
      throw error;
    }
  };
  const renew = (force = false) => {
    renewal = renewal.then(async () => {
      if (stopped) transferError(busyCode, 'state lock lease is no longer active');
      if (renewalFailure) throw renewalFailure;
      const current = await guardedOwner();
      if (current?.token !== token) transferError(busyCode, 'state lock ownership was lost');
      const renewedAtUnixMs = lockTime(now());
      if (!force && ownerExpiresAtUnixMs - renewedAtUnixMs > Math.floor(leaseMilliseconds / 2)) return;
      if (renewedAtUnixMs > Number.MAX_SAFE_INTEGER - leaseMilliseconds) {
        transferError('TRANSFER_BACKEND_IO', 'storage lock clock exceeds its safe range');
      }
      const nextOwner = {
        schemaVersion: 'ogvcs.object-transfer/lock-owner/v1',
        token,
        pid: process.pid,
        acquiredAtUnixMs: renewedAtUnixMs,
        expiresAtUnixMs: renewedAtUnixMs + leaseMilliseconds,
      };
      await atomicJsonWrite(`${lockPath}/${LOCK_OWNER}`, nextOwner, { directoryPin: lockPin });
      const confirmed = await guardedOwner();
      if (confirmed?.token !== token || confirmed.expiresAtUnixMs !== nextOwner.expiresAtUnixMs) {
        transferError(busyCode, 'state lock renewal lost its fencing token');
      }
      ownerExpiresAtUnixMs = nextOwner.expiresAtUnixMs;
    });
    return renewal;
  };
  const guard = Object.freeze({
    [LOCK_GUARD]: true,
    fencingToken: token,
    assertOwned: () => renew(true),
  });
  const heartbeat = setInterval(() => {
    if (stopped || renewalFailure) return;
    renew(false).catch((error) => { renewalFailure = error; });
  }, heartbeatMilliseconds);
  heartbeat.unref?.();
  const initialOwner = await guardedOwner();
  if (initialOwner?.token !== token) {
    clearInterval(heartbeat);
    transferError(busyCode, 'state lock ownership was lost');
  }
  ownerExpiresAtUnixMs = initialOwner.expiresAtUnixMs;
  let outcome;
  let failure;
  try { outcome = await operation(guard); } catch (error) { failure = error; }
  clearInterval(heartbeat);
  try { await renewal; } catch (error) { if (!failure) failure = error; }
  if (renewalFailure && !failure) failure = renewalFailure;
  stopped = true;
  try {
    const owner = await lockOwner(lockPath, lockPin);
    if (owner?.token !== token) transferError(busyCode, 'state lock ownership was lost');
    await unlink(`${lockPath}/${LOCK_OWNER}`);
    await rmdir(lockPath);
    await syncDirectory(rootPin.path, rootPin);
  } catch (error) { if (!failure) failure = error; }
  if (failure) throw failure;
  return outcome;
}
