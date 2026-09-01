import { createHash, randomBytes } from 'node:crypto';
import {
  constants,
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  unlink,
  link,
} from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { canonicalJson, isDigest, isId, sha256 } from './reference-contract.mjs';

const STATE_SCHEMA = 'ogvcs.untrusted-sandbox/reference-state/v1';
const NONTERMINAL = new Set(['acquiring', 'queued', 'running', 'staged', 'validating', 'committing']);
const MAXIMUM_STATE_FILES = 100_000;

const randomSuffix = () => randomBytes(16).toString('hex');
const withinRoot = (root, candidate) => candidate.startsWith(`${root}${sep}`);

const syncDirectory = async (path) => {
  const handle = await open(path, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
};

const syncDirectoryTree = async (path) => {
  const entries = await readdir(path, { withFileTypes: true });
  if (entries.length > MAXIMUM_STATE_FILES) throw new Error('output directory entry ceiling exceeded');
  for (const entry of entries) if (entry.isDirectory()) await syncDirectoryTree(join(path, entry.name));
  await syncDirectory(path);
};

const atomicBytes = async (path, bytes, mode = 0o600) => {
  const parent = dirname(path);
  const temporary = join(parent, `.tmp.${randomSuffix()}`);
  const handle = await open(temporary, 'wx', mode);
  try {
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    throw error;
  }
  await handle.close();
  await rename(temporary, path);
  await syncDirectory(parent);
};

const atomicJson = async (path, value) => atomicBytes(path, Buffer.from(`${canonicalJson(value)}\n`, 'utf8'));

const readJson = async (path) => {
  try {
    const bytes = await readFile(path);
    const text = bytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(bytes) || !text.endsWith('\n')) throw new Error('state record encoding differs');
    const value = JSON.parse(text.slice(0, -1));
    if (`${canonicalJson(value)}\n` !== text) throw new Error('state record is not canonical');
    return value;
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
};

const validateRoot = async (source) => {
  if (typeof source !== 'string' || !isAbsolute(source) || source.length > 4096) throw new TypeError('reference state root must be an absolute path');
  const requestedRoot = resolve(source);
  await mkdir(requestedRoot, { mode: 0o700, recursive: true });
  // Canonicalize platform-owned prefixes (for example macOS /var -> /private/var)
  // once, then use only this immutable root for every subsequent state path.
  const root = await realpath(requestedRoot);
  const details = await lstat(root);
  if (!details.isDirectory() || details.isSymbolicLink() || (details.mode & 0o077) !== 0 || (typeof process.geteuid === 'function' && details.uid !== process.geteuid())) throw new Error('reference state root ownership or mode is unsafe');
  return root;
};

const ensurePrivateDirectory = async (path) => {
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const details = await lstat(path);
  if (!details.isDirectory() || details.isSymbolicLink() || (details.mode & 0o077) !== 0 || (typeof process.geteuid === 'function' && details.uid !== process.geteuid())) throw new Error('reference state directory ownership or mode is unsafe');
};

const processIdentity = async () => {
  if (process.platform !== 'linux') return Object.freeze({ bootId: 'non-linux', pid: process.pid, startTicks: null });
  const [bootId, statText] = await Promise.all([
    readFile('/proc/sys/kernel/random/boot_id', 'utf8'),
    readFile(`/proc/${process.pid}/stat`, 'utf8'),
  ]);
  const close = statText.lastIndexOf(')');
  const fields = statText.slice(close + 2).split(' ');
  return Object.freeze({ bootId: bootId.trim(), pid: process.pid, startTicks: fields[19] });
};

const sameLiveProcess = async (owner) => {
  if (process.platform !== 'linux' || owner === null || typeof owner !== 'object' || !Number.isSafeInteger(owner.pid) || typeof owner.bootId !== 'string' || typeof owner.startTicks !== 'string') return true;
  try {
    const [bootId, statText] = await Promise.all([
      readFile('/proc/sys/kernel/random/boot_id', 'utf8'),
      readFile(`/proc/${owner.pid}/stat`, 'utf8'),
    ]);
    const close = statText.lastIndexOf(')');
    const fields = statText.slice(close + 2).split(' ');
    return bootId.trim() === owner.bootId && fields[19] === owner.startTicks;
  } catch {
    return false;
  }
};

const acquireServiceLease = async (root) => {
  const lockPath = join(root, '.worker-lock');
  const identity = await processIdentity();
  const create = async () => {
    await mkdir(lockPath, { mode: 0o700 });
    await atomicJson(join(lockPath, 'owner.json'), { ...identity, schemaVersion: STATE_SCHEMA });
    await syncDirectory(root);
  };
  try {
    await create();
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const owner = await readJson(join(lockPath, 'owner.json')).catch(() => null);
    if (await sameLiveProcess(owner)) throw new Error('reference state root already has an active or unprovable owner');
    const stale = join(root, `.worker-lock.stale.${randomSuffix()}`);
    try { await rename(lockPath, stale); } catch { throw new Error('reference state lease recovery lost a race'); }
    await create();
    await rm(stale, { recursive: true, force: true });
  }
  let released = false;
  return async () => {
    if (released) return;
    const owner = await readJson(join(lockPath, 'owner.json')).catch(() => null);
    if (owner?.pid !== identity.pid || owner?.bootId !== identity.bootId || owner?.startTicks !== identity.startTicks) throw new Error('reference state lease ownership changed');
    released = true;
    await rm(lockPath, { recursive: true, force: true });
    await syncDirectory(root);
  };
};

const fileDigest = async (path, maximumBytes = Number.MAX_SAFE_INTEGER) => {
  const handle = await open(path, 'r');
  const hash = createHash('sha256');
  let bytes = 0;
  const buffer = Buffer.allocUnsafe(64 * 1024);
  try {
    while (true) {
      const read = await handle.read(buffer, 0, buffer.length, null);
      if (read.bytesRead === 0) break;
      bytes += read.bytesRead;
      if (bytes > maximumBytes) throw new Error('file exceeds bounded digest input');
      hash.update(buffer.subarray(0, read.bytesRead));
    }
  } finally {
    await handle.close();
  }
  return Object.freeze({ bytes, digest: hash.digest('hex') });
};

export const digestOpenFile = async (handle, maximumBytes = Number.MAX_SAFE_INTEGER) => {
  const details = await handle.stat();
  if (!details.isFile() || details.size > maximumBytes) throw new Error('open immutable file exceeds its bound');
  const hash = createHash('sha256');
  const buffer = Buffer.allocUnsafe(64 * 1024);
  let position = 0;
  while (position < details.size) {
    const value = await handle.read(buffer, 0, Math.min(buffer.length, details.size - position), position);
    if (value.bytesRead === 0) throw new Error('open immutable file ended early');
    hash.update(buffer.subarray(0, value.bytesRead));
    position += value.bytesRead;
  }
  return Object.freeze({ bytes: position, digest: hash.digest('hex') });
};

export const openPinnedImmutableFile = async (path, expectedDigest, maximumBytes, { executable = false } = {}) => {
  if (!isDigest(expectedDigest) || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw new TypeError('immutable file request is invalid');
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const details = await handle.stat();
    const owner = typeof process.geteuid === 'function' ? process.geteuid() : details.uid;
    const expectedMode = executable ? 0o555 : 0o444;
    if (!details.isFile() || (details.mode & 0o777) !== expectedMode || ![0, owner].includes(details.uid)) throw new Error('immutable file ownership or mode differs');
    const value = await digestOpenFile(handle, maximumBytes);
    if (value.digest !== expectedDigest) throw new Error('immutable file digest differs');
    return Object.freeze({ ...value, handle });
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
};

const iterableFor = (source) => {
  if (Buffer.isBuffer(source) && Object.getPrototypeOf(source) === Buffer.prototype) return (async function* () { yield Buffer.from(source); }());
  if (source && typeof source[Symbol.asyncIterator] === 'function') return source;
  return null;
};

export class ReferenceStateStore {
  #root;
  #release;
  #serial = Promise.resolve();
  #closed = false;

  static async open(rootSource) {
    const root = await validateRoot(rootSource);
    const release = await acquireServiceLease(root);
    try {
      for (const directory of ['evidence', 'idempotency', 'jobs', 'outputs', 'quarantine', 'revocations', 'staged', 'temporary']) await ensurePrivateDirectory(join(root, directory));
      return new ReferenceStateStore(root, release);
    } catch (error) {
      await release().catch(() => {});
      throw error;
    }
  }

  constructor(root, release) {
    this.#root = root;
    this.#release = release;
  }

  get root() { return this.#root; }

  path(...segments) {
    const candidate = resolve(this.#root, ...segments);
    if (!withinRoot(this.#root, candidate)) throw new Error('state path escaped root');
    return candidate;
  }

  async serial(operation) {
    if (this.#closed) throw new Error('reference state is closed');
    const previous = this.#serial;
    let resolveCurrent;
    this.#serial = new Promise((resolve) => { resolveCurrent = resolve; });
    await previous;
    try { return await operation(); } finally { resolveCurrent(); }
  }

  async close() {
    if (this.#closed) return;
    await this.#serial;
    this.#closed = true;
    await this.#release();
  }

  async readJob(jobId) {
    if (!isId(jobId)) throw new TypeError('job id is invalid');
    return readJson(this.path('jobs', `${jobId}.json`));
  }

  async writeJob(record) {
    if (!isId(record?.jobId)) throw new TypeError('job record is invalid');
    await atomicJson(this.path('jobs', `${record.jobId}.json`), record);
  }

  async readIdempotency(idempotencyKey) {
    if (!isId(idempotencyKey)) throw new TypeError('idempotency key is invalid');
    return readJson(this.path('idempotency', `${sha256(Buffer.from(idempotencyKey, 'utf8'))}.json`));
  }

  async writeIdempotency(idempotencyKey, value) {
    if (!isId(idempotencyKey)) throw new TypeError('idempotency key is invalid');
    await atomicJson(this.path('idempotency', `${sha256(Buffer.from(idempotencyKey, 'utf8'))}.json`), value);
  }

  async recoverInterrupted(nowUnixMs) {
    const entries = (await readdir(this.path('jobs'), { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.endsWith('.json'));
    if (entries.length > MAXIMUM_STATE_FILES) throw new Error('reference state job ceiling exceeded');
    const recovered = [];
    for (const entry of entries) {
      const record = await readJson(this.path('jobs', entry.name));
      if (!record || !NONTERMINAL.has(record.state)) continue;
      const result = {
        cleanupReceiptDigest: null,
        code: 'SANDBOX_UNAVAILABLE',
        jobId: record.jobId,
        outputDigest: null,
        provenanceDigest: null,
        schemaVersion: 'ogvcs.untrusted-sandbox/reference-result/v1',
        status: 'denied',
      };
      await rm(this.path('outputs', record.jobId), { recursive: true, force: true });
      await this.writeJob({ ...record, completedAtUnixMs: nowUnixMs, result, state: 'denied', securityEvents: [...(record.securityEvents ?? []), 'WORKER_RESTART_RECOVERY'] });
      recovered.push(record.jobId);
    }
    await this.removeTemporaryEntries();
    return Object.freeze(recovered);
  }

  async removeTemporaryEntries() {
    const temporary = this.path('temporary');
    const entries = await readdir(temporary);
    if (entries.length > MAXIMUM_STATE_FILES) throw new Error('reference temporary ceiling exceeded');
    for (const entry of entries) await rm(join(temporary, entry), { recursive: true, force: true });
  }

  async stageInput({ expectedDigest, maximumBytes, source }) {
    if (!isDigest(expectedDigest) || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1) throw new TypeError('staging request is invalid');
    const iterator = iterableFor(source);
    if (!iterator) throw new TypeError('acquisition adapter did not return bytes');
    const finalPath = this.path('staged', expectedDigest);
    try {
      const existing = await fileDigest(finalPath, maximumBytes);
      if (existing.digest !== expectedDigest) throw new Error('persisted staged input digest differs');
      return Object.freeze({ bytes: existing.bytes, digest: existing.digest, path: finalPath });
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    const temporary = this.path('temporary', `stage.${randomSuffix()}`);
    const handle = await open(temporary, 'wx', 0o600);
    const hash = createHash('sha256');
    let bytes = 0;
    try {
      for await (const chunkSource of iterator) {
        if (!Buffer.isBuffer(chunkSource) || Object.getPrototypeOf(chunkSource) !== Buffer.prototype) throw new TypeError('acquisition adapter emitted a non-buffer chunk');
        const chunk = Buffer.from(chunkSource);
        bytes += chunk.length;
        if (bytes > maximumBytes) throw new Error('acquired input exceeds declared quota');
        hash.update(chunk);
        await handle.write(chunk);
      }
      await handle.sync();
    } catch (error) {
      await handle.close().catch(() => {});
      await unlink(temporary).catch(() => {});
      throw error;
    }
    await handle.close();
    const digest = hash.digest('hex');
    if (digest !== expectedDigest) {
      await unlink(temporary).catch(() => {});
      throw new Error('acquired input digest differs');
    }
    await chmod(temporary, 0o444);
    try {
      await link(temporary, finalPath);
      await syncDirectory(this.path('staged'));
    } catch (error) {
      if (error?.code !== 'EEXIST') {
        await unlink(temporary).catch(() => {});
        throw error;
      }
      const existing = await fileDigest(finalPath, maximumBytes);
      if (existing.digest !== expectedDigest || existing.bytes !== bytes) throw new Error('concurrent staged input differs');
    }
    await unlink(temporary).catch(() => {});
    return Object.freeze({ bytes, digest, path: finalPath });
  }

  async verifyImmutableFile(path, expectedDigest, maximumBytes) {
    const resolved = await realpath(path);
    const details = await lstat(resolved);
    if (!details.isFile() || details.isSymbolicLink() || (details.mode & 0o022) !== 0) throw new Error('immutable file mode differs');
    const value = await fileDigest(resolved, maximumBytes);
    if (value.digest !== expectedDigest) throw new Error('immutable file digest differs');
    return Object.freeze({ ...value, path: resolved });
  }

  async writeEvidence(label, value) {
    if (!isDigest(label) && !isId(label)) throw new TypeError('evidence label is invalid');
    const bytes = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
    await atomicBytes(this.path('evidence', `${label}.json`), bytes, 0o600);
    return sha256(bytes);
  }

  async createOutputTemporary(jobId) {
    if (!isId(jobId)) throw new TypeError('job id is invalid');
    const path = this.path('temporary', `output.${jobId}.${randomSuffix()}`);
    await mkdir(path, { mode: 0o700 });
    return path;
  }

  async createEphemeralPinnedFile(prefix, bytes) {
    if (!isId(prefix) || !Buffer.isBuffer(bytes) || Object.getPrototypeOf(bytes) !== Buffer.prototype || bytes.length < 1 || bytes.length > 1024 * 1024) throw new TypeError('ephemeral pinned file is invalid');
    const path = this.path('temporary', `${prefix}.${randomSuffix()}`);
    const writer = await open(path, 'wx', 0o444);
    try { await writer.writeFile(bytes); await writer.sync(); } finally { await writer.close(); }
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    await unlink(path);
    return handle;
  }

  async commitOutput(jobId, temporary) {
    if (!isId(jobId) || !withinRoot(this.path('temporary'), resolve(temporary))) throw new TypeError('output commit path is invalid');
    const finalPath = this.path('outputs', jobId);
    await syncDirectoryTree(temporary);
    await mkdir(finalPath, { mode: 0o700 });
    try {
      await rename(temporary, join(finalPath, 'bundle'));
    } catch (error) {
      await rm(finalPath, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
    await syncDirectory(join(finalPath, 'bundle'));
    await syncDirectory(finalPath);
    await syncDirectory(this.path('outputs'));
    return join(finalPath, 'bundle');
  }

  async removeOutput(jobId) {
    if (!isId(jobId)) throw new TypeError('job id is invalid');
    await rm(this.path('outputs', jobId), { recursive: true, force: true });
  }

  async writeRevocation(record) {
    if (!['runtime', 'tool'].includes(record?.kind) || !isDigest(record?.digest) || !Number.isSafeInteger(record?.throughGeneration) || record.throughGeneration < 1 || !isId(record?.reasonCode)) throw new TypeError('revocation record is invalid');
    await atomicJson(this.path('revocations', `${record.kind}.${record.digest}.json`), record);
  }

  async readRevocation(kind, digest) {
    if (!['runtime', 'tool'].includes(kind) || !isDigest(digest)) throw new TypeError('revocation lookup is invalid');
    return readJson(this.path('revocations', `${kind}.${digest}.json`));
  }

  async countCompletedForDigest(kind, digest, throughGeneration = Number.MAX_SAFE_INTEGER) {
    if (!['runtime', 'tool'].includes(kind) || !isDigest(digest) || !Number.isSafeInteger(throughGeneration) || throughGeneration < 1) throw new TypeError('affected-job lookup is invalid');
    const entries = (await readdir(this.path('jobs'), { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.endsWith('.json'));
    if (entries.length > MAXIMUM_STATE_FILES) throw new Error('reference state job ceiling exceeded');
    let count = 0;
    const key = kind === 'tool' ? 'toolDigest' : 'runtimeDigest';
    for (const entry of entries) {
      const record = await readJson(this.path('jobs', entry.name));
      if (record?.state === 'validated' && record[key] === digest && Number.isSafeInteger(record.manifestGeneration) && record.manifestGeneration <= throughGeneration) count += 1;
    }
    return count;
  }

  async quarantineCompletedForDigest(kind, digest, throughGeneration, nowUnixMs) {
    if (!['runtime', 'tool'].includes(kind) || !isDigest(digest) || !Number.isSafeInteger(throughGeneration) || throughGeneration < 1 || !Number.isSafeInteger(nowUnixMs) || nowUnixMs < 0) throw new TypeError('output quarantine request is invalid');
    const entries = (await readdir(this.path('jobs'), { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.endsWith('.json'));
    if (entries.length > MAXIMUM_STATE_FILES) throw new Error('reference state job ceiling exceeded');
    const key = kind === 'tool' ? 'toolDigest' : 'runtimeDigest';
    let affected = 0;
    for (const entry of entries) {
      const record = await readJson(this.path('jobs', entry.name));
      if (record?.state !== 'validated' || record[key] !== digest || !Number.isSafeInteger(record.manifestGeneration) || record.manifestGeneration > throughGeneration) continue;
      const outputPath = this.path('outputs', record.jobId);
      const quarantinePath = this.path('quarantine', `${record.jobId}.${kind}.${digest}.${throughGeneration}`);
      try {
        await rename(outputPath, quarantinePath);
        await syncDirectory(this.path('outputs'));
        await syncDirectory(this.path('quarantine'));
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
        const quarantined = await lstat(quarantinePath).catch(() => null);
        if (!quarantined?.isDirectory() || quarantined.isSymbolicLink()) throw new Error('validated output disappeared before revocation quarantine');
      }
      const securityEvents = [...new Set([...(record.securityEvents ?? []), 'OUTPUT_REVOKED'])].sort();
      await this.writeJob({
        ...record,
        result: { ...record.result, code: 'SANDBOX_REVOKED', outputDigest: null, status: 'denied' },
        revokedAtUnixMs: nowUnixMs,
        revocationGeneration: throughGeneration,
        securityEvents,
        state: 'denied',
      });
      affected += 1;
    }
    return affected;
  }

  async reconcileRevocations(nowUnixMs) {
    if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs < 0) throw new TypeError('revocation recovery clock is invalid');
    const entries = (await readdir(this.path('revocations'), { withFileTypes: true })).filter((entry) => entry.isFile() && entry.name.endsWith('.json'));
    if (entries.length > MAXIMUM_STATE_FILES) throw new Error('reference state revocation ceiling exceeded');
    for (const entry of entries) {
      const record = await readJson(this.path('revocations', entry.name));
      if (!['runtime', 'tool'].includes(record?.kind) || !isDigest(record?.digest) || !Number.isSafeInteger(record?.throughGeneration) || record.throughGeneration < 1) throw new Error('persisted revocation record is invalid');
      await this.quarantineCompletedForDigest(record.kind, record.digest, record.throughGeneration, nowUnixMs);
    }
  }
}

export const hashFile = fileDigest;
