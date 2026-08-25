import { types as utilTypes } from 'node:util';

import { canonicalDigest, codeUnitCompare, deepFreeze } from './canonical.mjs';
import { BenchmarkHarnessError, harnessFail } from './errors.mjs';
import { FaultScheduler, isInjectedFault } from './faults.mjs';
import { snapshotData, snapshotOptions } from './input.mjs';

const TASKS = new Set(['setup', 'status', 'sync', 'submit', 'lock', 'merge', 'ci', 'verify', 'backup', 'restore', 'export']);
const INCOMPLETE_CODES = new Set(['HARNESS_RETRYABLE', 'HARNESS_TASK_INCOMPLETE', 'HARNESS_DEADLINE_EXCEEDED', 'HARNESS_CANCELLED', 'HARNESS_IO']);

function initialState() {
  return {
    repositoryReady: false,
    objects: new Map(),
    commits: new Map([['root', { id: 'root', parent: null, objectIds: [], published: true, authorized: true, lockViolation: false }]]),
    branches: new Map([['main', 'root']]),
    locks: new Map(),
    events: [],
    outbox: [],
    indexCursor: 0,
    backups: new Map(),
    exports: new Map(),
    restored: false,
    unauthorizedReads: 0,
    workspaceEscapes: 0,
    gcMarks: new Set(),
  };
}

function projection(state) {
  const entries = (map) => [...map.entries()].sort(([a], [b]) => codeUnitCompare(a, b));
  return {
    repositoryReady: state.repositoryReady,
    objects: entries(state.objects), commits: entries(state.commits), branches: entries(state.branches), locks: entries(state.locks),
    events: state.events, outbox: state.outbox, indexCursor: state.indexCursor, backups: entries(state.backups), exports: entries(state.exports),
    restored: state.restored, unauthorizedReads: state.unauthorizedReads, workspaceEscapes: state.workspaceEscapes, gcMarks: [...state.gcMarks].sort(),
  };
}

function cloneState(state) { return structuredClone(state); }
function objectDigest(value) { return canonicalDigest(value, 'ogvcs.benchmark/fake-object/v1'); }

export class FakeRepositoryService {
  #state = initialState();
  #scheduler;
  #idempotency = new Map();
  #mutationCount = 0;
  #brokenMode;
  constructor(options = {}) { options = snapshotOptions(options, 'fake service options'); this.#brokenMode = options.brokenMode; }
  setFaultScheduler(scheduler) { if (utilTypes.isProxy(scheduler) || !(scheduler instanceof FaultScheduler)) harnessFail('HARNESS_INPUT_INVALID', 'fake service scheduler must be a non-proxy FaultScheduler'); this.#scheduler = scheduler; }
  mutationCount() { return this.#mutationCount; }
  snapshot() { return deepFreeze(projection(this.#state)); }
  snapshotDigest() { return canonicalDigest(projection(this.#state), 'ogvcs.benchmark/fake-service-state/v1'); }
  #point(id, phase = 'before') { return this.#scheduler?.point(id, phase) ?? []; }
  #mutated(count = 1) { this.#mutationCount += count; }
  #commit(draft) { this.#state = draft; this.#mutated(); }
  #requireReady() { if (!this.#state.repositoryReady) harnessFail('HARNESS_TASK_INCOMPLETE', 'repository setup has not completed'); }

  async executeTask(taskId, input = {}) {
    input = snapshotOptions(input, 'fake service task input');
    if (!TASKS.has(taskId)) harnessFail('HARNESS_INPUT_INVALID', 'task is not registered');
    const key = input.idempotencyKey;
    if (typeof key !== 'string' || key.length < 16 || key.length > 256) harnessFail('HARNESS_INPUT_INVALID', 'task idempotency key is invalid');
    const { idempotencyKey: _idempotencyKey, cache: _cache, network: _network, signal: _signal, ...semanticInput } = input;
    const requestDigest = canonicalDigest({ taskId, input: semanticInput }, 'ogvcs.benchmark/fake-task-request/v1');
    const prior = this.#idempotency.get(key);
    if (prior) {
      if (prior.requestDigest !== requestDigest) harnessFail('HARNESS_INPUT_INVALID', 'task idempotency key was reused with different input');
      const retries = prior.result.retries + 1;
      const result = { ...structuredClone(prior.result), mutationCount: 0, retries, metrics: { ...structuredClone(prior.result.metrics), retries } };
      this.#idempotency.set(key, { requestDigest, result: structuredClone(result) });
      return deepFreeze(result);
    }
    const beforeMutations = this.#mutationCount;
    const metrics = { diskReadBytes: 0, diskWriteBytes: 0, networkReadBytes: 0, networkWriteBytes: 0, logicalBytes: input.logicalBytes ?? 4096, uniqueBytes: input.uniqueBytes ?? 3072, retries: 0 };
    let output;
    let status = 'success';
    let code = 'HARNESS_OK';
    try {
      output = await this.#dispatch(taskId, input, metrics);
    } catch (error) {
      if (isInjectedFault(error)) { status = 'incomplete'; code = error.code; output = { injectedFault: error.event }; }
      else if (error instanceof BenchmarkHarnessError) { status = INCOMPLETE_CODES.has(error.code) ? 'incomplete' : 'failed'; code = error.code; output = null; }
      else throw error;
    }
    const invariants = checkRepositoryInvariants(this);
    const mutationCount = this.#mutationCount - beforeMutations;
    const assertions = taskAssertions(taskId, invariants, input, output, this.#state, mutationCount);
    if (status === 'success' && assertions.some(({ passed }) => !passed)) { status = 'failed'; code = 'HARNESS_ASSERTION_FAILED'; }
    const result = { status, code, mutationCount, retries: metrics.retries, metrics, assertions, output };
    if (status === 'success' || result.mutationCount > 0) this.#idempotency.set(key, { requestDigest, result: structuredClone(result) });
    return deepFreeze(result);
  }

  async #dispatch(taskId, input, metrics) {
    switch (taskId) {
      case 'setup': return this.#setup(input, metrics);
      case 'status': return this.#status(input, metrics);
      case 'sync': return this.#sync(input, metrics);
      case 'submit': return this.#submit(input, metrics, 'submit');
      case 'lock': return this.#lock(input, metrics);
      case 'merge': return this.#submit(input, metrics, 'merge');
      case 'ci': return this.#ci(input, metrics);
      case 'verify': return this.#verify(input, metrics);
      case 'backup': return this.#backup(input, metrics);
      case 'restore': return this.#restore(input, metrics);
      case 'export': return this.#export(input, metrics);
      default: harnessFail('HARNESS_INPUT_INVALID', 'task is not implemented');
    }
  }

  #setup(_input, metrics) {
    if (this.#state.repositoryReady) return { ready: true };
    this.#point('durable.write');
    metrics.diskWriteBytes += 4096;
    this.#point('durable.write', 'after');
    const draft = cloneState(this.#state);
    draft.repositoryReady = true;
    this.#point('metadata.commit');
    this.#commit(draft);
    this.#point('metadata.commit', 'after');
    return { ready: true };
  }

  #status(_input, metrics) {
    this.#requireReady();
    metrics.diskReadBytes += 1024;
    return { head: this.#state.branches.get('main'), generation: this.#state.commits.size - 1 };
  }

  async #sync(input, metrics) {
    this.#requireReady();
    const bytes = input.logicalBytes ?? 4096;
    this.#point('durable.write');
    this.#point('durable.write', 'after');
    this.#point('object.finalize');
    this.#point('object.finalize', 'after');
    input.cache?.read(bytes);
    const transfer = input.network ? await input.network.transfer(bytes, 'receive', input.signal) : { wireBytes: bytes, retries: 0 };
    metrics.diskWriteBytes += bytes;
    metrics.networkReadBytes += transfer.wireBytes;
    metrics.retries += transfer.retries;
    if (this.#brokenMode === 'workspace-escape') { this.#state.workspaceEscapes += 1; this.#mutated(); }
    return { materializedBytes: bytes, snapshot: this.#state.branches.get('main') };
  }

  async #submit(input, metrics, kind) {
    this.#requireReady();
    const parent = this.#state.branches.get('main');
    if (typeof input.expectedHead !== 'string' || input.expectedHead.length < 1 || input.expectedHead.length > 256) harnessFail('HARNESS_INPUT_INVALID', 'branch compare-and-swap input is required');
    if (input.expectedHead !== parent) harnessFail('HARNESS_ASSERTION_FAILED', 'branch compare-and-swap input is stale');
    const commitId = canonicalDigest({ kind, parent, key: input.idempotencyKey }, 'ogvcs.benchmark/fake-commit/v1').slice(0, 32);
    const objectId = objectDigest({ commitId, bytes: input.logicalBytes ?? 4096 }).slice(0, 32);
    const draft = cloneState(this.#state);
    this.#point('durable.write');
    metrics.diskWriteBytes += input.uniqueBytes ?? 3072;
    if (this.#brokenMode !== 'missing-content-publication') draft.objects.set(objectId, { available: false, bytes: input.uniqueBytes ?? 3072 });
    this.#point('durable.write', 'after');
    this.#point('object.finalize');
    if (draft.objects.has(objectId)) draft.objects.get(objectId).available = true;
    this.#point('object.finalize', 'after');
    this.#point('policy.decision');
    const authorized = input.authorized !== false;
    if (!authorized && this.#brokenMode !== 'unauthorized-access') harnessFail('HARNESS_ASSERTION_FAILED', 'submit was not authorized');
    this.#point('policy.decision', 'after');
    this.#point('branch.cas');
    if (draft.branches.get('main') !== parent) harnessFail('HARNESS_ASSERTION_FAILED', 'branch compare-and-swap failed');
    this.#point('branch.cas', 'after');
    const activeLock = input.fileId ? draft.locks.get(input.fileId) : undefined;
    const lockViolation = Boolean(activeLock && activeLock.owner !== input.actor);
    if (lockViolation && this.#brokenMode !== 'dual-hard-lock-submit') harnessFail('HARNESS_ASSERTION_FAILED', 'hard lock denied submit');
    draft.commits.set(commitId, { id: commitId, parent, objectIds: [objectId], published: this.#brokenMode !== 'invisible-committed-state', authorized, lockViolation });
    if (this.#brokenMode !== 'invisible-committed-state') draft.branches.set('main', commitId);
    draft.outbox.push({ type: 'commit', id: commitId });
    this.#point('metadata.commit');
    this.#commit(draft);
    this.#point('metadata.commit', 'after');
    this.#point('event.publish');
    const event = this.#state.outbox.shift();
    if (event) { this.#state.events.push(event); this.#mutated(); }
    this.#point('event.publish', 'after');
    this.#point('index.cursor');
    this.#state.indexCursor += 1;
    this.#mutated();
    this.#point('index.cursor', 'after');
    const transfer = input.network ? await input.network.transfer(input.logicalBytes ?? 4096, 'send', input.signal) : { wireBytes: input.logicalBytes ?? 4096, retries: 0 };
    metrics.networkWriteBytes += transfer.wireBytes;
    metrics.retries += transfer.retries;
    return { commitId, objectId, kind };
  }

  #lock(input, metrics) {
    this.#requireReady();
    const fileId = input.fileId ?? '00000000000000000000000000000001';
    const owner = input.actor ?? 'operator-a';
    this.#point('policy.decision');
    const draft = cloneState(this.#state);
    const existing = draft.locks.get(fileId);
    if (existing && existing.owner !== owner) harnessFail('HARNESS_ASSERTION_FAILED', 'hard lock already held');
    this.#point('policy.decision', 'after');
    this.#point('lock.mutation');
    draft.locks.set(fileId, { owner, generation: (existing?.generation ?? 0) + 1 });
    this.#point('lock.mutation', 'after');
    draft.outbox.push({ type: 'lock', id: fileId });
    this.#point('metadata.commit');
    this.#commit(draft);
    this.#point('metadata.commit', 'after');
    this.#point('event.publish');
    const event = this.#state.outbox.shift(); if (event) { this.#state.events.push(event); this.#mutated(); }
    this.#point('event.publish', 'after');
    metrics.diskWriteBytes += 512;
    return { fileId, owner };
  }

  #ci(input, metrics) {
    this.#requireReady();
    const head = this.#state.branches.get('main');
    const commit = this.#state.commits.get(head);
    for (const id of commit.objectIds) { this.#point('object.finalize'); metrics.diskReadBytes += this.#state.objects.get(id)?.bytes ?? 0; this.#point('object.finalize', 'after'); }
    this.#point('index.cursor');
    this.#point('index.cursor', 'after');
    input.cache?.read(metrics.diskReadBytes);
    return { snapshot: head, verified: true };
  }

  #verify(_input, metrics) {
    this.#requireReady();
    this.#point('gc.mark');
    const marks = new Set();
    for (const commit of this.#state.commits.values()) for (const id of commit.objectIds) marks.add(id);
    this.#state.gcMarks = marks;
    this.#mutated();
    this.#point('gc.mark', 'after');
    this.#point('gc.sweep');
    for (const id of [...this.#state.objects.keys()]) if (!marks.has(id)) { this.#state.objects.delete(id); this.#mutated(); }
    this.#point('gc.sweep', 'after');
    this.#point('index.cursor');
    this.#point('index.cursor', 'after');
    metrics.diskReadBytes += this.#state.objects.size * 128;
    return { invariants: checkRepositoryInvariants(this) };
  }

  #backup(_input, metrics) {
    this.#requireReady();
    const id = `backup-${String(this.#state.backups.size + 1).padStart(4, '0')}`;
    const content = { head: this.#state.branches.get('main'), objectIds: [...this.#state.objects.keys()].sort() };
    this.#point('backup.generate');
    const record = { content, digest: objectDigest(content) };
    if (this.#brokenMode === 'unverifiable-backup') record.digest = '0'.repeat(64);
    this.#point('backup.generate', 'after');
    const draft = cloneState(this.#state); draft.backups.set(id, record);
    this.#point('metadata.commit'); this.#commit(draft); this.#point('metadata.commit', 'after');
    metrics.diskReadBytes += this.#state.objects.size * 1024; metrics.diskWriteBytes += metrics.diskReadBytes;
    return { backupId: id };
  }

  #restore(input, metrics) {
    this.#requireReady();
    const id = input.backupId ?? [...this.#state.backups.keys()].at(-1);
    const backup = this.#state.backups.get(id);
    if (!backup || objectDigest(backup.content) !== backup.digest) harnessFail('HARNESS_ASSERTION_FAILED', 'backup is not independently verifiable');
    this.#point('durable.write'); this.#point('durable.write', 'after'); this.#point('object.finalize'); this.#point('object.finalize', 'after');
    const draft = cloneState(this.#state); draft.restored = true;
    this.#point('metadata.commit'); this.#commit(draft); this.#point('metadata.commit', 'after');
    metrics.diskWriteBytes += backup.content.objectIds.length * 1024;
    return { backupId: id, activated: true };
  }

  #export(_input, metrics) {
    this.#requireReady();
    const id = `export-${String(this.#state.exports.size + 1).padStart(4, '0')}`;
    const content = { head: this.#state.branches.get('main'), commits: [...this.#state.commits.keys()].sort() };
    this.#point('durable.write');
    this.#point('durable.write', 'after');
    this.#point('export.finalize');
    const record = { content, digest: objectDigest(content) };
    if (this.#brokenMode === 'unverifiable-export') record.digest = 'f'.repeat(64);
    this.#state.exports.set(id, record); this.#mutated();
    this.#point('export.finalize', 'after');
    metrics.diskReadBytes += content.commits.length * 1024; metrics.diskWriteBytes += metrics.diskReadBytes;
    return { exportId: id };
  }
}

export function checkRepositoryInvariants(stateOrService) {
  const state = !utilTypes.isProxy(stateOrService) && stateOrService instanceof FakeRepositoryService ? stateOrService.snapshot() : snapshotData(stateOrService, 'repository invariant state');
  const objects = state.objects instanceof Map ? state.objects : new Map(state.objects);
  const commits = state.commits instanceof Map ? state.commits : new Map(state.commits);
  const branches = state.branches instanceof Map ? state.branches : new Map(state.branches);
  const backups = state.backups instanceof Map ? state.backups : new Map(state.backups);
  const exports = state.exports instanceof Map ? state.exports : new Map(state.exports);
  const referenced = [...commits.values()].flatMap(({ objectIds }) => objectIds);
  const reachableCommits = new Set();
  for (const head of branches.values()) {
    let current = head;
    while (current !== null && !reachableCommits.has(current) && commits.has(current)) {
      reachableCommits.add(current);
      current = commits.get(current).parent;
    }
  }
  const checks = [
    { id: 'content-complete', passed: referenced.every((id) => objects.get(id)?.available === true) },
    { id: 'authorized', passed: state.unauthorizedReads === 0 && [...commits.values()].every(({ authorized }) => authorized !== false) },
    { id: 'single-hard-lock', passed: [...commits.values()].every(({ lockViolation }) => lockViolation !== true) },
    { id: 'single-visible-commit', passed: [...commits.values()].every(({ id, published }) => id === 'root' || published === true && reachableCommits.has(id)) },
    { id: 'backup-verifiable', passed: [...backups.values()].every(({ content, digest }) => objectDigest(content) === digest) },
    { id: 'export-verifiable', passed: [...exports.values()].every(({ content, digest }) => objectDigest(content) === digest) },
    { id: 'workspace-confined', passed: state.workspaceEscapes === 0 },
    { id: 'references-verifiable', passed: [...branches.values()].every((id) => commits.has(id)) },
  ];
  return deepFreeze({ passed: checks.every(({ passed }) => passed), checks });
}

function taskAssertions(taskId, invariants, input, output, state, mutationCount) {
  const byId = new Map(invariants.checks.map((check) => [check.id, check.passed]));
  const names = {
    setup: ['workspace-isolated', 'repository-ready'], status: ['status-complete', 'no-hidden-mutation'], sync: ['content-complete', 'cache-state-observed'],
    submit: ['content-complete', 'authorized', 'single-visible-commit'], lock: ['single-hard-lock', 'lock-generation-fenced'], merge: ['content-complete', 'merge-base-bound', 'single-visible-commit'],
    ci: ['content-complete', 'snapshot-bound'], verify: ['content-complete', 'references-verifiable'], backup: ['backup-verifiable', 'content-complete'], restore: ['backup-verifiable', 'content-complete', 'activation-atomic'], export: ['export-verifiable', 'content-complete'],
  }[taskId];
  const head = state.branches.get('main');
  const commit = output?.commitId ? state.commits.get(output.commitId) : undefined;
  const lock = output?.fileId ? state.locks.get(output.fileId) : undefined;
  const direct = new Map([
    ['workspace-isolated', state.workspaceEscapes === 0],
    ['repository-ready', state.repositoryReady === true && output?.ready === true],
    ['status-complete', typeof output?.head === 'string' && Number.isSafeInteger(output?.generation) && output.generation >= 0],
    ['no-hidden-mutation', mutationCount === 0],
    ['cache-state-observed', Boolean(input.cache) && output?.materializedBytes === input.logicalBytes],
    ['lock-generation-fenced', lock?.owner === output?.owner && Number.isSafeInteger(lock?.generation) && lock.generation >= 1],
    ['merge-base-bound', output?.kind === 'merge' && commit?.parent === input.expectedHead],
    ['snapshot-bound', output?.snapshot === head],
    ['activation-atomic', state.restored === true && output?.activated === true],
  ]);
  return names.map((id) => ({ id, passed: direct.has(id) ? direct.get(id) : (byId.get(id) ?? false) }));
}
