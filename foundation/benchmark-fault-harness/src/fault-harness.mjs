import { DeterministicCacheController } from './cache.mjs';
import { deepFreeze } from './canonical.mjs';
import { FakeRepositoryService, checkRepositoryInvariants } from './fake-service.mjs';
import { FaultScheduler, createFaultSchedule, isInjectedFault } from './faults.mjs';
import { NetworkController } from './network.mjs';

const TASK_FOR_FAULT = Object.freeze({
  'durable.write': 'submit', 'object.finalize': 'submit', 'policy.decision': 'submit', 'branch.cas': 'submit',
  'lock.mutation': 'lock', 'metadata.commit': 'submit', 'event.publish': 'submit', 'index.cursor': 'submit',
  'backup.generate': 'backup', 'export.finalize': 'export', 'gc.mark': 'verify', 'gc.sweep': 'verify',
});

function input(key, extras = {}) { return { idempotencyKey: key.padEnd(16, '-'), logicalBytes: 4096, uniqueBytes: 3072, actor: 'operator-a', fileId: '00000000000000000000000000000001', authorized: true, expectedHead: 'root', ...extras }; }

async function prepare(service, contract, taskId) {
  await service.executeTask('setup', input(`prepare-${taskId}-setup`));
  if (taskId === 'backup') return;
  if (taskId === 'export' || taskId === 'verify' || taskId === 'submit' || taskId === 'lock') return;
  const cache = new DeterministicCacheController(); cache.prepare('cold');
  const profile = contract.registries.networks.entries.find(({ id }) => id === 'loopback-simulated');
  return { cache, network: new NetworkController(profile) };
}

export async function runFaultMatrix(contract, options = {}) {
  const rows = []; const schedules = [];
  for (const entry of contract.registries.faults.entries) {
    for (const action of ['crash-before', 'crash-after', 'error']) {
      const taskId = TASK_FOR_FAULT[entry.id];
      const service = new FakeRepositoryService();
      const prepared = await prepare(service, contract, taskId);
      const schedule = createFaultSchedule(`${options.seed ?? 'ogvcs-fault-matrix-v1'}-${entry.id}-${action}`, [entry.id], { count: 1, actions: [action], shuffle: false });
      schedules.push(schedule);
      const scheduler = new FaultScheduler(schedule); service.setFaultScheduler(scheduler);
      const result = await service.executeTask(taskId, input(`fault-${entry.id}-${action}`, prepared));
      const invariants = checkRepositoryInvariants(service);
      const observed = scheduler.observed().some(({ faultPoint, action: observedAction }) => faultPoint === entry.id && observedAction === action);
      rows.push({ faultPoint: entry.id, action, taskId, injected: observed, taskStatus: result.status, invariantPassed: invariants.passed, invariantFailures: invariants.checks.filter(({ passed }) => !passed).map(({ id }) => id), scheduleDigest: schedule.scheduleDigest });
    }
  }
  return deepFreeze({ rows, schedules, failed: rows.filter(({ injected, taskStatus, invariantPassed }) => !injected || taskStatus !== 'incomplete' || !invariantPassed).length });
}

async function exerciseBrokenMode(mode, expectedInvariant, operation) {
  const service = new FakeRepositoryService({ brokenMode: mode });
  await service.executeTask('setup', input(`${mode}-setup`));
  await operation(service);
  const invariants = checkRepositoryInvariants(service);
  return { mode, expectedInvariant, detected: invariants.checks.some(({ id, passed }) => id === expectedInvariant && !passed), failures: invariants.checks.filter(({ passed }) => !passed).map(({ id }) => id) };
}

export async function runBrokenServiceSelfTest(contract) {
  const network = new NetworkController(contract.registries.networks.entries.find(({ id }) => id === 'loopback-simulated'));
  const cache = new DeterministicCacheController(); cache.prepare('cold');
  const cases = [
    await exerciseBrokenMode('missing-content-publication', 'content-complete', (service) => service.executeTask('submit', input('broken-missing-content'))),
    await exerciseBrokenMode('invisible-committed-state', 'single-visible-commit', (service) => service.executeTask('submit', input('broken-invisible-commit'))),
    await exerciseBrokenMode('dual-hard-lock-submit', 'single-hard-lock', async (service) => { await service.executeTask('lock', input('broken-lock-other', { actor: 'operator-b' })); await service.executeTask('submit', input('broken-dual-lock', { actor: 'operator-a' })); }),
    await exerciseBrokenMode('unauthorized-access', 'authorized', (service) => service.executeTask('submit', input('broken-unauthorized', { authorized: false }))),
    await exerciseBrokenMode('unverifiable-backup', 'backup-verifiable', (service) => service.executeTask('backup', input('broken-backup'))),
    await exerciseBrokenMode('unverifiable-export', 'export-verifiable', (service) => service.executeTask('export', input('broken-export'))),
    await exerciseBrokenMode('workspace-escape', 'workspace-confined', (service) => service.executeTask('sync', input('broken-workspace', { cache, network }))),
  ];
  return deepFreeze({ cases, missed: cases.filter(({ detected }) => !detected).length });
}

export function proveFaultDeterminism(contract, seed = 'fault-determinism-v1') {
  const points = contract.registries.faults.entries.map(({ id }) => id);
  const left = createFaultSchedule(seed, points, { actions: ['crash-before', 'crash-after', 'error', 'interrupt', 'duplicate', 'reorder'] });
  const right = createFaultSchedule(seed, points, { actions: ['crash-before', 'crash-after', 'error', 'interrupt', 'duplicate', 'reorder'] });
  const observe = (schedule) => {
    const scheduler = new FaultScheduler(schedule);
    for (const event of schedule.events) {
      try { scheduler.point(event.faultPoint, event.action === 'crash-after' ? 'after' : 'before'); }
      catch (error) { if (!isInjectedFault(error)) throw error; }
    }
    return scheduler.observed();
  };
  const leftObserved = observe(left); const rightObserved = observe(right);
  return deepFreeze({ deterministic: left.scheduleDigest === right.scheduleDigest && JSON.stringify(left.events) === JSON.stringify(right.events) && JSON.stringify(leftObserved) === JSON.stringify(rightObserved) && leftObserved.length === left.events.length, schedule: left });
}
