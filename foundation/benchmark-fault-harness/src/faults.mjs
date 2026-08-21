import { canonicalDigest, cloneData, deepFreeze } from './canonical.mjs';
import { BenchmarkHarnessError, harnessFail } from './errors.mjs';
import { HARNESS_LIMITS } from './limits.mjs';
import { DeterministicRandom } from './prng.mjs';

const ACTIONS = Object.freeze(['crash-before', 'crash-after', 'error', 'interrupt', 'duplicate', 'reorder']);

export class InjectedFault extends BenchmarkHarnessError {
  constructor(event) {
    super(event.action === 'interrupt' ? 'HARNESS_TASK_INCOMPLETE' : 'HARNESS_RETRYABLE', 'deterministic test fault injected', { details: { action: event.action, faultPoint: event.faultPoint, ordinal: event.ordinal } });
    this.name = 'InjectedFault';
    this.event = event;
  }
}

export function createFaultSchedule(seed, faultPointIds, options = {}) {
  try { faultPointIds = cloneData(faultPointIds); options = cloneData(options); }
  catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'fault schedule inputs must be inert bounded canonical data', { cause: error }); }
  if (!Array.isArray(faultPointIds) || faultPointIds.length < 1 || faultPointIds.length > HARNESS_LIMITS.maxFaultEvents || new Set(faultPointIds).size !== faultPointIds.length || faultPointIds.some((id) => typeof id !== 'string')) harnessFail('HARNESS_INPUT_INVALID', 'fault-point inventory is invalid');
  const random = new DeterministicRandom(seed);
  const count = options.count ?? faultPointIds.length;
  if (!Number.isSafeInteger(count) || count < 0 || count > HARNESS_LIMITS.maxFaultEvents) harnessFail('HARNESS_INPUT_INVALID', 'fault schedule count is invalid');
  const actionSet = options.actions ?? ['error'];
  if (!Array.isArray(actionSet) || actionSet.length < 1 || actionSet.some((value) => !ACTIONS.includes(value))) harnessFail('HARNESS_INPUT_INVALID', 'fault action set is invalid');
  const ordered = options.shuffle === false ? [...faultPointIds] : random.shuffle(faultPointIds);
  const occurrences = new Map();
  const events = Array.from({ length: count }, (_, ordinal) => {
    const faultPoint = ordered[ordinal % ordered.length];
    const action = actionSet[random.integer(actionSet.length)];
    const phase = action === 'crash-after' ? 'after' : 'before';
    const key = `${faultPoint}\0${phase}`;
    if (options.occurrence !== undefined && occurrences.has(key)) harnessFail('HARNESS_INPUT_INVALID', 'explicit fault occurrence creates an ambiguous duplicate event');
    const occurrence = options.occurrence ?? ((occurrences.get(key) ?? 0) + 1);
    occurrences.set(key, occurrence);
    if (!Number.isSafeInteger(occurrence) || occurrence < 1) harnessFail('HARNESS_INPUT_INVALID', 'fault occurrence is invalid');
    return { ordinal, faultPoint, action, occurrence };
  });
  const body = { schemaVersion: 'ogvcs.benchmark/fault-schedule/v1', seedDigest: canonicalDigest(seed, 'ogvcs.benchmark/fault-seed/v1'), events };
  return deepFreeze({ ...body, scheduleDigest: canonicalDigest(body, 'ogvcs.benchmark/fault-schedule/v1') });
}

export class FaultScheduler {
  #events;
  #counts = new Map();
  #observed = [];
  constructor(schedule) {
    try { schedule = cloneData(schedule); }
    catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'fault schedule must be inert bounded canonical data', { cause: error }); }
    if (!schedule || schedule.schemaVersion !== 'ogvcs.benchmark/fault-schedule/v1' || !/^[0-9a-f]{64}$/u.test(schedule.seedDigest) || !/^[0-9a-f]{64}$/u.test(schedule.scheduleDigest) || !Array.isArray(schedule.events) || schedule.events.length > HARNESS_LIMITS.maxFaultEvents) harnessFail('HARNESS_INPUT_INVALID', 'fault schedule is invalid');
    const keys = new Set();
    for (let index = 0; index < schedule.events.length; index += 1) {
      const event = schedule.events[index];
      if (!event || Object.keys(event).sort().join('\0') !== ['action', 'faultPoint', 'occurrence', 'ordinal'].join('\0') || event.ordinal !== index || typeof event.faultPoint !== 'string' || !ACTIONS.includes(event.action) || !Number.isSafeInteger(event.occurrence) || event.occurrence < 1) harnessFail('HARNESS_INPUT_INVALID', 'fault schedule event is invalid');
      const phase = event.action === 'crash-after' ? 'after' : 'before';
      const key = `${event.faultPoint}\0${phase}\0${event.occurrence}`;
      if (keys.has(key)) harnessFail('HARNESS_INPUT_INVALID', 'fault schedule contains an ambiguous duplicate event');
      keys.add(key);
    }
    const body = { schemaVersion: schedule.schemaVersion, seedDigest: schedule.seedDigest, events: schedule.events };
    if (canonicalDigest(body, 'ogvcs.benchmark/fault-schedule/v1') !== schedule.scheduleDigest) harnessFail('HARNESS_INPUT_INVALID', 'fault schedule digest differs from its events');
    this.#events = schedule.events.map((event) => ({ ...event }));
    this.schedule = deepFreeze({ schemaVersion: schedule.schemaVersion, seedDigest: schedule.seedDigest, scheduleDigest: schedule.scheduleDigest, events: this.#events.map((event) => ({ ...event })) });
  }
  point(faultPoint, phase = 'before') {
    if (typeof faultPoint !== 'string' || faultPoint.length < 1 || faultPoint.length > 256 || !['before', 'after'].includes(phase)) harnessFail('HARNESS_INPUT_INVALID', 'fault checkpoint is invalid');
    const key = `${faultPoint}\0${phase}`;
    const occurrence = (this.#counts.get(key) ?? 0) + 1;
    this.#counts.set(key, occurrence);
    const candidates = this.#events.filter((event) => event.faultPoint === faultPoint && event.occurrence === occurrence && (event.action === 'crash-after' ? phase === 'after' : phase === 'before'));
    for (const event of candidates) {
      this.#observed.push({ ...event, phase });
      if (['crash-before', 'crash-after', 'error', 'interrupt'].includes(event.action)) throw new InjectedFault(event);
    }
    return candidates.map((event) => ({ ...event }));
  }
  observed() { return this.#observed.map((event) => ({ ...event })); }
}

export function isInjectedFault(error) { return error instanceof InjectedFault; }
