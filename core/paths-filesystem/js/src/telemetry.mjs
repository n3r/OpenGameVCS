import { pathFail } from './errors.mjs';

const TELEMETRY = new WeakMap();

function stateFor(value) {
  const state = value === undefined ? null : TELEMETRY.get(value);
  if (value !== undefined && state === undefined) pathFail('PATH_INPUT_INVALID');
  return state;
}

export function createPathTelemetry() {
  const handle = Object.freeze({ schemaVersion: 'ogvcs.path/telemetry/v1' });
  TELEMETRY.set(handle, {
    profiles: new Set(), preflightFailures: new Map(), watcherGaps: 0,
    reconciliations: 0, reconciliationDurationMs: 0, busyRetries: 0,
    atomicFallbackRefusals: 0, unsafePathDenials: 0,
  });
  return handle;
}

export function assertPathTelemetry(value) {
  stateFor(value);
  return value;
}

export function recordPathTelemetry(value, event, detail) {
  const state = stateFor(value);
  if (state === null) return;
  if (event === 'profile') {
    if (typeof detail !== 'string' || detail.length === 0 || detail.length > 256) pathFail('PATH_INPUT_INVALID');
    state.profiles.add(detail);
  } else if (event === 'preflight-failure') {
    if (typeof detail !== 'string' || detail.length === 0 || detail.length > 64) pathFail('PATH_INPUT_INVALID');
    state.preflightFailures.set(detail, (state.preflightFailures.get(detail) ?? 0) + 1);
  } else if (event === 'watcher-gap') state.watcherGaps += 1;
  else if (event === 'reconciliation') {
    if (!Number.isSafeInteger(detail) || detail < 0) pathFail('PATH_INPUT_INVALID');
    state.reconciliations += 1; state.reconciliationDurationMs += detail;
  } else if (event === 'busy-retry') state.busyRetries += 1;
  else if (event === 'atomic-fallback-refused') state.atomicFallbackRefusals += 1;
  else if (event === 'unsafe-path-denial') state.unsafePathDenials += 1;
  else pathFail('PATH_INPUT_INVALID');
}

export function snapshotPathTelemetry(value) {
  const state = stateFor(value);
  if (state === null) pathFail('PATH_INPUT_INVALID');
  const preflightFailures = {};
  for (const [code, count] of [...state.preflightFailures].sort(([left], [right]) => left.localeCompare(right))) preflightFailures[code] = count;
  return Object.freeze({
    schemaVersion: 'ogvcs.path/telemetry-snapshot/v1',
    profiles: Object.freeze([...state.profiles].sort()),
    preflightFailures: Object.freeze(preflightFailures),
    watcherGaps: state.watcherGaps,
    reconciliations: state.reconciliations,
    reconciliationDurationMs: state.reconciliationDurationMs,
    busyRetries: state.busyRetries,
    atomicFallbackRefusals: state.atomicFallbackRefusals,
    unsafePathDenials: state.unsafePathDenials,
  });
}
