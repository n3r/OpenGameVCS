import { pathFail } from './errors.mjs';

const WORKSPACE_PLANS = new WeakMap();

function sameCapabilities(left, right) {
  const keys = [
    'schemaVersion',
    'atomicReplace', 'casePreserving', 'caseSensitive', 'directorySync',
    'executableBit', 'hardlink', 'normalizationSensitive', 'platform', 'symlink',
  ];
  return keys.every((key) => left?.[key] === right?.[key]);
}

export function bindWorkspaceMaterializationPlan(plan, authority) {
  WORKSPACE_PLANS.set(plan, Object.freeze({
    workspace: authority.workspace,
    capabilities: authority.capabilities,
    reprobe: authority.reprobe,
    entries: new Map(plan.entries.map((entry) => [entry.path, entry])),
  }));
  return plan;
}

export async function authorizeWorkspaceMutations(plan, workspace, requests) {
  const authority = plan !== null && typeof plan === 'object' ? WORKSPACE_PLANS.get(plan) : undefined;
  if (authority === undefined || authority.workspace !== workspace) {
    pathFail('CAPABILITY_UNAVAILABLE', undefined, { capability: 'workspace-preflight-plan' });
  }
  const measured = await authority.reprobe();
  if (!sameCapabilities(measured, authority.capabilities)) {
    pathFail('CAPABILITY_UNAVAILABLE', undefined, { capability: 'capability-changed' });
  }
  if (!Array.isArray(requests) || requests.length === 0 || requests.length > 100_000) {
    pathFail('ENTRY_INVALID', undefined, { rule: 'preflight-plan-requests' });
  }
  const entries = [];
  for (const request of requests) {
    const entry = authority.entries.get(request.path);
    if (entry === undefined || !Array.isArray(request.kinds) || !request.kinds.includes(entry.kind)) {
      pathFail('ENTRY_INVALID', undefined, { rule: 'preflight-plan-entry' });
    }
    if (request.symlinkTarget !== undefined && entry.symlinkTarget !== request.symlinkTarget) {
      pathFail('ENTRY_INVALID', undefined, { rule: 'preflight-plan-symlink' });
    }
    entries.push(entry);
  }
  return Object.freeze(entries);
}

export async function authorizeWorkspaceMutation(plan, workspace, request) {
  return (await authorizeWorkspaceMutations(plan, workspace, [request]))[0];
}
