import { deepFreeze, inspectJson } from './canonical.mjs';

function outcome(code) {
  return deepFreeze({ result: code.startsWith('ALLOW_') ? 'allow' : 'deny', code });
}

export function evaluateSandboxAttempt(profile, attempt) {
  inspectJson(profile);
  inspectJson(attempt);
  if (!profile || typeof profile !== 'object' || Array.isArray(profile) || !profile.runtime || typeof profile.runtime !== 'object' || !profile.filesystem || typeof profile.filesystem !== 'object' || !attempt || typeof attempt !== 'object' || Array.isArray(attempt)) return outcome('DENY_SANDBOX_REQUIREMENTS');
  const allowed = new Set(['network', 'credentials', 'cpuMilliseconds', 'elapsedMilliseconds', 'memoryBytes', 'outputBytes', 'fanout', 'processes', 'scratchBytes', 'hostPaths', 'declaredInputsReadOnly', 'isolatedScratch']);
  if (Object.keys(attempt).some((key) => !allowed.has(key))) return outcome('DENY_SANDBOX_REQUIREMENTS');
  if (attempt.network !== undefined && attempt.network !== 'deny') return outcome('DENY_SANDBOX_REQUIREMENTS');
  if (attempt.credentials !== undefined && attempt.credentials !== 'none') return outcome('DENY_SANDBOX_REQUIREMENTS');
  for (const key of ['cpuMilliseconds', 'elapsedMilliseconds', 'memoryBytes', 'outputBytes', 'fanout', 'processes']) {
    if (attempt[key] !== undefined && (!Number.isSafeInteger(attempt[key]) || attempt[key] < 0 || attempt[key] > profile.runtime[key])) return outcome('DENY_SANDBOX_REQUIREMENTS');
  }
  if (attempt.scratchBytes !== undefined && (!Number.isSafeInteger(attempt.scratchBytes) || attempt.scratchBytes < 0 || attempt.scratchBytes > profile.filesystem.scratchBytes)) return outcome('DENY_SANDBOX_REQUIREMENTS');
  if (attempt.hostPaths === true || attempt.declaredInputsReadOnly === false || attempt.isolatedScratch === false) return outcome('DENY_SANDBOX_REQUIREMENTS');
  return outcome('ALLOW_EXPLICIT');
}
