import { types } from 'node:util';

import {
  createReferenceServiceTestHookCapability,
  createTestingLauncherCapability,
  REFERENCE_SERVICE_HARD_KILL_BOUNDARIES,
} from './internal/capability.mjs';

export const createReferenceServiceHardKillHookForTesting = (boundary, beforeKill) => {
  if (!REFERENCE_SERVICE_HARD_KILL_BOUNDARIES.includes(boundary) || typeof beforeKill !== 'function' || types.isProxy(beforeKill)) throw new TypeError('hard-kill hook configuration is invalid');
  let fired = false;
  return createReferenceServiceTestHookCapability((actualBoundary) => {
    if (actualBoundary !== boundary) return;
    if (fired) throw new Error('hard-kill test hook already fired');
    fired = true;
    beforeKill(actualBoundary);
    process.kill(process.pid, 'SIGKILL');
  });
};

export const referenceServiceHardKillBoundariesForTesting = () => REFERENCE_SERVICE_HARD_KILL_BOUNDARIES;

export const requiredControls = () => Object.freeze({ networkDenied: true, credentialFree: true, readOnlyInput: true, isolatedScratch: true, cpuLimited: true, memoryLimited: true, processLimited: true });
const iterable = (chunks) => (async function* () { for await (const chunk of chunks) yield Buffer.isBuffer(chunk) ? Buffer.from(chunk) : Buffer.from(chunk, 'utf8'); }());
export class FakeCandidateLauncher {
  constructor({ assertedControls = requiredControls(), stdout = ['{"outputs":[],"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1"}'], stderr = [], exit = Promise.resolve({ code: 0, signal: null }), start, terminate, kill } = {}) {
    this.requests = []; this.terminated = 0; this.killed = 0;
    this.capability = createTestingLauncherCapability({ assertedControls, launch: async (request, signal) => {
      this.requests.push(request); if (start) return start(request, signal);
      const self = this; return Object.freeze({ stdout: iterable(stdout), stderr: iterable(stderr), exit, terminate: async (abort) => { self.terminated += 1; return terminate?.(abort); }, kill: async (abort) => { self.killed += 1; return kill?.(abort); } });
    } });
  }
}
