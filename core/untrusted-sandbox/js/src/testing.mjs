import { createTestingLauncherCapability } from './internal/capability.mjs';

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
