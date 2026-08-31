import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { CandidateSandboxSupervisor } from '../src/index.mjs';
import { FakeCandidateLauncher, requiredControls } from '../src/testing.mjs';
import { validateSandboxContract } from '../../../../spec/untrusted-sandbox/v1/validate-spec.mjs';

const vectors = JSON.parse(await readFile(new URL('../../../../spec/untrusted-sandbox/v1/vectors/canaries.json', import.meta.url)));
const job = Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-job/v1', jobId: 'vector.1', toolDigest: 'a'.repeat(64), runtimeDigest: 'b'.repeat(64), inputDigest: 'c'.repeat(64), resourceClass: 'parser-default', outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1', idempotencyKey: 'vector.1', purpose: 'parse' });
const staged = Object.freeze({ handle: 'opaque.handle.1', inputDigest: job.inputDigest });
const valid = `{"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","outputs":[{"digest":"${'d'.repeat(64)}","type":"tree","path":"tree/file"}]}`;
const launcherFor = (scenario) => {
  if (scenario === 'missing-control') return new FakeCandidateLauncher({ assertedControls: { ...requiredControls(), networkDenied: false } });
  if (scenario === 'stdout-flood') return new FakeCandidateLauncher({ stdout: ['x'.repeat(32)] });
  if (scenario === 'traversal') return new FakeCandidateLauncher({ stdout: [valid.replace('tree/file', '../secret')] });
  if (scenario === 'drive-path') return new FakeCandidateLauncher({ stdout: [valid.replace('tree/file', 'C:/host')] });
  if (scenario === 'unc-path') return new FakeCandidateLauncher({ stdout: [valid.replace('tree/file', '//server/share')] });
  if (scenario === 'duplicate-json') return new FakeCandidateLauncher({ stdout: ['{"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","outputs":[]}'] });
  if (scenario === 'extra-output-field') return new FakeCandidateLauncher({ stdout: [valid.replace('"path":"tree/file"', '"path":"tree/file","extra":true')] });
  if (scenario === 'nonzero-exit') return new FakeCandidateLauncher({ stdout: [valid], exit: Promise.resolve({ code: 1, signal: null }) });
  if (scenario === 'stderr-secret') return new FakeCandidateLauncher({ stdout: [valid], stderr: ['test-only-secret-canary'] });
  if (scenario === 'stalled-launch') return new FakeCandidateLauncher({ start: async () => new Promise(() => {}) });
  if (scenario === 'credential-canary') return new FakeCandidateLauncher({ stdout: [valid] });
  throw new Error(`unknown vector scenario: ${scenario}`);
};
test('authenticated canary inventory dispatches every expected outcome', async () => {
  await validateSandboxContract();
  for (const vector of vectors.cases) {
    const launcher = launcherFor(vector.scenario); const options = vector.scenario === 'stdout-flood' ? { maxOutputBytes: 8 } : vector.scenario === 'stalled-launch' ? { deadlineMilliseconds: 5 } : {};
    const value = await new CandidateSandboxSupervisor({ candidateLauncher: launcher.capability, ...options }).run(job, staged);
    assert.equal(value.code, vector.expectedCode, vector.id);
  }
});
