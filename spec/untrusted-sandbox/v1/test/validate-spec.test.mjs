import test from 'node:test';
import { validateSandboxContract } from '../validate-spec.mjs';
test('closed OGVCS-045 candidate contract is authenticated by independent checks', async () => { await validateSandboxContract(); });
