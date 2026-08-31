import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { validateSandboxManifest } from '../scripts/generate.mjs';
import { validateSandboxContract } from '../validate-spec.mjs';
test('closed OGVCS-045 candidate contract is authenticated by independent checks', async () => { const value = await validateSandboxContract(); assert.ok(value.vectors >= 10); });
test('manifest rejects even one-byte tampering', async () => { const bytes = await readFile(new URL('../manifest.json', import.meta.url)); const tampered = Buffer.from(bytes); tampered[0] ^= 1; await assert.rejects(validateSandboxManifest({ manifestBytes: tampered })); });
