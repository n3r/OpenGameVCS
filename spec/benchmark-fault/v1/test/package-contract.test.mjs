import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);

test('contract package is offline MIT authority data', async () => {
  const packageJson = JSON.parse(await readFile(new URL('package.json', root), 'utf8'));
  const license = await readFile(new URL('LICENSE', root), 'utf8');
  assert.equal(packageJson.license, 'MIT');
  assert.equal(packageJson.dependencies, undefined);
  assert.match(license, /^MIT License/u);
  assert.equal(fileURLToPath(root).includes('benchmark-fault'), true);
});
