import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);

test('runtime package is MIT, typed, documented, and has no install lifecycle scripts', async () => {
  const packageJson = JSON.parse(await readFile(new URL('package.json', root), 'utf8'));
  assert.equal(packageJson.license, 'MIT'); assert.equal(packageJson.engines.node, '>=22');
  assert.equal(Object.keys(packageJson.scripts).some((name) => /^(?:pre|post)?install$/u.test(name)), false);
  await Promise.all(['README.md', 'LICENSE', 'types/index.d.ts', 'examples/smoke.mjs', 'bin/ogvcs-benchmark.mjs'].map((path) => access(new URL(path, root))));
  assert.equal(packageJson.exports['.'].types, './types/index.d.ts');
});
