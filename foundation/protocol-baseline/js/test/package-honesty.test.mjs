import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const runtimeRoot = new URL('../', import.meta.url);
const adapterRoot = new URL('../../adapters/js-independent/', import.meta.url);

test('package metadata and documentation match the generated adapter boundary', async () => {
  const [runtimePackage, adapterPackage, runtimeReadme, adapterReadme] = await Promise.all([
    readFile(new URL('package.json', runtimeRoot), 'utf8').then(JSON.parse),
    readFile(new URL('package.json', adapterRoot), 'utf8').then(JSON.parse),
    readFile(new URL('README.md', runtimeRoot), 'utf8'),
    readFile(new URL('README.md', adapterRoot), 'utf8'),
  ]);
  assert.equal(runtimePackage.name, '@opengamevcs/protocol-baseline');
  assert.equal(adapterPackage.name, '@opengamevcs/protocol-baseline-independent-adapter');
  assert.equal(runtimePackage.version, '1.0.0-rc.1');
  assert.equal(adapterPackage.version, '1.0.0-rc.1');
  assert.equal(runtimePackage.license, 'MIT');
  assert.equal(adapterPackage.license, 'MIT');
  assert.equal(runtimePackage.dependencies['@opengamevcs/protocol-types-v1'], '1.0.0-rc.1');
  assert.equal(runtimePackage.dependencies['@opengamevcs/authorization-contract'], '1.0.0');
  assert.equal(adapterPackage.dependencies['@opengamevcs/authorization-contract'], '1.0.0');
  assert.match(runtimeReadme, /AdapterResult/u);
  assert.match(runtimeReadme, /projects? the safe `RunnerResult`|projects? the safe|projecting the safe/u);
  assert.match(adapterReadme, /AdapterResult/u);
  assert.match(adapterReadme, /must not contain vectors/u);
  assert.doesNotMatch(runtimeReadme, /\b\d+ artifacts?, \d+ schemas?, \d+ registries?.*\d+ conformance scenarios?/u);
  assert.doesNotMatch(adapterReadme, /RunnerHello` followed by one canonical `RunnerResult/u);
});
