import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const files = Object.freeze([
  'object-kinds.json',
  'hash-algorithms.json',
  'common-fields.json',
  'kind-fields.json',
  'entry-kinds.json',
  'entry-modes.json',
  'required-features.json',
  'extensions.json',
  'profiles.json',
  'logical-record-types.json',
  'semantic-enums.json',
  'limits.json'
]);
const crate = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(crate, '../../..');
const format = resolve(root, 'spec/repository-format/v1');
const source = resolve(format, 'registries');
const target = resolve(crate, 'registries');
const check = process.argv.includes('--check');

function sameInventory(actual) {
  return JSON.stringify(actual.filter(name => name.endsWith('.json')).sort()) ===
    JSON.stringify([...files].sort());
}

await mkdir(target, { recursive: true });
if (!sameInventory(await readdir(source)) || (check && !sameInventory(await readdir(target)))) {
  throw new Error('Rust registry inventory differs from the normative twelve-document set');
}
for (const file of files) {
  const expected = await readFile(resolve(source, file));
  const output = resolve(target, file);
  if (check) {
    const actual = await readFile(output).catch(() => undefined);
    if (!actual?.equals(expected)) throw new Error(`stale Rust registry authority: ${file}`);
  } else {
    await writeFile(output, expected);
  }
}

const snapshot = JSON.parse(await readFile(
  resolve(format, 'vectors/registries/live-snapshot.json'),
  'utf8'
));
if (!/^[0-9a-f]{64}$/u.test(snapshot.registrySetSha256)) {
  throw new Error('invalid normative registry-set digest');
}
const registrySource = await readFile(resolve(crate, 'src/registry.rs'), 'utf8');
const digestDeclaration =
  /pub const BUNDLED_REGISTRY_SET_DIGEST: \[u8; 32\] = \[([\s\S]*?)\];/u.exec(registrySource);
const digestBytes = digestDeclaration === null
  ? []
  : [...digestDeclaration[1].matchAll(/0x([0-9a-f]{2})/gu)].map(match => match[1]);
if (digestBytes.length !== 32 || digestBytes.join('') !== snapshot.registrySetSha256) {
  throw new Error('stale Rust bundled registry-set digest');
}

if (check) process.stdout.write(`Rust packaged registries current: ${files.length}\n`);
