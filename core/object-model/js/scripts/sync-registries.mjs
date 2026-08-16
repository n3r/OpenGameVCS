import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REGISTRY_FILES } from '../src/registry.js';

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');
const repositoryRoot = resolve(packageRoot, '../../..');
const sourceRoot = join(repositoryRoot, 'spec/repository-format/v1/registries');
const destinationRoot = join(packageRoot, 'registries');
const check = process.argv.slice(2).includes('--check');

await mkdir(destinationRoot, { recursive: true });
for (const file of REGISTRY_FILES) {
  const source = await readFile(join(sourceRoot, file));
  const destination = join(destinationRoot, file);
  if (check) {
    let installed;
    try { installed = await readFile(destination); } catch { throw new Error(`missing packaged registry: ${file}`); }
    if (!source.equals(installed)) throw new Error(`stale packaged registry: ${file}`);
  } else {
    await writeFile(destination, source);
  }
}

if (check) process.stdout.write(`packaged registries current: ${REGISTRY_FILES.length}\n`);
