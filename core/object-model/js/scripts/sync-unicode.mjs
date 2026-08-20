import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../');
const source = resolve(root, 'spec/repository-format/v1');
const target = resolve(root, 'core/object-model/js/unicode');
const files = [
  ['vectors/unicode/age-15.0.0-intervals.json', 'age-15.0.0-intervals.json'],
  ['unicode/DerivedAge-15.0.0.txt', 'DerivedAge-15.0.0.txt'],
  ['unicode/UNICODE-LICENSE.txt', 'UNICODE-LICENSE.txt'],
  ['unicode/NOTICE.md', 'NOTICE.md'],
];
const check = process.argv.includes('--check');
await mkdir(target, { recursive: true });
for (const [relative, name] of files) {
  const expected = await readFile(resolve(source, relative));
  const output = resolve(target, name);
  if (check) {
    const actual = await readFile(output).catch(() => undefined);
    if (!actual?.equals(expected)) throw new Error(`stale Unicode authority: ${name}`);
  } else {
    await writeFile(output, expected);
  }
}
