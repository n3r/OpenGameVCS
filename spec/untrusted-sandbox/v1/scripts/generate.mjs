import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
const walk = async (directory) => (await Promise.all((await readdir(resolve(root, directory), { withFileTypes: true })).map(async (entry) => entry.isDirectory() ? walk(`${directory}/${entry.name}`) : [`${directory}/${entry.name}`]))).flat();
const predecessors = Object.freeze(['../../authorization/v1/docs/sandbox-contract.md', '../../identity-policy-audit/v1/manifest.json', '../../path-filesystem/v1/manifest.json']);
export const expectedSandboxManifest = async () => {
  const paths = ['README.md', 'package.json', 'validate-spec.mjs', ...(await walk('schemas')), ...(await walk('vectors'))].sort();
  const artifacts = await Promise.all(paths.map(async (path) => { const bytes = await readFile(resolve(root, path)); return Object.freeze({ path, bytes: bytes.length, sha256: sha256(bytes) }); }));
  const predecessorPins = await Promise.all(predecessors.map(async (path) => Object.freeze({ path, sha256: sha256(await readFile(resolve(root, path))) })));
  return Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/contract-manifest/v1', generatorSha256: sha256(await readFile(fileURLToPath(import.meta.url))), artifacts, predecessorPins });
};
export async function validateSandboxManifest({ manifestBytes } = {}) {
  const expected = await expectedSandboxManifest(); const actual = manifestBytes ?? await readFile(resolve(root, 'manifest.json')); const canonicalExpected = Buffer.from(`${canonical(expected)}\n`, 'utf8');
  if (!Buffer.from(actual).equals(canonicalExpected)) throw new Error('sandbox manifest does not authenticate declared artifacts, generator, or predecessor pins');
  return Object.freeze({ manifestSha256: sha256(canonicalExpected), artifacts: expected.artifacts.length });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const bytes = Buffer.from(`${canonical(await expectedSandboxManifest())}\n`, 'utf8');
  if (process.argv.includes('--write')) await writeFile(resolve(root, 'manifest.json'), bytes); else await validateSandboxManifest();
}
