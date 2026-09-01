import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => value === null || typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
const walk = async (directory) => (await Promise.all((await readdir(resolve(root, directory), { withFileTypes: true })).map(async (entry) => entry.isDirectory() ? walk(`${directory}/${entry.name}`) : [`${directory}/${entry.name}`]))).flat();
const predecessors = Object.freeze([
  Object.freeze({ path: '../../authorization/v1/docs/sandbox-contract.md', sha256: '383ac42a7dbfdbe2e613a918e99df888184d2e1920cb6b589f309654e8117fc1' }),
  Object.freeze({ path: '../../authorization/v1/manifest.json', sha256: '3fb4dd4a89eb914f93a589b013bda8afcf4744c0d27171ee5849ca3b7bf62447' }),
  Object.freeze({ path: '../../identity-policy-audit/v1/manifest.json', sha256: 'f2793333fc2f02634a54caff7137e94cb8a8cab32ae301bb190f06efb769f401' }),
  Object.freeze({ path: '../../path-filesystem/v1/manifest.json', sha256: '2f343e1dac238da527fbd36160419ec6fb53b780ac7e33c01e11acabbdd4782b' }),
]);
export const verifySandboxPredecessors = async () => {
  for (const pin of predecessors) if (sha256(await readFile(resolve(root, pin.path))) !== pin.sha256) throw new Error(`sandbox predecessor pin drifted: ${pin.path}`);
  return Object.freeze(predecessors.map((pin) => Object.freeze({ ...pin })));
};
export const expectedSandboxManifest = async () => {
  const paths = ['README.md', 'package.json', 'test/validate-spec.test.mjs', 'validate-spec.mjs', ...(await walk('schemas')), ...(await walk('vectors'))].sort();
  const artifacts = await Promise.all(paths.map(async (path) => { const bytes = await readFile(resolve(root, path)); return Object.freeze({ path, bytes: bytes.length, sha256: sha256(bytes) }); }));
  const predecessorPins = Object.freeze(predecessors.map((pin) => Object.freeze({ ...pin })));
  return Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/contract-manifest/v1', generatorSha256: sha256(await readFile(fileURLToPath(import.meta.url))), artifacts, predecessorPins });
};
export async function validateSandboxManifest({ manifestBytes } = {}) {
  const expected = await expectedSandboxManifest(); const actual = manifestBytes ?? await readFile(resolve(root, 'manifest.json')); const canonicalExpected = Buffer.from(`${canonical(expected)}\n`, 'utf8');
  if (!Buffer.from(actual).equals(canonicalExpected)) throw new Error('sandbox manifest does not authenticate declared artifacts, generator, or predecessor pins');
  return Object.freeze({ manifestSha256: sha256(canonicalExpected), artifacts: expected.artifacts.length });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes('--verify-predecessors') || process.argv.includes('--write')) await verifySandboxPredecessors();
  const bytes = Buffer.from(`${canonical(await expectedSandboxManifest())}\n`, 'utf8');
  if (process.argv.includes('--write')) await writeFile(resolve(root, 'manifest.json'), bytes); else await validateSandboxManifest();
}
