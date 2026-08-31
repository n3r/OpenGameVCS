import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, cpSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const SPEC = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPOSITORY = resolve(SPEC, '../../..');
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const npmCache = mkdtempSync(join(tmpdir(), 'ogvcs011-npm-cache-'));
const run = (command, args, cwd) => spawnSync(command, args, {
  cwd,
  encoding: 'utf8',
  env: {
    ...process.env,
    npm_config_audit: 'false',
    npm_config_cache: npmCache,
    npm_config_fund: 'false',
  },
});

test('schema and vector semantics fail independently even after manifest regeneration', () => {
  for (const mutate of [
    (copy) => {
      const path = join(copy, 'schemas', 'WorkspaceMetadata.schema.json');
      const schema = JSON.parse(readFileSync(path, 'utf8'));
      schema.properties.state.enum = ['staging', 'banana'];
      writeFileSync(path, `${JSON.stringify(schema, null, 2)}\n`);
    },
    (copy) => {
      const path = join(copy, 'vectors', 'contract-v1.json');
      const vectors = JSON.parse(readFileSync(path, 'utf8'));
      vectors.cases.find(({ id }) => id === 'noninteractive-provider-unavailable').expected.exitClass = 'nonsense';
      writeFileSync(path, `${JSON.stringify(vectors, null, 2)}\n`);
    },
  ]) {
    const copy = mkdtempSync(join(tmpdir(), 'ogvcs011-mutated-spec-'));
    cpSync(SPEC, copy, { recursive: true });
    mutate(copy);
    const generated = run(process.execPath, ['scripts/generate.mjs'], copy);
    assert.equal(generated.status, 0, generated.stderr);
    const validated = run(process.execPath, ['validate-spec.mjs'], copy);
    assert.notEqual(validated.status, 0, 'semantic mutation unexpectedly validated');
  }
});

test('runtime generation cannot drift from a regenerated companion manifest', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'ogvcs011-binding-drift-'));
  const copiedSpec = join(temporary, 'spec', 'cli-workspace', 'v1');
  const copiedRuntime = join(temporary, 'client', 'native-cli', 'rust');
  mkdirSync(dirname(copiedSpec), { recursive: true });
  mkdirSync(join(copiedRuntime, 'scripts'), { recursive: true });
  mkdirSync(join(copiedRuntime, 'src'), { recursive: true });
  mkdirSync(join(copiedRuntime, 'tests'), { recursive: true });
  cpSync(SPEC, copiedSpec, { recursive: true });
  for (const relative of ['scripts/sync-contract.mjs', 'src/generated_contract.rs', 'tests/contract-v1.json']) {
    cpSync(join(REPOSITORY, 'client', 'native-cli', 'rust', relative), join(copiedRuntime, relative));
  }
  const registryPath = join(copiedSpec, 'registries', 'exit-classes.json');
  const registry = JSON.parse(readFileSync(registryPath, 'utf8'));
  registry.classes.find(({ name }) => name === 'internal').exitCode = 71;
  writeFileSync(registryPath, `${JSON.stringify(registry, null, 2)}\n`);
  assert.equal(run(process.execPath, ['scripts/generate.mjs'], copiedSpec).status, 0);
  assert.notEqual(run(process.execPath, ['scripts/sync-contract.mjs', '--check'], copiedRuntime).status, 0);
  assert.equal(run(process.execPath, ['scripts/sync-contract.mjs'], copiedRuntime).status, 0);
  assert.equal(run(process.execPath, ['scripts/sync-contract.mjs', '--check'], copiedRuntime).status, 0);
});

test('packed contract is complete and validates offline', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'ogvcs011-packed-spec-'));
  const packed = run(npm, ['pack', '--json', '--ignore-scripts', '--pack-destination', temporary, SPEC], temporary);
  assert.equal(packed.status, 0, packed.stderr);
  const [{ filename }] = JSON.parse(packed.stdout);
  const consumer = join(temporary, 'consumer');
  cpSync(SPEC, consumer, { recursive: true });
  writeFileSync(join(consumer, 'package.json'), '{"name":"ogvcs011-packed-consumer","private":true}\n');
  const installed = run(npm, [
    'install', '--offline', '--ignore-scripts', '--no-package-lock', '--no-audit', '--no-fund', join(temporary, filename),
  ], consumer);
  assert.equal(installed.status, 0, installed.stderr);
  const validated = run(
    process.execPath,
    [join(consumer, 'node_modules', '@opengamevcs', 'cli-workspace-contract-v1', 'validate-spec.mjs')],
    consumer,
  );
  assert.equal(validated.status, 0, validated.stderr);
});
