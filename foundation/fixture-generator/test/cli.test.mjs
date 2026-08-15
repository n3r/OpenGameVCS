import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import {
  jsonError,
  jsonOutput,
  readJson,
  runCli,
  smallCliArguments,
  temporaryDirectory,
} from './test-helpers.mjs';

const PROFILES = ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'];

test('list exposes all profiles and help documents every stable command and exit-code class', async (t) => {
  const cwd = await temporaryDirectory(t);
  const listed = await runCli(cwd, ['list']);
  assert.equal(listed.code, 0, listed.stderr);
  assert.equal(listed.stderr, '');
  const document = jsonOutput(listed);
  assert.equal(document.ok, true);
  assert.equal(document.command, 'list');
  assert.equal(document.schemaVersion, 'ogvcs.fixture/cli-result/v1');
  assert.deepEqual(document.result.profiles.map(({ id }) => id), PROFILES);

  const help = await runCli(cwd, ['--help']);
  assert.equal(help.code, 0, help.stderr);
  for (const command of ['list', 'plan', 'generate', 'inspect', 'verify']) {
    assert.match(help.stdout, new RegExp(`\\b${command}\\b`));
  }
  for (const exitCode of [0, 2, 3, 4, 5, 6, 7, 8, 70]) {
    assert.match(help.stdout, new RegExp(`\\b${exitCode}\\b`));
  }
  assert.match(help.stdout, /Examples:/);
});

test('every small profile plans, generates, inspects, and deeply verifies through the CLI', async (t) => {
  const cwd = await temporaryDirectory(t);

  for (const profile of PROFILES) {
    const destination = `fixtures/${profile}`;
    const requestArguments = smallCliArguments(profile, destination);
    const planned = await runCli(cwd, ['plan', ...requestArguments]);
    assert.equal(planned.code, 0, `${profile}: ${planned.stderr}`);
    const plan = jsonOutput(planned);
    assert.equal(plan.command, 'plan');
    assert.equal(plan.result.profile.id, profile);
    assert.equal(plan.result.destination, destination);
    assert.match(plan.result.requestDigest, /^[0-9a-f]{64}$/);
    assert.ok(Number(plan.result.estimates.physicalBytes) > 0);

    const generated = await runCli(cwd, ['generate', ...requestArguments]);
    assert.equal(generated.code, 0, `${profile}: ${generated.stderr}`);
    const generation = jsonOutput(generated);
    assert.equal(generation.command, 'generate');
    assert.equal(generation.result.summary.paths, 12);
    assert.equal(generation.result.summary.operations, 10);
    assert.equal(generation.result.requestDigest, plan.result.requestDigest);

    const inspected = await runCli(cwd, ['inspect', destination]);
    assert.equal(inspected.code, 0, `${profile}: ${inspected.stderr}`);
    const inspection = jsonOutput(inspected).result;
    assert.equal(inspection.profile.id, profile);
    assert.equal(inspection.manifestDigest, generation.result.manifestDigest);
    assert.equal(inspection.requestDigest, plan.result.requestDigest);
    assert.equal(inspection.provenance.classification, 'fully-synthetic');
    assert.equal(inspection.provenance.generatedArtifactsContainExternalIdentifiers, false);
    assert.equal(inspection.provenance.requestMetadata, 'caller-supplied-unattested');

    const verified = await runCli(cwd, ['verify', destination, '--deep']);
    assert.equal(verified.code, 0, `${profile}: ${verified.stderr}`);
    const verification = jsonOutput(verified).result;
    assert.equal(verification.verified, true);
    assert.equal(verification.status, 'valid');
    assert.equal(verification.mode, 'full');
    assert.equal(verification.summary.failed, 0);
    assert.ok(verification.summary.verifiedItems >= 22);
  }
});

test('same relative request in separate working directories has byte-identical logical artifacts', async (t) => {
  const root = await temporaryDirectory(t);
  const firstCwd = path.join(root, 'host-a');
  const secondCwd = path.join(root, 'host-b');
  const { mkdir } = await import('node:fs/promises');
  await Promise.all([mkdir(firstCwd), mkdir(secondCwd)]);
  const destination = 'fixtures/reproducible';
  const arguments_ = smallCliArguments('unity-like', destination, {
    historyOperationCount: 17,
    largeFileBytes: 8192,
    pathCount: 19,
    seed: 'same-request-on-every-host',
  });

  const [first, second] = await Promise.all([
    runCli(firstCwd, ['generate', ...arguments_]),
    runCli(secondCwd, ['generate', ...arguments_]),
  ]);
  assert.equal(first.code, 0, first.stderr);
  assert.equal(second.code, 0, second.stderr);

  const artifactNames = [
    'manifest.json',
    'inventory.ndjson',
    'operations.ndjson',
    'scenario.json',
    'groups.json',
    'fixture-request.json',
    'workload-profile.json',
    'large-file.json',
  ];
  for (const artifact of artifactNames) {
    const [firstBytes, secondBytes] = await Promise.all([
      readFile(path.join(firstCwd, destination, artifact)),
      readFile(path.join(secondCwd, destination, artifact)),
    ]);
    assert.deepEqual(firstBytes, secondBytes, artifact);
  }
  assert.equal(jsonOutput(first).result.manifestDigest, jsonOutput(second).result.manifestDigest);
});

test('verification reports physical and logical mutations with the integrity exit code', async (t) => {
  const cwd = await temporaryDirectory(t);
  const destination = 'fixtures/mutation';
  const generated = await runCli(cwd, [
    'generate',
    ...smallCliArguments('code-heavy', destination, { largeFileBytes: 0, pathCount: 8 }),
  ]);
  assert.equal(generated.code, 0, generated.stderr);

  const [firstRecord] = (await readFile(path.join(cwd, destination, 'inventory.ndjson'), 'utf8'))
    .trim()
    .split('\n')
    .map(JSON.parse);
  const { writeFile } = await import('node:fs/promises');
  await writeFile(path.join(cwd, destination, 'files', ...firstRecord.logicalPath.split('/')), 'tampered');

  const verified = await runCli(cwd, ['verify', destination, '--deep']);
  assert.equal(verified.code, 6);
  assert.equal(verified.stdout, '');
  const failure = jsonError(verified);
  assert.equal(failure.ok, false);
  assert.equal(failure.error.type, 'integrity-failure');
  assert.equal(failure.error.exitCode, 6);
  assert.equal(failure.error.details.verification.verified, false);
  assert.ok(failure.error.details.verification.checks.some(({ status }) => status === 'fail'));

  const manifest = await readJson(path.join(cwd, destination, 'manifest.json'));
  assert.equal(failure.error.details.verification.manifestDigest, manifest.manifestDigest);
});
