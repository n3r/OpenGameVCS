import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '..');

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function run(args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', code => resolvePromise({
      code,
      stderr: Buffer.concat(stderr).toString('utf8'),
      stdout: Buffer.concat(stdout).toString('utf8')
    }));
  });
}

test('two-language three-platform report comparison requires identical, intact conformance results', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-conformance-report-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const basePath = join(directory, 'base.json');
  const generated = await run(['tools/object-model-conformance-report.mjs', '--output', basePath]);
  assert.equal(generated.code, 0, generated.stderr || generated.stdout);
  const base = JSON.parse(await readFile(basePath, 'utf8'));
  const scenarioIndex = JSON.parse(await readFile(
    join(ROOT, 'spec/repository-format/v1/vectors/scenarios/index.json'),
    'utf8'
  ));
  const executable = row => row.materialization !== 'virtual-constructor' &&
    (row.materialization !== 'virtual-constructor-shared-bundle-baseline' ||
      row.scenarioId === 'bundle-export-claim');
  const javascriptRows = scenarioIndex.cases.filter(row =>
    (row.implementationScope ?? ['javascript', 'rust']).includes('javascript'));
  assert.deepEqual(base.artifact,
    { name: '@opengamevcs/object-model', type: 'workspace', version: '0.1.0' });
  assert.deepEqual(base.formatArtifact,
    { name: '@opengamevcs/repository-format-v1', type: 'workspace', version: '0.1.0' });
  assert.equal(base.conformance.scenarios.scenarios, scenarioIndex.cases.length);
  assert.equal(base.conformance.scenarios.executed, javascriptRows.filter(executable).length);
  assert.equal(base.conformance.scenarios.failed, 0);
  assert.equal(base.conformance.scenarios.inventoryOnly, 2);
  assert.equal(base.conformance.scenarios.notApplicable, 0);
  assert.equal(base.conformance.scenarios.rows.length, scenarioIndex.cases.length);
  assert.ok(base.conformance.scenarios.rows.every(row => row.status === 'passed' || row.status === 'not-executed'));
  const evidenceById = new Map(scenarioIndex.cases
    .filter(row => row.expected?.evidence !== undefined)
    .map(row => [row.scenarioId, row.expected.evidence]));
  assert.ok(evidenceById.size > 0);
  for (const row of base.conformance.scenarios.rows.filter(item => evidenceById.has(item.scenarioId))) {
    assert.equal(row.status, 'passed');
    assert.equal(canonicalJson(row.actual?.evidence), canonicalJson(evidenceById.get(row.scenarioId)));
    assert.equal(canonicalJson(row.expected?.evidence), canonicalJson(evidenceById.get(row.scenarioId)));
  }

  const reports = join(directory, 'reports');
  await mkdir(reports);
  for (const [implementation, runtime, prefix] of [
    ['@opengamevcs/object-model/javascript', 'v22.0.0', 'javascript'],
    ['ogvcs-object-model/rust', 'rustc 1.82.0', 'rust']
  ]) {
    for (const os of ['darwin', 'linux', 'win32']) {
      const report = structuredClone(base);
      report.implementation = implementation;
      report.artifact = {
        name: prefix === 'rust' ? 'ogvcs-object-model' : '@opengamevcs/object-model',
        type: 'workspace',
        version: '0.1.0'
      };
      report.platform = { arch: 'test', os };
      report.runtime = runtime;
      report.sourceRevision = '0123456789abcdef0123456789abcdef01234567';
      if (prefix === 'rust') {
        const rows = report.conformance.scenarios.rows.map(row =>
          row.implementationScope.includes('rust') ? row : {
            implementationScope: row.implementationScope,
            materialization: row.materialization,
            operation: row.operation,
            reason: 'implementation-out-of-scope',
            scenarioId: row.scenarioId,
            status: 'not-applicable'
          });
        report.conformance.scenarios = {
          executed: rows.filter(row => row.status === 'passed').length,
          failed: 0,
          inventoryOnly: rows.filter(row => row.status === 'not-executed').length,
          notApplicable: rows.filter(row => row.status === 'not-applicable').length,
          resultsSha256: digest(rows),
          rows,
          scenarios: rows.length,
          schema: report.conformance.scenarios.schema
        };
        report.conformanceSha256 = digest(report.conformance);
      }
      await writeFile(join(reports, `${prefix}-${os}.json`), `${JSON.stringify(report)}\n`, 'utf8');
    }
  }
  const output = join(directory, 'comparison.out');
  const compared = await run([
    'tools/compare-object-model-conformance.mjs', '--input', reports, '--output', output
  ]);
  assert.equal(compared.code, 0, compared.stderr || compared.stdout);
  const result = JSON.parse(await readFile(output, 'utf8'));
  assert.equal(result.result, 'identical');
  assert.deepEqual(result.formatArtifact,
    { name: '@opengamevcs/repository-format-v1', type: 'workspace', version: '0.1.0' });
  assert.deepEqual(result.implementations.map(item => item.implementation), [
    '@opengamevcs/object-model/javascript', 'ogvcs-object-model/rust'
  ]);
  assert.ok(result.implementations.every(item =>
    item.platforms.map(platform => platform.os).join(',') === 'darwin,linux,win32'));

  const evidencePath = join(reports, 'javascript-darwin.json');
  const evidenceOriginal = JSON.parse(await readFile(evidencePath, 'utf8'));
  const evidenceChanged = structuredClone(evidenceOriginal);
  const evidenceRow = evidenceChanged.conformance.scenarios.rows.find(
    row => row.operation === 'validate-tree-groups-memory'
  );
  assert.ok(evidenceRow, 'the scenario report must exercise resource recovery evidence');
  evidenceRow.actual.evidence.eachComponentAloneFit = false;
  evidenceChanged.conformance.scenarios.resultsSha256 =
    digest(evidenceChanged.conformance.scenarios.rows);
  evidenceChanged.conformanceSha256 = digest(evidenceChanged.conformance);
  await writeFile(evidencePath, `${JSON.stringify(evidenceChanged)}\n`, 'utf8');
  await rm(output, { force: true });
  const rejectedEvidence = await run([
    'tools/compare-object-model-conformance.mjs', '--input', reports, '--output', output
  ]);
  assert.notEqual(rejectedEvidence.code, 0);
  assert.match(rejectedEvidence.stderr, /invalid scenario outcome/);
  await assert.rejects(readFile(output));
  await writeFile(evidencePath, `${JSON.stringify(evidenceOriginal)}\n`, 'utf8');

  const stagePath = join(reports, 'javascript-linux.json');
  const stageOriginal = JSON.parse(await readFile(stagePath, 'utf8'));
  const stageChanged = structuredClone(stageOriginal);
  const rejectingRow = stageChanged.conformance.scenarios.rows.find(row => row.actual?.result === 'reject');
  assert.ok(rejectingRow, 'the scenario report must exercise at least one rejection');
  rejectingRow.actual.stage = 'not-a-validation-stage';
  rejectingRow.expected.stage = 'not-a-validation-stage';
  stageChanged.conformance.scenarios.resultsSha256 = digest(stageChanged.conformance.scenarios.rows);
  stageChanged.conformanceSha256 = digest(stageChanged.conformance);
  await writeFile(stagePath, `${JSON.stringify(stageChanged)}\n`, 'utf8');
  await rm(output, { force: true });
  const rejectedStage = await run([
    'tools/compare-object-model-conformance.mjs', '--input', reports, '--output', output
  ]);
  assert.notEqual(rejectedStage.code, 0);
  assert.match(rejectedStage.stderr, /invalid scenario outcome/);
  await assert.rejects(readFile(output));
  await writeFile(stagePath, `${JSON.stringify(stageOriginal)}\n`, 'utf8');

  const changedPath = join(reports, 'rust-win32.json');
  const changed = JSON.parse(await readFile(changedPath, 'utf8'));
  changed.conformance.formatVersion = 2;
  await writeFile(changedPath, `${JSON.stringify(changed)}\n`, 'utf8');
  await rm(output, { force: true });
  const rejected = await run([
    'tools/compare-object-model-conformance.mjs', '--input', reports, '--output', output
  ]);
  assert.notEqual(rejected.code, 0);
  await assert.rejects(readFile(output));
});
