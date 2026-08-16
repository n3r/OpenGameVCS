#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  copyFile, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const CARGO = process.env.CARGO ?? 'cargo';
const MAX_COMMAND_OUTPUT = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const JS_IMPLEMENTATION = '@opengamevcs/object-model/javascript';
const RUST_IMPLEMENTATION = 'ogvcs-object-model/rust';
const EXPECTED_SCENARIO_COUNTS = Object.freeze({
  [JS_IMPLEMENTATION]: Object.freeze({ executed: 233, failed: 0, inventoryOnly: 2, notApplicable: 0 }),
  [RUST_IMPLEMENTATION]: Object.freeze({ executed: 228, failed: 0, inventoryOnly: 2, notApplicable: 5 })
});

function fail(message) { throw new Error(`packed conformance failed: ${message}`); }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function digest(value) { return createHash('sha256').update(value).digest('hex'); }

function validationSites(catalogue) {
  if (!Array.isArray(catalogue?.errors) || !Array.isArray(catalogue?.precedence?.stageOrder)) {
    fail('invalid packed error catalogue');
  }
  const stages = new Set(catalogue.precedence.stageOrder);
  const sites = new Set();
  for (const error of catalogue.errors) {
    if (typeof error?.code !== 'string' || !Array.isArray(error.sites) || error.sites.length === 0) {
      fail('invalid packed error catalogue');
    }
    for (const site of error.sites) {
      if (!stages.has(site?.stage) || !Array.isArray(site.layers) || site.layers.length === 0) {
        fail('invalid packed error catalogue');
      }
      for (const layer of site.layers) sites.add(`${error.code}\0${layer}\0${site.stage}`);
    }
  }
  return sites;
}

function validOutcome(outcome, sites) {
  if (!outcome || typeof outcome !== 'object' || Array.isArray(outcome)) return false;
  if (outcome.result === 'accept') {
    return canonical(Object.keys(outcome).sort()) === canonical(['highestLayer', 'result']) &&
      Number.isInteger(outcome.highestLayer) && outcome.highestLayer >= 1 && outcome.highestLayer <= 3;
  }
  if (outcome.result === 'reject') {
    return canonical(Object.keys(outcome).sort()) === canonical(['code', 'layer', 'result', 'stage']) &&
      typeof outcome.code === 'string' && Number.isInteger(outcome.layer) &&
      sites.has(`${outcome.code}\0${outcome.layer}\0${outcome.stage}`);
  }
  return false;
}

function validateScenarioOutcomes(report, sites) {
  const scenarios = report.conformance?.scenarios;
  const rows = scenarios?.rows;
  if (!Array.isArray(rows)) fail(`invalid scenario report for ${report.implementation}`);
  const counts = {
    executed: rows.filter(row => row.status === 'passed' || row.status === 'failed').length,
    failed: rows.filter(row => row.status === 'failed').length,
    inventoryOnly: rows.filter(row => row.status === 'not-executed').length,
    notApplicable: rows.filter(row => row.status === 'not-applicable').length
  };
  if (rows.length !== 235 || canonical(counts) !== canonical(EXPECTED_SCENARIO_COUNTS[report.implementation]) ||
      Object.entries(counts).some(([name, value]) => scenarios[name] !== value)) {
    fail(`invalid frozen scenario cardinality for ${report.implementation}`);
  }
  for (const row of rows) {
    if (row.status === 'passed' || row.status === 'failed') {
      if (!validOutcome(row.actual, sites) || !validOutcome(row.expected, sites) ||
          (row.status === 'passed') !== (canonical(row.actual) === canonical(row.expected))) {
        fail(`invalid scenario outcome for ${report.implementation}: ${row.scenarioId}`);
      }
    } else if (row.actual !== undefined || row.expected !== undefined) {
      fail(`non-executed scenario exposes an outcome for ${report.implementation}: ${row.scenarioId}`);
    }
  }
}

function argumentsFor(values) {
  let output;
  let allowDirty = false;
  for (let index = 0; index < values.length; index++) {
    if (values[index] === '--allow-dirty') { allowDirty = true; continue; }
    if (values[index] === '--output' && index + 1 < values.length) {
      output = resolve(values[++index]);
      continue;
    }
    fail('usage: run-packed-object-model-conformance.mjs --output <directory> [--allow-dirty]');
  }
  if (!output) fail('usage: run-packed-object-model-conformance.mjs --output <directory> [--allow-dirty]');
  return { allowDirty, output };
}

function run(command, args, { cwd = ROOT, env = {}, label = command } = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    const append = target => chunk => {
      bytes += chunk.length;
      if (bytes > MAX_COMMAND_OUTPUT) {
        child.kill();
        return;
      }
      target.push(chunk);
    };
    child.stdout.on('data', append(stdout));
    child.stderr.on('data', append(stderr));
    child.once('error', reject);
    child.once('close', code => {
      const result = {
        code,
        stderr: Buffer.concat(stderr).toString('utf8'),
        stdout: Buffer.concat(stdout).toString('utf8')
      };
      if (bytes > MAX_COMMAND_OUTPUT) reject(new Error(`${label} produced excessive output`));
      else if (code !== 0) reject(new Error(`${label} failed (${code}): ${result.stderr || result.stdout}`));
      else resolvePromise(result);
    });
  });
}

async function archiveDigest(path) {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > MAX_ARCHIVE_BYTES) {
    fail(`invalid packed artifact ${path}`);
  }
  return digest(await readFile(path));
}

async function packageIdentity(packageRoot, expectedName, expectedLicense) {
  let metadata;
  try {
    metadata = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
  } catch {
    fail(`invalid installed package metadata for ${expectedName}`);
  }
  if (metadata?.name !== expectedName || metadata.license !== 'MIT' ||
      typeof metadata.version !== 'string' ||
      !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(metadata.version)) {
    fail(`invalid installed package identity for ${expectedName}`);
  }
  if (await readFile(join(packageRoot, 'LICENSE'), 'utf8') !== expectedLicense) {
    fail(`invalid installed package license for ${expectedName}`);
  }
  return { name: expectedName, version: metadata.version };
}

async function npmPack(packageRoot, destination, cache) {
  const result = await run(NPM, [
    'pack', packageRoot, '--json', '--pack-destination', destination, '--ignore-scripts'
  ], { env: { npm_config_cache: cache, npm_config_offline: 'true' }, label: `npm pack ${packageRoot}` });
  let records;
  try { records = JSON.parse(result.stdout); } catch { fail(`npm pack returned invalid JSON for ${packageRoot}`); }
  if (!Array.isArray(records) || records.length !== 1 || typeof records[0]?.filename !== 'string') {
    fail(`npm pack returned an unexpected result for ${packageRoot}`);
  }
  return join(destination, basename(records[0].filename));
}

function sharedConformance(report) {
  const conformance = structuredClone(report.conformance);
  const rows = conformance.scenarios?.rows?.filter(row =>
    Array.isArray(row.implementationScope) &&
    row.implementationScope.includes('javascript') && row.implementationScope.includes('rust'));
  if (!Array.isArray(rows) || rows.length !== 230 ||
      rows.some(row => row.status !== 'passed' && row.status !== 'not-executed')) {
    fail(`invalid shared scenario rows for ${report.implementation}`);
  }
  conformance.scenarios = {
    executed: rows.filter(row => row.status === 'passed').length,
    failed: 0,
    inventoryOnly: rows.filter(row => row.status === 'not-executed').length,
    notApplicable: 0,
    resultsSha256: digest(canonical(rows)),
    rows,
    scenarios: rows.length,
    schema: conformance.scenarios.schema
  };
  return conformance;
}

function validateReport(report, implementation, artifact, formatArtifact, revision, sites) {
  if (report.schema !== 'ogvcs.object-model.conformance-report/v1' ||
      report.implementation !== implementation || report.sourceRevision !== revision ||
      report.conformanceSha256 !== digest(canonical(report.conformance)) ||
      canonical(report.artifact) !== canonical(artifact) ||
      canonical(report.formatArtifact) !== canonical(formatArtifact) ||
      report.conformance?.scenarios?.failed !== 0) {
    fail(`invalid packed report for ${implementation}`);
  }
  validateScenarioOutcomes(report, sites);
}

async function main() {
  const { allowDirty, output } = argumentsFor(process.argv.slice(2));
  const expectedLicense = await readFile(join(ROOT, 'LICENSE'), 'utf8');
  if (!expectedLicense.startsWith('MIT License\n')) fail('workspace license must be MIT');
  const worktree = await run('git', ['status', '--porcelain=v1', '--untracked-files=all'], {
    label: 'git worktree status'
  });
  if (!allowDirty && worktree.stdout.trim().length !== 0) {
    fail('release evidence requires a clean worktree (use --allow-dirty only for local diagnosis)');
  }
  await mkdir(output, { recursive: true });
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-packed-conformance-'));
  try {
    const packs = join(scratch, 'packs');
    const cache = join(scratch, 'npm-cache');
    const consumer = join(scratch, 'consumer');
    await mkdir(packs);
    await mkdir(consumer);
    await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n', { flag: 'wx' });
    const fixtureArchive = await npmPack(join(ROOT, 'foundation', 'fixture-generator'), packs, cache);
    const javascriptArchive = await npmPack(join(ROOT, 'core', 'object-model', 'js'), packs, cache);
    const formatArchive = await npmPack(join(ROOT, 'spec', 'repository-format', 'v1'), packs, cache);
    await run(NPM, [
      'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--save-exact',
      fixtureArchive, javascriptArchive, formatArchive
    ], { cwd: consumer, env: { npm_config_cache: cache, npm_config_offline: 'true' }, label: 'offline npm install' });

    const fixtureSha = await archiveDigest(fixtureArchive);
    const javascriptSha = await archiveDigest(javascriptArchive);
    const formatSha = await archiveDigest(formatArchive);
    const nodeModules = join(consumer, 'node_modules');
    const javascriptRoot = join(nodeModules, '@opengamevcs', 'object-model');
    const fixtureRoot = join(nodeModules, '@opengamevcs', 'fixture-generator');
    const formatRoot = join(nodeModules, '@opengamevcs', 'repository-format-v1');
    const fixturePackage = await packageIdentity(
      fixtureRoot, '@opengamevcs/fixture-generator', expectedLicense);
    const javascriptPackage = await packageIdentity(
      javascriptRoot, '@opengamevcs/object-model', expectedLicense);
    const formatPackage = await packageIdentity(
      formatRoot, '@opengamevcs/repository-format-v1', expectedLicense);
    const fixtureArtifact = {
      ...fixturePackage, sha256: fixtureSha, type: 'npm-tarball'
    };
    const javascriptArtifact = {
      ...javascriptPackage, sha256: javascriptSha, type: 'npm-tarball'
    };
    const formatArtifact = {
      ...formatPackage, sha256: formatSha, type: 'npm-tarball'
    };
    const sites = validationSites(JSON.parse(await readFile(join(formatRoot, 'errors.json'), 'utf8')));
    const revisionResult = process.env.GITHUB_SHA === undefined
      ? await run('git', ['rev-parse', 'HEAD'], { label: 'git revision' })
      : { stdout: process.env.GITHUB_SHA };
    const revision = revisionResult.stdout.trim().toLowerCase();
    if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(revision)) fail('source revision is not a Git object ID');
    const javascriptReportPath = join(output, 'javascript-packed-conformance.json');
    await run(process.execPath, [
      join(ROOT, 'tools', 'object-model-conformance-report.mjs'), '--output', javascriptReportPath
    ], {
      env: {
        GITHUB_SHA: revision,
        OGVCS_FIXTURE_GENERATOR_JS_MODULE: join(fixtureRoot, 'src', 'index.mjs'),
        OGVCS_FORMAT_ARTIFACT: JSON.stringify(formatArtifact),
        OGVCS_FORMAT_ROOT: formatRoot,
        OGVCS_IMPLEMENTATION_ARTIFACT: JSON.stringify(javascriptArtifact),
        OGVCS_OBJECT_MODEL_JS_MODULE: join(javascriptRoot, 'src', 'index.js'),
        OGVCS_OBJECT_MODEL_JS_PACKAGE_JSON: join(javascriptRoot, 'package.json'),
        OGVCS_OBJECT_MODEL_JS_REGISTRIES: join(javascriptRoot, 'registries'),
        OGVCS_VECTOR_ROOT: join(formatRoot, 'vectors')
      },
      label: 'packed JavaScript conformance report'
    });

    const cargoTarget = join(scratch, 'cargo-target');
    const packageArguments = [
      'package', '--manifest-path', join(ROOT, 'core', 'object-model', 'rust', 'Cargo.toml'),
      '--locked', '--offline'
    ];
    if (allowDirty) packageArguments.push('--allow-dirty');
    await run(CARGO, packageArguments, {
      env: { CARGO_TARGET_DIR: cargoTarget }, label: 'cargo package'
    });
    const packageDirectory = join(cargoTarget, 'package');
    const packageEntries = await readdir(packageDirectory);
    const crateName = packageEntries.find(name => /^ogvcs-object-model-0\.1\.0\.crate$/u.test(name));
    const crateSource = packageEntries.find(name => /^ogvcs-object-model-0\.1\.0$/u.test(name));
    if (!crateName || !crateSource) fail('cargo package did not produce the expected crate and source tree');
    if (await readFile(join(packageDirectory, crateSource, 'LICENSE'), 'utf8') !== expectedLicense) {
      fail('packed Rust crate license differs from the workspace MIT license');
    }
    const cratePath = join(packageDirectory, crateName);
    const crateSha = await archiveDigest(cratePath);
    const rustArtifact = {
      name: 'ogvcs-object-model', sha256: crateSha, type: 'cargo-crate', version: '0.1.0'
    };
    const rustReportPath = join(output, 'rust-packed-conformance.json');
    await run(CARGO, [
      'run', '--manifest-path', join(packageDirectory, crateSource, 'Cargo.toml'), '--locked', '--offline',
      '--bin', 'object_model_scenario_report', '--', '--conformance',
      '--vectors', join(formatRoot, 'vectors'), '--registries', join(formatRoot, 'registries'),
      '--output', rustReportPath
    ], {
      env: {
        CARGO_TARGET_DIR: join(scratch, 'packed-cargo-target'),
        GITHUB_SHA: revision,
        OGVCS_FORMAT_ARTIFACT: JSON.stringify(formatArtifact),
        OGVCS_IMPLEMENTATION_ARTIFACT: JSON.stringify(rustArtifact)
      },
      label: 'packed Rust conformance report'
    });

    const javascriptReport = JSON.parse(await readFile(javascriptReportPath, 'utf8'));
    const rustReport = JSON.parse(await readFile(rustReportPath, 'utf8'));
    validateReport(javascriptReport, JS_IMPLEMENTATION, javascriptArtifact, formatArtifact, revision, sites);
    validateReport(rustReport, RUST_IMPLEMENTATION, rustArtifact, formatArtifact, revision, sites);
    const javascriptShared = digest(canonical(sharedConformance(javascriptReport)));
    const rustShared = digest(canonical(sharedConformance(rustReport)));
    if (javascriptShared !== rustShared) fail('packed JavaScript and Rust shared conformance differs');
    const retainedArchives = [
      {
        ...fixtureArtifact, filename: basename(fixtureArchive), source: fixtureArchive
      },
      {
        ...javascriptArtifact, filename: basename(javascriptArchive), source: javascriptArchive
      },
      {
        ...formatArtifact, filename: basename(formatArchive), source: formatArchive
      },
      {
        ...rustArtifact, filename: basename(cratePath), source: cratePath
      }
    ];
    for (const archive of retainedArchives) {
      await copyFile(archive.source, join(output, archive.filename), fsConstants.COPYFILE_EXCL);
    }
    const comparison = {
      artifacts: [javascriptReport.artifact, rustReport.artifact].sort((left, right) => left.name.localeCompare(right.name)),
      fixtureArtifact,
      formatArtifact,
      result: 'identical',
      retainedArchives: retainedArchives.map(({ filename, name, sha256, type, version }) => ({
        filename, name, sha256, type, version
      })),
      schema: 'ogvcs.object-model.packed-conformance-comparison/v1',
      sharedConformanceSha256: javascriptShared,
      sourceRevision: revision
    };
    const comparisonPath = join(output, 'packed-conformance-comparison.json');
    await writeFile(comparisonPath, `${canonical(comparison)}\n`, { flag: 'wx' });
    process.stdout.write(`${canonical(comparison)}\n`);
  } finally {
    await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
  }
}

await main();
