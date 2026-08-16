#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const EXPECTED_PLATFORMS = new Set(['darwin', 'linux', 'win32']);
const EXPECTED_IMPLEMENTATIONS = new Set([
  '@opengamevcs/object-model/javascript',
  'ogvcs-object-model/rust'
]);
const IMPLEMENTATION_ARTIFACT_NAMES = Object.freeze({
  '@opengamevcs/object-model/javascript': '@opengamevcs/object-model',
  'ogvcs-object-model/rust': 'ogvcs-object-model'
});
const MAX_REPORT_BYTES = 1_048_576;
const EXPECTED_SHARED_SCENARIOS = 230;
const EXPECTED_SCENARIO_COUNTS = Object.freeze({
  javascript: Object.freeze({ executed: 233, failed: 0, inventoryOnly: 2, notApplicable: 0 }),
  rust: Object.freeze({ executed: 228, failed: 0, inventoryOnly: 2, notApplicable: 5 })
});
const ERROR_CATALOGUE = resolve(import.meta.dirname, '../spec/repository-format/v1/errors.json');

function parseArguments(argv) {
  if (argv.length !== 4 || argv[0] !== '--input' || argv[2] !== '--output') {
    throw new Error('usage: node tools/compare-object-model-conformance.mjs --input <directory> --output <report.json>');
  }
  return { input: resolve(argv[1]), output: resolve(argv[3]) };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function validationSites(catalogue) {
  if (!Array.isArray(catalogue?.errors) || !Array.isArray(catalogue?.precedence?.stageOrder)) {
    throw new Error('invalid normative error catalogue');
  }
  const stages = new Set(catalogue.precedence.stageOrder);
  const sites = new Set();
  for (const error of catalogue.errors) {
    if (typeof error?.code !== 'string' || !Array.isArray(error.sites) || error.sites.length === 0) {
      throw new Error('invalid normative error catalogue');
    }
    for (const site of error.sites) {
      if (!stages.has(site?.stage) || !Array.isArray(site.layers) || site.layers.length === 0) {
        throw new Error('invalid normative error catalogue');
      }
      for (const layer of site.layers) sites.add(`${error.code}\0${layer}\0${site.stage}`);
    }
  }
  return sites;
}

function validOutcome(outcome, sites) {
  if (!outcome || typeof outcome !== 'object' || Array.isArray(outcome)) return false;
  if (outcome.result === 'accept') {
    return canonicalJson(Object.keys(outcome).sort()) === canonicalJson(['highestLayer', 'result']) &&
      Number.isInteger(outcome.highestLayer) && outcome.highestLayer >= 1 && outcome.highestLayer <= 3;
  }
  if (outcome.result === 'reject') {
    return canonicalJson(Object.keys(outcome).sort()) === canonicalJson(['code', 'layer', 'result', 'stage']) &&
      typeof outcome.code === 'string' && Number.isInteger(outcome.layer) &&
      sites.has(`${outcome.code}\0${outcome.layer}\0${outcome.stage}`);
  }
  return false;
}

function validateScenarioOutcomes(rows, sites, language) {
  for (const row of rows) {
    if (row.status === 'passed' || row.status === 'failed') {
      if (!validOutcome(row.actual, sites) || !validOutcome(row.expected, sites)) {
        throw new Error(`invalid scenario outcome for ${language}: ${row.scenarioId}`);
      }
      const equal = canonicalJson(row.actual) === canonicalJson(row.expected);
      if ((row.status === 'passed') !== equal) {
        throw new Error(`scenario status disagrees with its outcome for ${language}: ${row.scenarioId}`);
      }
    } else if (row.actual !== undefined || row.expected !== undefined) {
      throw new Error(`non-executed scenario exposes an outcome for ${language}: ${row.scenarioId}`);
    }
  }
}

function normalizedSharedConformance(report) {
  const conformance = structuredClone(report.conformance);
  const source = conformance.scenarios;
  if (!source || !Array.isArray(source.rows)) throw new Error('conformance report has no scenario rows');
  const rows = source.rows.filter(row =>
    Array.isArray(row.implementationScope) &&
    EXPECTED_IMPLEMENTATIONS.size === row.implementationScope.length &&
    row.implementationScope.includes('javascript') && row.implementationScope.includes('rust'));
  if (rows.length !== EXPECTED_SHARED_SCENARIOS ||
      rows.some(row => row.status !== 'passed' && row.status !== 'not-executed')) {
    throw new Error(`shared scenario did not pass for ${report.implementation}/${report.platform?.os}`);
  }
  conformance.scenarios = {
    executed: rows.filter(row => row.status === 'passed').length,
    failed: 0,
    inventoryOnly: rows.filter(row => row.status === 'not-executed').length,
    notApplicable: 0,
    resultsSha256: sha256(canonicalJson(rows)),
    rows,
    scenarios: rows.length,
    schema: source.schema
  };
  return conformance;
}

function validateApplicability(report, sites) {
  const language = report.implementation === '@opengamevcs/object-model/javascript' ? 'javascript' : 'rust';
  const expectedArtifact = {
    name: IMPLEMENTATION_ARTIFACT_NAMES[report.implementation], type: 'workspace', version: '0.1.0'
  };
  const expectedFormat = {
    name: '@opengamevcs/repository-format-v1', type: 'workspace', version: '0.1.0'
  };
  if (canonicalJson(report.artifact) !== canonicalJson(expectedArtifact) ||
      canonicalJson(report.formatArtifact) !== canonicalJson(expectedFormat)) {
    throw new Error(`invalid source artifact identity for ${language}`);
  }
  const scenarios = report.conformance?.scenarios;
  const rows = scenarios?.rows;
  if (!Array.isArray(rows) || rows.length !== scenarios.scenarios ||
      scenarios.resultsSha256 !== sha256(canonicalJson(rows)) ||
      new Set(rows.map(row => row.scenarioId)).size !== rows.length) {
    throw new Error(`invalid scenario result envelope for ${language}`);
  }
  const counts = {
    executed: rows.filter(row => row.status === 'passed' || row.status === 'failed').length,
    failed: rows.filter(row => row.status === 'failed').length,
    inventoryOnly: rows.filter(row => row.status === 'not-executed').length,
    notApplicable: rows.filter(row => row.status === 'not-applicable').length
  };
  if (rows.length !== 235 || canonicalJson(counts) !== canonicalJson(EXPECTED_SCENARIO_COUNTS[language])) {
    throw new Error(`unexpected frozen scenario cardinality for ${language}`);
  }
  for (const [name, value] of Object.entries(counts)) {
    if (scenarios[name] !== value) throw new Error(`invalid scenario ${name} count for ${language}`);
  }
  validateScenarioOutcomes(rows, sites, language);
  for (const row of rows) {
    if (!Array.isArray(row.implementationScope) || row.implementationScope.length === 0 ||
        new Set(row.implementationScope).size !== row.implementationScope.length ||
        row.implementationScope.some(value => value !== 'javascript' && value !== 'rust')) {
      throw new Error(`scenario scope is missing for ${row.scenarioId}`);
    }
    const applicable = row.implementationScope.includes(language);
    if (applicable && row.status !== 'passed' && row.status !== 'not-executed') {
      throw new Error(`applicable scenario did not pass for ${language}: ${row.scenarioId}`);
    }
    if (!applicable && row.status !== 'not-applicable') {
      throw new Error(`out-of-scope scenario was not marked not-applicable for ${language}: ${row.scenarioId}`);
    }
  }
}

async function jsonFiles(directory) {
  const files = [];
  async function visit(path) {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = resolve(path, entry.name);
      if (entry.isDirectory()) await visit(child);
      else if (entry.isFile() && entry.name.endsWith('.json')) files.push(child);
    }
  }
  await visit(directory);
  return files.sort();
}

async function main() {
  const { input, output } = parseArguments(process.argv.slice(2));
  const sites = validationSites(JSON.parse(await readFile(ERROR_CATALOGUE, 'utf8')));
  const reports = [];
  for (const path of await jsonFiles(input)) {
    const metadata = await stat(path);
    if (!metadata.isFile() || metadata.size > MAX_REPORT_BYTES) {
      throw new Error(`invalid conformance report file: ${path}`);
    }
    const report = JSON.parse(await readFile(path, 'utf8'));
    if (report.schema === 'ogvcs.object-model.conformance-report/v1') reports.push(report);
  }
  const expectedReportCount = EXPECTED_PLATFORMS.size * EXPECTED_IMPLEMENTATIONS.size;
  if (reports.length !== expectedReportCount) {
    throw new Error(`expected ${expectedReportCount} conformance reports, found ${reports.length}`);
  }
  const matrix = new Map();
  for (const report of reports) {
    const os = report.platform?.os;
    const implementation = report.implementation;
    if (!EXPECTED_PLATFORMS.has(os) || !EXPECTED_IMPLEMENTATIONS.has(implementation)) {
      throw new Error(`unexpected implementation/platform: ${implementation}/${os}`);
    }
    const key = `${implementation}\0${os}`;
    if (matrix.has(key)) throw new Error(`duplicate implementation/platform: ${implementation}/${os}`);
    const calculated = sha256(canonicalJson(report.conformance));
    if (calculated !== report.conformanceSha256) {
      throw new Error(`invalid conformance digest for ${implementation}/${os}`);
    }
    validateApplicability(report, sites);
    matrix.set(key, report);
  }
  for (const implementation of EXPECTED_IMPLEMENTATIONS) {
    for (const os of EXPECTED_PLATFORMS) {
      if (!matrix.has(`${implementation}\0${os}`)) {
        throw new Error(`missing implementation/platform: ${implementation}/${os}`);
      }
    }
  }
  const revisions = new Set(reports.map(report => report.sourceRevision));
  if (revisions.size !== 1) throw new Error('platform reports were produced from different revisions');
  const [sourceRevision] = revisions;
  if (typeof sourceRevision !== 'string' || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(sourceRevision)) {
    throw new Error('platform reports do not identify one lowercase Git object ID');
  }
  for (const implementation of EXPECTED_IMPLEMENTATIONS) {
    const digests = new Set(reports.filter(report => report.implementation === implementation)
      .map(report => report.conformanceSha256));
    if (digests.size !== 1) throw new Error(`cross-platform conformance output differs for ${implementation}`);
  }
  const sharedDigests = new Set(reports.map(report =>
    sha256(canonicalJson(normalizedSharedConformance(report)))));
  if (sharedDigests.size !== 1) throw new Error('cross-language shared conformance output differs');
  const [sharedConformanceSha256] = sharedDigests;

  const comparison = {
    conformanceSha256: sharedConformanceSha256,
    implementations: [...EXPECTED_IMPLEMENTATIONS].sort().map(implementation => ({
      artifact: matrix.get(`${implementation}\0darwin`).artifact,
      implementation,
      implementationConformanceSha256: matrix.get(`${implementation}\0darwin`).conformanceSha256,
      platforms: [...EXPECTED_PLATFORMS].sort().map(os => {
        const report = matrix.get(`${implementation}\0${os}`);
        return { arch: report.platform.arch, os, runtime: report.runtime };
      })
    })),
    formatArtifact: matrix.get('@opengamevcs/object-model/javascript\0darwin').formatArtifact,
    result: 'identical',
    schema: 'ogvcs.object-model.conformance-comparison/v1',
    sharedConformanceSha256,
    sourceRevision
  };
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${canonicalJson(comparison)}\n`, { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(`${canonicalJson(comparison)}\n`);
}

await main();
