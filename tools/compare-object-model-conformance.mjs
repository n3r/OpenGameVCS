#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const EXPECTED_PLATFORMS = new Set(['darwin', 'linux', 'win32']);
const EXPECTED_IMPLEMENTATIONS = new Set([
  '@opengamevcs/object-model/javascript',
  'ogvcs-object-model/rust'
]);
const JS_IMPLEMENTATION = '@opengamevcs/object-model/javascript';
const RUST_IMPLEMENTATION = 'ogvcs-object-model/rust';
const IMPLEMENTATION_ARTIFACT_NAMES = Object.freeze({
  '@opengamevcs/object-model/javascript': '@opengamevcs/object-model',
  'ogvcs-object-model/rust': 'ogvcs-object-model'
});
const MAX_REPORT_BYTES = 1_048_576;
const ERROR_CATALOGUE = resolve(import.meta.dirname, '../spec/repository-format/v1/errors.json');
const SCENARIO_INDEX = resolve(
  import.meta.dirname,
  '../spec/repository-format/v1/vectors/scenarios/index.json'
);

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

function validOutcome(outcome, sites, { evidence } = {}) {
  if (!outcome || typeof outcome !== 'object' || Array.isArray(outcome)) return false;
  const keys = Object.keys(outcome).filter(key => key !== 'evidence').sort();
  if ((Object.hasOwn(outcome, 'evidence') !== (evidence !== undefined)) ||
      (evidence !== undefined && canonicalJson(outcome.evidence) !== canonicalJson(evidence))) return false;
  if (outcome.result === 'accept') {
    return canonicalJson(keys) === canonicalJson(['highestLayer', 'result']) &&
      Number.isInteger(outcome.highestLayer) && outcome.highestLayer >= 1 && outcome.highestLayer <= 3;
  }
  if (outcome.result === 'reject') {
    return canonicalJson(keys) === canonicalJson(['code', 'layer', 'result', 'stage']) &&
      typeof outcome.code === 'string' && Number.isInteger(outcome.layer) &&
      sites.has(`${outcome.code}\0${outcome.layer}\0${outcome.stage}`);
  }
  return false;
}

function scenarioAuthority(index) {
  if (!Array.isArray(index?.cases)) throw new Error('invalid normative scenario index');
  const rows = index.cases;
  const ids = rows.map(row => row?.scenarioId);
  if (ids.some(id => typeof id !== 'string') || new Set(ids).size !== ids.length) {
    throw new Error('invalid normative scenario inventory');
  }
  const scope = row => row.implementationScope ?? ['javascript', 'rust'];
  const executable = row => row.materialization !== 'virtual-constructor' &&
    (row.materialization !== 'virtual-constructor-shared-bundle-baseline' ||
      row.scenarioId === 'bundle-export-claim');
  const counts = language => {
    const result = { executed: 0, failed: 0, inventoryOnly: 0, notApplicable: 0 };
    for (const row of rows) {
      if (!scope(row).includes(language)) result.notApplicable += 1;
      else if (executable(row)) result.executed += 1;
      else result.inventoryOnly += 1;
    }
    return result;
  };
  return Object.freeze({
    counts: Object.freeze({
      [JS_IMPLEMENTATION]: Object.freeze(counts('javascript')),
      [RUST_IMPLEMENTATION]: Object.freeze(counts('rust'))
    }),
    evidenceById: new Map(rows.filter(row => row.expected?.evidence !== undefined)
      .map(row => [row.scenarioId, row.expected.evidence])),
    ids: Object.freeze(ids),
    sharedIds: new Set(rows.filter(row =>
      scope(row).includes('javascript') && scope(row).includes('rust'))
      .map(row => row.scenarioId))
  });
}

function validateScenarioOutcomes(rows, sites, language, authority) {
  for (const row of rows) {
    if (row.status === 'passed' || row.status === 'failed') {
      const evidence = authority.evidenceById.get(row.scenarioId);
      if (!validOutcome(row.actual, sites, { evidence }) ||
          !validOutcome(row.expected, sites, { evidence })) {
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

function normalizedSharedConformance(report, authority) {
  const conformance = structuredClone(report.conformance);
  const source = conformance.scenarios;
  if (!source || !Array.isArray(source.rows)) throw new Error('conformance report has no scenario rows');
  const rows = source.rows.filter(row => authority.sharedIds.has(row.scenarioId));
  if (rows.length !== authority.sharedIds.size ||
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

function validateApplicability(report, sites, authority) {
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
      canonicalJson(rows.map(row => row.scenarioId)) !== canonicalJson(authority.ids)) {
    throw new Error(`invalid scenario result envelope for ${language}`);
  }
  const counts = {
    executed: rows.filter(row => row.status === 'passed' || row.status === 'failed').length,
    failed: rows.filter(row => row.status === 'failed').length,
    inventoryOnly: rows.filter(row => row.status === 'not-executed').length,
    notApplicable: rows.filter(row => row.status === 'not-applicable').length
  };
  if (canonicalJson(counts) !== canonicalJson(authority.counts[report.implementation])) {
    throw new Error(`unexpected frozen scenario cardinality for ${language}`);
  }
  for (const [name, value] of Object.entries(counts)) {
    if (scenarios[name] !== value) throw new Error(`invalid scenario ${name} count for ${language}`);
  }
  validateScenarioOutcomes(rows, sites, language, authority);
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
  const authority = scenarioAuthority(JSON.parse(await readFile(SCENARIO_INDEX, 'utf8')));
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
    validateApplicability(report, sites, authority);
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
    sha256(canonicalJson(normalizedSharedConformance(report, authority)))));
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
