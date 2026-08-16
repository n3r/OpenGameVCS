#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

const paths = process.argv.slice(2);
if (paths.length < 2) throw new Error('usage: node tools/compare-authorization-contract-reports.mjs <report.json> <report.json> [...]');

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  throw new Error('value outside canonical JSON domain');
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

async function fileSha256(path) {
  return sha256(await readFile(path));
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new Error(`${label} has an invalid field set`);
}

const reports = await Promise.all(paths.map(async (path) => {
  const bytes = await readFile(path);
  const report = JSON.parse(bytes);
  if (report.schemaVersion !== 'ogvcs.authorization/runner-report/v1' ||
      report.contractVersion !== '1.0.0' || report.vectors !== 30 || report.passed !== 30 || report.failed !== 0 ||
      !['reference-fixture', 'external-adapter'].includes(report.adapter) ||
      !/^[0-9a-f]{64}$/.test(report.manifestSha256) || !/^[0-9a-f]{64}$/.test(report.registrySetSha256) || !/^[0-9a-f]{64}$/.test(report.resultsSha256) ||
      !Array.isArray(report.rows) || report.rows.length !== 30) {
    throw new Error(`invalid authorization conformance report: ${path}`);
  }
  for (const row of report.rows) {
    exactKeys(row, ['id', 'status', 'expectedCode', 'actualCode'], `authorization conformance row in ${path}`);
    if (row.status !== 'passed' || row.expectedCode !== row.actualCode || !/^[a-z][a-z0-9.-]{0,127}$/.test(row.id) || !/^[A-Z][A-Z0-9_]{0,127}$/.test(row.actualCode)) {
      throw new Error(`invalid authorization conformance row: ${path}`);
    }
  }
  if (sha256(Buffer.from(canonicalJson(report.rows), 'utf8')) !== report.resultsSha256) throw new Error(`authorization conformance row digest differs: ${path}`);
  return { path, bytes, report };
}));

const authority = reports[0].report;
for (const { path, report } of reports.slice(1)) {
  for (const field of ['contractVersion', 'manifestSha256', 'registrySetSha256', 'resultsSha256', 'vectors', 'passed', 'failed']) {
    if (report[field] !== authority[field]) throw new Error(`authorization conformance ${field} differs: ${path}`);
  }
  if (canonicalJson(report.rows) !== canonicalJson(authority.rows)) throw new Error(`authorization conformance rows differ: ${path}`);
}
const adapters = new Set(reports.map(({ report }) => report.adapter));
if (adapters.size !== 2 || !adapters.has('reference-fixture') || !adapters.has('external-adapter')) throw new Error('comparison must include reference and external-adapter reports');

const directories = [...new Set(reports.map(({ path }) => dirname(path)))];
const evidenceSets = await Promise.all(directories.map(async (directory) => {
  const evidencePath = join(directory, 'packed-evidence.json');
  const evidence = JSON.parse(await readFile(evidencePath));
  if (evidence.schemaVersion !== 'ogvcs.authorization/packed-evidence/v1' || evidence.contractVersion !== authority.contractVersion ||
      evidence.manifestSha256 !== authority.manifestSha256 || evidence.registrySetSha256 !== authority.registrySetSha256 ||
      evidence.resultsSha256 !== authority.resultsSha256 || !Array.isArray(evidence.packages) || evidence.packages.length !== 2 ||
      !Array.isArray(evidence.reports) || evidence.reports.length !== 2) throw new Error(`invalid packed authorization evidence: ${evidencePath}`);
  const packageNames = new Set(evidence.packages.map(({ name }) => name));
  if (packageNames.size !== 2 || !packageNames.has('@opengamevcs/authorization-contract') || !packageNames.has('@opengamevcs/authorization-contract-v1')) throw new Error(`invalid packed package inventory: ${evidencePath}`);
  for (const item of evidence.packages) {
    exactKeys(item, ['name', 'version', 'filename', 'sha256'], `packed package evidence in ${evidencePath}`);
    if (basename(item.filename) !== item.filename || !/^[0-9a-f]{64}$/.test(item.sha256) || await fileSha256(join(directory, 'packages', item.filename)) !== item.sha256) throw new Error(`packed package digest differs: ${item.name}`);
  }
  const reportAdapters = new Set();
  for (const item of evidence.reports) {
    exactKeys(item, ['adapter', 'filename', 'sha256'], `packed report evidence in ${evidencePath}`);
    if (basename(item.filename) !== item.filename || !/^[0-9a-f]{64}$/.test(item.sha256) || await fileSha256(join(directory, item.filename)) !== item.sha256) throw new Error(`packed report digest differs: ${item.adapter}`);
    reportAdapters.add(item.adapter);
  }
  if (reportAdapters.size !== 2 || !reportAdapters.has('reference-fixture') || !reportAdapters.has('external-adapter')) throw new Error(`packed report inventory differs: ${evidencePath}`);
  return evidence.packages.map(({ name, version, filename, sha256: digest }) => ({ name, version, filename, sha256: digest })).sort((left, right) => left.name.localeCompare(right.name));
}));

const packageAuthority = canonicalJson(evidenceSets[0]);
for (const packages of evidenceSets.slice(1)) {
  if (canonicalJson(packages) !== packageAuthority) throw new Error('packed authorization package evidence differs across operating systems');
}

process.stdout.write(`${JSON.stringify({
  schemaVersion: 'ogvcs.authorization/comparison/v1',
  reports: reports.length,
  adapters: [...adapters].sort(),
  contractVersion: authority.contractVersion,
  manifestSha256: authority.manifestSha256,
  registrySetSha256: authority.registrySetSha256,
  resultsSha256: authority.resultsSha256,
  packages: evidenceSets[0].map(({ name, version, sha256: digest }) => ({ name, version, sha256: digest })),
  vectors: authority.vectors,
  result: 'equal',
})}\n`);
