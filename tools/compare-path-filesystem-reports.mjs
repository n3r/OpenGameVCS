#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';

const paths = process.argv.slice(2).map((path) => resolve(path));
if (paths.length !== 3) throw new Error('usage: node tools/compare-path-filesystem-reports.mjs <linux-report.json> <macos-report.json> <windows-report.json>');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}
function exactKeys(value, expected, label) {
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new Error(`${label} has an invalid field set`);
}

const reports = await Promise.all(paths.map(async (path) => {
  const report = JSON.parse(await readFile(path));
  if (report.schemaVersion !== 'ogvcs.path/conformance-report/v1' || report.contractVersion !== '1.0.0' || report.total !== 78 || report.passed !== 78 || report.failed !== 0 || !Array.isArray(report.results) || report.results.length !== 78 || !/^[0-9a-f]{64}$/u.test(report.resultsSha256)) throw new Error(`invalid path report: ${path}`);
  if (sha256(Buffer.from(canonicalJson(report.results), 'utf8')) !== report.resultsSha256) throw new Error(`path result digest differs: ${path}`);
  if (report.results.some(({ passed, expectedSha256, actualSha256 }) => !passed || expectedSha256 !== actualSha256)) throw new Error(`path report contains a failed row: ${path}`);
  if (report.capabilities.atomicReplace !== true || report.capabilities.casePreserving !== true) throw new Error(`required host capability unavailable: ${path}`);
  return { path, report };
}));
const platforms = new Set(reports.map(({ report }) => report.platform));
if (platforms.size !== 3 || !platforms.has('linux') || !platforms.has('macos') || !platforms.has('windows')) throw new Error('reports must cover Linux, macOS, and Windows exactly once');
const authority = reports[0].report;
for (const { path, report } of reports.slice(1)) {
  for (const field of ['contractVersion', 'manifestSha256', 'registrySetSha256', 'unicodeCaseFoldingSha256', 'resultsSha256', 'total', 'passed', 'failed']) if (report[field] !== authority[field]) throw new Error(`path ${field} differs: ${path}`);
  if (canonicalJson(report.results) !== canonicalJson(authority.results)) throw new Error(`path decisions differ: ${path}`);
}
const packageSets = [];
for (const { path, report } of reports) {
  const directory = dirname(path); const evidencePath = join(directory, 'packed-evidence.json');
  const evidence = JSON.parse(await readFile(evidencePath));
  if (evidence.schemaVersion !== 'ogvcs.path/packed-evidence/v1' || evidence.platform !== report.platform || evidence.resultsSha256 !== report.resultsSha256 || !Array.isArray(evidence.packages) || evidence.packages.length !== 2) throw new Error(`invalid path packed evidence: ${evidencePath}`);
  const names = new Set(evidence.packages.map(({ name }) => name));
  if (!names.has('@opengamevcs/path-contract-v1') || !names.has('@opengamevcs/path-filesystem')) throw new Error(`packed package inventory differs: ${evidencePath}`);
  for (const item of evidence.packages) {
    exactKeys(item, ['name', 'version', 'filename', 'sha256'], `package evidence ${item.name}`);
    if (basename(item.filename) !== item.filename || sha256(await readFile(join(directory, 'packages', item.filename))) !== item.sha256) throw new Error(`packed package digest differs: ${item.name}`);
  }
  if (basename(evidence.report.filename) !== evidence.report.filename || sha256(await readFile(path)) !== evidence.report.sha256) throw new Error(`packed report digest differs: ${path}`);
  packageSets.push(evidence.packages.map(({ name, version, sha256: digest }) => ({ name, version, sha256: digest })).sort((left, right) => left.name.localeCompare(right.name)));
}
for (const packages of packageSets.slice(1)) if (canonicalJson(packages) !== canonicalJson(packageSets[0])) throw new Error('packed path package bytes differ across operating systems');
process.stdout.write(`${JSON.stringify({ schemaVersion: 'ogvcs.path/comparison/v1', reports: 3, platforms: [...platforms].sort(), contractVersion: authority.contractVersion, manifestSha256: authority.manifestSha256, registrySetSha256: authority.registrySetSha256, unicodeCaseFoldingSha256: authority.unicodeCaseFoldingSha256, resultsSha256: authority.resultsSha256, packages: packageSets[0], total: authority.total, result: 'equal' })}\n`);
