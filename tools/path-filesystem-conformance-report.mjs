#!/usr/bin/env node

import { resolve } from 'node:path';

import { writeConformanceReport } from '../core/paths-filesystem/js/src/report.mjs';

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--output' || !args[1]) throw new Error('usage: node tools/path-filesystem-conformance-report.mjs --output <report.json>');
const destination = resolve(args[1]);
const report = await writeConformanceReport(destination);
process.stdout.write(`${JSON.stringify({ output: destination, platform: report.platform, total: report.total, passed: report.passed, failed: report.failed, resultsSha256: report.resultsSha256 })}\n`);
if (report.failed !== 0) process.exitCode = 1;
