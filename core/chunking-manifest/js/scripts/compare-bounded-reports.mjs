#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const [javascriptPath, rustPath] = process.argv.slice(2);
if (!javascriptPath || !rustPath) throw new Error('usage: compare-bounded-reports.mjs <javascript.json> <rust.json>');
const javascript = JSON.parse(await readFile(javascriptPath));
const rust = JSON.parse(await readFile(rustPath));
assert.deepEqual(rust, javascript);
process.stdout.write(`matched ${javascript.cases.length} bounded cases\n`);
