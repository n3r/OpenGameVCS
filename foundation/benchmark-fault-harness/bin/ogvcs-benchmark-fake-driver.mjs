#!/usr/bin/env node

import { parseArgs } from 'node:util';

import { loadBenchmarkContract } from '../src/contract.mjs';
import { serveFakeDriver } from '../src/fake-driver.mjs';

const { values } = parseArgs({ options: {
  contract: { type: 'string' }, incompatible: { type: 'boolean', default: false }, 'malformed-hello': { type: 'boolean', default: false },
  'oversized-hello': { type: 'boolean', default: false }, stderr: { type: 'boolean', default: false }, 'retry-once-operation': { type: 'string' }, help: { type: 'boolean', short: 'h', default: false },
}, strict: true });

if (values.help) {
  process.stdout.write('Usage: ogvcs-benchmark-fake-driver [--contract <root>] [--incompatible] [--retry-once-operation <operation>]\n');
  process.exit(0);
}

const contract = await loadBenchmarkContract({ ...(values.contract ? { root: values.contract } : {}), cache: false });
await serveFakeDriver(contract, { incompatible: values.incompatible, malformedHello: values['malformed-hello'], oversizedHello: values['oversized-hello'], stderr: values.stderr, retryOnceOperation: values['retry-once-operation'] });
