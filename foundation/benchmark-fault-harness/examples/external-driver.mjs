import { fileURLToPath } from 'node:url';

import { loadBenchmarkContract, runExternalDriverConformance } from '@opengamevcs/benchmark-fault-harness';

const contract = await loadBenchmarkContract();
const driver = [process.execPath, fileURLToPath(new URL('../bin/ogvcs-benchmark-fake-driver.mjs', import.meta.url))];
const report = await runExternalDriverConformance(driver, contract);
process.stdout.write(`${JSON.stringify({ failed: report.failed, traceDigest: report.traceDigest })}\n`);
