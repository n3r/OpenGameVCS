import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runReferenceHarness } from '@opengamevcs/benchmark-fault-harness';

const root = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-example-'));
const result = await runReferenceHarness({ workspace: join(root, 'workspace'), output: join(root, 'result'), harnessProfile: 'local-smoke', seed: 'readme-smoke-v1' });
process.stdout.write(`${JSON.stringify({ status: result.publication.result.overallStatus, samples: result.matrix.samples.length, result: join(root, 'result') })}\n`);
