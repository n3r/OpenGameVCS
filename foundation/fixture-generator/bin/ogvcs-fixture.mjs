#!/usr/bin/env node

import { writeSync } from 'node:fs';

import { runCli } from '../src/cli.mjs';

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    writeSync(
      2,
      `${JSON.stringify({
        error: {
          details: { signal },
          exitCode: 8,
          message: `Operation interrupted by ${signal}`,
          type: 'interrupted',
        },
        ok: false,
        schemaVersion: 'ogvcs.fixture/cli-result/v1',
      })}\n`,
    );
    process.exit(8);
  });
}

process.exitCode = await runCli(process.argv.slice(2), {
  cwd: process.cwd(),
  env: process.env,
  stdout: process.stdout,
  stderr: process.stderr,
});
