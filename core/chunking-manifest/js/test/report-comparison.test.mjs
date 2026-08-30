import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const comparator = fileURLToPath(new URL('../scripts/compare-bounded-reports.mjs', import.meta.url));

test('bounded comparator requires all supplied language and platform reports to match', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-reports-'));
  try {
    const report = { cases: [{ caseId: 'bounded' }], schemaVersion: 'test/v1' };
    const paths = [];
    for (let index = 0; index < 6; index += 1) {
      const path = join(directory, `${index}.json`);
      await writeFile(path, `${JSON.stringify(report)}\n`);
      paths.push(path);
    }
    const matched = spawnSync(process.execPath, [comparator, ...paths], {
      encoding: 'utf8',
    });
    assert.equal(matched.status, 0, matched.stderr);
    assert.match(matched.stdout, /across 6 reports/u);

    await writeFile(paths.at(-1), `${JSON.stringify({ ...report, drift: true })}\n`);
    const drifted = spawnSync(process.execPath, [comparator, ...paths], {
      encoding: 'utf8',
    });
    assert.notEqual(drifted.status, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
