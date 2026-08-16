import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { auditPathFilesystemTrace } from './path-filesystem-trace-audit.mjs';

test('trace audit proves workspace coverage and rejects outside references', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-path-trace-audit-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const workspace = join(root, 'workspace'); const outside = join(root, 'outside'); const trace = join(root, 'trace.log');
  await writeFile(trace, `1 openat(AT_FDCWD, "${workspace}/asset", O_CREAT|O_WRONLY, 0600) = 3\n`);
  const result = await auditPathFilesystemTrace(trace, workspace, outside);
  assert.equal(result.outsideReferences, 0);
  assert.match(result.sha256, /^[0-9a-f]{64}$/u);
  await writeFile(trace, `1 openat(AT_FDCWD, "${workspace}/asset", O_RDONLY) = 3\n2 openat(AT_FDCWD, "${outside}/pwned", O_CREAT|O_WRONLY, 0600) = 4\n`);
  await assert.rejects(auditPathFilesystemTrace(trace, workspace, outside), /outside fixture/u);
});
