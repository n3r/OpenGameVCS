import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export const verifyRetainedSourceFiles = async ({
  root,
  evidence,
  revision,
  paths,
}) => {
  assert.equal(evidence.run.headSha, revision);
  assert.deepEqual(evidence.sourceFiles.map(({ path }) => path), paths);

  for (const expected of evidence.sourceFiles) {
    assert.deepEqual(
      Object.keys(expected).sort(),
      ['bytes', 'path', 'sha256'],
      `${expected.path ?? '<missing path>'}: source entry keys`,
    );
    assert.equal(typeof expected.path, 'string');
    assert.match(expected.sha256, /^[0-9a-f]{64}$/u);
    assert.ok(Number.isSafeInteger(expected.bytes) && expected.bytes >= 0);
    const { stdout: bytes } = await execFileAsync(
      'git',
      ['show', `${revision}:${expected.path}`],
      {
        cwd: fileURLToPath(root),
        encoding: null,
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    assert.equal(bytes.byteLength, expected.bytes, `${expected.path}: byte length`);
    assert.equal(
      createHash('sha256').update(bytes).digest('hex'),
      expected.sha256,
      `${expected.path}: SHA-256`,
    );
  }
};
