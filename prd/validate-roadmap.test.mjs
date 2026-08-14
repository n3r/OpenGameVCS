import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const sourcePrdRoot = path.dirname(fileURLToPath(import.meta.url));
const sourceRoot = path.resolve(sourcePrdRoot, '..');

function makeFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ogvcs-roadmap-validator-'));
  fs.cpSync(sourcePrdRoot, path.join(root, 'prd'), { recursive: true });
  fs.cpSync(path.join(sourceRoot, 'adr'), path.join(root, 'adr'), { recursive: true });
  fs.copyFileSync(path.join(sourceRoot, 'architecture.md'), path.join(root, 'architecture.md'));
  fs.copyFileSync(
    path.join(sourceRoot, 'GAME_DEV_VCS_ANALYSIS.md'),
    path.join(root, 'GAME_DEV_VCS_ANALYSIS.md'),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function runValidator(root) {
  const result = spawnSync(process.execPath, [path.join(root, 'prd', 'validate-roadmap.mjs')], {
    cwd: root,
    encoding: 'utf8',
  });
  return { ...result, output: `${result.stdout}${result.stderr}` };
}

function findPrd(root, id, folder = 'todo') {
  const directory = path.join(root, 'prd', folder);
  const filename = fs.readdirSync(directory).find((name) => name.startsWith(`${id}-`));
  assert.ok(filename, `fixture contains ${id}`);
  return path.join(directory, filename);
}

function rewrite(filePath, transform) {
  fs.writeFileSync(filePath, transform(fs.readFileSync(filePath, 'utf8')));
}

test('current roadmap is valid', (t) => {
  const root = makeFixture(t);
  const result = runValidator(root);
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /Roadmap valid: 45 PRDs/);
});

test('rejects a dependency placed in a later release', (t) => {
  const root = makeFixture(t);
  rewrite(findPrd(root, 'OGVCS-041'), (body) => body.replace(
    '**Release:** R0 — Engineering Foundation',
    '**Release:** R2 — Studio Alpha',
  ));
  const result = runValidator(root);
  assert.notEqual(result.status, 0);
  assert.match(result.output, /depends on later-release OGVCS-041/);
});

test('rejects done PRD whose dependency remains todo', (t) => {
  const root = makeFixture(t);
  const source = findPrd(root, 'OGVCS-002');
  const destination = path.join(root, 'prd', 'done', path.basename(source));
  rewrite(source, (body) => body.replace('**Status:** Todo', '**Status:** Done'));
  fs.renameSync(source, destination);
  rewrite(path.join(root, 'prd', 'ROADMAP.md'), (body) => body.replace(
    `todo/${path.basename(source)}`,
    `done/${path.basename(source)}`,
  ));
  const result = runValidator(root);
  assert.notEqual(result.status, 0);
  assert.match(result.output, /done PRD depends on unfinished OGVCS-001/);
});

test('rejects duplicate required headings even outside their normal section', (t) => {
  const root = makeFixture(t);
  rewrite(findPrd(root, 'OGVCS-001'), (body) => `${body}\n## Outcome\n\nDuplicate.\n`);
  const result = runValidator(root);
  assert.notEqual(result.status, 0);
  assert.match(result.output, /heading ## Outcome appears 2 times/);
});

test('rejects placeholder completion evidence and requires criterion links', (t) => {
  const root = makeFixture(t);
  const source = findPrd(root, 'OGVCS-001');
  const destination = path.join(root, 'prd', 'done', path.basename(source));
  rewrite(source, (body) => {
    const acceptanceIds = [...body.matchAll(/OGVCS-001-AC-\d{2}/g)]
      .map((match) => match[0])
      .filter((value, index, values) => values.indexOf(value) === index);
    const evidence = [
      '## Completion evidence',
      '',
      '- Implementation changes: TBD',
      '- Test and benchmark results: [proof](../../architecture.md)',
      '- Security/reliability review: [proof](../../architecture.md)',
      '- Documentation/runbooks: [proof](../../architecture.md)',
      '- Rollout result: [proof](../../architecture.md)',
      ...acceptanceIds.slice(0, -1).map((id) => `- ${id}: [proof](../../architecture.md)`),
      '',
    ].join('\n');
    return body
      .replace('**Status:** Todo', '**Status:** Done')
      .replace('**Owner:** Unassigned', '**Owner:** Test owner')
      .replace(/^## Completion evidence[\s\S]*$/m, evidence);
  });
  fs.renameSync(source, destination);
  rewrite(path.join(root, 'prd', 'ROADMAP.md'), (body) => body.replace(
    `todo/${path.basename(source)}`,
    `done/${path.basename(source)}`,
  ));
  const result = runValidator(root);
  assert.notEqual(result.status, 0);
  assert.match(result.output, /completion evidence is blank for Implementation changes/);
  assert.match(result.output, /completion evidence must link proof for OGVCS-001-AC-/);
});

test('rejects an undeclared contract reference', (t) => {
  const root = makeFixture(t);
  rewrite(findPrd(root, 'OGVCS-001'), (body) => body.replace(
    '## Interfaces and data',
    '## Interfaces and data\n\nConsumes an undeclared contract from OGVCS-040.\n',
  ));
  const result = runValidator(root);
  assert.notEqual(result.status, 0);
  assert.match(result.output, /Requirements\/interfaces\/verification references OGVCS-040/);
});

test('rejects unexpected Markdown files in lifecycle folders', (t) => {
  const root = makeFixture(t);
  fs.writeFileSync(path.join(root, 'prd', 'todo', 'notes.md'), '# Notes\n');
  const result = runValidator(root);
  assert.notEqual(result.status, 0);
  assert.match(result.output, /unexpected Markdown file/);
});
