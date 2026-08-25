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
  fs.cpSync(path.join(sourceRoot, 'docs'), path.join(root, 'docs'), { recursive: true });
  fs.cpSync(path.join(sourceRoot, 'foundation'), path.join(root, 'foundation'), { recursive: true });
  fs.copyFileSync(path.join(sourceRoot, 'architecture.md'), path.join(root, 'architecture.md'));
  fs.copyFileSync(
    path.join(sourceRoot, 'GAME_DEV_VCS_ANALYSIS.md'),
    path.join(root, 'GAME_DEV_VCS_ANALYSIS.md'),
  );
  const repositoryReadme = fs.readFileSync(path.join(sourceRoot, 'README.md'), 'utf8');
  fs.writeFileSync(path.join(root, 'README.md'), repositoryReadme);
  for (const match of repositoryReadme.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = match[1];
    if (/^(?:https?:|mailto:|#)/.test(target)) continue;
    const relativeTarget = target.split('#')[0];
    if (!relativeTarget) continue;
    const sourceTarget = path.resolve(sourceRoot, relativeTarget);
    assert.ok(fs.existsSync(sourceTarget), `source README link exists: ${target}`);
    const fixtureTarget = path.resolve(root, relativeTarget);
    if (fs.existsSync(fixtureTarget)) continue;
    if (fs.statSync(sourceTarget).isDirectory()) {
      fs.mkdirSync(fixtureTarget, { recursive: true });
    } else {
      fs.mkdirSync(path.dirname(fixtureTarget), { recursive: true });
      fs.copyFileSync(sourceTarget, fixtureTarget);
    }
  }
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

function findPrd(root, id, folder) {
  const folders = folder ? [folder] : ['todo', 'done'];
  const matches = folders.flatMap((candidateFolder) => {
    const directory = path.join(root, 'prd', candidateFolder);
    return fs.readdirSync(directory)
      .filter((name) => name.startsWith(`${id}-`))
      .map((name) => path.join(directory, name));
  });
  assert.equal(matches.length, 1, `fixture contains exactly one ${id}`);
  return matches[0];
}

function rewrite(filePath, transform) {
  fs.writeFileSync(filePath, transform(fs.readFileSync(filePath, 'utf8')));
}

function placePrd(root, id, folder, status) {
  const source = findPrd(root, id);
  const destination = path.join(root, 'prd', folder, path.basename(source));
  rewrite(source, (body) => body.replace(/^\*\*Status:\*\* .+$/m, `**Status:** ${status}`));
  if (source !== destination) fs.renameSync(source, destination);
  rewrite(path.join(root, 'prd', 'ROADMAP.md'), (body) => body.replace(
    new RegExp(`(?:todo|done)/${path.basename(source)}`),
    `${folder}/${path.basename(source)}`,
  ));
  return destination;
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
  placePrd(root, 'OGVCS-001', 'todo', 'Todo');
  placePrd(root, 'OGVCS-002', 'done', 'Done');
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
  const source = findPrd(root, 'OGVCS-001', 'done');
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
    return body.replace(/^## Completion evidence[\s\S]*$/m, evidence);
  });
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

test('rejects a missing or broken repository README', (t) => {
  const missingRoot = makeFixture(t);
  fs.rmSync(path.join(missingRoot, 'README.md'));
  const missingResult = runValidator(missingRoot);
  assert.notEqual(missingResult.status, 0);
  assert.match(missingResult.output, /missing repository entry-point documentation/);

  const brokenRoot = makeFixture(t);
  rewrite(path.join(brokenRoot, 'README.md'), (body) => `${body}\n[Broken](missing-document.md)\n`);
  const brokenResult = runValidator(brokenRoot);
  assert.notEqual(brokenResult.status, 0);
  assert.match(brokenResult.output, /broken local link missing-document\.md/);
});
