import assert from 'node:assert/strict';
import { mkdir, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { createRequest, inspectFixture, verifyFixture } from '../src/index.mjs';
import { readRequestFile } from '../src/cli.mjs';
import {
  isPortableRelativePath,
  portableRelativePathIssue,
  validateSchemaDocument,
} from '../src/schema-validator.mjs';
import {
  jsonError,
  runCli,
  smallCliArguments,
  temporaryDirectory,
} from './test-helpers.mjs';

const WINDOWS_DEVICES = [
  'CON', 'con.txt', 'PRN', 'prn.json', 'AUX', 'aux.log', 'NUL', 'nul.bin',
  'COM1', 'com9.txt', 'LPT1', 'lpt9.cache',
  'COM¹.txt', 'com²', 'COM³.data', 'LPT¹', 'lpt².log', 'LPT³',
  'CLOCK$', 'clock$.txt', 'CONIN$', 'conin$.log', 'CONOUT$', 'conout$.txt',
];

const INVALID_DESTINATIONS = [
  '',
  '/absolute',
  'C:/drive-relative',
  'C:drive-relative',
  './dot',
  '../traversal',
  'a/../traversal',
  'a//empty',
  'a\\windows-separator',
  ...WINDOWS_DEVICES.map((name) => `fixtures/${name}`),
  ...['<', '>', ':', '"', '\\', '|', '?', '*'].map((character) => `fixtures/a${character}b`),
  ...['\u0000', '\u0001', '\u001f', '\u007f', '\u0080', '\u009f'].map(
    (character) => `fixtures/a${character}b`,
  ),
  'fixtures/trailing.',
  'fixtures/trailing ',
  'fixtures/trailing./child',
  'fixtures/trailing /child',
  `fixtures/${'a'.repeat(256)}`,
  `fixtures/${'😀'.repeat(64)}`,
  `fixtures/${'a'.repeat(250)}/${'b'.repeat(250)}/${'c'.repeat(250)}/${'d'.repeat(250)}/${'e'.repeat(250)}/${'f'.repeat(250)}/${'g'.repeat(250)}/${'h'.repeat(250)}/${'i'.repeat(250)}/${'j'.repeat(250)}/${'k'.repeat(250)}/${'l'.repeat(250)}/${'m'.repeat(250)}/${'n'.repeat(250)}/${'o'.repeat(250)}/${'p'.repeat(250)}/${'q'.repeat(250)}`,
  Array.from({ length: 17 }, () => '😀'.repeat(63)).join('/'),
  'fixtures/lone-high-\ud800',
  'fixtures/lone-low-\udfff',
  'fixtures/Cafe\u0301',
  null,
  7,
];

const VALID_DESTINATIONS = [
  'fixture',
  'fixtures/code-heavy',
  '.hidden/cache',
  'src/CMakeLists.txt',
  'Assets/Café/item.asset',
  'Assets/日本語/データ.bin',
  'fixtures/emoji-😀',
  `fixtures/${'a'.repeat(255)}`,
  `fixtures/${'😀'.repeat(63)}`,
  'fixtures/COM0',
  'fixtures/COM10.txt',
  'fixtures/LPT0',
  'fixtures/LPT10.txt',
  'fixtures/console',
  'fixtures/auxiliary.txt',
  'fixtures/file.nul',
];

test('runtime and FixtureRequest schema reject the same non-portable destinations', () => {
  const baseline = createRequest({ destination: 'fixtures/safe' });
  for (const destination of INVALID_DESTINATIONS) {
    assert.notEqual(portableRelativePathIssue(destination), null, String(destination));
    assert.equal(isPortableRelativePath(destination), false, String(destination));
    assert.throws(() => createRequest({ destination }), undefined, String(destination));

    const document = { ...baseline, destination };
    const issues = validateSchemaDocument('FixtureRequest', document);
    assert.ok(issues.some(({ path: issuePath }) => issuePath === '$.destination'), String(destination));
  }
});

test('runtime and FixtureRequest schema accept Windows-safe POSIX relative destinations', () => {
  for (const destination of VALID_DESTINATIONS) {
    assert.equal(portableRelativePathIssue(destination), null, destination);
    assert.equal(isPortableRelativePath(destination), true, destination);
    const request = createRequest({ destination });
    assert.equal(request.destination, destination);
    assert.deepEqual(validateSchemaDocument('FixtureRequest', request), [], destination);
  }
});

test('portable limits constrain both UTF-16 code units and UTF-8 encoded bytes', () => {
  assert.match(portableRelativePathIssue(`fixtures/${'😀'.repeat(64)}`), /255 UTF-8 bytes/u);
  assert.match(
    portableRelativePathIssue(Array.from({ length: 17 }, () => '😀'.repeat(63)).join('/')),
    /4096 UTF-8 bytes/u,
  );
  assert.equal(portableRelativePathIssue(`fixtures/${'😀'.repeat(63)}`), null);
  assert.equal(portableRelativePathIssue(`fixtures/${'a'.repeat(255)}`), null);
});

test('Windows device basenames are rejected case-insensitively, including extensions', () => {
  for (const name of WINDOWS_DEVICES) {
    assert.match(portableRelativePathIssue(`root/${name}`), /reserved Windows device name/);
  }
  for (const valid of ['COM0', 'COM10', 'LPT0', 'LPT10', 'CONSOLE', 'AUXILIARY', 'file.prn']) {
    assert.equal(portableRelativePathIssue(`root/${valid}`), null, valid);
  }
});

test('CLI returns typed invalid-request errors for portable destination hazards', async (t) => {
  const cwd = await temporaryDirectory(t);
  for (const destination of ['fixtures/NUL.txt', 'fixtures/data:stream', 'fixtures/trailing.']) {
    const result = await runCli(cwd, ['plan', '--destination', destination]);
    assert.equal(result.code, 3, `${destination}: ${result.stderr}`);
    const failure = jsonError(result);
    assert.equal(failure.error.type, 'invalid-request');
    assert.equal(failure.error.exitCode, 3);
    assert.ok(failure.error.details.reason, destination);
  }

  const valid = await runCli(cwd, ['plan', '--destination', 'fixtures/.cache/Café']);
  assert.equal(valid.code, 0, valid.stderr);
});

test('inspect and verify reject absolute or traversing positionals in CLI and library calls', async (t) => {
  const cwd = await temporaryDirectory(t);
  for (const destination of ['../outside', '/absolute', 'C:/drive-qualified']) {
    for (const command of ['inspect', 'verify']) {
      const result = await runCli(cwd, [command, destination]);
      assert.equal(result.code, 3, `${command} ${destination}: ${result.stderr}`);
      assert.equal(jsonError(result).error.type, 'invalid-request');
    }
    await assert.rejects(
      inspectFixture(destination, { cwd }),
      (error) => error.type === 'invalid-request',
    );
    await assert.rejects(
      verifyFixture(destination, { cwd }),
      (error) => error.type === 'invalid-request',
    );
  }
});

test('request-file ingestion reads one opened inode within the fixed byte snapshot', async (t) => {
  const cwd = await temporaryDirectory(t);
  const requestPath = path.join(cwd, 'request.json');
  await writeFile(requestPath, JSON.stringify(createRequest({ destination: 'fixture' })));
  await assert.rejects(
    readRequestFile('request.json', cwd, {
      afterStat: () => writeFile(requestPath, ' '.repeat(2 * 1024 * 1024 + 1)),
    }),
    (error) => error.type === 'usage' && /grew|changed/u.test(error.message),
  );
});

test('POSIX symlink destination ancestors are explicitly rejected', {
  skip: process.platform === 'win32' ? 'POSIX symlink case; Windows junction case runs separately' : false,
}, async (t) => {
  const cwd = await temporaryDirectory(t);
  const target = path.join(cwd, 'target');
  const link = path.join(cwd, 'linked');
  await mkdir(target);
  await symlink(target, link, 'dir');
  const result = await runCli(cwd, [
    'generate',
    ...smallCliArguments('code-heavy', 'linked/fixture', {
      historyOperationCount: 1,
      largeFileBytes: 0,
      pathCount: 2,
    }),
  ]);
  assert.equal(result.code, 4, result.stderr);
  assert.equal(jsonError(result).error.type, 'unsafe-destination');
});

test('Windows junction destination ancestors are explicitly rejected', {
  skip: process.platform !== 'win32' ? 'Windows-only junction coverage runs on windows-latest' : false,
}, async (t) => {
  const cwd = await temporaryDirectory(t);
  const target = path.join(cwd, 'target');
  const junction = path.join(cwd, 'junction');
  await mkdir(target);
  await symlink(target, junction, 'junction');
  const result = await runCli(cwd, [
    'generate',
    ...smallCliArguments('code-heavy', 'junction/fixture', {
      historyOperationCount: 1,
      largeFileBytes: 0,
      pathCount: 2,
    }),
  ]);
  assert.equal(result.code, 4, result.stderr);
  assert.equal(jsonError(result).error.type, 'unsafe-destination');
});
