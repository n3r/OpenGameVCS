#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import {
  access,
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_ROOT = dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = resolve(SCRIPT_ROOT, '..');
const REPOSITORY_ROOT = resolve(CLI_ROOT, '../../..');
const OBJECT_MODEL_ROOT = resolve(REPOSITORY_ROOT, 'core/object-model/rust');
const PATH_CONTRACT_ROOT = resolve(REPOSITORY_ROOT, 'core/paths-filesystem/rust');
const CONTRACT_ROOT = resolve(REPOSITORY_ROOT, 'spec/cli-workspace/v1');
const CLI_VERSION = '0.2.0-rc.2';
const OBJECT_MODEL_VERSION = '0.1.0';
const PATH_CONTRACT_VERSION = '1.0.0';
const HARD_EXIT_CODE = 86;
const MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_SIGNAL_OUTPUT_BYTES = 64 * 1024;
const SIGNAL_TIMEOUT_MS = 20_000;
const SAFE_RUNTIME_INHERITED_KEYS = Object.freeze([
  'COMSPEC',
  'LANG',
  'LC_ALL',
  'NUMBER_OF_PROCESSORS',
  'OS',
  'PATH',
  'PATHEXT',
  'PROCESSOR_ARCHITECTURE',
  'PROCESSOR_IDENTIFIER',
  'SYSTEMROOT',
  'TERM',
  'TZ',
  'WINDIR',
]);

class GateError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const check = (condition, code) => {
  if (!condition) throw new GateError(code);
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
const executableSuffix = process.platform === 'win32' ? '.exe' : '';
const cargoConfigPath = (path) => path.split(sep).join('/');
const patchArguments = (objectModel, pathContract) => [
  '--config',
  `patch.crates-io.ogvcs-object-model.path='${cargoConfigPath(objectModel)}'`,
  '--config',
  `patch.crates-io.ogvcs-path-contract.path='${cargoConfigPath(pathContract)}'`,
];

function runRaw(command, commandArguments, { cwd, env = process.env } = {}) {
  const result = spawnSync(command, commandArguments, {
    cwd,
    env,
    encoding: 'utf8',
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    shell: false,
    windowsHide: true,
  });
  check(result.error === undefined, 'PROCESS_START_FAILED');
  check(typeof result.stdout === 'string' && typeof result.stderr === 'string', 'PROCESS_OUTPUT_INVALID');
  return result;
}

function runChecked(command, commandArguments, options, code) {
  const result = runRaw(command, commandArguments, options);
  check(result.status === 0 && result.signal === null, code);
  return result;
}

async function copyAuthenticatedContract(destination) {
  const manifestBytes = await readFile(join(CONTRACT_ROOT, 'manifest.json'));
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes);
  } catch {
    throw new GateError('CONTRACT_MANIFEST_INVALID');
  }
  check(manifest.schema === 'ogvcs.cli-workspace/contract-manifest/v1', 'CONTRACT_MANIFEST_INVALID');
  check(manifest.contractVersion === CLI_VERSION, 'CONTRACT_VERSION_MISMATCH');
  check(Array.isArray(manifest.artifacts) && manifest.artifacts.length > 0, 'CONTRACT_MANIFEST_INVALID');
  check(manifest.artifacts.length <= 64, 'CONTRACT_MANIFEST_INVALID');
  const seen = new Set();
  for (const record of manifest.artifacts) {
    check(
      record !== null
        && typeof record === 'object'
        && typeof record.path === 'string'
        && /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u.test(record.path)
        && Number.isSafeInteger(record.bytes)
        && record.bytes >= 0
        && /^[0-9a-f]{64}$/u.test(record.sha256)
        && !seen.has(record.path),
      'CONTRACT_MANIFEST_INVALID',
    );
    seen.add(record.path);
    const bytes = await readFile(join(CONTRACT_ROOT, record.path));
    check(bytes.length === record.bytes && sha256(bytes) === record.sha256, 'CONTRACT_ARTIFACT_INVALID');
    const target = join(destination, record.path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes, { flag: 'wx' });
  }
  check(sha256(canonicalBytes(manifest.artifacts)) === manifest.artifactSetSha256, 'CONTRACT_SET_INVALID');
  await writeFile(join(destination, 'manifest.json'), manifestBytes, { flag: 'wx' });
  for (const record of manifest.artifacts) {
    const bytes = await readFile(join(destination, record.path));
    check(bytes.length === record.bytes && sha256(bytes) === record.sha256, 'COPIED_CONTRACT_INVALID');
  }
  return { manifest, manifestBytes, manifestSha256: sha256(manifestBytes) };
}

async function assertAbsent(path, code) {
  await access(path).then(
    () => { throw new GateError(code); },
    (error) => check(error?.code === 'ENOENT', `${code}_INSPECTION_FAILED`),
  );
}

function assertNoPathDisclosure(result, paths, code) {
  const output = `${result.stdout}\n${result.stderr}`.replaceAll('\\', '/').toLowerCase();
  for (const path of paths) {
    check(
      !output.includes(path.replaceAll('\\', '/').toLowerCase()),
      `${code}_PATH_DISCLOSURE`,
    );
  }
}

async function listFiles(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile()) files.push(relative(root, path).split(sep).join('/'));
      else throw new GateError('RUNTIME_TREE_INVALID');
    }
  }
  return files.sort();
}

async function makePrivateDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') await chmod(path, 0o700);
}

function freshRuntimeEnvironment(paths) {
  const environment = {};
  const inherited = Object.entries(process.env);
  for (const key of SAFE_RUNTIME_INHERITED_KEYS) {
    const entry = inherited.find(([candidate]) => candidate.toUpperCase() === key);
    if (entry?.[1] !== undefined) environment[key] = entry[1];
  }
  const forbiddenRoots = [REPOSITORY_ROOT, CLI_ROOT]
    .map((path) => path.replaceAll('\\', '/').toLowerCase());
  for (const value of Object.values(environment)) {
    const normalized = value.replaceAll('\\', '/').toLowerCase();
    check(
      forbiddenRoots.every((root) => !normalized.includes(root)),
      'SOURCE_PATH_IN_RUNTIME_ENVIRONMENT',
    );
  }
  return {
    ...environment,
    HOME: paths.home,
    USERPROFILE: paths.profile,
    XDG_CONFIG_HOME: paths.config,
    APPDATA: paths.roaming,
    LOCALAPPDATA: paths.local,
    TMPDIR: paths.temp,
    TMP: paths.temp,
    TEMP: paths.temp,
    RUST_BACKTRACE: '0',
    RUST_LIB_BACKTRACE: '0',
  };
}

function parseMachineResult(result, expectedStatus, code) {
  check(result.status === expectedStatus && result.signal === null, code);
  check(result.stderr.length === 0, `${code}_STDERR`);
  check(Buffer.byteLength(result.stdout, 'utf8') <= MAX_SIGNAL_OUTPUT_BYTES, `${code}_OUTPUT_LIMIT`);
  let value;
  try {
    value = JSON.parse(result.stdout);
  } catch {
    throw new GateError(`${code}_JSON`);
  }
  check(value !== null && typeof value === 'object' && !Array.isArray(value), `${code}_JSON`);
  return value;
}

function assertCancellationResult(result) {
  check(result.code === 'OPERATION_CANCELLED', 'SIGNAL_RESULT_CODE');
  check(result.exitClass === 'cancelled', 'SIGNAL_RESULT_CLASS');
  check(result.data?.phase === 'hermetic-signal', 'SIGNAL_RESULT_PHASE');
  check(result.data?.remoteDurableState === 'unchanged', 'SIGNAL_RESULT_REMOTE_STATE');
}

async function waitForReady(path, exited) {
  const deadline = Date.now() + SIGNAL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const metadata = await stat(path);
      if (metadata.isFile()) return;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw new GateError('SIGNAL_READY_INVALID');
    }
    check(!exited(), 'SIGNAL_CHILD_EARLY_EXIT');
    await new Promise((resolveWait) => setTimeout(resolveWait, 10));
  }
  throw new GateError('SIGNAL_READY_TIMEOUT');
}

async function runUnixSignal(helper, signal, ready, cwd, env) {
  const child = spawn(helper, ['signal-child', ready], {
    cwd,
    env,
    shell: false,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let exited = false;
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    if (Buffer.byteLength(stdout, 'utf8') > MAX_SIGNAL_OUTPUT_BYTES) child.kill('SIGKILL');
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
    if (Buffer.byteLength(stderr, 'utf8') > MAX_SIGNAL_OUTPUT_BYTES) child.kill('SIGKILL');
  });
  const completion = new Promise((resolveCompletion, rejectCompletion) => {
    child.once('error', () => rejectCompletion(new GateError('SIGNAL_CHILD_START_FAILED')));
    child.once('close', (status, exitSignal) => {
      exited = true;
      resolveCompletion({ status, exitSignal });
    });
  });
  let timeoutHandle;
  try {
    await waitForReady(ready, () => exited);
    check(child.kill(signal), 'SIGNAL_DELIVERY_FAILED');
    const timeout = new Promise((_, rejectTimeout) => {
      timeoutHandle = setTimeout(
        () => rejectTimeout(new GateError('SIGNAL_CHILD_TIMEOUT')),
        SIGNAL_TIMEOUT_MS,
      );
    });
    const settled = await Promise.race([completion, timeout]);
    check(settled.status === 0 && settled.exitSignal === null, 'SIGNAL_CHILD_FAILED');
    check(stderr.length === 0, 'SIGNAL_CHILD_STDERR');
    let result;
    try {
      result = JSON.parse(stdout);
    } catch {
      throw new GateError('SIGNAL_RESULT_JSON');
    }
    assertCancellationResult(result);
  } catch (error) {
    if (!exited) child.kill('SIGKILL');
    throw error;
  } finally {
    clearTimeout(timeoutHandle);
  }
}

async function main() {
  const temporary = await mkdtemp(join(process.env.RUNNER_TEMP ?? tmpdir(), 'ogvcs011-hermetic.'));
  try {
    const packageTarget = join(temporary, 'package-target');
    const unpacked = join(temporary, 'unpacked');
    const buildTarget = join(temporary, 'build-target');
    const controllerRoot = join(temporary, 'controller');
    const runtimeRoot = join(temporary, 'runtime');
    await Promise.all([
      mkdir(packageTarget),
      mkdir(unpacked),
      mkdir(buildTarget),
      mkdir(controllerRoot),
      mkdir(runtimeRoot),
    ]);
    check((await readdir(runtimeRoot)).length === 0, 'RUNTIME_ROOT_NOT_EMPTY');

    const cargoEnvironment = {
      ...process.env,
      CARGO_TARGET_DIR: packageTarget,
      CARGO_TERM_COLOR: 'never',
    };
    runChecked(
      'cargo',
      ['package', '--manifest-path', join(OBJECT_MODEL_ROOT, 'Cargo.toml'), '--locked', '--offline', '--allow-dirty'],
      { cwd: OBJECT_MODEL_ROOT, env: cargoEnvironment },
      'OBJECT_MODEL_PACKAGE_FAILED',
    );
    runChecked(
      'cargo',
      ['package', '--manifest-path', join(PATH_CONTRACT_ROOT, 'Cargo.toml'), '--locked', '--offline', '--allow-dirty'],
      { cwd: PATH_CONTRACT_ROOT, env: cargoEnvironment },
      'PATH_CONTRACT_PACKAGE_FAILED',
    );
    runChecked(
      'cargo',
      [
        'package',
        '--manifest-path',
        join(CLI_ROOT, 'Cargo.toml'),
        '--locked',
        '--offline',
        '--allow-dirty',
        ...patchArguments(OBJECT_MODEL_ROOT, PATH_CONTRACT_ROOT),
      ],
      { cwd: CLI_ROOT, env: cargoEnvironment },
      'CLI_PACKAGE_FAILED',
    );

    const archives = [
      join(packageTarget, 'package', `ogvcs-object-model-${OBJECT_MODEL_VERSION}.crate`),
      join(packageTarget, 'package', `ogvcs-path-contract-${PATH_CONTRACT_VERSION}.crate`),
      join(packageTarget, 'package', `ogvcs-local-cli-${CLI_VERSION}.crate`),
    ];
    for (const archive of archives) {
      await access(archive);
      runChecked('tar', ['-xzf', archive, '-C', unpacked], { cwd: unpacked }, 'PACKAGE_EXTRACT_FAILED');
    }
    const unpackedObject = join(unpacked, `ogvcs-object-model-${OBJECT_MODEL_VERSION}`);
    const unpackedPath = join(unpacked, `ogvcs-path-contract-${PATH_CONTRACT_VERSION}`);
    const unpackedCli = join(unpacked, `ogvcs-local-cli-${CLI_VERSION}`);
    runChecked(
      'rustfmt',
      ['--edition', '2021', '--check', join(unpackedCli, 'tests/support/hermetic_fixture.rs')],
      { cwd: unpackedCli },
      'FIXTURE_FORMAT_FAILED',
    );

    const buildEnvironment = {
      ...process.env,
      CARGO_TARGET_DIR: buildTarget,
      CARGO_TERM_COLOR: 'never',
    };
    const patches = patchArguments(unpackedObject, unpackedPath);
    runChecked(
      'cargo',
      [
        'build',
        '--manifest-path',
        join(unpackedCli, 'Cargo.toml'),
        '--locked',
        '--offline',
        '--release',
        '--bin',
        'ogvcs',
        ...patches,
      ],
      { cwd: unpackedCli, env: buildEnvironment },
      'CLI_RELEASE_BUILD_FAILED',
    );
    runChecked(
      'cargo',
      [
        'build',
        '--manifest-path',
        join(unpackedCli, 'Cargo.toml'),
        '--locked',
        '--offline',
        '--release',
        '--example',
        'ogvcs-hermetic-fixture',
        ...patches,
      ],
      { cwd: unpackedCli, env: buildEnvironment },
      'FIXTURE_RELEASE_BUILD_FAILED',
    );

    const installedBinary = join(runtimeRoot, `ogvcs${executableSuffix}`);
    const fixtureBinary = join(controllerRoot, `hermetic-fixture${executableSuffix}`);
    await copyFile(join(buildTarget, 'release', `ogvcs${executableSuffix}`), installedBinary);
    await copyFile(
      join(buildTarget, 'release', 'examples', `ogvcs-hermetic-fixture${executableSuffix}`),
      fixtureBinary,
    );
    if (process.platform !== 'win32') {
      await chmod(installedBinary, 0o755);
      await chmod(fixtureBinary, 0o755);
    }
    const installedBinarySha256 = sha256(await readFile(installedBinary));
    const fixtureBinarySha256 = sha256(await readFile(fixtureBinary));
    const contractRoot = join(runtimeRoot, 'contract');
    await mkdir(contractRoot);
    const { manifest, manifestBytes, manifestSha256 } = await copyAuthenticatedContract(contractRoot);

    await Promise.all([
      rm(packageTarget, { recursive: true, force: true }),
      rm(unpacked, { recursive: true, force: true }),
      rm(buildTarget, { recursive: true, force: true }),
    ]);
    for (const removedPath of [packageTarget, unpacked, buildTarget]) {
      await assertAbsent(removedPath, 'SOURCE_TREE_RETAINED');
    }
    const initialRuntimeFiles = await listFiles(runtimeRoot);
    const expectedRuntimeFiles = [
      `ogvcs${executableSuffix}`,
      'contract/manifest.json',
      ...manifest.artifacts.map(({ path }) => `contract/${path}`),
    ].sort();
    assert.deepEqual(initialRuntimeFiles, expectedRuntimeFiles, 'runtime contains only binary and contract');
    check(
      initialRuntimeFiles.every((path) => !path.endsWith('.rs') && !path.endsWith('.crate') && !path.endsWith('Cargo.toml')),
      'RUNTIME_SOURCE_PRESENT',
    );

    const environmentRoot = join(temporary, 'environment');
    const environmentPaths = {
      home: join(environmentRoot, 'home'),
      profile: join(environmentRoot, 'profile'),
      config: join(environmentRoot, 'config'),
      roaming: join(environmentRoot, 'roaming'),
      local: join(environmentRoot, 'local'),
      temp: join(environmentRoot, 'temp'),
    };
    const stateRoot = join(temporary, 'state');
    await Promise.all([
      ...Object.values(environmentPaths).map(makePrivateDirectory),
      makePrivateDirectory(stateRoot),
    ]);
    const runtimeEnvironment = freshRuntimeEnvironment(environmentPaths);

    const installed = (commandArguments, expectedStatus, code, extraEnvironment = {}) => {
      const raw = runRaw(installedBinary, commandArguments, {
        cwd: runtimeRoot,
        env: { ...runtimeEnvironment, ...extraEnvironment },
      });
      assertNoPathDisclosure(raw, [temporary, REPOSITORY_ROOT, CLI_ROOT], code);
      return { raw, value: parseMachineResult(raw, expectedStatus, code) };
    };
    const fixture = (action, path, expectedStatus = 0) => {
      const result = runRaw(fixtureBinary, [action, path], {
        cwd: controllerRoot,
        env: runtimeEnvironment,
      });
      check(result.status === expectedStatus && result.signal === null, 'FIXTURE_ACTION_FAILED');
      if (expectedStatus === 0) {
        check(result.stderr.length === 0, 'FIXTURE_ACTION_STDERR');
        let value;
        try {
          value = JSON.parse(result.stdout);
        } catch {
          throw new GateError('FIXTURE_ACTION_JSON');
        }
        check(value?.ok === true, 'FIXTURE_ACTION_RESULT');
      } else {
        check(result.stdout.length === 0 && result.stderr.length === 0, 'FIXTURE_CRASH_OUTPUT');
      }
      return result;
    };
    const openReady = (root, code, stagedIntents = 0) => {
      const openedResult = installed(
        ['--format', 'json', 'workspace', 'open', '--root', root],
        0,
        code,
      ).value;
      check(openedResult.code === 'WORKSPACE_OPEN', `${code}_CODE`);
      check(
        openedResult.data?.schema === 'ogvcs.cli-workspace/verified-workspace-report/v2'
          && openedResult.data?.state === 'ready'
          && openedResult.data?.stagedIntents === stagedIntents,
        `${code}_STATE`,
      );
      return openedResult.data;
    };

    const help = installed(['--format', 'json', 'help'], 0, 'HELP_FAILED').value;
    check(help.schema === 'ogvcs.cli-workspace/result/v1', 'HELP_SCHEMA_MISMATCH');
    check(help.contractVersion === CLI_VERSION, 'HELP_VERSION_MISMATCH');
    check(help.contractManifestSha256 === manifestSha256, 'HELP_MANIFEST_MISMATCH');
    check(help.code === 'HELP' && help.ok === true, 'HELP_RESULT_MISMATCH');

    const config = installed(['--format', 'json', 'config', 'show'], 0, 'CONFIG_FAILED').value;
    check(config.code === 'CONFIG_RESOLVED', 'CONFIG_RESULT_MISMATCH');
    check(config.data?.endpoint?.source === 'system-default', 'CONFIG_SOURCE_MISMATCH');
    check(config.data?.profile?.source === 'system-default', 'CONFIG_SOURCE_MISMATCH');

    const authentication = installed(
      ['--format', 'json', '--non-interactive', 'auth', 'check'],
      6,
      'AUTH_FAILURE_MISMATCH',
    ).value;
    check(authentication.code === 'AUTHENTICATION_REQUIRED', 'AUTH_FAILURE_MISMATCH');
    check(authentication.data?.prompted === false, 'AUTH_PROMPTED');

    const remoteRoot = join(stateRoot, 'remote-fail');
    fixture('empty-root', remoteRoot);
    const locator = 'repo:hermetic-private-locator';
    const secret = 'hermetic-must-never-appear';
    const remote = installed(
      [
        '--format',
        'json',
        '--non-interactive',
        'workspace',
        'create',
        '--root',
        remoteRoot,
        '--repository',
        locator,
        '--branch',
        'main',
        '--credential-env',
        'OGVCS_TOKEN_HERMETIC',
      ],
      7,
      'REMOTE_FAILURE_MISMATCH',
      { OGVCS_TOKEN_HERMETIC: secret },
    );
    check(remote.value.code === 'PUBLIC_ROUTE_UNAVAILABLE', 'REMOTE_FAILURE_MISMATCH');
    check(remote.value.data?.mutationStarted === false, 'REMOTE_MUTATION_STARTED');
    for (const forbidden of [remoteRoot, locator, secret]) {
      check(!remote.raw.stdout.includes(forbidden) && !remote.raw.stderr.includes(forbidden), 'REMOTE_DETAIL_LEAK');
    }
    await access(join(remoteRoot, '.ogvcs')).then(
      () => { throw new GateError('REMOTE_PARTIAL_WORKSPACE'); },
      (error) => check(error?.code === 'ENOENT', 'REMOTE_ROOT_INSPECTION_FAILED'),
    );

    const readyRoot = join(stateRoot, 'ready');
    fixture('ready', readyRoot);
    const opened = installed(
      ['--format', 'json', 'workspace', 'open', '--root', readyRoot],
      0,
      'WORKSPACE_OPEN_FAILED',
    );
    check(opened.value.code === 'WORKSPACE_OPEN', 'WORKSPACE_OPEN_MISMATCH');
    check(!opened.raw.stdout.includes(readyRoot), 'WORKSPACE_OPEN_PATH_LEAK');
    const rootsFile = join(stateRoot, 'roots.json');
    await writeFile(rootsFile, `${JSON.stringify([readyRoot])}\n`, { flag: 'wx', mode: 0o600 });
    const listed = installed(
      ['--format', 'json', 'workspace', 'list', '--roots-file', rootsFile],
      0,
      'WORKSPACE_LIST_FAILED',
    );
    check(listed.value.data?.workspaces?.length === 1, 'WORKSPACE_LIST_MISMATCH');
    check(!listed.raw.stdout.includes(readyRoot), 'WORKSPACE_LIST_PATH_LEAK');
    const removed = installed(
      [
        '--format',
        'json',
        '--non-interactive',
        'workspace',
        'remove',
        '--root',
        readyRoot,
        '--confirm',
        'remove-local-metadata',
      ],
      0,
      'WORKSPACE_REMOVE_FAILED',
    ).value;
    check(removed.code === 'WORKSPACE_REMOVED', 'WORKSPACE_REMOVE_MISMATCH');
    check(removed.data?.remoteDurableState === 'unchanged', 'WORKSPACE_REMOVE_REMOTE_STATE');

    const createCrashRoot = join(stateRoot, 'crash-create');
    fixture('crash-create-journal', createCrashRoot, HARD_EXIT_CODE);
    await access(join(createCrashRoot, '.ogvcs/pending-workspace-v2.json'));
    const recoveredCreate = installed(
      ['--format', 'json', 'workspace', 'recover', '--root', createCrashRoot],
      0,
      'CREATE_RECOVERY_FAILED',
    ).value;
    check(recoveredCreate.code === 'WORKSPACE_RECOVERED', 'CREATE_RECOVERY_MISMATCH');
    await assertAbsent(
      join(createCrashRoot, '.ogvcs/pending-workspace-v2.json'),
      'CREATE_RECOVERY_PENDING_RETAINED',
    );
    assert.deepEqual(
      openReady(createCrashRoot, 'CREATE_RECOVERY_OPEN_FAILED'),
      recoveredCreate.data,
      'create recovery and subsequent open disagree',
    );

    const configureCrashRoot = join(stateRoot, 'crash-configure');
    const mainBranchDigest = sha256(Buffer.from('main', 'utf8'));
    const devBranchDigest = sha256(Buffer.from('dev', 'utf8'));
    fixture('crash-configure-journal', configureCrashRoot, HARD_EXIT_CODE);
    await access(join(configureCrashRoot, '.ogvcs/pending-workspace-v2.json'));
    const recoveredConfigure = installed(
      ['--format', 'json', 'workspace', 'recover', '--root', configureCrashRoot],
      0,
      'CONFIGURE_RECOVERY_FAILED',
    ).value;
    check(recoveredConfigure.code === 'WORKSPACE_RECOVERED', 'CONFIGURE_RECOVERY_MISMATCH');
    check(
      recoveredConfigure.data?.branchDigest === devBranchDigest
        && recoveredConfigure.data.branchDigest !== mainBranchDigest,
      'CONFIGURE_RECOVERY_BRANCH_MISMATCH',
    );
    await assertAbsent(
      join(configureCrashRoot, '.ogvcs/pending-workspace-v2.json'),
      'CONFIGURE_RECOVERY_PENDING_RETAINED',
    );
    assert.deepEqual(
      openReady(configureCrashRoot, 'CONFIGURE_RECOVERY_OPEN_FAILED'),
      recoveredConfigure.data,
      'configure recovery and subsequent open disagree',
    );

    const stageCrashRoot = join(stateRoot, 'crash-stage-add');
    fixture('crash-stage-add-journal', stageCrashRoot, HARD_EXIT_CODE);
    const recoveredStage = installed(
      ['--format', 'json', 'workspace', 'recover', '--root', stageCrashRoot],
      0,
      'STAGE_RECOVERY_FAILED',
    ).value;
    check(recoveredStage.code === 'WORKSPACE_RECOVERED', 'STAGE_RECOVERY_MISMATCH');
    const staged = installed(
      ['--format', 'json', 'file', 'list', '--root', stageCrashRoot],
      0,
      'STAGE_LIST_FAILED',
    ).value;
    check(staged.data?.intents?.length === 1, 'STAGE_RECOVERY_INTENT_MISMATCH');
    check(staged.data.intents[0].remoteDurableState === 'unchanged', 'STAGE_REMOTE_STATE_MISMATCH');

    const removeJournalRoot = join(stateRoot, 'crash-remove-journal');
    fixture('crash-remove-journal', removeJournalRoot, HARD_EXIT_CODE);
    await access(join(removeJournalRoot, '.ogvcs-remove-v2.json'));
    await access(join(removeJournalRoot, '.ogvcs'));
    const recoveredRemoveJournal = installed(
      ['--format', 'json', 'workspace', 'recover', '--root', removeJournalRoot],
      0,
      'REMOVE_JOURNAL_RECOVERY_FAILED',
    ).value;
    check(recoveredRemoveJournal.code === 'WORKSPACE_RECOVERED', 'REMOVE_JOURNAL_RECOVERY_MISMATCH');
    await assertAbsent(
      join(removeJournalRoot, '.ogvcs-remove-v2.json'),
      'REMOVE_JOURNAL_RECORD_RETAINED',
    );
    await assertAbsent(
      join(removeJournalRoot, '.ogvcs-removed-v2'),
      'REMOVE_JOURNAL_TOMBSTONE_RETAINED',
    );
    assert.deepEqual(
      openReady(removeJournalRoot, 'REMOVE_JOURNAL_OPEN_FAILED'),
      recoveredRemoveJournal.data,
      'remove-journal recovery and subsequent open disagree',
    );

    const removeMutationRoot = join(stateRoot, 'crash-remove-mutation');
    fixture('crash-remove-mutation', removeMutationRoot, HARD_EXIT_CODE);
    await access(join(removeMutationRoot, '.ogvcs-remove-v2.json'));
    await access(join(removeMutationRoot, '.ogvcs-removed-v2'));
    const recoveredRemoveMutation = installed(
      ['--format', 'json', 'workspace', 'recover', '--root', removeMutationRoot],
      3,
      'REMOVE_MUTATION_RECOVERY_FAILED',
    ).value;
    check(recoveredRemoveMutation.code === 'WORKSPACE_REMOVED', 'REMOVE_MUTATION_RECOVERY_MISMATCH');
    check(recoveredRemoveMutation.data?.removed === true, 'REMOVE_MUTATION_RESULT_MISMATCH');
    check(
      recoveredRemoveMutation.data?.remoteDurableState === 'unchanged',
      'REMOVE_MUTATION_REMOTE_STATE_MISMATCH',
    );
    for (const marker of ['.ogvcs', '.ogvcs-remove-v2.json', '.ogvcs-removed-v2']) {
      await access(join(removeMutationRoot, marker)).then(
        () => { throw new GateError('REMOVE_MUTATION_LEFTOVER'); },
        (error) => check(error?.code === 'ENOENT', 'REMOVE_MUTATION_INSPECTION_FAILED'),
      );
    }

    if (process.platform === 'win32') {
      const ready = join(environmentPaths.temp, 'windows-signal-ready');
      const result = runRaw(fixtureBinary, ['signal-windows', ready], {
        cwd: controllerRoot,
        env: runtimeEnvironment,
      });
      assertCancellationResult(parseMachineResult(result, 0, 'WINDOWS_SIGNAL_FAILED'));
    } else {
      await runUnixSignal(
        fixtureBinary,
        'SIGINT',
        join(environmentPaths.temp, 'sigint-ready'),
        controllerRoot,
        runtimeEnvironment,
      );
      await runUnixSignal(
        fixtureBinary,
        'SIGTERM',
        join(environmentPaths.temp, 'sigterm-ready'),
        controllerRoot,
        runtimeEnvironment,
      );
    }

    const finalInstallFiles = await listFiles(runtimeRoot);
    assert.deepEqual(finalInstallFiles, expectedRuntimeFiles, 'installed binary and contract remain exact');
    assert.deepEqual(
      await listFiles(controllerRoot),
      [`hermetic-fixture${executableSuffix}`],
      'controller contains only the test-only fixture',
    );
    check(
      sha256(await readFile(installedBinary)) === installedBinarySha256,
      'INSTALLED_BINARY_MUTATED',
    );
    check(
      sha256(await readFile(fixtureBinary)) === fixtureBinarySha256,
      'CONTROLLER_BINARY_MUTATED',
    );
    const retainedManifestBytes = await readFile(join(contractRoot, 'manifest.json'));
    check(
      retainedManifestBytes.equals(manifestBytes)
        && sha256(retainedManifestBytes) === manifestSha256,
      'CONTRACT_MANIFEST_MUTATED',
    );
    for (const record of manifest.artifacts) {
      const bytes = await readFile(join(contractRoot, record.path));
      check(
        bytes.length === record.bytes && sha256(bytes) === record.sha256,
        'CONTRACT_ARTIFACT_MUTATED',
      );
    }
    process.stdout.write(`${JSON.stringify({
      gate: 'native-cli-hermetic',
      status: 'passed',
      ogvcsSha256: installedBinarySha256,
      controllerSha256: fixtureBinarySha256,
      contractManifestSha256: manifestSha256,
      runtimeFileCount: expectedRuntimeFiles.length,
    })}\n`);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

main().catch((error) => {
  const code = error instanceof GateError ? error.code : 'UNEXPECTED_FAILURE';
  process.stderr.write(`native-cli-hermetic: ${code}\n`);
  process.exitCode = 1;
});
