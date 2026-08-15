import { constants as fsConstants } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';

import { canonicalStringify } from './canonical.mjs';
import { CLI_RESULT_SCHEMA, MAX_REQUEST_DOCUMENT_BYTES } from './constants.mjs';
import { EXIT_CODES, asFixtureError, publicError, usageError } from './errors.mjs';
import { generateFixture } from './generator.mjs';
import { inspectFixture } from './inspect.mjs';
import { planFixture } from './plan.mjs';
import { listProfiles } from './profiles.mjs';
import { createRequest, referenceScaleRequest } from './request.mjs';
import { verifyFixture } from './verify.mjs';

const HELP = `ogvcs-fixture — deterministic synthetic game-repository fixtures

Usage:
  ogvcs-fixture list
  ogvcs-fixture plan [request options]
  ogvcs-fixture generate [request options] [--resume] [--progress]
  ogvcs-fixture inspect <destination>
  ogvcs-fixture verify <destination> [--deep]

Request options:
  --request <file>                  Read a canonical FixtureRequest JSON document
  --preset <small|reference-scale> Use a documented scale preset
  --profile <name>                 code-heavy, unreal-like, unity-like,
                                   large-binary, or global-studio
  --profile-version <version>      Profile contract version (currently 2.0.0)
  --seed <text>                    Deterministic NFC seed
  --destination <relative/path>    Portable relative output path
  --path-count <integer>           Number of logical file paths
  --history-operations <integer>   Number of ordered history/scenario operations
  --large-file-bytes <decimal>     Logical bytes in the mutable large file
  --max-depth <integer>            Maximum generated logical path depth
  --checkpoint-every <integer>     Path records between durable checkpoints
  --materialization <mode>         full, sampled, or index-only
  --materialized-path-limit <n>    Physical-file cap for sampled mode
  --large-file-mode <mode>         full, sparse, stream-verified, or virtual
  --negative-cases                 Include Unity-like negative cases
  --no-negative-cases              Exclude Unity-like negative cases

Output is one canonical JSON document on stdout. Progress, when requested, is
canonical NDJSON on stderr. No command performs network access.

Examples:
  ogvcs-fixture list
  ogvcs-fixture plan --profile unity-like --destination fixtures/unity-small
  ogvcs-fixture generate --profile code-heavy --seed ci-42 --destination fixtures/code
  ogvcs-fixture generate --preset reference-scale --destination fixtures/scale --resume
  ogvcs-fixture inspect fixtures/code
  ogvcs-fixture verify fixtures/code --deep

Exit codes: 0 success, 2 usage, 3 invalid request, 4 unsafe destination,
5 concurrent/incompatible generation, 6 integrity failure, 7 resource limit,
8 interrupted before success acknowledgement, 70 internal failure.
`;

const REQUEST_OPTIONS = {
  'checkpoint-every': { type: 'string' },
  destination: { type: 'string' },
  'history-operations': { type: 'string' },
  'large-file-bytes': { type: 'string' },
  'large-file-mode': { type: 'string' },
  'materialization': { type: 'string' },
  'materialized-path-limit': { type: 'string' },
  'max-depth': { type: 'string' },
  'negative-cases': { type: 'boolean' },
  'no-negative-cases': { type: 'boolean' },
  'path-count': { type: 'string' },
  preset: { type: 'string' },
  profile: { type: 'string' },
  'profile-version': { type: 'string' },
  request: { type: 'string' },
  seed: { type: 'string' },
};

function integerOption(value, name) {
  if (value === undefined) return undefined;
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw usageError(`--${name} must be a canonical non-negative integer`);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw usageError(`--${name} exceeds the safe integer range`);
  return number;
}

async function readRequestFile(filePath, cwd, options = {}) {
  const resolvedPath = path.resolve(cwd, filePath);
  let handle;
  let body;
  try {
    handle = await open(resolvedPath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const metadata = await handle.stat({ bigint: true });
    if (!metadata.isFile()) throw new Error('request path is not a regular file');
    if (metadata.size > BigInt(MAX_REQUEST_DOCUMENT_BYTES)) {
      throw new Error(`request file exceeds ${MAX_REQUEST_DOCUMENT_BYTES} bytes`);
    }
    await options.afterStat?.(resolvedPath);
    const size = Number(metadata.size);
    const bytes = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const result = await handle.read(bytes, offset, size - offset, offset);
      if (result.bytesRead === 0) throw new Error('request file changed while being read');
      offset += result.bytesRead;
    }
    const extra = Buffer.alloc(1);
    if ((await handle.read(extra, 0, 1, size)).bytesRead !== 0) {
      throw new Error('request file grew while being read');
    }
    const after = await handle.stat({ bigint: true });
    if (
      after.dev !== metadata.dev
      || after.ino !== metadata.ino
      || after.size !== metadata.size
      || after.mtimeNs !== metadata.mtimeNs
      || after.ctimeNs !== metadata.ctimeNs
    ) {
      throw new Error('request file changed while being read');
    }
    body = bytes.toString('utf8');
  } catch (error) {
    throw usageError(`Cannot read request file: ${error.message}`, { path: filePath });
  } finally {
    await handle?.close().catch(() => {});
  }
  try {
    return JSON.parse(body);
  } catch (error) {
    throw usageError(`Request file is not valid JSON: ${error.message}`, { path: filePath });
  }
}

function mutableCopy(value) {
  return JSON.parse(JSON.stringify(value));
}

async function requestFromOptions(values, cwd) {
  if (values.preset !== undefined && !['small', 'reference-scale'].includes(values.preset)) {
    throw usageError('--preset must be small or reference-scale');
  }
  let input = {};
  if (values.preset === 'reference-scale') input = mutableCopy(referenceScaleRequest());
  if (values.preset === 'small') {
    const profileId = values.profile ?? 'code-heavy';
    input = {
      extensions: {
        'generation.checkpoint-every': 16,
        'generation.large-file-mode': 'full',
        'generation.materialization': 'full',
        'generation.materialized-path-limit': 64,
      },
      profile: { id: profileId, version: values['profile-version'] ?? '2.0.0' },
      scale: {
        historyOperationCount: 32,
        largeFileBytes: profileId === 'code-heavy' ? 0 : 1024 * 1024,
        maxDepth: 8,
        pathCount: 64,
      },
      seed: `opengamevcs-${profileId}-small-v1`,
    };
  }
  if (values.request !== undefined) {
    if (values.preset !== undefined) throw usageError('--request and --preset cannot be combined');
    input = await readRequestFile(values.request, cwd);
  }
  input = mutableCopy(input);

  if (values.profile !== undefined || values['profile-version'] !== undefined) {
    input.profile = {
      id: values.profile ?? input.profile?.id ?? 'code-heavy',
      version: values['profile-version'] ?? input.profile?.version ?? '2.0.0',
    };
  }
  if (values.seed !== undefined) input.seed = values.seed;
  if (values.destination !== undefined) input.destination = values.destination;

  const scaleOverrides = {
    historyOperationCount: integerOption(values['history-operations'], 'history-operations'),
    largeFileBytes: integerOption(values['large-file-bytes'], 'large-file-bytes'),
    maxDepth: integerOption(values['max-depth'], 'max-depth'),
    pathCount: integerOption(values['path-count'], 'path-count'),
  };
  for (const [key, value] of Object.entries(scaleOverrides)) {
    if (value !== undefined) input.scale = { ...(input.scale ?? {}), [key]: value };
  }

  if (values['negative-cases'] && values['no-negative-cases']) {
    throw usageError('--negative-cases and --no-negative-cases cannot be combined');
  }
  const negativeCases = values['negative-cases']
    ? true
    : values['no-negative-cases']
      ? false
      : undefined;
  if (negativeCases !== undefined) {
    input.featureFlags = { ...(input.featureFlags ?? {}), 'negative-cases': negativeCases };
  }
  const extensionOverrides = {
    'generation.checkpoint-every': integerOption(values['checkpoint-every'], 'checkpoint-every'),
    'generation.large-file-mode': values['large-file-mode'],
    'generation.materialization': values.materialization,
    'generation.materialized-path-limit': integerOption(
      values['materialized-path-limit'],
      'materialized-path-limit',
    ),
  };
  for (const [key, value] of Object.entries(extensionOverrides)) {
    if (value !== undefined) input.extensions = { ...(input.extensions ?? {}), [key]: value };
  }

  return createRequest(input);
}

function parse(command, args, options = {}) {
  try {
    return parseArgs({
      args,
      allowPositionals: options.allowPositionals ?? false,
      options: options.options ?? {},
      strict: true,
    });
  } catch (error) {
    throw usageError(error.message);
  }
}

function successful(command, result) {
  return {
    command,
    ok: true,
    result,
    schemaVersion: CLI_RESULT_SCHEMA,
  };
}

function writeJson(stream, value) {
  stream.write(`${canonicalStringify(value)}\n`);
}

function exactlyOneDestination(positionals, command) {
  if (positionals.length !== 1) throw usageError(`${command} requires exactly one destination`);
  return positionals[0];
}

export async function runCli(args, io) {
  const [command, ...rest] = args;
  if (!command || command === '--help' || command === '-h' || command === 'help') {
    io.stdout.write(HELP);
    return EXIT_CODES.OK;
  }

  try {
    let result;
    if (command === 'list') {
      const parsed = parse(command, rest, { options: { help: { short: 'h', type: 'boolean' } } });
      if (parsed.values.help) {
        io.stdout.write(HELP);
        return EXIT_CODES.OK;
      }
      result = successful('list', { profiles: listProfiles() });
    } else if (command === 'plan') {
      const parsed = parse(command, rest, {
        options: { ...REQUEST_OPTIONS, help: { short: 'h', type: 'boolean' } },
      });
      if (parsed.values.help) {
        io.stdout.write(HELP);
        return EXIT_CODES.OK;
      }
      const request = await requestFromOptions(parsed.values, io.cwd);
      result = successful('plan', planFixture(request));
    } else if (command === 'generate') {
      const parsed = parse(command, rest, {
        options: {
          ...REQUEST_OPTIONS,
          help: { short: 'h', type: 'boolean' },
          progress: { type: 'boolean' },
          resume: { type: 'boolean' },
        },
      });
      if (parsed.values.help) {
        io.stdout.write(HELP);
        return EXIT_CODES.OK;
      }
      const request = await requestFromOptions(parsed.values, io.cwd);
      const onProgress = parsed.values.progress
        ? (event) => writeJson(io.stderr, event)
        : undefined;
      result = successful('generate', await generateFixture(request, {
        cwd: io.cwd,
        env: io.env,
        onProgress,
        resume: parsed.values.resume ?? false,
      }));
    } else if (command === 'inspect') {
      const parsed = parse(command, rest, {
        allowPositionals: true,
        options: { help: { short: 'h', type: 'boolean' } },
      });
      if (parsed.values.help) {
        io.stdout.write(HELP);
        return EXIT_CODES.OK;
      }
      result = successful('inspect', await inspectFixture(
        exactlyOneDestination(parsed.positionals, command),
        { cwd: io.cwd },
      ));
    } else if (command === 'verify') {
      const parsed = parse(command, rest, {
        allowPositionals: true,
        options: {
          deep: { type: 'boolean' },
          help: { short: 'h', type: 'boolean' },
        },
      });
      if (parsed.values.help) {
        io.stdout.write(HELP);
        return EXIT_CODES.OK;
      }
      const verification = await verifyFixture(
        exactlyOneDestination(parsed.positionals, command),
        { cwd: io.cwd, deep: parsed.values.deep ?? false },
      );
      if (!verification.verified) {
        const error = asFixtureError(new Error('Fixture verification failed'));
        error.type = 'integrity-failure';
        error.exitCode = EXIT_CODES.INTEGRITY;
        error.details = { verification };
        throw error;
      }
      result = successful('verify', verification);
    } else {
      throw usageError(`Unknown command ${JSON.stringify(command)}; run ogvcs-fixture --help`);
    }

    writeJson(io.stdout, result);
    return EXIT_CODES.OK;
  } catch (error) {
    const known = asFixtureError(error);
    writeJson(io.stderr, publicError(known));
    return known.exitCode;
  }
}

export { HELP, readRequestFile, requestFromOptions };
