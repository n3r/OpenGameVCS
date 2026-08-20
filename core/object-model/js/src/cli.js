import { constants, createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { resolve } from 'node:path';

import { verifyLogicalBundleFile } from './bundle-spool.js';
import { decodeMetadata, scanMetadata, validateKnownSchema } from './schema.js';
import { createObjectHashWriter, verifyObjectId } from './hash.js';
import { fail, isOgvcsError } from './errors.js';
import { hardLimitMaximum } from './hard-limits.js';
import {
  bundledRegistryDirectory,
  loadBundledRegistry,
  profileDecision,
  registrySetDigest
} from './registry.js';
import { ObjectRef, toHex } from './types.js';
import { createDiskFileIdIndex, verifyTreeFile } from './tree-stream.js';

const MAX_METADATA_BYTES = hardLimitMaximum('metadata-payload-bytes');
const MAX_CHUNK_BYTES = hardLimitMaximum('chunk-payload-bytes');
const MAX_BUNDLE_BYTES = hardLimitMaximum('bundle-sequence-bytes');
const MAX_BUNDLE_SCRATCH_BYTES = 4_398_046_511_104;
const DEFAULT_OBJECT_MEMORY_BYTES = 67_108_864;
const MAX_OBJECT_MEMORY_BYTES = 268_435_456;

export const CLI_EXIT = Object.freeze({
  success: 0,
  usage: 2,
  invalid: 3,
  resource: 4,
  unsupported: 5,
  internal: 70
});

export const CLI_HELP = `ogvcs-object — OpenGameVCS format-v1 inspector and verifier

Usage:
  ogvcs-object inspect <object-file> [--max-bytes <integer>] [--max-memory-bytes <integer>]
  ogvcs-object id <object-file> --kind <code|token> [--max-bytes <integer>] [--max-memory-bytes <integer>]
  ogvcs-object verify object <object-file> --ref <ObjectRef> --operation <read|conformance|production-write> [--max-bytes <integer>] [--max-memory-bytes <integer>]
  ogvcs-object tree verify <tree-file> --descriptor <ObjectRef> --scratch <directory> --operation <read|conformance|production-write>
  ogvcs-object bundle verify <bundle-file> --scratch <directory> --operation <read|conformance|production-write> [--max-bytes <integer>]
  ogvcs-object registry list
  ogvcs-object registry profiles
  ogvcs-object registry profile <ProfileRef> [--operation <read|conformance|production-write>]

All successful output and all failures are one JSON document on stdout. Object
inspection reports structural summaries only; it never prints payload bytes,
paths, messages, identities embedded in payloads, or extension values.

Exit codes: 0 success, 2 usage, 3 invalid input, 4 resource limit,
5 unsupported capability/profile, 70 internal failure.
`;

function usage(message) {
  const error = new Error(message);
  error.name = 'CliUsageError';
  throw error;
}

function parsePositiveInteger(text, name, maximum) {
  if (typeof text !== 'string' || !/^[1-9][0-9]*$/.test(text)) usage(`${name} must be a positive decimal integer`);
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > maximum) usage(`${name} exceeds ${maximum}`);
  return value;
}

function options(args, allowed) {
  const positional = [];
  const flags = new Map();
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (!argument.startsWith('--')) {
      positional.push(argument);
      continue;
    }
    const name = argument.slice(2);
    if (!allowed.has(name) || flags.has(name)) usage(`unknown or repeated option: --${name}`);
    const value = args[++index];
    if (value === undefined || value.startsWith('--')) usage(`missing value for --${name}`);
    flags.set(name, value);
  }
  return { positional, flags };
}

function requiredLifecycleOperation(flags) {
  const operation = flags.get('operation');
  if (!['read', 'conformance', 'production-write'].includes(operation)) {
    usage('--operation must be read, conformance, or production-write');
  }
  return operation;
}

async function openRegularReadOnly(filePath) {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  let handle;
  try {
    handle = await open(filePath, constants.O_RDONLY | noFollow);
    const stat = await handle.stat();
    if (!stat.isFile()) usage('input must be a regular file');
    return { handle, stat };
  } catch (error) {
    await handle?.close().catch(() => {});
    throw error;
  }
}

async function readBoundedFile(filePath, maximum) {
  const { handle, stat } = await openRegularReadOnly(filePath);
  try {
    if (stat.size > maximum) {
      const error = new Error('configured input byte limit exceeded');
      error.name = 'CliResourceError';
      error.code = 'LIMIT_MEMORY';
      error.layer = 1;
      error.stage = 'configured-resource-preflight';
      throw error;
    }
    const bytes = new Uint8Array(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (result.bytesRead === 0) usage('input changed or truncated while being read');
      offset += result.bytesRead;
    }
    const after = await handle.stat();
    if (after.size !== stat.size) usage('input changed while being read');
    return bytes;
  } finally {
    await handle.close();
  }
}

function objectLimits(flags, formatMaximum, streaming = false) {
  const maxMemoryBytes = flags.has('max-memory-bytes')
    ? parsePositiveInteger(flags.get('max-memory-bytes'), '--max-memory-bytes', MAX_OBJECT_MEMORY_BYTES)
    : DEFAULT_OBJECT_MEMORY_BYTES;
  const requestedBytes = flags.has('max-bytes')
    ? parsePositiveInteger(flags.get('max-bytes'), '--max-bytes', formatMaximum)
    : formatMaximum;
  // The retained input and scan payload copy coexist. Decoded CBOR working
  // state receives the remaining budget below.
  const maxBytes = streaming ? requestedBytes : Math.min(requestedBytes, Math.floor(maxMemoryBytes / 2));
  if (maxBytes < 1) {
    const error = new Error('configured object memory limit is too small');
    error.name = 'CliResourceError';
    error.code = 'LIMIT_MEMORY';
    error.layer = 1;
    error.stage = 'configured-resource-preflight';
    throw error;
  }
  return { maxBytes, maxMemoryBytes };
}

function metadataOptions(payloadBytes, limits, registry) {
  const maxWorkingBytes = limits.maxMemoryBytes - (payloadBytes * 2);
  if (maxWorkingBytes < 1) {
    const error = new Error('configured object memory limit exceeded');
    error.name = 'CliResourceError';
    error.code = 'LIMIT_MEMORY';
    error.layer = 1;
    error.stage = 'configured-resource-preflight';
    throw error;
  }
  return { maxBytes: limits.maxBytes, maxWorkingBytes, registry };
}

async function hashFile(filePath, kind, registry, configuredMaximum) {
  const { handle, stat } = await openRegularReadOnly(filePath);
  const maximum = Math.min(configuredMaximum, kind === 1 ? MAX_CHUNK_BYTES : MAX_METADATA_BYTES);
  try {
    if (stat.size > maximum) {
      const error = new Error('configured input byte limit exceeded');
      error.name = 'CliResourceError';
      error.code = 'LIMIT_MEMORY';
      error.layer = 1;
      error.stage = 'configured-resource-preflight';
      throw error;
    }
    const writer = createObjectHashWriter(kind, { registry: registry.kindNames });
    let bytes = 0;
    const stream = createReadStream(filePath, { autoClose: false, fd: handle.fd });
    for await (const part of stream) {
      bytes += part.length;
      if (bytes > stat.size) usage('input changed while being read');
      writer.update(part);
    }
    const after = await handle.stat();
    if (bytes !== stat.size || after.size !== stat.size) usage('input changed or truncated while being read');
    return { bytes, reference: writer.finish() };
  } finally {
    await handle.close();
  }
}

function kindFromText(text, registry) {
  if (/^[1-9][0-9]*$/.test(text)) {
    const code = Number(text);
    if (registry.objectKinds.has(code)) return code;
  }
  for (const [code, token] of registry.kindNames) if (token === text) return code;
  usage(`unknown object kind: ${text}`);
}

function registryCounts(registry) {
  return {
    commonFields: registry.commonFields.size,
    entryKinds: registry.entryKinds.size,
    entryModes: registry.entryModes.size,
    extensions: registry.extensions.size,
    hashAlgorithms: registry.hashAlgorithms.size,
    kindFields: registry.kindFields.size,
    limits: registry.limits.size,
    logicalRecordTypes: registry.logicalRecordTypes.size,
    objectKinds: registry.objectKinds.size,
    profiles: registry.profiles.size,
    requiredFeatures: registry.requiredFeatures.size,
    semanticEnumDomains: registry.semanticEnums.size
  };
}

async function inspectObject(filePath, registry, limits) {
  const bytes = await readBoundedFile(filePath, limits.maxBytes);
  const scan = scanMetadata(bytes, metadataOptions(bytes.length, limits));
  let knownSchema = false;
  if (registry.objectKinds.has(scan.kind)) {
    // Inspection is deliberately structural: callers must be able to inspect
    // and forward objects whose required features are unknown locally.
    validateKnownSchema(scan.value, scan.kind, { semantic: false });
    knownSchema = true;
  }
  return {
    bytes: bytes.length,
    highestLayer: knownSchema ? 2 : scan.highestLayer,
    identityDigest: toHex(scan.identityDigest.bytes),
    kind: scan.kind,
    kindToken: registry.kindNames.get(scan.kind) ?? null,
    knownSchema,
    objectRef: scan.objectId?.toString() ?? null,
    requiredFeatureCount: scan.requiredFeatures.length
  };
}

async function runCommand(argv, cwd) {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') return { help: CLI_HELP };
  const registry = await loadBundledRegistry();
  const command = argv[0];

  if (command === 'inspect') {
    const parsed = options(argv.slice(1), new Set(['max-bytes', 'max-memory-bytes']));
    if (parsed.positional.length !== 1) usage('inspect requires exactly one object file');
    const limits = objectLimits(parsed.flags, MAX_METADATA_BYTES);
    return { command: 'inspect', result: await inspectObject(resolve(cwd, parsed.positional[0]), registry, limits) };
  }

  if (command === 'id') {
    const parsed = options(argv.slice(1), new Set(['kind', 'max-bytes', 'max-memory-bytes']));
    if (parsed.positional.length !== 1 || !parsed.flags.has('kind')) usage('id requires one file and --kind');
    const kind = kindFromText(parsed.flags.get('kind'), registry);
    const filePath = resolve(cwd, parsed.positional[0]);
    const limits = objectLimits(parsed.flags, kind === 1 ? MAX_CHUNK_BYTES : MAX_METADATA_BYTES, kind === 1);
    if (kind === 1) {
      const hashed = await hashFile(filePath, kind, registry, limits.maxBytes);
      return { command: 'id', result: { bytes: hashed.bytes, kind, objectRef: hashed.reference.toString() } };
    } else {
      const payload = await readBoundedFile(filePath, limits.maxBytes);
      const decoded = decodeMetadata(payload, { ...metadataOptions(payload.length, limits), semantic: false });
      if (decoded.kind !== kind) usage('--kind does not match metadata discriminator');
      const writer = createObjectHashWriter(kind, { registry: registry.kindNames });
      writer.update(payload);
      const reference = writer.finish();
      return { command: 'id', result: { bytes: payload.length, kind, objectRef: reference.toString() } };
    }
  }

  if (command === 'verify') {
    if (argv[1] !== 'object') usage('verify currently requires the object subcommand');
    const parsed = options(argv.slice(2), new Set(['ref', 'operation', 'max-bytes', 'max-memory-bytes']));
    if (parsed.positional.length !== 1 || !parsed.flags.has('ref')) usage('verify object requires one file and --ref');
    const operation = requiredLifecycleOperation(parsed.flags);
    const reference = ObjectRef.parse(parsed.flags.get('ref'), registry.kindNames);
    const limits = objectLimits(parsed.flags, reference.kind === 1 ? MAX_CHUNK_BYTES : MAX_METADATA_BYTES,
      reference.kind === 1);
    const filePath = resolve(cwd, parsed.positional[0]);
    let bytes; let decoded;
    if (reference.kind === 1) {
      const hashed = await hashFile(filePath, reference.kind, registry, limits.maxBytes);
      if (hashed.reference.toString() !== reference.toString()) fail('OBJECT_ID_MISMATCH', { layer: 1 });
      bytes = hashed.bytes;
    } else {
      const payload = await readBoundedFile(filePath, limits.maxBytes);
      verifyObjectId(reference, payload);
      decoded = decodeMetadata(payload, { ...metadataOptions(payload.length, limits, registry), operation });
      bytes = payload.length;
    }
    return { command: 'verify object', result: {
      bytes,
      highestLayer: decoded?.highestLayer ?? 1,
      kind: reference.kind,
      objectRef: reference.toString(),
      status: 'valid'
    } };
  }

  if (command === 'tree') {
    if (argv[1] !== 'verify') usage('tree currently requires the verify subcommand');
    const parsed = options(argv.slice(2), new Set(['descriptor', 'scratch', 'operation', 'max-bytes', 'max-memory-bytes', 'max-scratch-bytes']));
    if (parsed.positional.length !== 1 || !parsed.flags.has('descriptor') || !parsed.flags.has('scratch')) {
      usage('tree verify requires one file, --descriptor, and --scratch');
    }
    const operation = requiredLifecycleOperation(parsed.flags);
    const descriptor = ObjectRef.parse(parsed.flags.get('descriptor'), registry.kindNames);
    if (descriptor.kind !== 6) usage('--descriptor must be a repository-descriptor ObjectRef');
    const maximum = parsed.flags.has('max-bytes')
      ? parsePositiveInteger(parsed.flags.get('max-bytes'), '--max-bytes', MAX_METADATA_BYTES)
      : MAX_METADATA_BYTES;
    const maxMemoryBytes = parsed.flags.has('max-memory-bytes')
      ? parsePositiveInteger(parsed.flags.get('max-memory-bytes'), '--max-memory-bytes', 1_073_741_824)
      : 67_108_864;
    const maxScratchBytes = parsed.flags.has('max-scratch-bytes')
      ? parsePositiveInteger(parsed.flags.get('max-scratch-bytes'), '--max-scratch-bytes', 1_073_741_824)
      : 268_435_456;
    const index = await createDiskFileIdIndex({
      scratchDirectory: resolve(cwd, parsed.flags.get('scratch')),
      maxMemoryBytes: Math.min(maxMemoryBytes, 16_777_216),
      maxRunBytes: Math.min(maxMemoryBytes, 8_388_608),
      maxOpenRuns: 32,
      maxScratchBytes
    });
    try {
      const verified = await verifyTreeFile(resolve(cwd, parsed.positional[0]), {
        descriptor,
        registry,
        operation,
        fileIdIndex: index,
        maxBytes: maximum,
        maxMemoryBytes
      });
      return { command: 'tree verify', result: {
        ...verified.summary,
        highestLayer: verified.highestLayer,
        peakScratchBytes: verified.metrics.peakScratchBytes,
        processMaxRssBytes: process.resourceUsage().maxRSS * 1024,
        status: 'valid'
      } };
    } catch (error) {
      await index.abort().catch(() => {});
      throw error;
    }
  }

  if (command === 'bundle') {
    if (argv[1] !== 'verify') usage('bundle currently requires the verify subcommand');
    const parsed = options(argv.slice(2), new Set([
      'scratch', 'max-bytes', 'max-memory-bytes', 'max-scratch-bytes', 'max-time-ms'
      , 'operation'
    ]));
    if (parsed.positional.length !== 1 || !parsed.flags.has('scratch')) {
      usage('bundle verify requires exactly one bundle file and --scratch');
    }
    const operation = requiredLifecycleOperation(parsed.flags);
    const maximum = parsed.flags.has('max-bytes')
      ? parsePositiveInteger(parsed.flags.get('max-bytes'), '--max-bytes', MAX_BUNDLE_BYTES)
      : MAX_BUNDLE_BYTES;
    const maxMemoryBytes = parsed.flags.has('max-memory-bytes')
      ? parsePositiveInteger(parsed.flags.get('max-memory-bytes'), '--max-memory-bytes', 1_073_741_824)
      : 67_108_864;
    const maxScratchBytes = parsed.flags.has('max-scratch-bytes')
      ? parsePositiveInteger(parsed.flags.get('max-scratch-bytes'), '--max-scratch-bytes', MAX_BUNDLE_SCRATCH_BYTES)
      : 8_589_934_592;
    const maxTimeMs = parsed.flags.has('max-time-ms')
      ? parsePositiveInteger(parsed.flags.get('max-time-ms'), '--max-time-ms', Number.MAX_SAFE_INTEGER)
      : undefined;
    const verified = await verifyLogicalBundleFile(resolve(cwd, parsed.positional[0]), {
      registry,
      operation,
      scratchDirectory: resolve(cwd, parsed.flags.get('scratch')),
      sequenceBytes: maximum,
      maxMemoryBytes,
      maxScratchBytes,
      maxTimeMs
    });
    return { command: 'bundle verify', result: {
      ...verified,
      format: 'logical-bundle-v1',
      claim: 'supplied-closure',
      metrics: {
        ...verified.metrics,
        processMaxRssBytes: process.resourceUsage().maxRSS * 1024
      },
      status: 'valid'
    } };
  }

  if (command === 'registry') {
    const subcommand = argv[1];
    if (subcommand === 'list' && argv.length === 2) return { command: 'registry list', result: {
      counts: registryCounts(registry),
      registrySetDigest: await registrySetDigest(bundledRegistryDirectory())
    } };
    if (subcommand === 'profiles' && argv.length === 2) return { command: 'registry profiles', result: {
      profiles: [...registry.profiles.values()].map(entry => ({
        family: entry.family,
        profile: `${entry.namespace}/${entry.id}@${entry.major}`,
        productionWriteAllowed: entry.productionWriteAllowed,
        state: entry.state
      }))
    } };
    if (subcommand === 'profile') {
      const parsed = options(argv.slice(2), new Set(['operation']));
      if (parsed.positional.length !== 1) usage('registry profile requires one ProfileRef');
      const operation = parsed.flags.get('operation') ?? 'read';
      if (!['read', 'conformance', 'production-write'].includes(operation)) usage('invalid --operation');
      const entry = profileDecision(registry, parsed.positional[0], operation);
      return { command: 'registry profile', result: {
        family: entry.family,
        profile: `${entry.namespace}/${entry.id}@${entry.major}`,
        productionWriteAllowed: entry.productionWriteAllowed,
        state: entry.state
      } };
    }
    usage('unknown registry subcommand');
  }

  usage(`unknown command: ${command}`);
}

function exitFor(error) {
  if (error?.name === 'CliUsageError') return CLI_EXIT.usage;
  if (error?.name === 'CliResourceError' || error?.errorClass === 'resource') return CLI_EXIT.resource;
  if (['unsupported', 'capability'].includes(error?.errorClass)) return CLI_EXIT.unsupported;
  if (isOgvcsError(error)) return CLI_EXIT.invalid;
  return CLI_EXIT.internal;
}

function json(value) {
  return `${JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? item.toString() : item)}\n`;
}

export async function runCli(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const cwd = io.cwd ?? process.cwd();
  const started = performance.now();
  try {
    const output = await runCommand(argv, cwd);
    if (output.help) {
      stdout.write(output.help);
      return CLI_EXIT.success;
    }
    stdout.write(json({ ...output, durationMilliseconds: Math.round((performance.now() - started) * 1000) / 1000, ok: true }));
    return CLI_EXIT.success;
  } catch (error) {
    const exitCode = exitFor(error);
    stdout.write(json({
      durationMilliseconds: Math.round((performance.now() - started) * 1000) / 1000,
      error: {
        class: error?.errorClass ?? (exitCode === CLI_EXIT.usage ? 'usage' : exitCode === CLI_EXIT.resource ? 'resource' : 'internal'),
        code: error?.code ?? (exitCode === CLI_EXIT.usage ? 'CLI_USAGE' : exitCode === CLI_EXIT.resource ? 'LIMIT_INPUT_BYTES' : 'INTERNAL'),
        ...(error?.layer === undefined ? {} : { layer: error.layer }),
        ...(error?.stage === undefined ? {} : { stage: error.stage }),
        ...(error?.offset === undefined ? {} : { offset: error.offset })
      },
      ok: false
    }));
    return exitCode;
  }
}
