#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import readline from 'node:readline';

const HELP = `Object-mapping black-box consumer

Generates a tiny fixture for every installed profile and maps each public
inventory record to a content-addressed object reference. The example imports
no fixture-generator implementation module.

Usage:
  node examples/object-mapping.mjs --workspace <relative/path> [--cli <executable>] [--seed <text>]

Options:
  --workspace <path>  New relative directory prefix for generated fixtures
  --cli <path|name>   Installed executable (default: OGVCS_FIXTURE_BIN or ogvcs-fixture)
  --seed <text>       Stable seed prefix (default: object-mapping-example-v1)
  --help              Show this help

Source-checkout smoke run:
  node examples/object-mapping.mjs --cli ./bin/ogvcs-fixture.mjs \
    --workspace example-output/object-mapping
`;

function canonicalJson(value) {
  function ordered(input) {
    if (Array.isArray(input)) return input.map(ordered);
    if (input !== null && typeof input === 'object') {
      return Object.fromEntries(
        Object.keys(input).sort().map((key) => [key, ordered(input[key])]),
      );
    }
    return input;
  }
  return JSON.stringify(ordered(value));
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function portableRelative(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.includes('\\')
    || value.includes('\0')
    || path.posix.isAbsolute(value)
    || /^[A-Za-z]:/.test(value)
  ) {
    throw new Error(`${label} must be a portable relative path`);
  }
  const segments = value.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new Error(`${label} must not contain empty, dot, or traversal segments`);
  }
  return value;
}

function artifactPath(root, relative, label) {
  portableRelative(relative, label);
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, ...relative.split('/'));
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new Error(`${label} escapes its fixture directory`);
  }
  return resolved;
}

const EXPECTED_ROLES = Object.freeze({
  'code-heavy': ['configuration', 'documentation', 'header', 'script', 'source'],
  'global-studio': ['asset', 'configuration', 'package', 'review-input', 'source'],
  'large-binary': ['binary-version', 'mutable-large-file'],
  'unity-like': ['binary-import', 'meta', 'negative-evidence', 'prefab', 'scene'],
  'unreal-like': ['configuration', 'external-actor', 'header', 'map', 'package', 'sidecar', 'source'],
});

function requiredFields(value, names, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  for (const name of names ?? []) {
    if (!Object.hasOwn(value, name)) throw new Error(`${label} lacks schema-required field ${name}`);
  }
}

function sha256(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} is not a lowercase SHA-256 digest`);
  }
}

function validateContent(record, inventorySchema) {
  const definitions = Object.values(inventorySchema.$defs ?? {});
  const definition = definitions.find(
    (candidate) => candidate?.properties?.representation?.const === record.content?.representation,
  );
  if (!definition) {
    throw new Error(`inventory record ${record.index} uses an unknown public representation`);
  }
  requiredFields(record.content, definition.required, `inventory record ${record.index} content`);
  sha256(record.content.digest, `inventory record ${record.index} content digest`);
  if (!Number.isSafeInteger(record.content.logicalBytes) || record.content.logicalBytes < 0) {
    throw new Error(`inventory record ${record.index} has invalid logical byte accounting`);
  }

  if (record.content.representation !== 'semantic-v2') return 1;
  const versions = record.content.versions;
  if (!Array.isArray(versions) || versions.length === 0) {
    throw new Error(`semantic inventory record ${record.index} has no versions`);
  }
  for (let index = 0; index < versions.length; index += 1) {
    const version = versions[index];
    requiredFields(
      version,
      inventorySchema.$defs.semanticVersion.required,
      `inventory record ${record.index} version ${index}`,
    );
    sha256(version.digest, `inventory record ${record.index} version ${index} digest`);
    if (
      version.version !== index
      || version.baseVersion !== (index === 0 ? null : index - 1)
      || (index === 0 && version.delta !== 'create')
      || (index > 0 && version.delta === 'create')
    ) {
      throw new Error(`inventory record ${record.index} has an incoherent version chain`);
    }
  }
  const current = versions.at(-1);
  if (
    record.content.version !== current.version
    || record.content.digest !== current.digest
    || record.content.logicalBytes !== current.logicalBytes
  ) {
    throw new Error(`inventory record ${record.index} does not bind its current semantic version`);
  }
  return versions.length;
}

function validateProfileSemantics(profileId, records, roles, groups) {
  for (const role of EXPECTED_ROLES[profileId] ?? []) {
    if (!roles.has(role)) throw new Error(`${profileId} fixture lacks expected ${role} content`);
  }
  if (profileId === 'code-heavy' && !records.some(({ mode }) => mode === '100755')) {
    throw new Error('code-heavy fixture does not preserve an executable mode');
  }
  if (profileId !== 'unity-like') return { negativeCases: 0 };

  const missing = records.filter(({ negativeCase }) => negativeCase === 'missing-sidecar');
  const duplicate = records.filter(({ negativeCase }) => negativeCase === 'duplicate-guid');
  if (
    missing.length < 2
    || !missing.some(({ group }) => group === undefined)
    || !groups.some(({ negativeCase }) => negativeCase === 'missing-sidecar')
  ) {
    throw new Error('Unity-like fixture does not expose a real missing-sidecar relationship');
  }
  const groupsByGuid = new Map();
  for (const record of duplicate) {
    if (!record.group) continue;
    const ids = groupsByGuid.get(record.syntheticGuid) ?? new Set();
    ids.add(record.group.id);
    groupsByGuid.set(record.syntheticGuid, ids);
  }
  if (![...groupsByGuid.values()].some((ids) => ids.size > 1)) {
    throw new Error('Unity-like fixture does not expose a duplicate GUID across distinct groups');
  }
  return { negativeCases: missing.length + duplicate.length };
}

function commandSpec(cli) {
  const looksLikeScript = /\.(?:cjs|mjs|js)$/i.test(cli);
  return looksLikeScript
    ? { executable: process.execPath, prefix: [path.resolve(cli)] }
    : { executable: cli, prefix: [] };
}

async function invoke(cli, args) {
  const spec = commandSpec(cli);
  return new Promise((resolve, reject) => {
    const child = spawn(spec.executable, [...spec.prefix, ...args], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`ogvcs-fixture ${args[0]} exited ${code}: ${stderr.trim()}`));
        return;
      }
      try {
        const document = JSON.parse(stdout);
        if (document.ok !== true || document.command !== args[0]) {
          throw new Error(`unexpected CLI result for ${args[0]}`);
        }
        resolve(document.result);
      } catch (error) {
        reject(new Error(`invalid machine output from ogvcs-fixture ${args[0]}: ${error.message}`));
      }
    });
  });
}

async function mapInventory(fixtureRoot, manifest, schemas, profileId) {
  const inventory = artifactPath(fixtureRoot, manifest.inventory.path, 'manifest.inventory.path');
  const groupsPath = artifactPath(
    fixtureRoot,
    manifest.extensions['artifacts.groups'],
    'manifest.extensions.artifacts.groups',
  );
  const groups = JSON.parse(await readFile(groupsPath, 'utf8'));
  if (!Array.isArray(groups) || canonicalJson(groups) !== canonicalJson(manifest.groups)) {
    throw new Error('public group artifact does not match the manifest relationship contract');
  }
  for (const group of groups) {
    requiredFields(group, schemas.groups.$defs.group.required, `group ${group?.id ?? '<unknown>'}`);
  }

  const objects = new Set();
  const roles = new Map();
  const recordsByPath = new Map();
  let records = 0;
  let logicalBytes = 0;
  let semanticVersions = 0;
  const input = createReadStream(inventory, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (line.length === 0) continue;
    const record = JSON.parse(line);
    requiredFields(record, schemas.inventory.required, `inventory record ${records}`);
    portableRelative(record.logicalPath, `inventory record ${records} logicalPath`);
    if (record.index !== records || recordsByPath.has(record.logicalPath)) {
      throw new Error(`inventory record ${records} has a duplicate path or non-canonical index`);
    }
    semanticVersions += validateContent(record, schemas.inventory);
    objects.add(record.content.digest);
    roles.set(record.role, (roles.get(record.role) ?? 0) + 1);
    recordsByPath.set(record.logicalPath, record);
    logicalBytes += record.content.logicalBytes;
    records += 1;
  }

  const groupsById = new Map(groups.map((group) => [group.id, group]));
  if (groupsById.size !== groups.length || groups.length !== manifest.counts.groups) {
    throw new Error('group identifiers/counts are not unique and manifest-bound');
  }
  for (const record of recordsByPath.values()) {
    if (!record.group) continue;
    const group = groupsById.get(record.group.id);
    if (!group || group.kind !== record.group.kind || !group.members.includes(record.logicalPath)) {
      throw new Error(`inventory group reference is dangling for ${record.logicalPath}`);
    }
  }
  for (const group of groups) {
    for (const member of group.members) {
      const record = recordsByPath.get(member);
      if (!record || record.group?.id !== group.id || record.group?.kind !== group.kind) {
        throw new Error(`group ${group.id} contains an incoherent member ${member}`);
      }
    }
  }
  const semantics = validateProfileSemantics(
    profileId,
    [...recordsByPath.values()],
    roles,
    groups,
  );
  return {
    groupCount: groups.length,
    logicalBytes,
    negativeCases: semantics.negativeCases,
    objectCount: objects.size,
    pathCount: records,
    roles: Object.fromEntries([...roles].sort(([left], [right]) => compareText(left, right))),
    semanticVersions,
  };
}

async function main() {
  const { values } = parseArgs({
    options: {
      cli: { type: 'string' },
      help: { short: 'h', type: 'boolean' },
      seed: { type: 'string' },
      workspace: { type: 'string' },
    },
    strict: true,
  });
  if (values.help) {
    process.stdout.write(HELP);
    return;
  }
  if (!values.workspace) throw new Error('--workspace is required; it must name a new relative path');
  const workspace = portableRelative(values.workspace, '--workspace');
  const cli = values.cli ?? process.env.OGVCS_FIXTURE_BIN ?? 'ogvcs-fixture';
  const seed = values.seed ?? 'object-mapping-example-v1';

  const [manifestSchema, inventorySchema, groupSchema] = await Promise.all([
    'FixtureManifest',
    'InventoryRecord',
    'GroupRelationships',
  ].map(async (name) => JSON.parse(await readFile(
    fileURLToPath(new URL(`../schemas/${name}.schema.json`, import.meta.url)),
    'utf8',
  ))));
  const requiredManifestFields = new Set(manifestSchema.required ?? []);
  for (const field of ['counts', 'digests', 'inventory', 'profile', 'requestDigest']) {
    if (!requiredManifestFields.has(field)) throw new Error(`public manifest schema does not require ${field}`);
  }

  const listed = await invoke(cli, ['list']);
  const profiles = [...listed.profiles].sort((left, right) => compareText(left.id, right.id));
  const summaries = [];
  for (const profile of profiles) {
    const destination = `${workspace}/${profile.id}`;
    const requestFlags = [
      '--profile', profile.id,
      '--profile-version', profile.version,
      '--seed', `${seed}-${profile.id}`,
      '--destination', destination,
      '--path-count', '32',
      '--history-operations', '20',
      '--large-file-bytes', '8192',
      '--max-depth', '5',
      '--checkpoint-every', '4',
      '--materialization', 'index-only',
      '--materialized-path-limit', '0',
      '--large-file-mode', 'virtual',
    ];
    if (profile.id === 'unity-like') requestFlags.push('--negative-cases');
    const plan = await invoke(cli, ['plan', ...requestFlags]);
    const generated = await invoke(cli, ['generate', ...requestFlags]);
    const inspected = await invoke(cli, ['inspect', destination]);
    const verification = await invoke(cli, ['verify', destination, '--deep']);
    const fixtureRoot = path.resolve(process.cwd(), ...destination.split('/'));
    const manifest = JSON.parse(await readFile(path.join(fixtureRoot, 'manifest.json'), 'utf8'));
    const schemaVersionProperties = manifestSchema.properties.schemaVersions.properties;
    for (const [key, expected] of [
      ['inventoryRecord', schemaVersionProperties.inventoryRecord.const],
      ['groupRelationships', schemaVersionProperties.groupRelationships.const],
    ]) {
      if (manifest.schemaVersions[key] !== expected) {
        throw new Error(`manifest does not bind public ${key} schema ${expected}`);
      }
    }
    const mapping = await mapInventory(
      fixtureRoot,
      manifest,
      { groups: groupSchema, inventory: inventorySchema },
      profile.id,
    );
    if (
      generated.manifestDigest !== manifest.manifestDigest
      || inspected.manifestDigest !== manifest.manifestDigest
      || verification.manifestDigest !== manifest.manifestDigest
      || mapping.pathCount !== manifest.counts.paths
      || mapping.groupCount !== manifest.counts.groups
      || mapping.logicalBytes !== manifest.logicalBytes
    ) {
      throw new Error(`public artifacts disagree for profile ${profile.id}`);
    }
    summaries.push({
      contentDigest: manifest.digests.content,
      groupCount: mapping.groupCount,
      logicalBytes: manifest.logicalBytes,
      manifestDigest: manifest.manifestDigest,
      objectCount: mapping.objectCount,
      negativeCases: mapping.negativeCases,
      pathCount: mapping.pathCount,
      pathDigest: manifest.digests.paths,
      plannedPhysicalBytes: plan.estimates.physicalBytes,
      profile: `${profile.id}@${profile.version}`,
      representation: inspected.representation,
      requestDigest: manifest.requestDigest,
      roles: mapping.roles,
      semanticVersions: mapping.semanticVersions,
      treeDigest: manifest.digests.tree,
      verified: verification.verified,
    });
  }

  process.stdout.write(`${canonicalJson({
    consumer: 'ogvcs-object-mapping-example/v1',
    profiles: summaries,
    schema: manifestSchema.$id,
    artifactSchemas: [groupSchema.$id, inventorySchema.$id].sort(),
  })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${canonicalJson({ error: error.message, ok: false })}\n`);
  process.exitCode = 1;
});
