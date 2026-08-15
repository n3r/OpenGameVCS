import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  copyFile,
  mkdir,
  open,
  readFile,
  symlink,
  truncate,
  unlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { canonicalDigest, canonicalStringify } from '../src/canonical.mjs';
import { createRequest, generateFixture, verifyFixture } from '../src/index.mjs';
import { validateSchemaDocument } from '../src/schema-validator.mjs';
import { temporaryDirectory } from './test-helpers.mjs';

function request(destination, overrides = {}) {
  return createRequest({
    destination,
    extensions: {
      'generation.large-file-mode': overrides.largeFileMode ?? 'virtual',
      'generation.materialization': overrides.materialization ?? 'index-only',
    },
    profile: { id: overrides.profile ?? 'code-heavy', version: '2.0.0' },
    scale: {
      historyOperationCount: overrides.historyOperationCount ?? 8,
      largeFileBytes: overrides.largeFileBytes ?? 0,
      maxDepth: 6,
      pathCount: overrides.pathCount ?? 12,
    },
    seed: overrides.seed ?? `verification-security-${destination}`,
  });
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

async function writeCanonical(filePath, value) {
  await writeFile(filePath, `${canonicalStringify(value)}\n`, 'utf8');
}

async function rewriteManifest(filePath, mutate) {
  const manifest = await readJson(filePath);
  mutate(manifest);
  const { manifestDigest: ignored, ...body } = manifest;
  await writeCanonical(filePath, {
    ...body,
    manifestDigest: canonicalDigest(body, 'ogvcs.fixture/manifest/v1'),
  });
}

function failedCheck(result, code) {
  const check = result.checks.find((candidate) => candidate.code === code);
  assert.ok(check, `missing ${code} check`);
  assert.equal(check.status, 'fail');
  return check;
}

test('sparse fixtures generate and deep-verify against the portable allocation contract', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-sparse-');
  await generateFixture(request('fixture', {
    largeFileBytes: 2 * 1024 * 1024,
    largeFileMode: 'sparse',
    pathCount: 1,
  }), { cwd });
  const result = await verifyFixture('fixture', { cwd, deep: true });
  assert.equal(result.verified, true);
});

test('deep verification rejects a coherently relocated sparse extent after digest rebinding', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-sparse-relocation-');
  await generateFixture(request('fixture', {
    largeFileBytes: 4 * 1024 * 1024,
    largeFileMode: 'sparse',
    pathCount: 1,
    profile: 'large-binary',
  }), { cwd });
  const fixture = path.join(cwd, 'fixture');
  const descriptorPath = path.join(fixture, 'large-file.json');
  const descriptor = await readJson(descriptorPath);
  const [first, second] = descriptor.physical.extents;
  const relocatedOffset = Math.floor((second.offset - first.length) / 2);
  assert.ok(relocatedOffset > first.offset);
  const largePath = path.join(fixture, 'files', ...descriptor.logicalPath.split('/'));
  const handle = await open(largePath, 'r+');
  try {
    const bytes = Buffer.alloc(first.length);
    const read = await handle.read(bytes, 0, bytes.length, first.offset);
    assert.equal(read.bytesRead, bytes.length);
    await handle.write(bytes, 0, bytes.length, relocatedOffset);
    await handle.sync();
  } finally {
    await handle.close();
  }
  first.offset = relocatedOffset;
  const { descriptorDigest: ignoredDescriptorDigest, ...descriptorBody } = descriptor;
  void ignoredDescriptorDigest;
  descriptor.descriptorDigest = canonicalDigest(
    descriptorBody,
    'ogvcs.fixture/large-file-descriptor/v2',
  );
  await writeCanonical(descriptorPath, descriptor);
  await rewriteManifest(path.join(fixture, 'manifest.json'), (manifest) => {
    manifest.extensions['large-file.descriptor-digest'] = descriptor.descriptorDigest;
  });

  const result = await verifyFixture('fixture', { cwd, deep: true });
  assert.equal(result.verified, false);
  assert.match(
    failedCheck(result, 'LARGE_FILE_REPRESENTATION').message,
    /canonical request-derived layout/iu,
  );
});

test('deep verification is normative for cross-record group-ID uniqueness', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-group-semantics-');
  await generateFixture(request('fixture', { pathCount: 12, profile: 'unity-like' }), { cwd });
  const groupsPath = path.join(cwd, 'fixture', 'groups.json');
  const groups = await readJson(groupsPath);
  assert.ok(groups.length >= 2);
  groups[1].id = groups[0].id;
  assert.deepEqual(
    validateSchemaDocument('GroupRelationships', groups),
    [],
    'JSON Schema intentionally validates structure; cross-record identities are semantic',
  );
  await writeCanonical(groupsPath, groups);

  const result = await verifyFixture('fixture', { cwd, deep: true });
  assert.equal(result.verified, false);
  assert.equal(failedCheck(result, 'GROUP_RELATIONSHIPS').status, 'fail');
});

test('normative JSON artifacts are budgeted and size-bounded before parsing', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-bounded-json-');
  await generateFixture(request('fixture'), { cwd });
  await assert.rejects(
    verifyFixture('fixture', {
      cwd,
      env: { OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE: 'verification-groups-preparse' },
    }),
    (error) => error?.type === 'resource-limit'
      && error?.details?.phase === 'verification-groups-preparse',
  );

  await truncate(path.join(cwd, 'fixture', 'groups.json'), 128 * 1024 * 1024 + 1);
  const result = await verifyFixture('fixture', { cwd });
  assert.equal(result.verified, false);
  assert.match(failedCheck(result, 'GROUP_RELATIONSHIPS').message, /safe byte bound/iu);
});

test('manifest schema rejects an unsafe artifact path as typed integrity before path use', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-manifest-path-');
  await generateFixture(request('fixture'), { cwd });
  const manifestPath = path.join(cwd, 'fixture', 'manifest.json');
  await rewriteManifest(manifestPath, (manifest) => {
    manifest.inventory.path = '../inventory.ndjson';
  });

  await assert.rejects(
    verifyFixture('fixture', { cwd }),
    (error) => error?.type === 'integrity-failure' && error?.exitCode === 6,
  );
});

test('manifest-controlled artifacts cannot be redirected through symlinks', async (t) => {
  if (process.platform === 'win32') {
    t.skip('requires unprivileged POSIX symlink creation');
    return;
  }
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-symlink-');
  await generateFixture(request('fixture'), { cwd });
  const fixture = path.join(cwd, 'fixture');
  const groupsPath = path.join(fixture, 'groups.json');
  const outside = path.join(cwd, 'groups-copy.json');
  await copyFile(groupsPath, outside);
  await unlink(groupsPath);
  await symlink('../groups-copy.json', groupsPath);

  const result = await verifyFixture('fixture', { cwd });
  assert.equal(result.verified, false);
  assert.match(failedCheck(result, 'GROUP_RELATIONSHIPS').message, /symlink|junction/iu);
  assert.equal(failedCheck(result, 'WORKSPACE_SAFETY').status, 'fail');
});

test('deep verification enforces executable mode bits on POSIX', async (t) => {
  if (process.platform === 'win32') {
    t.skip('POSIX mode bits are not portable to Windows');
    return;
  }
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-mode-');
  await generateFixture(request('fixture', {
    materialization: 'full',
    pathCount: 64,
  }), { cwd });
  const fixture = path.join(cwd, 'fixture');
  const records = (await readFile(path.join(fixture, 'inventory.ndjson'), 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line));
  const executable = records.find(({ mode }) => mode === '100755');
  assert.ok(executable, 'code-heavy fixture must contain an executable record');
  await chmod(path.join(fixture, 'files', ...executable.logicalPath.split('/')), 0o644);

  const result = await verifyFixture('fixture', { cwd, deep: true });
  assert.equal(result.verified, false);
  assert.match(failedCheck(result, 'INVENTORY_STREAM').message, /mode/iu);
});

test('deep verification enforces physical large-file mode bits on POSIX', async (t) => {
  if (process.platform === 'win32') {
    t.skip('POSIX mode bits are not portable to Windows');
    return;
  }
  for (const largeFileMode of ['full', 'sparse']) {
    const destination = `fixture-${largeFileMode}`;
    const cwd = await temporaryDirectory(t, `ogvcs-verification-large-mode-${largeFileMode}-`);
    await generateFixture(request(destination, {
      largeFileBytes: 256 * 1024,
      largeFileMode,
      pathCount: 1,
      profile: 'large-binary',
    }), { cwd });
    const fixture = path.join(cwd, destination);
    const descriptor = await readJson(path.join(fixture, 'large-file.json'));
    await chmod(path.join(fixture, 'files', ...descriptor.logicalPath.split('/')), 0o600);

    const result = await verifyFixture(destination, { cwd, deep: true });
    assert.equal(result.verified, false);
    assert.match(failedCheck(result, 'LARGE_FILE_REPRESENTATION').message, /mode/iu);
  }
});

test('verification rejects unexpected empty directories below the materialized tree', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-empty-directory-');
  await generateFixture(request('fixture', {
    materialization: 'full',
    pathCount: 8,
  }), { cwd });
  await mkdir(path.join(cwd, 'fixture', 'files', 'unexpected', 'empty'), { recursive: true });

  const result = await verifyFixture('fixture', { cwd, deep: true });
  assert.equal(result.verified, false);
  assert.match(failedCheck(result, 'WORKSPACE_SAFETY').message, /directory prefixes/iu);
});

test('large descriptor binding and streamed byte accounting survive digest recomputation attacks', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-descriptor-');
  await generateFixture(request('binding', {
    largeFileBytes: 65_536,
    largeFileMode: 'stream-verified',
    profile: 'large-binary',
  }), { cwd });
  const bindingFixture = path.join(cwd, 'binding');
  const bindingDescriptorPath = path.join(bindingFixture, 'large-file.json');
  const bindingDescriptor = await readJson(bindingDescriptorPath);
  bindingDescriptor.physical.versionDigests[0].digest = '0'.repeat(64);
  const { descriptorDigest: ignoredBindingDigest, ...bindingBody } = bindingDescriptor;
  bindingDescriptor.descriptorDigest = canonicalDigest(bindingBody, 'ogvcs.fixture/large-file-descriptor/v2');
  await writeCanonical(bindingDescriptorPath, bindingDescriptor);

  const bindingResult = await verifyFixture('binding', { cwd, deep: true });
  assert.equal(bindingResult.verified, false);
  assert.match(failedCheck(bindingResult, 'LARGE_FILE_REPRESENTATION').message, /manifest binding/iu);

  await generateFixture(request('accounting', {
    largeFileBytes: 65_536,
    largeFileMode: 'stream-verified',
    profile: 'large-binary',
    seed: 'verification-security-accounting',
  }), { cwd });
  const accountingFixture = path.join(cwd, 'accounting');
  const descriptorPath = path.join(accountingFixture, 'large-file.json');
  const descriptor = await readJson(descriptorPath);
  descriptor.physical.streamedLogicalBytes += 1;
  const { descriptorDigest: ignoredDescriptorDigest, ...descriptorBody } = descriptor;
  descriptor.descriptorDigest = canonicalDigest(descriptorBody, 'ogvcs.fixture/large-file-descriptor/v2');
  await writeCanonical(descriptorPath, descriptor);
  await rewriteManifest(path.join(accountingFixture, 'manifest.json'), (manifest) => {
    manifest.extensions['large-file.descriptor-digest'] = descriptor.descriptorDigest;
  });

  const accountingResult = await verifyFixture('accounting', { cwd, deep: true });
  assert.equal(accountingResult.verified, false);
  assert.match(failedCheck(accountingResult, 'LARGE_FILE_REPRESENTATION').message, /byte accounting/iu);
});

test('scenario verification streams and rejects a substituted operation above 100k records', {
  // Windows filesystem and process scanning can make this streaming integration
  // test several times slower than macOS/Linux without changing its work bound.
  timeout: 300_000,
}, async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-verification-scenario-');
  await generateFixture(request('fixture', {
    historyOperationCount: 100_001,
    pathCount: 1,
  }), { cwd });
  const fixture = path.join(cwd, 'fixture');
  const scenarioPath = path.join(fixture, 'scenario.json');
  const scenario = await readFile(scenarioPath, 'utf8');
  const actorMatch = scenario.match(/"actor":"actor-([0-7])"/u);
  assert.ok(actorMatch, 'scenario must contain an operation actor');
  const replacementActor = `"actor":"actor-${(Number(actorMatch[1]) + 1) % 8}"`;
  const mutated = scenario.replace(actorMatch[0], replacementActor);
  assert.equal(Buffer.byteLength(mutated), Buffer.byteLength(scenario));
  await writeFile(scenarioPath, mutated, 'utf8');
  const scenarioDigest = createHash('sha256').update(mutated).digest('hex');
  await rewriteManifest(path.join(fixture, 'manifest.json'), (manifest) => {
    manifest.operationScenario.digest = scenarioDigest;
  });

  const result = await verifyFixture('fixture', { cwd });
  assert.equal(result.verified, false);
  assert.match(failedCheck(result, 'SCENARIO_ARTIFACT').message, /canonical operation scenario/iu);
});
