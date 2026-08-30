import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const SOURCE_ROOT = path.resolve(import.meta.dirname, '../../../..');

function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]));
  return value;
}

function writeCanonical(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(ordered(value))}\n`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ogvcs-authz-spec-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.copyFileSync(path.join(SOURCE_ROOT, 'LICENSE'), path.join(root, 'LICENSE'));
  fs.mkdirSync(path.join(root, 'prd'), { recursive: true });
  fs.copyFileSync(path.join(SOURCE_ROOT, 'prd/ROADMAP.md'), path.join(root, 'prd/ROADMAP.md'));
  fs.mkdirSync(path.join(root, 'spec/authorization'), { recursive: true });
  fs.cpSync(path.join(SOURCE_ROOT, 'spec/authorization/v1'), path.join(root, 'spec/authorization/v1'), { recursive: true });
  return root;
}

function readJson(root, relative) {
  return JSON.parse(fs.readFileSync(path.join(root, relative), 'utf8'));
}

function rewrite(root, relative, mutate) {
  const file = path.join(root, relative);
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  mutate(value);
  writeCanonical(file, value);
}

function refreshIntegrity(root) {
  const spec = path.join(root, 'spec/authorization/v1');
  const manifestFile = path.join(spec, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const registryFiles = fs.readdirSync(path.join(spec, 'registries')).filter((name) => name.endsWith('.json')).sort();
  const registryInput = Buffer.concat(registryFiles.flatMap((name) => [
    Buffer.from(name), Buffer.from([0]), fs.readFileSync(path.join(spec, 'registries', name)),
  ]));
  manifest.registrySetSha256 = sha256(registryInput);
  const vectorManifestFile = path.join(spec, 'vectors/manifest.json');
  const vectorManifest = JSON.parse(fs.readFileSync(vectorManifestFile, 'utf8'));
  vectorManifest.registrySetSha256 = manifest.registrySetSha256;
  for (const entry of vectorManifest.vectors) entry.sha256 = sha256(fs.readFileSync(path.join(spec, entry.path)));
  writeCanonical(vectorManifestFile, vectorManifest);
  for (const artifact of manifest.artifacts) artifact.sha256 = sha256(fs.readFileSync(path.join(spec, artifact.path)));
  writeCanonical(manifestFile, manifest);
}

function validate(root) {
  const validator = path.join(root, 'spec/authorization/v1/validate-spec.mjs');
  try {
    return { status: 0, output: execFileSync(process.execPath, [validator], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) };
  } catch (error) {
    return { status: error.status, output: `${error.stdout ?? ''}${error.stderr ?? ''}` };
  }
}

test('checked-in authorization contract validates in an isolated repository', (t) => {
  const result = validate(fixture(t));
  assert.equal(result.status, 0, result.output);
  const report = JSON.parse(result.output);
  assert.deepEqual({
    result: report.result,
    schemas: report.schemas,
    registries: report.registries,
    decisionVectors: report.decisionVectors,
    abuseVectors: report.abuseVectors,
    grantVectors: report.grantVectors,
    roadmapPrds: report.roadmapPrds,
  }, { result: 'valid', schemas: 10, registries: 13, decisionVectors: 40, abuseVectors: 30, grantVectors: 16, roadmapPrds: 46 });
});

const mutations = [
  {
    name: 'self-consistent unresolved high threat',
    expected: /registry document drift: threats/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/registries/threats.json', (value) => { value.entries.find(({ severity }) => severity === 'high').status = 'accepted'; });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent permission reassignment',
    expected: /registry assignment drift: permissions/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/registries/permissions.json', (value) => { value.entries[0].name = 'enumerate'; });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent decision-code reassignment',
    expected: /registry assignment drift: decision-codes/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/registries/decision-codes.json', (value) => { value.entries[0].code = 1001; });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent roadmap omission',
    expected: /registry assignment drift: roadmap-surfaces/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/registries/roadmap-surfaces.json', (value) => { value.entries.pop(); });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent roadmap audit omission',
    expected: /registry document drift: roadmap-surfaces/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/registries/roadmap-surfaces.json', (value) => { delete value.entries[0].auditBehavior; });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent registry semantic drift',
    expected: /registry document drift: resources/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/registries/resources.json', (value) => { value.entries[0].description = 'Changed security meaning.'; });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent grant expectation drift',
    expected: /grant vector mismatch/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/vectors/grants.json', (value) => { value.cases.find(({ id }) => id === 'wrong-audience').expected.code = 'DENY_RESOURCE_SCOPE'; });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent claims-schema detachment',
    expected: /transfer-grant envelope does not bind the claims schema/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/schemas/TransferGrantEnvelope.schema.json', (value) => { value.properties.claims = { type: 'object' }; });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent decision polarity detachment',
    expected: /decision allowed\/code schema binding is invalid/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/schemas/AuthorizationDecision.schema.json', (value) => { value.allOf[0].oneOf[0].properties.code.enum.push('DENY_NOT_AUTHORIZED'); });
      refreshIntegrity(root);
    },
  },
  {
    name: 'self-consistent audit permission detachment',
    expected: /audit class\/permission schema binding is invalid/,
    apply(root) {
      rewrite(root, 'spec/authorization/v1/schemas/AuditEvent.schema.json', (value) => { value.allOf[0].oneOf[0].properties.permission.const = 'audit.read'; });
      refreshIntegrity(root);
    },
  },
  {
    name: 'noncanonical generated JSON',
    expected: /not canonical JSON/,
    apply(root) {
      const file = path.join(root, 'spec/authorization/v1/registries/resources.json');
      fs.writeFileSync(file, `${JSON.stringify(readJson(root, 'spec/authorization/v1/registries/resources.json'), null, 2)}\n`);
    },
  },
  {
    name: 'missing privacy review',
    expected: /required document missing: docs\/privacy-review\.md/,
    apply(root) { fs.unlinkSync(path.join(root, 'spec/authorization/v1/docs/privacy-review.md')); },
  },
  {
    name: 'license drift',
    expected: /MIT license text differs/,
    apply(root) { fs.appendFileSync(path.join(root, 'spec/authorization/v1/LICENSE'), '\nchanged\n'); },
  },
];

for (const mutation of mutations) {
  test(`independent validator rejects ${mutation.name}`, (t) => {
    const root = fixture(t);
    mutation.apply(root);
    const result = validate(root);
    assert.equal(result.status, 1, result.output);
    assert.match(result.output, mutation.expected);
  });
}
