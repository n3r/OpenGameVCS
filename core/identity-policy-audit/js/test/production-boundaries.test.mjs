import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const contractRoot = resolve(here, '../../../../spec/identity-policy-audit/v1');

const executions = Object.freeze({
  'oidc-pkce-code-success': Object.freeze({
    expected: 'session-issued', file: 'oidc-bootstrap.test.mjs',
    name: 'authorization code flow uses PKCE S256 and one-use state before issuing an identity',
  }),
  'oidc-state-replay-denied': Object.freeze({
    expected: 'AUTHENTICATION_DENIED', file: 'oidc-bootstrap.test.mjs',
    name: 'authorization code flow uses PKCE S256 and one-use state before issuing an identity',
  }),
  'oidc-id-token-signature-invalid': Object.freeze({
    expected: 'AUTHENTICATION_DENIED', file: 'oidc-bootstrap.test.mjs',
    name: 'signed ID-token validation rejects signature, audience, nonce, and clock substitution',
  }),
  'oidc-outage-no-local-fallback': Object.freeze({
    expected: 'AUTHENTICATION_DENIED', file: 'oidc-bootstrap.test.mjs',
    name: 'OIDC outage fails closed and never invokes a local bootstrap path',
  }),
  'device-flow-slow-down': Object.freeze({
    expected: 'pending', file: 'oidc-bootstrap.test.mjs',
    name: 'device flow retains pending and slow-down state without consuming the transaction',
  }),
  'bootstrap-disable-requires-recovery': Object.freeze({
    expected: 'STATE_CONFLICT', file: 'oidc-bootstrap.test.mjs',
    name: 'bootstrap recovery rotates one-use material and local login disables only after independent recovery',
  }),
  'policy-preview-cas-audit': Object.freeze({
    expected: 'committed', file: 'policy-authority.test.mjs',
    name: 'policy mutation previews the exact generation and commits policy plus policy.changed atomically',
  }),
  'policy-change-lost-race': Object.freeze({
    expected: 'STATE_CONFLICT', file: 'policy-authority.test.mjs',
    name: 'policy mutation loses a generation race without appending an audit record',
  }),
  'transaction-credential-caller-epoch-ignored': Object.freeze({
    expected: 'DENY_EPOCH_STALE', file: 'transaction-authorization.test.mjs',
    name: 'transaction view rejects resource, transaction, policy-generation, and revocation substitution',
  }),
  'transaction-view-resource-substitution': Object.freeze({
    expected: 'DENY_NOT_AUTHORIZED', file: 'transaction-authorization.test.mjs',
    name: 'transaction view rejects resource, transaction, policy-generation, and revocation substitution',
  }),
  'transaction-decision-commitment-same-tx': Object.freeze({
    expected: 'committed', file: 'transaction-authorization.test.mjs',
    name: 'decision commitment is exact, same-transaction, resource-bound, and single append',
  }),
  'trusted-checkpoint-request-substitution': Object.freeze({
    expected: 'AUDIT_INTEGRITY', file: 'security-core.test.mjs',
    name: 'authorized audit reads reject a request-selected checkpoint even when it is well formed',
  }),
  'revocation-receipt-bounded': Object.freeze({
    expected: 'revoked', file: 'security-authority.test.mjs',
    name: 'credential revocation is bounded, audited, idempotent, and non-enumerating',
  }),
  'rotating-invalid-token-source-rate': Object.freeze({
    expected: 'DENY_RATE_LIMITED', file: 'security-core.test.mjs',
    name: 'rotating invalid credentials cannot evade the trusted source rate bucket',
  }),
});

const regexEscape = (value) => value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');

test('all production-boundary vectors dispatch through executable public regressions', async () => {
  const document = JSON.parse(await readFile(resolve(contractRoot, 'vectors/production-boundaries.json'), 'utf8'));
  assert.equal(document.schemaVersion, 'ogvcs.identity-policy/vectors/v1');
  assert.deepEqual(Object.keys(executions).sort(), document.cases.map(({ id }) => id).sort());
  for (const vector of document.cases) assert.equal(executions[vector.id].expected, vector.expected, vector.id);

  const targets = new Map();
  for (const execution of Object.values(executions)) targets.set(`${execution.file}\u0000${execution.name}`, execution);
  const childEnvironment = { ...process.env };
  delete childEnvironment.NODE_TEST_CONTEXT;
  for (const execution of targets.values()) {
    const result = spawnSync(process.execPath, [
      '--test', `--test-name-pattern=^${regexEscape(execution.name)}$`, resolve(here, execution.file),
    ], { encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 * 1024, env: childEnvironment });
    assert.equal(result.error, undefined, `${execution.file}: ${result.error?.message ?? ''}`);
    assert.equal(result.signal, null, `${execution.file} terminated by ${result.signal}`);
    assert.equal(result.status, 0, `${execution.file}:\n${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, new RegExp(`(?:✔|ok \\d+ -) ${regexEscape(execution.name)}`, 'u'));
  }
});
