#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SHA = /^[0-9a-f]{40}$/u;
const SCALE_TAG = /^ogvcs-007-scale-([0-9a-f]{40})$/u;

function fail(message) {
  throw new Error(`chunking exact-scale dispatch rejected: ${message}`);
}

export function validateChunkingScaleDispatch({
  actualSourceRevision,
  confirmed,
  eventName,
  expectedSourceRevision,
  refName,
  refType,
}) {
  if (typeof actualSourceRevision !== 'string' || !SHA.test(actualSourceRevision)) {
    fail('the checked-out source revision is invalid');
  }

  let expected;
  if (eventName === 'workflow_dispatch') {
    if (confirmed !== 'true') fail('manual execution was not explicitly confirmed');
    if (typeof expectedSourceRevision !== 'string' || !SHA.test(expectedSourceRevision)) {
      fail('manual execution requires one exact lowercase source revision');
    }
    expected = expectedSourceRevision;
  } else if (eventName === 'push') {
    if (refType !== 'tag') fail('push execution requires a tag ref');
    const matched = typeof refName === 'string' ? SCALE_TAG.exec(refName) : null;
    if (matched === null) fail('tag execution requires ogvcs-007-scale-<40 lowercase hex>');
    [, expected] = matched;
  } else {
    fail('the event type is not authorized for exact scale');
  }

  if (actualSourceRevision !== expected) fail('the checked-out source differs from the reviewed revision');
  return actualSourceRevision;
}

function checkedOutRevision() {
  let revision;
  try {
    revision = execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
      encoding: 'utf8',
      maxBuffer: 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    fail('the checked-out Git revision is unavailable');
  }
  return revision;
}

function main() {
  const revision = validateChunkingScaleDispatch({
    actualSourceRevision: checkedOutRevision(),
    confirmed: process.env.OGVCS_CONFIRM_EXACT_SCALE,
    eventName: process.env.GITHUB_EVENT_NAME,
    expectedSourceRevision: process.env.OGVCS_EXPECTED_SOURCE_REVISION,
    refName: process.env.GITHUB_REF_NAME,
    refType: process.env.GITHUB_REF_TYPE,
  });
  process.stdout.write(`${revision}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'chunking exact-scale dispatch rejected'}\n`);
    process.exitCode = 1;
  }
}
