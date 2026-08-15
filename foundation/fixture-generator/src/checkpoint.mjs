import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import path from 'node:path';

import { canonicalDigest } from './canonical.mjs';
import { CHECKPOINT_SCHEMA, GENERATOR_VERSION, TOOL_NAME } from './constants.mjs';
import { EXIT_CODES, FixtureError, integrityFailure } from './errors.mjs';
import { atomicWriteCanonical } from './io.mjs';
import { validateSchemaDocument } from './schema-validator.mjs';

const ZERO_DOMAINS = Object.freeze({
  content: 'ogvcs.fixture/content-chain/v1',
  operations: 'ogvcs.fixture/operation-chain/v1',
  paths: 'ogvcs.fixture/path-chain/v1',
  tree: 'ogvcs.fixture/tree-chain/v1',
});
const MAX_CHECKPOINT_BYTES = 2 * 1024 * 1024;

export class ChainDigest {
  constructor(domain, snapshot) {
    this.domain = domain;
    this.records = 0;
    this.digest = createHash('sha256').update(`${domain}\0`, 'utf8').digest('hex');
    if (snapshot) {
      if (snapshot.algorithm !== 'sha256-chain-v1') throw new TypeError('unsupported chain snapshot');
      this.records = snapshot.records;
      this.digest = snapshot.digest;
    }
  }

  update(bytes) {
    const prior = Buffer.from(this.digest, 'hex');
    this.digest = createHash('sha256')
      .update(`${this.domain}\0`, 'utf8')
      .update(prior)
      .update(bytes)
      .digest('hex');
    this.records += 1;
    return this;
  }

  snapshot() {
    return { algorithm: 'sha256-chain-v1', digest: this.digest, records: this.records };
  }
}

export function createChains() {
  return Object.fromEntries(
    Object.entries(ZERO_DOMAINS).map(([name, domain]) => [name, new ChainDigest(domain)]),
  );
}

export function rollingSnapshots(chains) {
  return Object.fromEntries(
    Object.keys(ZERO_DOMAINS).map((name) => [name, chains[name].snapshot()]),
  );
}

export function checkpointDocument({
  chains,
  completedItems,
  completedLogicalBytes,
  nextItemIndex,
  phase,
  requestDigest,
  sequence,
  stageId,
  state = 'generating',
}) {
  const body = {
    checkpointSequence: sequence,
    completedItems,
    completedLogicalBytes,
    extensions: { 'generation.phase': phase },
    nextItemIndex,
    requestDigest,
    rollingDigests: rollingSnapshots(chains),
    schemaVersion: CHECKPOINT_SCHEMA,
    stageId,
    state,
    tool: { name: TOOL_NAME, version: GENERATOR_VERSION },
  };
  const document = {
    ...body,
    checkpointDigest: canonicalDigest(body, 'ogvcs.fixture/checkpoint/v1'),
  };
  const issues = validateSchemaDocument('GenerationCheckpoint', document);
  if (issues.length > 0) {
    throw new FixtureError('internal', 'Generated checkpoint violates GenerationCheckpoint.schema.json', {
      details: { issues },
      exitCode: EXIT_CODES.INTERNAL,
    });
  }
  return document;
}

export async function writeCheckpoint(stage, state) {
  const document = checkpointDocument(state);
  await atomicWriteCanonical(path.join(stage, 'checkpoint.json'), document);
  return document;
}

export async function readCheckpoint(stage, requestDigest, stageId) {
  const checkpointPath = path.join(stage, 'checkpoint.json');
  let metadata;
  try {
    metadata = await lstat(checkpointPath);
  } catch (error) {
    throw integrityFailure('Generation checkpoint is missing', {
      code: error.code,
      path: checkpointPath,
    });
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw integrityFailure('Generation checkpoint is not a regular file', { path: checkpointPath });
  }
  if (metadata.size > MAX_CHECKPOINT_BYTES) {
    throw integrityFailure('Generation checkpoint exceeds its safe byte bound', {
      limit: MAX_CHECKPOINT_BYTES,
      path: checkpointPath,
      size: metadata.size,
    });
  }

  let document;
  try {
    document = JSON.parse(await readFile(checkpointPath, 'utf8'));
  } catch (error) {
    throw integrityFailure('Generation checkpoint is malformed', {
      path: checkpointPath,
      reason: error.message,
    });
  }
  const schemaIssues = validateSchemaDocument('GenerationCheckpoint', document);
  if (schemaIssues.length > 0) {
    throw integrityFailure('Generation checkpoint violates GenerationCheckpoint.schema.json', {
      issues: schemaIssues,
      path: checkpointPath,
    });
  }
  const { checkpointDigest, ...body } = document;
  const actualDigest = canonicalDigest(body, 'ogvcs.fixture/checkpoint/v1');
  if (checkpointDigest !== actualDigest) {
    throw integrityFailure('Generation checkpoint digest does not match its body', {
      actual: actualDigest,
      expected: checkpointDigest,
    });
  }
  if (
    document.schemaVersion !== CHECKPOINT_SCHEMA
    || document.tool?.name !== TOOL_NAME
    || document.tool?.version !== GENERATOR_VERSION
    || document.requestDigest !== requestDigest
    || document.stageId !== stageId
  ) {
    throw integrityFailure('Generation checkpoint is incompatible with this request');
  }
  if (!['paths', 'large-file', 'operations', 'finalize'].includes(document.extensions?.['generation.phase'])) {
    throw integrityFailure('Generation checkpoint has an unsupported phase');
  }
  return document;
}

export function assertChainSnapshots(chains, expected) {
  for (const name of Object.keys(ZERO_DOMAINS)) {
    const actual = chains[name].snapshot();
    const wanted = expected?.[name];
    if (
      wanted?.algorithm !== actual.algorithm
      || wanted?.digest !== actual.digest
      || wanted?.records !== actual.records
    ) {
      throw integrityFailure(`Checkpoint ${name} rolling digest does not match generated artifacts`, {
        actual,
        expected: wanted,
      });
    }
  }
}
