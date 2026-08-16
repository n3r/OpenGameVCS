#!/usr/bin/env node

import { createInterface } from 'node:readline';

import { canonicalJson, executeReferenceVector, loadAuthorizationContract, parseCanonicalJson } from '@opengamevcs/authorization-contract';

// Protocol demonstration only. A conformance claim must connect this boundary to
// the implementation under test, not call the packaged reference fixture.
let hello = true;
const contract = await loadAuthorizationContract();
for await (const line of createInterface({ input: process.stdin, crlfDelay: Infinity })) {
  const message = parseCanonicalJson(line);
  if (hello) {
    hello = false;
    if (Object.keys(message).sort().join(',') !== 'contractVersion,manifestSha256,registrySetSha256,schemaVersion,vectors' ||
        message.schemaVersion !== 'ogvcs.authorization/runner-hello/v1' ||
        message.contractVersion !== contract.manifest.contractVersion ||
        message.manifestSha256 !== contract.manifestSha256 ||
        message.registrySetSha256 !== contract.manifest.registrySetSha256 || message.vectors !== 30) throw new Error('invalid runner hello');
    continue;
  }
  if (message.schemaVersion !== 'ogvcs.authorization/runner-vector/v1') throw new Error('invalid runner vector');
  const outcome = await executeReferenceVector(message.vector);
  process.stdout.write(`${canonicalJson({ schemaVersion: 'ogvcs.authorization/runner-result/v1', id: message.vector.id, result: outcome.result, code: outcome.code })}\n`);
}
