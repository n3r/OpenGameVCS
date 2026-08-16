#!/usr/bin/env node

import { canonicalJson, loadAuthority, parseCanonical } from '../src/core.mjs';
import { OPERATIONS, evaluateIndependentCase } from '../src/engine.mjs';

function commandLine(args) {
  if (args.length !== 2 || args[0] !== '--contract' || typeof args[1] !== 'string' || args[1].length === 0 || args[1].length > 16_384 || args[1].includes('\0')) {
    throw new Error('usage: ogvcs-protocol-independent-adapter --contract <authority-root>');
  }
  return args[1];
}

async function emit(value) {
  const line = `${canonicalJson(value)}\n`;
  if (!process.stdout.write(line)) await new Promise((resolve) => process.stdout.once('drain', resolve));
}

async function main() {
  const authority = await loadAuthority(commandLine(process.argv.slice(2)));
  const hello = authority.validator.validate({
    schemaVersion: 'ogvcs.protocol/runner-hello/v1',
    adapterId: 'ogvcs.protocol/independent-js@1',
    contractManifestSha256: authority.manifestSha256,
    operations: [...OPERATIONS],
  }, 'RunnerHello.schema.json');
  await emit(hello);

  let pending = Buffer.alloc(0);
  let receivedBytes = 0;
  let cases = 0;
  for await (const raw of process.stdin) {
    const chunk = Buffer.from(raw);
    receivedBytes += chunk.length;
    if (!Number.isSafeInteger(receivedBytes) || receivedBytes > authority.limits.maxJsonlStreamBytes) throw new Error('adapter input stream ceiling exceeded');
    pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk], pending.length + chunk.length);
    while (true) {
      const newline = pending.indexOf(0x0a);
      if (newline === -1) break;
      if (newline === 0 || newline > authority.limits.maxControlMessageBytes || pending[newline - 1] === 0x0d) throw new Error('adapter input line is invalid');
      const line = pending.subarray(0, newline);
      pending = pending.subarray(newline + 1);
      const runnerCase = parseCanonical(line, {
        maxControlMessageBytes: authority.limits.maxControlMessageBytes,
        maxCanonicalInputBytes: authority.limits.maxControlMessageBytes,
      });
      authority.validator.validate(runnerCase, 'RunnerCase.schema.json');
      cases += 1;
      if (cases > authority.limits.maxRunnerCases) throw new Error('adapter case ceiling exceeded');
      await emit(await evaluateIndependentCase(authority, runnerCase));
    }
    if (pending.length > authority.limits.maxControlMessageBytes) throw new Error('adapter input line ceiling exceeded');
  }
  if (pending.length !== 0) throw new Error('adapter input does not end with LF');
}

main().catch(() => {
  // The runner treats any stderr as hostile observable output. Keep failures
  // deliberately opaque and communicate only by the non-zero exit status.
  process.exitCode = 1;
});
