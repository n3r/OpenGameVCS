import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  collectProtocolScenarios,
  loadProtocolContract,
  PROTOCOL_OPERATIONS,
  runExternalProtocolConformance,
  runReferenceProtocolConformance,
} from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

const adapterScript = new URL('../../adapters/js-independent/bin/ogvcs-protocol-independent-adapter.mjs', import.meta.url);

test('reference and genuinely independent process adapter execute every case with identical semantic rows', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const reference = await runReferenceProtocolConformance(contract);
  const external = await runExternalProtocolConformance(contract, [process.execPath, fileURLToPath(adapterScript), '--contract', fileURLToPath(protocolRoot)], { expectedAdapterId: 'ogvcs.protocol/independent-js@1' });
  assert.equal(reference.passed, contract.manifest.counts.scenarios);
  assert.equal(external.passed, contract.manifest.counts.scenarios);
  assert.equal(reference.failed, 0);
  assert.equal(external.failed, 0);
  assert.equal(reference.reportDigest, external.reportDigest);
  assert.deepEqual(reference.results, external.results);
  const sources = await Promise.all([
    readFile(adapterScript, 'utf8'),
    readFile(new URL('../../adapters/js-independent/src/core.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../../adapters/js-independent/src/engine.mjs', import.meta.url), 'utf8'),
  ]);
  const joined = sources.join('\n');
  assert.doesNotMatch(joined, /@opengamevcs\/protocol-baseline|executeReferenceProtocolCase|requirementIds|forbiddenResponseFields|[.'"]expected["']?\s*:/u);
  assert.doesNotMatch(joined, /vectors\/(?:negotiation|envelopes|idempotency|cursors|streams|transfer|malformed|resources|security|release)\.json/u);
  assert.doesNotMatch(joined, /loadAuthorizationContract|authorizationCase(?:Id|Sha256)|authorizationVectorPath|grantVerification|vectors\/grants\.json/u);
});

test('runner never sends oracle fields to a process and counts semantic disagreement without trusting it', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const script = `let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const rows=s.trimEnd().split('\\n').map(JSON.parse);if(rows.some(r=>'expected'in r||'requirementIds'in r||'forbiddenResponseFields'in r||!/^case-[0-9a-f]{32}$/.test(r.id)))process.exit(9);const h={adapterId:'ogvcs.protocol/oracle-spy@1',contractManifestSha256:process.env.MANIFEST,operations:${JSON.stringify(PROTOCOL_OPERATIONS)},schemaVersion:'ogvcs.protocol/runner-hello/v1'};const trace={logEntries:[],responseBody:null,responseHeaders:[],semanticOutput:null,streamFrames:[]};const out=[h,...rows.map(r=>({code:'NONE',id:r.id,mutationCount:0,preMutation:true,result:'accept',schemaVersion:'ogvcs.protocol/adapter-result/v1',trace}))];process.stdout.write(out.map(JSON.stringify).join('\\n')+'\\n')})`;
  const report = await runExternalProtocolConformance(contract, { command: process.execPath, args: ['-e', script], env: { MANIFEST: contract.manifestSha256 } }, { expectedAdapterId: 'ogvcs.protocol/oracle-spy@1' });
  assert.ok(report.failed > 0);
  assert.equal(report.results.length, contract.manifest.counts.scenarios);
});

test('runner rejects switched handles, protected digest traces, and every successful stderr byte', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const common = `const crypto=require('node:crypto');let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const rows=s.trimEnd().split('\\n').map(JSON.parse);const h={adapterId:'ogvcs.protocol/hostile@1',contractManifestSha256:process.env.MANIFEST,operations:${JSON.stringify(PROTOCOL_OPERATIONS)},schemaVersion:'ogvcs.protocol/runner-hello/v1'};const empty={logEntries:[],responseBody:null,responseHeaders:[],semanticOutput:null,streamFrames:[]};`;
  const switched = `${common}const out=[h,...rows.map((r,i)=>({code:'NONE',id:i===1?rows[0].id:r.id,mutationCount:0,preMutation:true,result:'accept',schemaVersion:'ogvcs.protocol/adapter-result/v1',trace:empty}))];process.stdout.write(out.map(JSON.stringify).join('\\n')+'\\n')})`;
  await assert.rejects(() => runExternalProtocolConformance(contract, { command: process.execPath, args: ['-e', switched], env: { MANIFEST: contract.manifestSha256 } }, { expectedAdapterId: 'ogvcs.protocol/hostile@1' }), /missing, duplicated|unknown opaque/u);

  const digestLeak = `${common}function first(v){if(typeof v==='string')return v;if(v&&typeof v==='object')for(const x of Object.values(v)){const y=first(x);if(y)return y}}const out=[h,...rows.map(r=>{const marker=first(r.serverContext);const trace=marker?{...empty,semanticOutput:crypto.createHash('sha256').update(marker).digest('hex')}:empty;return {code:'NONE',id:r.id,mutationCount:0,preMutation:true,result:'accept',schemaVersion:'ogvcs.protocol/adapter-result/v1',trace}})];process.stdout.write(out.map(JSON.stringify).join('\\n')+'\\n')})`;
  await assert.rejects(() => runExternalProtocolConformance(contract, { command: process.execPath, args: ['-e', digestLeak], env: { MANIFEST: contract.manifestSha256 } }, { expectedAdapterId: 'ogvcs.protocol/hostile@1' }), /protected material|disclosed/u);

  const stderrLeak = `${common}const marker=JSON.stringify(rows.find(r=>r.serverContext)?.serverContext??'forbidden');process.stderr.write(marker);const out=[h,...rows.map(r=>({code:'NONE',id:r.id,mutationCount:0,preMutation:true,result:'accept',schemaVersion:'ogvcs.protocol/adapter-result/v1',trace:empty}))];process.stdout.write(out.map(JSON.stringify).join('\\n')+'\\n')})`;
  await assert.rejects(() => runExternalProtocolConformance(contract, { command: process.execPath, args: ['-e', stderrLeak], env: { MANIFEST: contract.manifestSha256 } }, { expectedAdapterId: 'ogvcs.protocol/hostile@1' }), /stderr|adapter/u);
});

test('runner derives protected canaries from actual sensitive carrier fields', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const common = `let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const rows=s.trimEnd().split('\\n').map(JSON.parse);const h={adapterId:'ogvcs.protocol/carrier-echo@1',contractManifestSha256:process.env.MANIFEST,operations:${JSON.stringify(PROTOCOL_OPERATIONS)},schemaVersion:'ogvcs.protocol/runner-hello/v1'};const empty={logEntries:[],responseBody:null,responseHeaders:[],semanticOutput:null,streamFrames:[]};function carrier(r){switch(process.env.MODE){case'grant':return r.input?.probe?.grant?.envelope;case'receipt':return r.input?.receiptKeyBase64url;case'idempotency':return r.input?.idempotencyKey;case'cursor':return r.input?.page?.nextCursor?.token||r.input?.suppliedToken;default:return undefined}}const out=[h,...rows.map(r=>{const value=carrier(r);return {code:'NONE',id:r.id,mutationCount:0,preMutation:true,result:'accept',schemaVersion:'ogvcs.protocol/adapter-result/v1',trace:value?{...empty,semanticOutput:{innocuous:value}}:empty}})];process.stdout.write(out.map(JSON.stringify).join('\\n')+'\\n')})`;
  for (const mode of ['grant', 'receipt', 'idempotency', 'cursor']) {
    await assert.rejects(() => runExternalProtocolConformance(contract, {
      command: process.execPath,
      args: ['-e', common],
      env: { MANIFEST: contract.manifestSha256, MODE: mode },
    }, { expectedAdapterId: 'ogvcs.protocol/carrier-echo@1' }), /protected material|disclosed/u, mode);
  }
});

test('Node permission mode confines an adapter to its closure and staged authority', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const permissionContract = {
    ...contract,
    vectors: { permission: { cases: [collectProtocolScenarios(contract)[0]] } },
  };
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-permission-test-'));
  const closure = join(root, 'adapter');
  const forbidden = [join(root, 'protocol-vectors.json'), join(root, 'authorization-vectors.json')];
  const script = join(closure, 'adapter.mjs');
  await mkdir(dirname(script), { recursive: true });
  await Promise.all(forbidden.map((path) => writeFile(path, '{"expected":"oracle"}\n', 'utf8')));
  try {
    for (const path of forbidden) {
      await writeFile(script, `import { readFileSync } from 'node:fs'; readFileSync(${JSON.stringify(path)});`, 'utf8');
      await assert.rejects(() => runExternalProtocolConformance(permissionContract, [process.execPath, script], {
        nodeAdapterReadRoots: [closure],
        timeoutMs: 30_000,
      }), /adapter|stderr|permission/u, path);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runner rejects malformed handshakes and terminates stalled processes at the deadline', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const malformed = `let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const n=s.trimEnd().split('\\n').length;process.stdout.write(Array(n+1).fill('{}').join('\\n')+'\\n')})`;
  await assert.rejects(() => runExternalProtocolConformance(contract, [process.execPath, '-e', malformed]), /handshake/u);
  await assert.rejects(() => runExternalProtocolConformance(contract, [process.execPath, '-e', 'setInterval(()=>{},1000)'], { timeoutMs: 20 }), /deadline/u);

  const oversizedWorkingSet = `process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(JSON.stringify({padding:'x'.repeat(2048)})+'\\n'))`;
  await assert.rejects(
    () => runExternalProtocolConformance(contract, [process.execPath, '-e', oversizedWorkingSet], { maxWorkingMemoryBytes: 1024 }),
    (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED',
  );
});

test('external adapter descriptors are inertly snapshotted before property access', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  let traps = 0;
  const descriptor = new Proxy({}, {
    ownKeys() { traps += 1; throw new Error('descriptor trap'); },
  });
  await assert.rejects(
    () => runExternalProtocolConformance(contract, descriptor),
    (error) => error.code === 'PROTOCOL_INPUT_INVALID',
  );
  assert.equal(traps, 0);
});
