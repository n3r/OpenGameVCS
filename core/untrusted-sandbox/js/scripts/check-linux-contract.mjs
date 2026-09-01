import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { LINUX_REFERENCE_SECCOMP_SHA256 } from '../src/linux.mjs';
import { LINUX_RUNTIME_CONTRACT_SHA256, canonicalJson, sha256 } from '../src/internal/reference-contract.mjs';

const linuxRoot = new URL('../linux/', import.meta.url);
const [contractBytes, dockerfile, seccompBytes, shimBytes, anchorBytes] = await Promise.all([
  readFile(new URL('runtime-contract.json', linuxRoot)),
  readFile(new URL('Dockerfile.reference', linuxRoot), 'utf8'),
  readFile(new URL('seccomp-linux-reference-v1.json', linuxRoot)),
  readFile(new URL('output_shim.c', linuxRoot)),
  readFile(new URL('volume_anchor.c', linuxRoot)),
]);
const contract = JSON.parse(contractBytes);
assert.equal(contractBytes.toString('utf8'), `${canonicalJson(contract)}\n`);
assert.equal(sha256(Buffer.from(canonicalJson(contract), 'utf8')), LINUX_RUNTIME_CONTRACT_SHA256);
assert.equal(contract.schemaVersion, 'ogvcs.untrusted-sandbox/linux-runtime-contract/v1');
assert.equal(contract.architecture, 'linux/amd64');
assert.deepEqual(contract.containerProfile, {
  capabilities: 'drop-all',
  credentialChannel: 'none',
  filesystemRoot: 'read-only',
  network: 'none',
  outputFrame: 'ogvcs.untrusted-sandbox/output-frame/v1',
  runtimeGid: 65532,
  runtimeUid: 65532,
  shimPath: '/ogvcs-output-shim',
  volumeAnchorPath: '/ogvcs-volume-anchor',
});
assert.equal(contract.outputShimSourceSha256, sha256(shimBytes));
assert.equal(contract.volumeAnchorSourceSha256, sha256(anchorBytes));
assert.equal(anchorBytes.toString('utf8'), '#include <unistd.h>\n\nint main(void) {\n  for (;;) (void)pause();\n}\n');
assert.equal(contract.seccompProfileSha256, sha256(seccompBytes));
assert.equal(contract.seccompProfileSha256, LINUX_REFERENCE_SECCOMP_SHA256);

const seccomp = JSON.parse(seccompBytes);
assert.equal(seccomp.defaultAction, 'SCMP_ACT_ERRNO');
assert.equal(seccomp.defaultErrnoRet, 1);
const unrestricted = seccomp.syscalls.find((entry) => entry.action === 'SCMP_ACT_ALLOW' && !Object.hasOwn(entry, 'args'));
assert(unrestricted && !unrestricted.names.includes('clone3') && !unrestricted.names.includes('unshare') && !unrestricted.names.includes('setns'));
const clone = seccomp.syscalls.find((entry) => entry.names?.length === 1 && entry.names[0] === 'clone');
assert.deepEqual(clone, { action: 'SCMP_ACT_ALLOW', args: [{ index: 0, op: 'SCMP_CMP_MASKED_EQ', value: 2122457088, valueTwo: 0 }], names: ['clone'] });

assert.match(dockerfile, /^FROM scratch$/mu);
assert.match(dockerfile, new RegExp(`runtime-contract-sha256="${LINUX_RUNTIME_CONTRACT_SHA256}"`, 'u'));
assert.match(dockerfile, /^COPY --chmod=0555 core\/untrusted-sandbox\/js\/linux\/output-shim \/ogvcs-output-shim$/mu);
assert.match(dockerfile, /^COPY --chmod=0555 core\/untrusted-sandbox\/js\/linux\/volume-anchor \/ogvcs-volume-anchor$/mu);
assert.equal(dockerfile.match(/^COPY /gmu)?.length, 2);
