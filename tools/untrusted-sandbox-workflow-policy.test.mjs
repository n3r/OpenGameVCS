import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/untrusted-sandbox.yml', import.meta.url);
const packageUrl = new URL('../package.json', import.meta.url);
const conformanceUrl = new URL('../core/untrusted-sandbox/js/scripts/linux-conformance.mjs', import.meta.url);

test('untrusted sandbox workflow pins portable protocol and live Linux isolation lanes', async () => {
  const [workflow, rootPackage, conformance] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(packageUrl, 'utf8').then(JSON.parse),
    readFile(conformanceUrl, 'utf8'),
  ]);
  assert.match(workflow, /^name: Untrusted parser sandbox boundary$/mu);
  assert.match(workflow, /os: \[ubuntu-latest, macos-latest, windows-latest\]/u);
  assert.match(workflow, /linux-reference-conformance:\n    name: Linux reference isolation and hostile canaries\n    runs-on: ubuntu-latest/u);
  assert.equal(workflow.match(/node-version: 24/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/gu)?.length, 1);
  assert.match(workflow, /cc -static -O2 -std=c17 -Wall -Wextra -Werror core\/untrusted-sandbox\/js\/linux\/output_shim\.c/u);
  assert.match(workflow, /cc -static -O2 -std=c17 -Wall -Wextra -Werror core\/untrusted-sandbox\/js\/linux\/volume_anchor\.c/u);
  const importStart = workflow.indexOf('      - name: Import the deterministic one-layer credential-free scratch runtime');
  const importEnd = workflow.indexOf('      - name: Run live Docker/cgroup/seccomp conformance');
  assert(importStart >= 0 && importEnd > importStart);
  const importStep = workflow.slice(importStart, importEnd);
  assert.match(importStep, /mktemp -d "\$\{RUNNER_TEMP\}\/ogvcs-sandbox-rootfs\.XXXXXX"/u);
  assert.match(importStep, /install -m 0555 core\/untrusted-sandbox\/js\/linux\/output-shim/u);
  assert.match(importStep, /install -m 0555 core\/untrusted-sandbox\/js\/linux\/volume-anchor/u);
  assert.match(importStep, /find "\$\{runtime_rootfs_dir\}" -mindepth 1 -maxdepth 1 -printf '%f\\n' \| sort\)" = "\$\(printf '%s\\n' ogvcs-output-shim ogvcs-volume-anchor\)"/u);
  assert.match(importStep, /tar --format=ustar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner --mode=0555 --no-recursion/u);
  assert.match(importStep, /ogvcs-output-shim ogvcs-volume-anchor/u);
  assert.match(importStep, /test "\$\(tar -tf "\$\{runtime_rootfs_tar\}"\)" = "\$\(printf '%s\\n' ogvcs-output-shim ogvcs-volume-anchor\)"/u);
  assert.match(importStep, /docker image import --platform=linux\/amd64/u);
  assert.equal(importStep.match(/--change 'LABEL org\.opengamevcs\.sandbox\./gu)?.length, 2);
  assert.equal(importStep.match(/--change 'LABEL org\.opengamevcs\.sandbox\.runtime="linux-reference-v1"'/gu)?.length, 1);
  assert.equal(importStep.match(/--change 'LABEL org\.opengamevcs\.sandbox\.runtime-contract-sha256="f83f457feac8010f3415998877233f4bbbbaca3e13eb52b96bfd45232e99383c"'/gu)?.length, 1);
  assert.match(importStep, /test "\$\(docker image inspect --format '\{\{if \.Config\.Env\}\}nonempty\{\{else\}\}empty\{\{end\}\}:\{\{len \.RootFS\.Layers\}\}'[^\n]+\)" = "empty:1"/u);
  assert.doesNotMatch(importStep, /canary-tool|Dockerfile|docker build|--change 'ENV|--change 'CMD|--change 'ENTRYPOINT|--change 'VOLUME/iu);
  assert.doesNotMatch(workflow, /docker build/iu);
  assert.match(workflow, /npm run test:linux --workspace @opengamevcs\/untrusted-sandbox/u);
  assert.match(workflow, /OGVCS_DOCKER_BINARY: \/usr\/bin\/docker/u);
  assert.match(workflow, /untrusted-sandbox-linux-reference\.json/u);
  assert.match(workflow, /Retain Linux reference evidence\n        if: always\(\)/u);
  assert.match(workflow, /Retain Linux reference evidence[\s\S]+if-no-files-found: error/u);
  assert.match(workflow, /timeout-minutes: 20/u);
  assert.doesNotMatch(workflow, /continue-on-error|privileged|--network=(?:host|bridge)|--cap-add|--security-opt[= ]seccomp=unconfined/iu);
  assert.match(rootPackage.scripts['test:sandbox'], /untrusted-sandbox-workflow-policy\.test\.mjs/u);
  const diagnosticBeforeOutput = conformance.indexOf('const diagnostic = await safeResultDiagnostic(result);');
  const outputRead = conformance.indexOf("if (expectedCode === 'VALIDATED') await readOutput", diagnosticBeforeOutput);
  assert(diagnosticBeforeOutput >= 0 && outputRead > diagnosticBeforeOutput);
  assert.match(conformance, /buildLinuxConformanceReport\(\{ cases: \[\], failure, outcome: 'failed'/u);
  assert.match(conformance, /if \(!reportRetained\)[\s\S]+writeFile\(reportPath, reportBytes, \{ flag: 'wx', mode: 0o600 \}\)/u);
  assert.doesNotMatch(conformance, /failure\s*:\s*error|diagnostic\s*:\s*error\.(?:message|stack)|process\.stderr\.write\(error/iu);
});
