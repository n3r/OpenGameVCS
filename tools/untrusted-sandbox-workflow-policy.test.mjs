import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/untrusted-sandbox.yml', import.meta.url);
const packageUrl = new URL('../package.json', import.meta.url);
const conformanceUrl = new URL('../core/untrusted-sandbox/js/scripts/linux-conformance.mjs', import.meta.url);
const dockerReferenceUrl = new URL('../core/untrusted-sandbox/js/src/internal/docker-reference.mjs', import.meta.url);
const referenceWorkerTestUrl = new URL('../core/untrusted-sandbox/js/test/reference-worker.test.mjs', import.meta.url);
const readmeUrl = new URL('../core/untrusted-sandbox/js/README.md', import.meta.url);
const restartReviewUrl = new URL('../docs/reviews/OGVCS-045-restart-reconciliation-boundary-review.md', import.meta.url);
const prdUrl = new URL('../prd/todo/OGVCS-045-untrusted-parser-sandbox-credential-broker.md', import.meta.url);

test('untrusted sandbox workflow pins portable protocol and live Linux isolation lanes', async () => {
  const [workflow, rootPackage, conformance] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(packageUrl, 'utf8').then(JSON.parse),
    readFile(conformanceUrl, 'utf8'),
  ]);
  assert.match(workflow, /^name: Untrusted parser sandbox boundary$/mu);
  assert.match(workflow, /push:\n    branches: \[main, r1-foundation-integration, "ogvcs-045\/\*\*", "ogvcs045-\*", "r1-ogvcs045", "r1-sandbox-worker-v1"\]/u);
  assert.match(workflow, /os: \[ubuntu-latest, macos-latest, windows-latest\]/u);
  assert.match(workflow, /linux-reference-conformance:\n    name: Linux reference isolation and hostile canaries\n    runs-on: ubuntu-latest/u);
  assert.equal(workflow.match(/node-version: 24/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length, 2);
  assert.equal(workflow.match(/persist-credentials: false/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/gu)?.length, 1);
  for (const protectedPath of [
    '"docs/evidence/OGVCS-045/**"',
    '"docs/reviews/OGVCS-045-*.md"',
    '"tools/compare-untrusted-sandbox-conformance.mjs"',
    '"tools/untrusted-sandbox-conformance-evidence.test.mjs"',
    '"tools/untrusted-sandbox-retained-evidence.test.mjs"',
  ]) assert.equal(workflow.split(protectedPath).length - 1, 2, `${protectedPath} must trigger pull-request and push gates`);
  assert.match(workflow, /Exercise source-bound private portable evidence locally[\s\S]+--output "\$\{\{ runner\.temp \}\}\/untrusted-sandbox-portable-\$\{\{ runner\.os \}\}\.json"[\s\S]+--source-revision "\$\{\{ github\.sha \}\}"/u);
  assert.match(workflow, /Exercise test-only hard-kill boundaries locally[\s\S]+--output "\$\{\{ runner\.temp \}\}\/untrusted-sandbox-kill-boundaries\.json"[\s\S]+--source-revision "\$\{\{ github\.sha \}\}"/u);
  assert.equal(workflow.match(/actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/gu)?.length, 1);
  const retainedUpload = workflow.slice(workflow.indexOf('      - name: Retain Linux reference evidence'));
  assert.match(retainedUpload, /path: artifacts\/untrusted-sandbox-linux-reference\.json/u);
  assert.doesNotMatch(retainedUpload, /portable|kill-boundar|source-revision|sourceFiles|sourceSetSha256/iu);
  assert.doesNotMatch(workflow, /OGVCS_SANDBOX_SOURCE_REVISION/u);
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

test('restart reconciliation remains current-authority detection without cleanup authority', async () => {
  const [source, runtimeTests, readme, review, prd] = await Promise.all([
    readFile(dockerReferenceUrl, 'utf8'),
    readFile(referenceWorkerTestUrl, 'utf8'),
    readFile(readmeUrl, 'utf8'),
    readFile(restartReviewUrl, 'utf8'),
    readFile(prdUrl, 'utf8'),
  ]);

  assert.match(source, /async reconcileDaemonOrphans\(requestSource\)/u);
  assert.match(source, /label=\$\{AUTHORITY_LABEL\}=\$\{authorityId\}/u);
  assert.match(source, /AUTHENTICATED_ORPHANS_REQUIRE_SETTLEMENT/u);
  assert.match(source, /return reconciliationReport\('quarantined'/u);
  assert.match(runtimeTests, /destructiveCalls, \[\]/u);
  assert.match(runtimeTests, /quarantines without deleting before settlement approval/u);
  for (const text of [readme, review, prd]) {
    assert.match(text, /detection-and-quarantine|detection and quarantine|detection tranche/iu);
    assert.match(text, /no orphan deletion|does not yet\s+delete|performs no orphan deletion|not cleanup/iu);
    assert.match(text, /foreign|legacy/iu);
    assert.match(text, /OGVCS-045\s+(?:stays|remains)\s+Todo/iu);
  }
  assert.match(review, /requires explicit approval/iu);
  assert.match(prd, /all five acceptance criteria\s+remain open/iu);
});
