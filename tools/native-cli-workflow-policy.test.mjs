import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/native-cli-local-candidate.yml', import.meta.url);
const packageUrl = new URL('../package.json', import.meta.url);
const cargoUrl = new URL('../client/native-cli/rust/Cargo.toml', import.meta.url);
const gateUrl = new URL('../client/native-cli/rust/scripts/test-hermetic.mjs', import.meta.url);
const fixtureUrl = new URL(
  '../client/native-cli/rust/tests/support/hermetic_fixture.rs',
  import.meta.url,
);

test('native CLI workflow pins the three-OS hermetic installed-binary gate', async () => {
  const [workflow, rootPackage] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(packageUrl, 'utf8').then(JSON.parse),
  ]);

  assert.match(workflow, /^name: Native CLI local candidate$/mu);
  assert.match(workflow, /runner: ubuntu-latest, label: Linux/u);
  assert.match(workflow, /runner: macos-latest, label: macOS/u);
  assert.match(workflow, /runner: windows-latest, label: Windows/u);
  assert.equal(
    workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length,
    1,
  );
  assert.equal(
    workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length,
    1,
  );
  assert.equal(
    workflow.match(/dtolnay\/rust-toolchain@7d11e79e1714f6b6da93cac39ad8435666f5c337/gu)?.length,
    1,
  );
  assert.match(workflow, /node-version: 24/u);
  assert.match(workflow, /# 1\.82\.0/u);
  assert.match(workflow, /components: clippy, rustfmt/u);
  assert.match(workflow, /timeout-minutes: 30/u);
  assert.match(workflow, /branches: \[main, r1-foundation-integration\]/u);
  assert.match(workflow, /node --test tools\/native-cli-workflow-policy\.test\.mjs/u);
  assert.match(workflow, /node scripts\/test-hermetic\.mjs/u);
  assert.match(workflow, /working-directory: client\/native-cli\/rust/u);
  assert.equal(workflow.match(/tools\/native-cli-workflow-policy\.test\.mjs/gu)?.length, 3);
  assert.match(
    rootPackage.scripts['test:cli-workspace:spec'],
    /tools\/native-cli-workflow-policy\.test\.mjs/u,
  );
  assert.doesNotMatch(
    workflow,
    /continue-on-error|upload-artifact|release|publish|cosign|sigstore|PUBLIC_ROUTE|request-root/iu,
  );
});

test('hermetic gate separates the normal release target from the controller and sources', async () => {
  const [cargo, gate, fixture] = await Promise.all([
    readFile(cargoUrl, 'utf8'),
    readFile(gateUrl, 'utf8'),
    readFile(fixtureUrl, 'utf8'),
  ]);

  assert.match(cargo, /\[\[bin\]\]\nname = "ogvcs"\npath = "src\/main\.rs"/u);
  assert.match(
    cargo,
    /\[\[example\]\]\nname = "ogvcs-hermetic-fixture"\npath = "tests\/support\/hermetic_fixture\.rs"\ntest = false\nbench = false/u,
  );
  assert.doesNotMatch(cargo, /^\[features\]$/mu);

  const binaryBuild = gate.indexOf("'--bin',\n        'ogvcs'");
  const fixtureBuild = gate.indexOf("'--example',\n        'ogvcs-hermetic-fixture'");
  const sourceRemoval = gate.indexOf('rm(packageTarget, { recursive: true, force: true })');
  const firstInstalledInvocation = gate.indexOf("const help = installed(");
  assert(binaryBuild >= 0 && fixtureBuild > binaryBuild);
  assert(sourceRemoval > fixtureBuild && firstInstalledInvocation > sourceRemoval);
  const binaryBuildSlice = gate.slice(binaryBuild - 240, fixtureBuild);
  assert.match(binaryBuildSlice, /'--release'/u);
  assert.doesNotMatch(binaryBuildSlice, /--example|--features|OGVCS_/u);
  assert.match(gate, /const installedBinary = join\(runtimeRoot, `ogvcs\$\{executableSuffix\}`\)/u);
  assert.match(gate, /const fixtureBinary = join\(controllerRoot, `hermetic-fixture\$\{executableSuffix\}`\)/u);
  assert.match(gate, /runtime contains only binary and contract/u);
  assert.match(gate, /controller contains only the test-only fixture/u);
  assert.match(gate, /const environmentRoot = join\(temporary, 'environment'\)/u);
  assert.match(gate, /const stateRoot = join\(temporary, 'state'\)/u);
  assert.doesNotMatch(gate, /join\(runtimeRoot, '(?:environment|state)'\)/u);
  assert.match(gate, /!path\.endsWith\('\.rs'\)/u);
  assert.match(gate, /!path\.endsWith\('\.crate'\)/u);
  assert.match(gate, /!path\.endsWith\('Cargo\.toml'\)/u);
  assert.match(gate, /HOME: paths\.home/u);
  assert.match(gate, /USERPROFILE: paths\.profile/u);
  assert.match(gate, /XDG_CONFIG_HOME: paths\.config/u);
  assert.match(gate, /APPDATA: paths\.roaming/u);
  assert.match(gate, /LOCALAPPDATA: paths\.local/u);
  assert.match(gate, /TMPDIR: paths\.temp/u);
  assert.match(gate, /const SAFE_RUNTIME_INHERITED_KEYS = Object\.freeze/u);
  assert.match(gate, /'PATH'/u);
  assert.match(gate, /SOURCE_PATH_IN_RUNTIME_ENVIRONMENT/u);
  assert.match(gate, /SOURCE_TREE_RETAINED/u);
  assert.match(gate, /assertNoPathDisclosure\(raw, \[temporary, REPOSITORY_ROOT, CLI_ROOT\], code\)/u);
  assert.match(gate, /AUTH_ROUTE_STATUS_MISMATCH/u);
  assert.match(gate, /AUTH_ROUTE_CODE_MISMATCH/u);
  assert.match(gate, /AUTH_ROUTE_CLASS_MISMATCH/u);
  assert.match(gate, /AUTH_ROUTE_MUTATION_STARTED/u);
  assert.match(gate, /REMOTE_STATUS_MISMATCH/u);
  assert.match(gate, /REMOTE_CODE_MISMATCH/u);
  assert.match(gate, /REMOTE_CLASS_MISMATCH/u);
  assert.match(gate, /HOSTILE_ROOT_PARTIAL_WORKSPACE/u);
  assert.match(gate, /forbidden: \[locator, secret\]/u);
  const installedHelper = gate.slice(
    gate.indexOf('const installed = ('),
    gate.indexOf('const fixture = ('),
  );
  const forbiddenCheck = installedHelper.indexOf('for (const value of forbidden)');
  const machineParse = installedHelper.indexOf('value: parseMachineResult');
  assert.ok(forbiddenCheck >= 0 && machineParse > forbiddenCheck);
  assert.match(installedHelper, /statusMismatchCode = code/u);
  assert.match(gate, /CREATE_RECOVERY_PENDING_RETAINED/u);
  assert.match(gate, /CONFIGURE_RECOVERY_BRANCH_MISMATCH/u);
  assert.match(gate, /REMOVE_JOURNAL_RECORD_RETAINED/u);
  assert.match(gate, /openReady\(removeJournalRoot/u);
  assert.match(gate, /INSTALLED_BINARY_MUTATED/u);
  assert.match(gate, /CONTROLLER_BINARY_MUTATED/u);
  assert.match(gate, /CONTRACT_MANIFEST_MUTATED/u);
  assert.match(gate, /CONTRACT_ARTIFACT_MUTATED/u);
  assert.doesNotMatch(gate, /for \(const \[key, value\] of Object\.entries\(process\.env\)\)/u);

  assert.match(fixture, /impl RepositoryPublicRoutes for FixtureRoutes/u);
  assert.match(fixture, /process::exit\(HARD_EXIT_CODE\)/u);
  assert.doesNotMatch(fixture, /UnavailablePublicRoutes|std::env::set_var|Command::new\("ogvcs"\)/u);
});

test('recovery and signal claims are exact and fail closed', async () => {
  const [gate, fixture] = await Promise.all([
    readFile(gateUrl, 'utf8'),
    readFile(fixtureUrl, 'utf8'),
  ]);

  for (const boundary of [
    'crash-create-journal',
    'crash-configure-journal',
    'crash-stage-add-journal',
    'crash-remove-journal',
    'crash-remove-mutation',
  ]) {
    assert.match(gate, new RegExp(boundary, 'u'));
    assert.match(fixture, new RegExp(boundary, 'u'));
  }
  assert.match(gate, /'SIGINT'/u);
  assert.match(gate, /'SIGTERM'/u);
  assert.match(fixture, /CREATE_NEW_PROCESS_GROUP/u);
  assert.match(fixture, /GenerateConsoleCtrlEvent\(CTRL_BREAK_EVENT, child\.id\(\)\)/u);
  assert.match(fixture, /#\[path = "\.\.\/\.\.\/src\/windows_security\.rs"\]/u);
  assert.match(fixture, /windows_security::create_new_private_directory\(root\)/u);
  assert.match(fixture, /"hostile-root"/u);
  assert.match(fixture, /\*S-1-1-0:\(OI\)\(CI\)F/u);
  assert.equal(fixture.match(/Command::new\("icacls"\)/gu)?.length, 1);
  assert.equal(fixture.match(/\.stdout\(Stdio::null\(\)\)/gu)?.length, 1);
  assert.equal(fixture.match(/\.stderr\(Stdio::null\(\)\)/gu)?.length, 1);
  assert.match(fixture, /if unsafe \{ GenerateConsoleCtrlEvent[\s\S]+child\.kill\(\)[\s\S]+return Err\("SIGNAL_DELIVERY_FAILED"/u);
  assert.match(gate, /result\.data\?\.remoteDurableState === 'unchanged'/u);
  assert.match(gate, /result\.status === expectedStatus && result\.signal === null/u);
  assert.doesNotMatch(gate, /SIGKILL[\s\S]{0,160}assertCancellationResult/u);
  assert.doesNotMatch(gate, /https?:\/\/|fetch\(|curl|gh |git |workflow_dispatch|upload-artifact/iu);
});
