import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';

import {
  cliPath,
  packageDirectory,
  runProcess,
  temporaryDirectory,
} from './test-helpers.mjs';

for (const example of ['object-mapping', 'workload-driver']) {
  test(`${example} black-box consumer processes every profile`, async (t) => {
    const cwd = await temporaryDirectory(t, `ogvcs-${example}-`);
    const result = await runProcess(process.execPath, [
      path.join(packageDirectory, 'examples', `${example}.mjs`),
      '--cli', cliPath,
      '--workspace', 'fixtures',
    ], { cwd });
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr, '');
    const output = JSON.parse(result.stdout);
    assert.equal(output.consumer, `ogvcs-${example}-example/v1`);
    assert.deepEqual(output.profiles.map(({ profile }) => profile), [
      'code-heavy@2.0.0',
      'global-studio@2.0.0',
      'large-binary@2.0.0',
      'unity-like@2.0.0',
      'unreal-like@2.0.0',
    ]);
    assert.ok(output.profiles.every(({ verified }) => verified === true));
    if (example === 'object-mapping') {
      assert.deepEqual(output.artifactSchemas, [
        'https://schemas.opengamevcs.org/fixture/v2/GroupRelationships.schema.json',
        'https://schemas.opengamevcs.org/fixture/v2/InventoryRecord.schema.json',
      ]);
      assert.ok(output.profiles.every(({ groupCount, semanticVersions, pathCount }) => (
        groupCount >= 0 && semanticVersions >= pathCount
      )));
      const unity = output.profiles.find(({ profile }) => profile.startsWith('unity-like@'));
      assert.ok(unity.negativeCases >= 6);
      assert.ok(unity.roles['negative-evidence'] > 0);
    } else {
      assert.equal(
        output.schema,
        'https://schemas.opengamevcs.org/fixture/v2/OperationScenario.schema.json',
      );
      assert.ok(output.profiles.every(({
        aclRuleCount,
        authorizationChecks,
        identityCount,
        operationCount,
        semanticChecks,
        stateTransitions,
      }) => (
        aclRuleCount >= 2
        && identityCount === 8
        && authorizationChecks === operationCount
        && semanticChecks === operationCount
        && stateTransitions === operationCount
      )));
      const global = output.profiles.find(({ profile }) => profile.startsWith('global-studio@'));
      assert.ok(global.kinds['lock-conflict'] > 0);
      assert.ok(global.kinds['lock-loss'] > 0);
      assert.ok(global.kinds['network-condition'] > 0);
      assert.ok(global.rejectedOutcomes >= 2);
      assert.deepEqual(global.networkConditionsUsed, ['link-1', 'link-2']);
    }
  });
}
