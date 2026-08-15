import path from 'node:path';
import { realpath } from 'node:fs/promises';

import { invalidRequest } from './errors.mjs';
import { loadFixtureRequest, loadManifest } from './manifest.mjs';
import { planFixture } from './plan.mjs';
import { portableRelativePathIssue } from './schema-validator.mjs';
import { ResourceBudget } from './writer.mjs';

export async function inspectFixture(destination, options = {}) {
  const startedAt = Date.now();
  const issue = portableRelativePathIssue(destination);
  if (issue !== null) throw invalidRequest(`destination ${issue}`, { reason: issue, value: destination });
  const cwd = await realpath(options.cwd ?? process.cwd());
  const directory = path.resolve(cwd, ...destination.split('/'));
  let bootstrap;
  let budget = options.budget;
  if (!budget) {
    bootstrap = await loadFixtureRequest(directory);
    const plan = planFixture(bootstrap.request);
    const explicitMaximumMemoryBytes = bootstrap.request.resourceLimits?.maximumMemoryBytes;
    budget = new ResourceBudget({
      deadline: bootstrap.request.resourceLimits?.maximumDurationSeconds === undefined
        ? undefined
        : startedAt + bootstrap.request.resourceLimits.maximumDurationSeconds * 1000,
      maximumMemoryBytes: explicitMaximumMemoryBytes,
      maximumMemoryGrowthBytes: explicitMaximumMemoryBytes === undefined
        ? Number(plan.estimates.standaloneVerificationMemoryGrowthBytes)
        : undefined,
      maximumPhysicalBytes: bootstrap.request.resourceLimits?.maximumPhysicalBytes,
      testFailurePhase: options.env?.OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE,
    });
  }
  budget.checkRuntime('inspection:start');
  const { manifest } = await loadManifest(directory, { bootstrap, budget });
  budget.checkRuntime('inspection:complete');
  return {
    counts: manifest.counts,
    destination: manifest.request.destination,
    digests: manifest.digests,
    history: manifest.history,
    logicalBytes: manifest.logicalBytes,
    manifestDigest: manifest.manifestDigest,
    plan: planFixture(manifest.request).estimates,
    profile: manifest.profile,
    provenance: manifest.provenance,
    representation: {
      largeFile: manifest.extensions['representation.large-file'],
      paths: manifest.extensions['representation.paths'],
    },
    requestDigest: manifest.requestDigest,
    schemaVersion: manifest.schemaVersion,
  };
}
