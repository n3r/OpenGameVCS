import { runThreatVectors } from '@opengamevcs/authorization-contract';
import { evaluatePath, pathContract } from '@opengamevcs/path-filesystem';

import { canonicalDigest, deepFreeze } from './canonical.mjs';
import { FakeRepositoryService, checkRepositoryInvariants } from './fake-service.mjs';

const HOSTILE_PATHS = Object.freeze(['../escape', '.ogvcs/secret', 'CON/file', 'safe\\escape']);

export function expectedSecurityPathCases() {
  return deepFreeze(HOSTILE_PATHS.map((path) => {
    const decision = evaluatePath(path, { profile: 'path.opengamevcs/portable@1' });
    return { caseDigest: canonicalDigest(path, 'ogvcs.benchmark/security-path-case/v1'), rejected: decision.accepted !== true, code: decision.error ?? 'PATH_ACCEPTED' };
  }));
}

function input(key, extras = {}) { return { idempotencyKey: key.padEnd(16, '-'), logicalBytes: 4096, uniqueBytes: 3072, actor: 'operator-a', fileId: '00000000000000000000000000000001', authorized: true, expectedHead: 'root', ...extras }; }

export async function runSecurityNegativeSuites() {
  const authorization = await runThreatVectors();
  const service = new FakeRepositoryService({ brokenMode: 'unauthorized-access' });
  await service.executeTask('setup', input('security-enumeration-setup'));
  await service.executeTask('submit', input('security-enumeration', { authorized: false }));
  const enumerationDetected = checkRepositoryInvariants(service).checks.some(({ id, passed }) => id === 'authorized' && !passed);
  const pathRows = HOSTILE_PATHS.map((path) => ({ path, decision: evaluatePath(path, { profile: 'path.opengamevcs/portable@1' }) }));
  const workspaceEscapeDetected = pathRows.every(({ decision }) => decision.accepted !== true);
  const misses = authorization.failed + (enumerationDetected ? 0 : 1) + (workspaceEscapeDetected ? 0 : 1);
  return deepFreeze({ authorization, pathManifestSha256: pathContract.manifestSha256, enumerationDetected, workspaceEscapeDetected, pathRows, misses });
}
