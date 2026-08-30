import { asIdentityError, identityFail } from './errors.mjs';
import { RUNTIME_LIMITS, cloneBounded, deepFreeze } from './validate.mjs';

export function buildAuthorizedView({ engine, principal, credentialAuthority, request, candidates, resourceFor, maxCandidates = RUNTIME_LIMITS.maxAuthorizedViewCandidates, maxItems = RUNTIME_LIMITS.maxAuthorizedViewItems }) {
  if (!engine || typeof engine.authorize !== 'function' || !credentialAuthority || typeof credentialAuthority.authorizePrincipal !== 'function'
      || typeof resourceFor !== 'function' || !Array.isArray(candidates)) identityFail('INPUT_INVALID', 'authorized view input is invalid');
  if (!Number.isSafeInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > RUNTIME_LIMITS.maxAuthorizedViewCandidates
      || !Number.isSafeInteger(maxItems) || maxItems < 1 || maxItems > RUNTIME_LIMITS.maxAuthorizedViewItems) identityFail('INPUT_INVALID', 'authorized view bounds are invalid');
  if (candidates.length > maxCandidates) identityFail('LIMIT_EXCEEDED', 'authorized view candidate bound exceeded');
  let baseRequest;
  let actor;
  try { baseRequest = cloneBounded(request); actor = cloneBounded(principal.actor, { maxBytes: 64 * 1024 }); }
  catch (error) { throw asIdentityError(error, 'INPUT_INVALID'); }
  const visible = [];
  let moreAuthorizedItems = false;
  for (let index = 0; index < candidates.length; index += 1) {
    let candidate;
    let resource;
    try {
      candidate = cloneBounded(candidates[index], { maxBytes: 64 * 1024, maxDepth: 12, maxNodes: 10_000 });
      resource = cloneBounded(resourceFor(candidate, index), { maxBytes: 64 * 1024, maxDepth: 12, maxNodes: 10_000 });
    } catch (error) {
      throw asIdentityError(error, 'POLICY_UNAVAILABLE');
    }
    const scoped = { ...structuredClone(baseRequest), actor: structuredClone(actor), resource };
    const decision = engine.authorize(scoped, {
      credentialCheck: (validated) => credentialAuthority.authorizePrincipal(principal, validated),
    });
    if (!decision.allowed) continue;
    if (visible.length < maxItems) visible.push(candidate);
    else moreAuthorizedItems = true;
  }
  return deepFreeze({
    schemaVersion: 'ogvcs.identity-policy/authorized-view/v1',
    items: visible,
    partialView: true,
    moreAuthorizedItems,
  });
}
