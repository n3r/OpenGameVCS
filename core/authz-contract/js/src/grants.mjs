import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

import { canonicalBytes, cloneJson, deepFreeze } from './canonical.mjs';
import { validateGrantContext, validateRequestObjectIds, validateTransferGrantClaims, validateTransferGrantEnvelope } from './validate.mjs';

export const GRANT_DOMAIN = Buffer.from('OGVCS-AUTH-GRANT-V1\0', 'ascii');
export const REQUEST_ROOT_DOMAIN = Buffer.from('OGVCS-AUTH-REQUEST-ROOT-V1\0', 'ascii');

function outcome(code) {
  return deepFreeze({ result: code.startsWith('ALLOW_') ? 'allow' : 'deny', code });
}

export function requestRootForObjectIds(objectIdsInput) {
  const objectIds = validateRequestObjectIds(objectIdsInput).sort();
  const digest = createHash('sha256').update(REQUEST_ROOT_DOMAIN).update(canonicalBytes(objectIds)).digest('hex');
  return `sha256:${digest}`;
}

export function signConformanceGrant(claimsInput, privateJwk, options = {}) {
  if (options.conformanceOnly !== true) throw new TypeError('signConformanceGrant requires conformanceOnly: true');
  const claims = validateTransferGrantClaims(claimsInput);
  let signature;
  try {
    signature = sign(null, Buffer.concat([GRANT_DOMAIN, canonicalBytes(claims)]), createPrivateKey({ key: privateJwk, format: 'jwk' })).toString('base64url');
  } catch (error) {
    throw new TypeError('invalid conformance signing key', { cause: error });
  }
  return deepFreeze({
    schemaVersion: 'ogvcs.authorization/transfer-grant/v1',
    algorithm: 'Ed25519',
    keyId: claims.keyId,
    claims: cloneJson(claims),
    signature,
  });
}

export function verifyTransferGrant(envelopeInput, contextInput, publicJwk) {
  let envelope;
  let context;
  try {
    envelope = validateTransferGrantEnvelope(envelopeInput);
    context = validateGrantContext(contextInput);
    const valid = verify(null, Buffer.concat([GRANT_DOMAIN, canonicalBytes(envelope.claims)]), createPublicKey({ key: publicJwk, format: 'jwk' }), Buffer.from(envelope.signature, 'base64url'));
    if (!valid) return outcome('DENY_GRANT_INVALID');
  } catch {
    return outcome('DENY_GRANT_INVALID');
  }
  const claims = envelope.claims;
  if (claims.authorityEpoch !== context.authorityEpoch || claims.keyGeneration !== context.keyGeneration || claims.keyId !== context.keyId) return outcome('DENY_EPOCH_STALE');
  if (context.now < claims.issuedAt || context.now >= claims.expiresAt) return outcome('DENY_GRANT_EXPIRED');
  if (claims.audience !== context.audience) return outcome('DENY_AUDIENCE_MISMATCH');
  if (claims.issuer !== context.issuer || claims.subject !== context.subject || claims.permission !== context.permission || claims.operation !== context.operation || claims.tenant !== context.tenant || claims.repository !== context.repository) return outcome('DENY_RESOURCE_SCOPE');
  if (claims.requestRoot === null
    ? context.requestObjectIds.length !== 0 || !claims.objectIds.includes(context.objectId)
    : !context.requestObjectIds.includes(context.objectId) || requestRootForObjectIds(context.requestObjectIds) !== claims.requestRoot) return outcome('DENY_RESOURCE_SCOPE');
  if (claims.replay === 'single-use' && context.consumedNonces.includes(claims.nonce)) return outcome('DENY_GRANT_REPLAY');
  return outcome('ALLOW_EXPLICIT');
}
