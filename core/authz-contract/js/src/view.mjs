import { canonicalBytes, cloneJson, deepFreeze, parseCanonicalJson, sha256 } from './canonical.mjs';
import { ERROR_CODES, contractError } from './errors.mjs';
import { evaluateFixturePolicy, makeFixtureRequest } from './evaluator.mjs';

const MAX_CANDIDATES = 100_000;
const DEFAULT_CANDIDATES = 10_000;

function cursorFor(offset, visibleIds) {
  return canonicalBytes({ v: 1, o: offset, f: sha256(canonicalBytes(visibleIds)) }).toString('base64url');
}

export function buildAuthorizedView(options) {
  if (!options || typeof options !== 'object') contractError(ERROR_CODES.INPUT_INVALID, 'authorized view options are required');
  const {
    policy, repository, actorId, permission, candidates = repository?.resources,
    pageSize = 100, cursor = null, maxCandidates = DEFAULT_CANDIDATES,
  } = options;
  if (!Array.isArray(candidates) || !Number.isSafeInteger(maxCandidates) || maxCandidates <= 0 || maxCandidates > MAX_CANDIDATES || candidates.length > maxCandidates) {
    contractError(ERROR_CODES.LIMIT_EXCEEDED, 'authorized-view candidate ceiling exceeded');
  }
  if (!Number.isSafeInteger(pageSize) || pageSize <= 0 || pageSize > 1000) contractError(ERROR_CODES.INPUT_INVALID, 'authorized-view pageSize is invalid');
  let start = 0;
  const visible = [];
  const candidateIds = new Set();
  for (const [index, candidate] of candidates.entries()) {
    const id = candidate?.id;
    if (typeof id !== 'string') contractError(ERROR_CODES.INPUT_INVALID, `authorized-view candidate ${index} has no ID`);
    if (candidateIds.has(id)) contractError(ERROR_CODES.INPUT_INVALID, 'authorized-view candidate IDs contain duplicates');
    candidateIds.add(id);
    const request = makeFixtureRequest({ ...repository, resources: candidates }, `view-${index}`, actorId, id, permission);
    if (evaluateFixturePolicy(policy, request).allowed) {
      const exposed = cloneJson(candidate);
      delete exposed.visibility;
      visible.push(exposed);
    }
  }
  const visibleIds = visible.map(({ id }) => id);
  if (cursor !== null) {
    let decoded;
    try {
      if (typeof cursor !== 'string' || Buffer.from(cursor, 'base64url').toString('base64url') !== cursor) throw new TypeError('noncanonical base64url');
      decoded = parseCanonicalJson(Buffer.from(cursor, 'base64url'), { maxBytes: 1024 });
    } catch { contractError(ERROR_CODES.INPUT_INVALID, 'authorized-view cursor is invalid'); }
    if (!decoded || decoded.v !== 1 || !Number.isSafeInteger(decoded.o) || decoded.o < 0 || decoded.o > visible.length || decoded.f !== sha256(canonicalBytes(visibleIds))) {
      contractError(ERROR_CODES.INPUT_INVALID, 'authorized-view cursor does not bind this authorized set');
    }
    start = decoded.o;
  }
  const items = visible.slice(start, start + pageSize);
  const next = start + items.length;
  return deepFreeze({ items, nextCursor: next < visible.length ? cursorFor(next, visibleIds) : null });
}
