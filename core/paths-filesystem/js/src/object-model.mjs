import { evaluatePath } from './path.mjs';

export function objectModelPathProfileValidator({ profile, caseMode, segments }) {
  if (typeof profile !== 'string' || !profile.startsWith('path.opengamevcs/') ||
      (caseMode !== 'case-sensitive' && caseMode !== 'case-folded') || !Array.isArray(segments)) {
    return Object.freeze({ accepted: false });
  }
  const result = evaluatePath(segments, { caseMode, profile });
  if (result.accepted !== true) return Object.freeze({ accepted: false });
  return Object.freeze({
    accepted: true,
    repositoryKey: result.repositoryKey,
    platformKey: result.platformKey
  });
}

/** Create the exact profile/case-mode adapter consumed by OGVCS-002. */
export function createObjectModelPathProfileAdapter({ profile, caseMode }) {
  if (typeof profile !== 'string' || !profile.startsWith('path.opengamevcs/') ||
      (caseMode !== 'case-sensitive' && caseMode !== 'case-folded')) {
    throw new TypeError('profile and caseMode must be exact supported pins');
  }
  const validate = request => {
    if (request?.profile !== profile || request?.caseMode !== caseMode) {
      return Object.freeze({ accepted: false });
    }
    return objectModelPathProfileValidator(request);
  };
  return Object.freeze({ profile, caseMode, validate });
}
