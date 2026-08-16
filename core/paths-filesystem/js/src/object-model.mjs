import { evaluatePath } from './path.mjs';

export function objectModelPathProfileValidator({ profile, segments }) {
  if (typeof profile !== 'string' || !profile.startsWith('path.opengamevcs/') || !Array.isArray(segments)) return Object.freeze({ accepted: false, error: 'PATH_PROFILE_UNKNOWN' });
  return evaluatePath(segments, { caseMode: 'case-sensitive', profile });
}
