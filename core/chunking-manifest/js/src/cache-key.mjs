import { createHash } from 'node:crypto';
import { ObjectRef } from '@opengamevcs/object-model';
import { normalizeError } from './errors.mjs';
import { PROFILE } from './identity.mjs';

export const CACHE_KEY_DOMAIN = 'OpenGameVCS chunk cache key v1\0';
export const CACHE_KEY_VERSION = 'ogvcs:chunk-cache:v1:sha256';
const PROFILE_TEXT = `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`;

export function chunkCacheKey(value) {
  try {
    const candidate = typeof value === 'string' ? value : value?.objectId ?? value?.reference ?? value;
    const reference = candidate instanceof ObjectRef ? candidate : ObjectRef.parse(candidate);
    if (reference.kind !== 1) {
      throw new TypeError('cache keys require a Chunk ObjectRef');
    }
    const objectId = reference.toString();
    const digest = createHash('sha256')
      .update(CACHE_KEY_DOMAIN, 'ascii')
      .update(PROFILE_TEXT, 'ascii')
      .update('\0', 'ascii')
      .update(objectId, 'ascii')
      .digest('hex');
    return `${CACHE_KEY_VERSION}:${digest}`;
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_SOURCE_INVALID', { resource: 'cache-key' });
  }
}
