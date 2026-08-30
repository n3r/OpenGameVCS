import { createHash } from 'node:crypto';

export { MemoryCredentialStore } from './credentials.mjs';
export { MemoryAuditStore } from './audit.mjs';
export { MemoryGrantNonceLedger } from './grants.mjs';

export function deterministicSecretSource(seed = 'ogvcs-identity-test') {
  let sequence = 0;
  return () => createHash('sha256').update(seed).update(String(sequence++)).digest();
}

export function fakeIdentityProviderAdapter({ id = 'fake-oidc', subject = 'user.test', groups = [] } = {}) {
  return Object.freeze({
    id,
    flows: Object.freeze(['authorization-code-pkce', 'device-code']),
    async begin(flow) {
      return { flow, interaction: 'fake', handle: `fake.${flow}` };
    },
    async complete(flow, input) {
      if (input?.handle !== `fake.${flow}`) throw new Error('fake flow mismatch');
      return { subject, groups, authenticationMethod: `fake-${flow}` };
    },
  });
}
