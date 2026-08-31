import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  createLifecycleAdapterPort,
  LifecycleStore,
  ObjectTransferService,
} from '../src/index.mjs';

const config = (root, lifecycleAdapter) => ({
  root,
  backendSecret: Buffer.alloc(32, 7),
  authorizationPublicJwk: {},
  audience: 'objects.example',
  authorityEpoch: 1,
  keyGeneration: 1,
  issuer: 'auth.example',
  keyId: 'key-one',
  lifecycleAdapter,
});

test('repository-metadata lifecycle integration requires the explicit captured adapter seam', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-lifecycle-port-'));
  const store = new LifecycleStore({
    root: join(root, 'metadata-lifecycle'),
    deleteObject: async () => ({ deleted: false }),
  });
  const adapter = {
    initialize: () => store.initialize(),
    get: (...args) => store.get(...args),
    createStaged: (...args) => store.createStaged(...args),
    compareAndSwap: (...args) => store.compareAndSwap(...args),
    deleteAuthorized: (...args) => store.deleteAuthorized(...args),
    issueReuploadPermit: (...args) => store.issueReuploadPermit(...args),
    listBounded: (...args) => store.listBounded(...args),
    recordReverifiedDeleted: (...args) => store.recordReverifiedDeleted(...args),
    receipt: (...args) => store.receipt(...args),
  };
  assert.throws(() => new ObjectTransferService(config(join(root, 'raw-service'), adapter)), {
    code: 'TRANSFER_INPUT_INVALID',
  });

  const port = createLifecycleAdapterPort({
    adapter,
    capabilities: {
      schemaVersion: 'ogvcs.object-transfer/lifecycle-adapter-capabilities/v1',
      storageAuthority: 'repository-metadata',
      lifecycleContractVersion: 'repository-metadata/v9',
      atomicWithRepositoryMetadata: true,
      generationFenced: true,
      receiptGatedContentManifest: true,
    },
  });
  adapter.initialize = async () => { throw new Error('mutable adapter dispatch'); };
  const service = await new ObjectTransferService(config(join(root, 'bound-service'), port)).initialize();
  assert.deepEqual(service.lifecycleCapabilities, {
    schemaVersion: 'ogvcs.object-transfer/lifecycle-adapter-capabilities/v1',
    storageAuthority: 'repository-metadata',
    lifecycleContractVersion: 'repository-metadata/v9',
    atomicWithRepositoryMetadata: true,
    generationFenced: true,
    receiptGatedContentManifest: true,
  });
  assert.equal(await service.lifecycle.get('0'.repeat(64)), null);
});
