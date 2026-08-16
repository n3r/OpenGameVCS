import {
  bundledRegistryDirectory,
  loadBundledRegistry,
  registrySetDigest
} from '@opengamevcs/object-model';

const registry = await loadBundledRegistry();
process.stdout.write(`${JSON.stringify({
  counts: {
    commonFields: registry.commonFields.size,
    entryKinds: registry.entryKinds.size,
    entryModes: registry.entryModes.size,
    extensions: registry.extensions.size,
    hashAlgorithms: registry.hashAlgorithms.size,
    kindFields: registry.kindFields.size,
    limits: registry.limits.size,
    logicalRecordTypes: registry.logicalRecordTypes.size,
    objectKinds: registry.objectKinds.size,
    profiles: registry.profiles.size,
    requiredFeatures: registry.requiredFeatures.size,
    semanticEnumDomains: registry.semanticEnums.size
  },
  registrySetDigest: await registrySetDigest(bundledRegistryDirectory())
})}\n`);
