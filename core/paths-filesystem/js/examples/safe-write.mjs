import { readFile } from 'node:fs/promises';

import {
  atomicWriteFile, openWorkspaceRoot, preflightWorkspaceMaterialization,
  probeFilesystemCapabilities, validateRepositoryPath,
} from '@opengamevcs/path-filesystem';

const [root, repositoryPath, source] = process.argv.slice(2);
if (!root || !repositoryPath || !source) throw new Error('usage: node safe-write.mjs <absolute-root> <repository-path> <source-file>');
const workspace = await openWorkspaceRoot(root);
const canonical = validateRepositoryPath(repositoryPath, { profile: workspace.profile }).canonical;
const capabilities = await probeFilesystemCapabilities(workspace.root);
const segments = canonical.split('/');
const entries = segments.slice(0, -1).map((_, index) => ({
  id: `directory-${index}`, path: segments.slice(0, index + 1).join('/'), kind: 'directory', mode: 'directory',
}));
entries.push({ id: 'source', path: canonical, kind: 'regular', mode: 'regular-file' });
const plan = await preflightWorkspaceMaterialization(workspace, {
  schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: workspace.caseMode,
  profile: workspace.profile, platform: capabilities.platform,
  capabilities: { atomicReplace: capabilities.atomicReplace, executableBit: capabilities.executableBit, symlink: capabilities.symlink },
  entries,
});
const result = await atomicWriteFile(workspace, canonical, await readFile(source), { createParents: true, plan });
process.stdout.write(`${JSON.stringify(result)}\n`);
