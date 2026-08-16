import { readFile } from 'node:fs/promises';

import { atomicWriteFile, openWorkspaceRoot } from '@opengamevcs/path-filesystem';

const [root, repositoryPath, source] = process.argv.slice(2);
if (!root || !repositoryPath || !source) throw new Error('usage: node safe-write.mjs <absolute-root> <repository-path> <source-file>');
const workspace = await openWorkspaceRoot(root);
const result = await atomicWriteFile(workspace, repositoryPath, await readFile(source), { createParents: true });
process.stdout.write(`${JSON.stringify(result)}\n`);
