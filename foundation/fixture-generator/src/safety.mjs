import { constants as fsConstants } from 'node:fs';
import {
  access,
  link,
  lstat,
  mkdir,
  open,
  opendir,
  readdir,
  realpath,
  rm,
  rmdir,
  unlink,
} from 'node:fs/promises';
import path from 'node:path';

import { canonicalDigest, canonicalStringify } from './canonical.mjs';
import { GENERATOR_VERSION, TOOL_NAME } from './constants.mjs';
import { conflict, integrityFailure, unsafeDestination } from './errors.mjs';
import { atomicWriteCanonical, injectPersistenceFault, syncDirectory } from './io.mjs';

const OWNER_FILENAME = '.ogvcs-fixture-owner.json';
const OWNER_KIND = 'opengamevcs-fixture-generator-owned/v1';
const STAGE_INITIALIZATION_KIND = 'opengamevcs-fixture-stage-initialization/v1';
const PUBLICATION_RESERVATION_KIND = 'opengamevcs-fixture-publication-reservation/v1';
const STAGE_INITIALIZATION_ARTIFACT = '.stage-initialization-receipt';
const PUBLICATION_RESERVATION_ARTIFACT = '.publication-reservation-receipt';
const OWNED_ARTIFACTS = new Set([
  'checkpoint.json',
  'fixture-request.json',
  'groups.json',
  'inventory.ndjson',
  'large-file.json',
  'manifest.json',
  'operations.ndjson',
  'scenario.json',
  'workload-profile.json',
  'files',
]);
const ATOMIC_ARTIFACTS = new Set([
  OWNER_FILENAME,
  'checkpoint.json',
  'fixture-request.json',
  'groups.json',
  'large-file.json',
  'manifest.json',
  'workload-profile.json',
]);
let guardSequence = 0;
const MAX_OWNERSHIP_CONTROL_BYTES = 64 * 1024;

function hasExactKeys(value, expectedKeys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

async function exists(filePath) {
  try {
    await access(filePath, fsConstants.F_OK);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

export async function rejectSymlinkChain(targetPath, budget) {
  const absolute = path.resolve(targetPath);
  const parsed = path.parse(absolute);
  const relative = absolute.slice(parsed.root.length);
  const segments = relative.split(path.sep).filter(Boolean);
  let cursor = parsed.root;

  for (const segment of segments) {
    budget?.checkRuntime('workspace-path-validation');
    cursor = path.join(cursor, segment);
    let metadata;
    try {
      metadata = await lstat(cursor);
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    if (metadata.isSymbolicLink()) {
      throw unsafeDestination('Destination path traverses a symlink or junction', {
        path: cursor,
      });
    }
  }
}

export function deriveWorkspacePaths(destinationPath, requestDigest) {
  const destination = path.resolve(destinationPath);
  const parent = path.dirname(destination);
  const basename = path.basename(destination);
  const safeName = basename.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80) || 'fixture';
  // safeName is deliberately filesystem-friendly, but it is lossy and
  // truncated. Bind every control path to the exact resolved destination so
  // distinct Unicode or long sibling names remain cryptographically bound to
  // their exact resolved destination instead of relying on the display name.
  const destinationKey = canonicalDigest(
    { destination },
    'ogvcs.fixture/workspace-destination/v1',
  );
  const workspaceName = `${safeName}-${destinationKey}`;
  const requestKey = requestDigest.slice(0, 32);
  const controlPrefix = path.join(
    parent,
    `.${workspaceName}.ogvcs-fixture-${requestKey}`,
  );
  return {
    destination,
    lock: path.join(parent, `.${workspaceName}.ogvcs-fixture.lock`),
    parent,
    publicationReservation: `${controlPrefix}.publishing`,
    stage: path.join(parent, `.${workspaceName}.ogvcs-fixture-${requestKey}.stage`),
    stageInitialization: `${controlPrefix}.stage-initializing`,
  };
}

export async function prepareWorkspace(destinationPath, requestDigest, options = {}) {
  options.budget?.checkRuntime('workspace-prepare');
  const paths = deriveWorkspacePaths(destinationPath, requestDigest);
  await rejectSymlinkChain(paths.destination, options.budget);
  await mkdir(paths.parent, { recursive: true });
  await rejectSymlinkChain(paths.parent, options.budget);
  const parentRealpath = await realpath(paths.parent);
  const parentIdentity = await pathIdentity(paths.parent, 'directory');
  // The destination lock must cover every recovery mutation, not only new
  // generation. Otherwise a second resume can remove a live publisher's
  // manifest-free reservation between its artifact and manifest links.
  const releaseLock = await acquireWorkspaceLock(paths.lock, requestDigest, {
    budget: options.budget,
    env: options.env,
    resume: options.resume ?? false,
  });

  try {
    await recoverControlReceiptTemporaries(paths.stageInitialization, options);
    await recoverControlReceiptTemporaries(paths.publicationReservation, options);
    const expectedPublicationReceipt = publicationReservationDocument(paths, requestDigest);
    let publicationReceiptPresent = await exists(paths.publicationReservation);
    if (publicationReceiptPresent) {
      if (!options.resume) {
        throw unsafeDestination('A publication reservation receipt requires explicit --resume', {
          path: paths.publicationReservation,
        });
      }
      await assertControlReceipt(
        paths.publicationReservation,
        expectedPublicationReceipt,
        'Publication reservation receipt',
        { artifact: PUBLICATION_RESERVATION_ARTIFACT, budget: options.budget },
      );
    }

    if (await exists(paths.destination)) {
      const metadata = await lstat(paths.destination);
      if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
        throw unsafeDestination('Destination must be a real directory', {
          path: paths.destination,
        });
      }
      if (!options.resume) {
        throw unsafeDestination('Destination already exists; use --resume only for a compatible fixture', {
          path: paths.destination,
        });
      }
      const manifestMetadata = await lstat(path.join(paths.destination, 'manifest.json')).catch((error) => {
        if (error.code === 'ENOENT') return null;
        throw error;
      });
      if (manifestMetadata) {
        if (manifestMetadata.isSymbolicLink() || !manifestMetadata.isFile()) {
          throw unsafeDestination('Destination manifest is not a regular file', {
            path: paths.destination,
          });
        }
        if (publicationReceiptPresent) {
          throw unsafeDestination('Completed destination has a dangling publication reservation receipt', {
            path: paths.publicationReservation,
          });
        }
        return {
          ...paths,
          completedDestination: true,
          parentIdentity,
          parentRealpath,
          releaseLock,
        };
      }

      // Publication reserves the destination before linking artifacts and links
      // the manifest last. A killed publisher can therefore leave an owned,
      // incomplete destination. Every entry must still be a hard link/subtree of
      // the intact owned stage before we remove that reservation for resume.
      if (!await exists(paths.stage)) {
        throw unsafeDestination('Incomplete destination has no owned stage for recovery', {
          path: paths.destination,
        });
      }
      await assertOwnedDirectory(paths.stage, requestDigest);
      const destinationEntries = await readdir(paths.destination, { withFileTypes: true });
      if (destinationEntries.length === 0) {
        // The durable request-bound sibling receipt is installed before mkdir,
        // so an arbitrary pre-existing empty directory is never adopted as a
        // generator publication reservation.
        if (!publicationReceiptPresent) {
          throw unsafeDestination('Empty destination has no publication reservation proof', {
            path: paths.destination,
          });
        }
        await rmdir(paths.destination);
      } else {
        await assertOwnedDirectory(paths.destination, requestDigest);
        await assertLinkedPublicationSubset(paths.stage, paths.destination, options.budget);
        await rm(paths.destination, { recursive: true });
      }
      await syncDirectory(paths.parent, 'incomplete-publication-cleanup-sync');
      if (publicationReceiptPresent) {
        await removeControlReceipt(
          paths.publicationReservation,
          PUBLICATION_RESERVATION_ARTIFACT,
          'publication-reservation-recovery-sync',
          options.budget,
        );
        publicationReceiptPresent = false;
      }
      options.budget?.checkRuntime('workspace-recovery');
    } else if (publicationReceiptPresent) {
      if (!await exists(paths.stage)) {
        throw unsafeDestination('Publication receipt has no intact owned stage', {
          path: paths.publicationReservation,
        });
      }
      await assertOwnedDirectory(paths.stage, requestDigest);
      await removeControlReceipt(
        paths.publicationReservation,
        PUBLICATION_RESERVATION_ARTIFACT,
        'publication-reservation-recovery-sync',
        options.budget,
      );
      publicationReceiptPresent = false;
    }

    const expectedStageReceipt = stageInitializationDocument(paths, requestDigest);
    let stageReceiptPresent = await exists(paths.stageInitialization);
    if (stageReceiptPresent) {
      if (!options.resume) {
        throw unsafeDestination('A stage initialization receipt requires explicit --resume', {
          path: paths.stageInitialization,
        });
      }
      await assertControlReceipt(
        paths.stageInitialization,
        expectedStageReceipt,
        'Stage initialization receipt',
        { artifact: STAGE_INITIALIZATION_ARTIFACT, budget: options.budget },
      );
    }

    if (await exists(paths.stage)) {
      if (!options.resume) {
        throw unsafeDestination('A staging directory already exists; explicit --resume is required', {
          path: paths.stage,
        });
      }
      try {
        await assertOwnedDirectory(paths.stage, requestDigest);
      } catch (error) {
        if (
          !stageReceiptPresent
          || !await recoverInitializingStage(paths.stage, requestDigest, options)
        ) throw error;
      }
      if (stageReceiptPresent) {
        await removeControlReceipt(
          paths.stageInitialization,
          STAGE_INITIALIZATION_ARTIFACT,
          'stage-initialization-recovery-sync',
          options.budget,
        );
        stageReceiptPresent = false;
      }
    } else {
      let createdStage = false;
      let createdStageIdentity;
      let stageRemoved = false;
      try {
        if (!stageReceiptPresent) {
          await installControlReceipt(
            paths.stageInitialization,
            expectedStageReceipt,
            'Stage initialization receipt',
            { artifact: STAGE_INITIALIZATION_ARTIFACT, budget: options.budget },
          );
          stageReceiptPresent = true;
        }
        await mkdir(paths.stage, { mode: 0o700 });
        createdStage = true;
        await syncDirectory(paths.parent, 'stage-create-parent-sync');
        if (options.env?.OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_STAGE_CREATE === '1') {
          process.exit(99);
        }
        createdStageIdentity = await pathIdentity(paths.stage, 'directory');
        await atomicWriteCanonical(
          path.join(paths.stage, OWNER_FILENAME),
          ownerDocument(requestDigest),
          {
            artifact: OWNER_FILENAME,
            budget: options.budget,
          },
        );
        await removeControlReceipt(
          paths.stageInitialization,
          STAGE_INITIALIZATION_ARTIFACT,
          'stage-initialization-commit-sync',
          options.budget,
        );
        stageReceiptPresent = false;
      } catch (error) {
        if (createdStage) {
          try {
            if (createdStageIdentity) {
              await assertSameIdentity(paths.stage, createdStageIdentity, 'directory');
            } else {
              const metadata = await lstat(paths.stage);
              if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
                throw unsafeDestination('New staging directory changed type during initialization', {
                  path: paths.stage,
                });
              }
            }
            const entries = await readdir(paths.stage, { withFileTypes: true });
            if (entries.some((entry) => entry.isSymbolicLink() || entry.name !== OWNER_FILENAME)) {
              throw unsafeDestination('New staging directory changed during initialization', {
                path: paths.stage,
              });
            }
            await rm(paths.stage, { recursive: true });
            stageRemoved = true;
            options.budget?.removeArtifact(OWNER_FILENAME);
            await syncDirectory(paths.parent, 'stage-create-abort-parent-sync');
          } catch (cleanupError) {
            error.workspaceCleanup = cleanupError.message;
          }
        } else {
          stageRemoved = true;
        }
        if (stageReceiptPresent && stageRemoved) {
          try {
            await removeControlReceipt(
              paths.stageInitialization,
              STAGE_INITIALIZATION_ARTIFACT,
              'stage-initialization-abort-sync',
              options.budget,
            );
            stageReceiptPresent = false;
          } catch (cleanupError) {
            error.workspaceReceiptCleanup = cleanupError.message;
          }
        }
        throw error;
      }
    }

    options.budget?.checkRuntime('workspace-prepare');
    return {
      ...paths,
      completedDestination: false,
      parentIdentity,
      parentRealpath,
      releaseLock,
      stageIdentity: await pathIdentity(paths.stage, 'directory'),
    };
  } catch (error) {
    try {
      await releaseLock();
    } catch (cleanupError) {
      error.workspaceLockCleanup = cleanupError.message;
    }
    throw error;
  }
}

async function pathIdentity(targetPath, kind) {
  // Windows file indices and POSIX inode/device numbers may exceed the exact
  // integer range of a JavaScript Number. BigInt stats keep identity checks
  // lossless on every supported host.
  const metadata = await lstat(targetPath, { bigint: true }).catch((error) => {
    throw unsafeDestination(`Expected ${kind} is unavailable`, { code: error.code, path: targetPath });
  });
  if (
    metadata.isSymbolicLink()
    || (kind === 'directory' && !metadata.isDirectory())
    || (kind === 'file' && !metadata.isFile())
  ) {
    throw unsafeDestination(`Expected ${kind} changed type`, { path: targetPath });
  }
  return { dev: metadata.dev.toString(), ino: metadata.ino.toString() };
}

async function assertSameIdentity(targetPath, expected, kind) {
  const actual = await pathIdentity(targetPath, kind);
  if (actual.dev !== expected.dev || actual.ino !== expected.ino) {
    throw unsafeDestination(`Workspace ${kind} identity changed during generation`, {
      actual,
      expected,
      path: targetPath,
    });
  }
}

export async function assertOwnedDirectory(directory, requestDigest) {
  const metadata = await lstat(directory).catch((error) => {
    throw unsafeDestination('Expected generator staging directory is unavailable', {
      code: error.code,
      path: directory,
    });
  });
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw unsafeDestination('Generator staging path is not a real directory', { path: directory });
  }

  const ownerPath = path.join(directory, OWNER_FILENAME);
  const ownerMetadata = await lstat(ownerPath).catch(() => null);
  if (!ownerMetadata?.isFile() || ownerMetadata.isSymbolicLink()) {
    throw unsafeDestination('Staging directory has no valid ownership marker', { path: directory });
  }

  let owner;
  try {
    owner = await readRegularJson(ownerPath, 'staging ownership marker');
  } catch (error) {
    throw unsafeDestination('Staging ownership marker is malformed', {
      path: ownerPath,
      reason: error.message,
    });
  }
  if (
    !hasExactKeys(owner, ['generatorVersion', 'kind', 'requestDigest', 'tool'])
    || owner.generatorVersion !== GENERATOR_VERSION
    || owner.kind !== OWNER_KIND
    || owner.tool !== TOOL_NAME
    || owner.requestDigest !== requestDigest
  ) {
    throw unsafeDestination('Staging directory belongs to another request or tool', {
      path: directory,
    });
  }
  return owner;
}

function pidIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

async function readRegularJson(filePath, description) {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  let handle;
  try {
    handle = await open(filePath, fsConstants.O_RDONLY | noFollow);
    const metadata = await handle.stat();
    if (!metadata.isFile()) throw new Error(`${description} is not a regular file`);
    if (metadata.size > MAX_OWNERSHIP_CONTROL_BYTES) {
      throw new Error(`${description} exceeds its ${MAX_OWNERSHIP_CONTROL_BYTES}-byte safe bound`);
    }
    return JSON.parse(await handle.readFile('utf8'));
  } finally {
    await handle?.close().catch(() => {});
  }
}

function ownerDocument(requestDigest) {
  return {
    generatorVersion: GENERATOR_VERSION,
    kind: OWNER_KIND,
    requestDigest,
    tool: TOOL_NAME,
  };
}

function stageInitializationDocument(paths, requestDigest) {
  return {
    generatorVersion: GENERATOR_VERSION,
    kind: STAGE_INITIALIZATION_KIND,
    requestDigest,
    stageName: path.basename(paths.stage),
    tool: TOOL_NAME,
  };
}

function publicationReservationDocument(paths, requestDigest) {
  return {
    destinationName: path.basename(paths.destination),
    generatorVersion: GENERATOR_VERSION,
    kind: PUBLICATION_RESERVATION_KIND,
    requestDigest,
    stageName: path.basename(paths.stage),
    tool: TOOL_NAME,
  };
}

async function assertControlReceipt(filePath, expected, description, options = {}) {
  let actual;
  try {
    actual = await readRegularJson(filePath, description);
  } catch (error) {
    throw unsafeDestination(`${description} is missing, malformed, or unsafe`, {
      path: filePath,
      reason: error.message,
    });
  }
  if (canonicalStringify(actual) !== canonicalStringify(expected)) {
    throw unsafeDestination(`${description} belongs to another request or workspace`, {
      path: filePath,
    });
  }
  const metadata = await lstat(filePath);
  options.budget?.setArtifactBytes(options.artifact, metadata.size);
}

async function installControlReceipt(filePath, document, description, options = {}) {
  if (await exists(filePath)) {
    throw unsafeDestination(`${description} already exists; explicit recovery is required`, {
      path: filePath,
    });
  }
  await atomicWriteCanonical(filePath, document, {
    artifact: options.artifact,
    budget: options.budget,
  });
}

async function removeControlReceipt(filePath, artifact, boundary, budget) {
  await unlink(filePath);
  budget?.removeArtifact(artifact);
  await syncDirectory(path.dirname(filePath), boundary);
}

async function recoverControlReceiptTemporaries(filePath, options = {}) {
  const prefix = `${path.basename(filePath)}.tmp-`;
  const candidates = [];
  const directory = await opendir(path.dirname(filePath));
  for await (const entry of directory) {
    options.budget?.checkRuntime('control-receipt-recovery-scan');
    if (!entry.name.startsWith(prefix)) continue;
    const match = /^([1-9][0-9]*)-([1-9][0-9]*)$/u.exec(entry.name.slice(prefix.length));
    if (!match || !entry.isFile() || entry.isSymbolicLink()) {
      throw unsafeDestination('Control-receipt temporary is malformed or unsafe', {
        path: path.join(path.dirname(filePath), entry.name),
      });
    }
    const pid = Number(match[1]);
    if (!Number.isSafeInteger(pid) || pidIsAlive(pid)) {
      throw conflict('A generator may still own a control-receipt temporary', {
        path: path.join(path.dirname(filePath), entry.name),
        pid,
      });
    }
    candidates.push(path.join(path.dirname(filePath), entry.name));
  }
  if (candidates.length === 0) return;
  if (!options.resume) {
    throw unsafeDestination('A stale control-receipt temporary requires explicit --resume', {
      path: filePath,
    });
  }
  for (const candidate of candidates) await unlink(candidate);
  await syncDirectory(path.dirname(filePath), 'control-receipt-temporary-cleanup-sync');
}

function isOwnedAtomicTemporaryName(entryName, artifact) {
  if (!entryName.startsWith(`${artifact}.tmp-`)) return false;
  return /^[1-9][0-9]*-[1-9][0-9]*$/u.test(
    entryName.slice(`${artifact}.tmp-`.length),
  );
}

async function recoverInitializingStage(stage, requestDigest, options = {}) {
  if (!options.resume) return false;
  const metadata = await lstat(stage).catch(() => null);
  if (!metadata?.isDirectory() || metadata.isSymbolicLink()) return false;
  const entries = await readdir(stage, { withFileTypes: true });
  for (const entry of entries) {
    if (
      !isOwnedAtomicTemporaryName(entry.name, OWNER_FILENAME)
      || !entry.isFile()
      || entry.isSymbolicLink()
    ) return false;
  }
  for (const entry of entries) await unlink(path.join(stage, entry.name));
  if (entries.length > 0) await syncDirectory(stage, 'stage-initialization-temporary-cleanup-sync');
  await atomicWriteCanonical(path.join(stage, OWNER_FILENAME), ownerDocument(requestDigest), {
    artifact: OWNER_FILENAME,
    budget: options.budget,
  });
  return true;
}

async function installLockGuard(guardPath, document) {
  let candidatePath;
  let handle;
  while (!handle) {
    guardSequence += 1;
    candidatePath = `${guardPath}.candidate-${process.pid}-${guardSequence}`;
    try {
      injectPersistenceFault('lock-guard-open', guardPath);
      handle = await open(candidatePath, 'wx', 0o600);
    } catch (error) {
      if (error.code === 'EEXIST') continue;
      throw error;
    }
  }
  try {
    injectPersistenceFault('lock-guard-write', guardPath);
    await handle.writeFile(`${canonicalStringify(document)}\n`);
    injectPersistenceFault('lock-guard-sync', guardPath);
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => {});
    await unlink(candidatePath).catch(() => {});
    throw error;
  }
  await handle.close();

  let installed = false;
  try {
    await link(candidatePath, guardPath);
    installed = true;
  } catch (error) {
    if (error.code !== 'EEXIST') {
      if (['EACCES', 'EMLINK', 'ENOTSUP', 'EOPNOTSUPP', 'EPERM', 'EROFS', 'EXDEV'].includes(error.code)) {
        throw unsafeDestination('Filesystem cannot provide required hard-link lock arbitration', {
          code: error.code,
          path: guardPath,
        });
      }
      throw error;
    }
  } finally {
    await unlink(candidatePath).catch(() => {});
  }
  if (!installed) return false;
  try {
    await syncDirectory(path.dirname(guardPath), 'lock-guard-parent-sync');
  } catch (error) {
    await unlink(guardPath).catch(() => {});
    throw error;
  }
  return true;
}

async function removeStaleLockGuardCandidates(guardPath, options = {}) {
  const parent = path.dirname(guardPath);
  const prefix = `${path.basename(guardPath)}.candidate-`;
  const candidates = [];
  const directory = await opendir(parent);
  for await (const entry of directory) {
    options.budget?.checkRuntime('lock-guard-candidate-recovery-scan');
    if (!entry.name.startsWith(prefix)) continue;
    const match = /^([1-9][0-9]*)-([1-9][0-9]*)$/u.exec(entry.name.slice(prefix.length));
    if (!match || !entry.isFile() || entry.isSymbolicLink()) {
      throw conflict('Lock-guard candidate is malformed or unsafe', {
        path: path.join(parent, entry.name),
      });
    }
    const pid = Number(match[1]);
    if (!Number.isSafeInteger(pid) || pidIsAlive(pid)) {
      throw conflict('A generator may still own a lock-guard candidate', {
        path: path.join(parent, entry.name),
        pid,
      });
    }
    candidates.push(path.join(parent, entry.name));
  }
  if (candidates.length === 0) return;
  if (!options.resume) {
    throw conflict('A stale compatible lock-guard candidate requires explicit --resume', {
      path: guardPath,
    });
  }
  for (const candidate of candidates) await unlink(candidate);
  await syncDirectory(parent, 'lock-guard-candidate-cleanup-sync');
}

async function removeOrphanedGuardRecoveryControls(guardPath, requestDigest, options = {}) {
  const parent = path.dirname(guardPath);
  const prefix = `${path.basename(guardPath)}.recovery-`;
  const stalePaths = [];
  const directory = await opendir(parent);
  for await (const entry of directory) {
    options.budget?.checkRuntime('lock-guard-orphan-recovery-scan');
    if (!entry.name.startsWith(prefix)) continue;
    if (!entry.isFile() || entry.isSymbolicLink()) {
      throw conflict('Lock-guard recovery control is malformed or unsafe', {
        path: path.join(parent, entry.name),
      });
    }
    const suffix = entry.name.slice(prefix.length);
    const candidate = /^([0-9a-f]{64})-([1-9][0-9]*)\.candidate-([1-9][0-9]*)-([1-9][0-9]*)$/u.exec(suffix);
    if (candidate) {
      const pid = Number(candidate[3]);
      if (!Number.isSafeInteger(pid) || pidIsAlive(pid)) continue;
      stalePaths.push(path.join(parent, entry.name));
      continue;
    }
    const final = /^([0-9a-f]{64})-([1-9][0-9]*)$/u.exec(suffix);
    if (!final) {
      throw conflict('Lock-guard recovery control has an invalid name', {
        path: path.join(parent, entry.name),
      });
    }
    const staleGuardDigest = final[1];
    const generation = Number(final[2]);
    const epochPath = path.join(parent, entry.name);
    let epoch;
    try {
      epoch = await readRegularJson(epochPath, 'lock-guard recovery epoch');
    } catch (error) {
      throw conflict('Orphaned lock-guard recovery epoch is malformed', {
        path: epochPath,
        reason: error.message,
      });
    }
    if (
      !hasExactKeys(epoch, [
        'generation',
        'kind',
        'pid',
        'requestDigest',
        'staleGuardDigest',
        'tool',
      ])
      || epoch.kind !== 'opengamevcs-fixture-generator-lock-guard-recovery/v1'
      || epoch.tool !== TOOL_NAME
      || epoch.requestDigest !== requestDigest
      || epoch.staleGuardDigest !== staleGuardDigest
      || epoch.generation !== generation
      || !Number.isSafeInteger(epoch.pid)
      || epoch.pid <= 0
    ) {
      throw conflict('Orphaned lock-guard recovery epoch is incompatible', {
        path: epochPath,
      });
    }
    if (!pidIsAlive(epoch.pid)) stalePaths.push(epochPath);
  }
  if (stalePaths.length === 0) return;
  if (!options.resume) {
    throw conflict('Orphaned lock-guard recovery controls require explicit --resume', {
      path: guardPath,
    });
  }
  for (const stalePath of stalePaths) await unlink(stalePath);
  await syncDirectory(parent, 'lock-guard-orphan-recovery-cleanup-sync');
}

async function installWorkspaceLock(lockPath, document, options = {}) {
  let candidatePath;
  let handle;
  const requestKey = document.requestDigest.slice(0, 32);
  while (!handle) {
    guardSequence += 1;
    candidatePath = `${lockPath}.candidate-${requestKey}-${process.pid}-${guardSequence}`;
    try {
      injectPersistenceFault('lock-open', lockPath);
      handle = await open(candidatePath, 'wx', 0o600);
    } catch (error) {
      if (error.code === 'EEXIST') continue;
      throw error;
    }
  }
  if (options.env?.OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_LOCK_CANDIDATE_CREATE === '1') {
    process.exit(99);
  }
  try {
    injectPersistenceFault('lock-write', lockPath);
    await handle.writeFile(`${canonicalStringify(document)}\n`);
    injectPersistenceFault('lock-sync', lockPath);
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => {});
    await unlink(candidatePath).catch(() => {});
    throw error;
  }
  await handle.close();

  let installed = false;
  try {
    await link(candidatePath, lockPath);
    installed = true;
  } catch (error) {
    if (error.code !== 'EEXIST') {
      if (['EACCES', 'EMLINK', 'ENOTSUP', 'EOPNOTSUPP', 'EPERM', 'EROFS', 'EXDEV'].includes(error.code)) {
        throw unsafeDestination('Filesystem cannot provide required hard-link lock installation', {
          code: error.code,
          path: lockPath,
        });
      }
      throw error;
    }
  } finally {
    await unlink(candidatePath).catch(() => {});
  }
  if (!installed) return false;
  try {
    await syncDirectory(path.dirname(lockPath), 'lock-parent-sync');
  } catch (error) {
    await unlink(lockPath).catch(() => {});
    throw error;
  }
  return true;
}

async function removeStaleWorkspaceLockCandidates(lockPath, requestDigest, options = {}) {
  const parent = path.dirname(lockPath);
  const prefix = `${path.basename(lockPath)}.candidate-${requestDigest.slice(0, 32)}-`;
  const candidates = [];
  const directory = await opendir(parent);
  for await (const entry of directory) {
    options.budget?.checkRuntime('lock-candidate-recovery-scan');
    if (!entry.name.startsWith(prefix)) continue;
    const suffix = entry.name.slice(prefix.length);
    const match = /^([1-9][0-9]*)-([1-9][0-9]*)$/u.exec(suffix);
    if (!match || !entry.isFile() || entry.isSymbolicLink()) {
      throw conflict('Workspace lock candidate is malformed or unsafe', {
        path: path.join(parent, entry.name),
      });
    }
    const pid = Number(match[1]);
    if (!Number.isSafeInteger(pid) || pidIsAlive(pid)) {
      throw conflict('A generator may still own a workspace lock candidate', {
        path: path.join(parent, entry.name),
        pid,
      });
    }
    candidates.push(path.join(parent, entry.name));
  }
  if (candidates.length === 0) return;
  if (!options.resume) {
    throw conflict('A stale compatible lock candidate requires explicit --resume', {
      path: lockPath,
    });
  }
  for (const candidate of candidates) await unlink(candidate);
  await syncDirectory(parent, 'lock-candidate-cleanup-sync');
}

async function acquireGuardRecoveryEpoch(
  guardPath,
  staleGuard,
  requestDigest,
  options = {},
) {
  const parent = path.dirname(guardPath);
  const guardName = path.basename(guardPath);
  const staleGuardDigest = canonicalDigest(
    staleGuard,
    'ogvcs.fixture/lock-guard-recovery-key/v1',
  );
  const prefix = `${guardName}.recovery-${staleGuardDigest}-`;
  let latest;
  const priorDeadEpochPaths = [];
  const parentDirectory = await opendir(parent);
  for await (const entry of parentDirectory) {
    options.budget?.checkRuntime('lock-guard-recovery-scan');
    const entryName = entry.name;
    if (!entryName.startsWith(prefix)) continue;
    const suffix = entryName.slice(prefix.length);
    // Atomic-install candidates deliberately share the prefix but never have a
    // canonical integer suffix. They are not admission receipts.
    if (!/^[1-9][0-9]*$/u.test(suffix)) continue;
    const generation = Number(suffix);
    if (!Number.isSafeInteger(generation)) {
      throw conflict('Lock-guard recovery generation exceeds the safe integer range', {
        path: path.join(parent, entryName),
      });
    }
    const epochPath = path.join(parent, entryName);
    let epoch;
    try {
      epoch = await readRegularJson(epochPath, 'lock-guard recovery epoch');
    } catch (error) {
      throw conflict('Existing lock-guard recovery epoch is not a valid owned receipt', {
        path: epochPath,
        reason: error.message,
      });
    }
    if (
      !hasExactKeys(epoch, [
        'generation',
        'kind',
        'pid',
        'requestDigest',
        'staleGuardDigest',
        'tool',
      ])
      || epoch.kind !== 'opengamevcs-fixture-generator-lock-guard-recovery/v1'
      || epoch.tool !== TOOL_NAME
      || epoch.requestDigest !== requestDigest
      || epoch.staleGuardDigest !== staleGuardDigest
      || epoch.generation !== generation
      || !Number.isSafeInteger(epoch.pid)
      || epoch.pid <= 0
    ) {
      throw conflict('Existing lock-guard recovery epoch is incompatible or malformed', {
        path: epochPath,
      });
    }
    if (!latest || epoch.generation > latest.generation) {
      latest = { ...epoch, path: epochPath };
    }
    if (!pidIsAlive(epoch.pid)) priorDeadEpochPaths.push(epochPath);
  }

  if (latest && pidIsAlive(latest.pid)) {
    throw conflict('Another resume process is recovering the stale destination guard', {
      path: guardPath,
      pid: latest.pid,
    });
  }
  const generation = (latest?.generation ?? 0) + 1;
  if (!Number.isSafeInteger(generation)) {
    throw conflict('Lock-guard recovery generation is exhausted', { path: guardPath });
  }
  const pauseValue = options.env?.OGVCS_FIXTURE_TEST_PAUSE_AFTER_GUARD_RECOVERY_EPOCH_MS;
  let pauseMilliseconds;
  if (pauseValue !== undefined) {
    if (!/^[1-9][0-9]*$/u.test(pauseValue)) {
      throw unsafeDestination('Test recovery-epoch pause must be a positive canonical integer');
    }
    pauseMilliseconds = Number(pauseValue);
    if (!Number.isSafeInteger(pauseMilliseconds) || pauseMilliseconds > 30_000) {
      throw unsafeDestination('Test recovery-epoch pause cannot exceed 30000 milliseconds');
    }
  }
  const epochPath = path.join(parent, `${prefix}${generation}`);
  await removeStaleLockGuardCandidates(epochPath, options);
  const installed = await installLockGuard(epochPath, {
    generation,
    kind: 'opengamevcs-fixture-generator-lock-guard-recovery/v1',
    pid: process.pid,
    requestDigest,
    staleGuardDigest,
    tool: TOOL_NAME,
  });
  if (!installed) {
    throw conflict('Another resume process won stale lock-guard recovery admission', {
      path: guardPath,
    });
  }

  if (options.env?.OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_GUARD_RECOVERY_EPOCH === '1') {
    process.exit(99);
  }

  if (priorDeadEpochPaths.length > 0) {
    for (const priorPath of priorDeadEpochPaths) await unlink(priorPath);
    await syncDirectory(parent, 'lock-guard-prior-epoch-cleanup-sync');
  }

  if (pauseMilliseconds !== undefined) {
    await new Promise((resolve) => setTimeout(resolve, pauseMilliseconds));
  }
  return epochPath;
}

async function acquireLockGuard(guardPath, requestDigest, options = {}) {
  const document = {
    kind: 'opengamevcs-fixture-generator-lock-guard/v1',
    pid: process.pid,
    requestDigest,
    tool: TOOL_NAME,
  };
  await removeStaleLockGuardCandidates(guardPath, options);
  const installedFresh = await installLockGuard(guardPath, document);
  if (installedFresh) {
    try {
      await removeOrphanedGuardRecoveryControls(guardPath, requestDigest, options);
    } catch (error) {
      await unlink(guardPath).catch(() => {});
      await syncDirectory(path.dirname(guardPath), 'lock-guard-orphan-recovery-abort-sync').catch(() => {});
      throw error;
    }
  } else {
    let existing;
    try {
      existing = await readRegularJson(guardPath, 'generator lock guard');
    } catch (error) {
      throw conflict('Existing generator lock guard is not a valid owned guard', {
        path: guardPath,
        reason: error.message,
      });
    }
    if (
      !hasExactKeys(existing, ['kind', 'pid', 'requestDigest', 'tool'])
      || !Number.isSafeInteger(existing.pid)
      || existing.pid <= 0
      || existing.kind !== document.kind
      || existing.tool !== TOOL_NAME
      || existing.requestDigest !== requestDigest
    ) {
      throw conflict('Destination lock guard belongs to another or incompatible request', {
        path: guardPath,
      });
    }
    if (pidIsAlive(existing.pid)) {
      throw conflict('Another generator is acquiring this destination lock', {
        path: guardPath,
        pid: existing.pid,
      });
    }
    if (!options.resume) {
      throw conflict('A stale compatible lock guard requires explicit --resume', { path: guardPath });
    }

    let recoveryEpochPath;
    try {
      recoveryEpochPath = await acquireGuardRecoveryEpoch(
        guardPath,
        existing,
        requestDigest,
        options,
      );
      const current = await readRegularJson(guardPath, 'generator lock guard').catch((error) => {
        throw conflict('Stale generator lock guard changed during recovery', {
          path: guardPath,
          reason: error.message,
        });
      });
      if (canonicalDigest(current) !== canonicalDigest(existing) || pidIsAlive(current.pid)) {
        throw conflict('Stale generator lock guard changed during recovery', { path: guardPath });
      }
      await unlink(guardPath);
      if (options.env?.OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_STALE_GUARD_UNLINK === '1') {
        process.exit(99);
      }
      if (!await installLockGuard(guardPath, document)) {
        throw conflict('Another generator won stale lock-guard recovery', { path: guardPath });
      }
      try {
        await unlink(recoveryEpochPath);
        await syncDirectory(path.dirname(guardPath), 'lock-guard-recovery-epoch-cleanup-sync');
        recoveryEpochPath = undefined;
      } catch (error) {
        // Do not return a held guard while reporting acquisition failure.
        // The newly installed guard is still known to be ours at this point.
        await unlink(guardPath).catch(() => {});
        await syncDirectory(path.dirname(guardPath), 'lock-guard-recovery-abort-sync').catch(() => {});
        throw error;
      }
    } catch (error) {
      // This process is no longer a recovery contender. Removing only the
      // receipt it atomically installed permits a later explicit resume while
      // every delayed contender must still re-read the exact stale guard.
      if (recoveryEpochPath) await unlink(recoveryEpochPath).catch(() => {});
      throw error;
    }
  }
  return async () => {
    const current = await readRegularJson(guardPath, 'generator lock guard').catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (current && canonicalDigest(current) !== canonicalDigest(document)) {
      throw conflict('Generator lock guard changed while held', { path: guardPath });
    }
    if (current) await unlink(guardPath);
  };
}

export async function acquireWorkspaceLock(lockPath, requestDigest, options = {}) {
  const lockDocument = {
    kind: 'opengamevcs-fixture-generator-lock/v1',
    pid: process.pid,
    requestDigest,
    tool: TOOL_NAME,
  };

  const guardPath = `${lockPath}.guard`;
  const releaseGuard = await acquireLockGuard(guardPath, requestDigest, options);
  let installedByThisProcess = false;
  try {
    await removeStaleWorkspaceLockCandidates(lockPath, requestDigest, options);
    installedByThisProcess = await installWorkspaceLock(lockPath, lockDocument, options);
    if (!installedByThisProcess) {
      let existing;
      try {
        existing = await readRegularJson(lockPath, 'generator lock');
      } catch (readError) {
        throw conflict('Existing generator lock is not a valid owned lock', {
          path: lockPath,
          reason: readError.message,
        });
      }

      if (
        !hasExactKeys(existing, ['kind', 'pid', 'requestDigest', 'tool'])
        || !Number.isSafeInteger(existing.pid)
        || existing.pid <= 0
        || existing.kind !== lockDocument.kind
        || existing.tool !== TOOL_NAME
        || existing.requestDigest !== requestDigest
      ) {
        throw conflict('Destination is locked by another or incompatible request', {
          path: lockPath,
        });
      }
      if (pidIsAlive(existing.pid)) {
        throw conflict('A generator process already owns this destination', {
          path: lockPath,
          pid: existing.pid,
        });
      }
      if (!options.resume) {
        throw conflict('A stale compatible lock requires explicit --resume', { path: lockPath });
      }
      await unlink(lockPath);
      installedByThisProcess = await installWorkspaceLock(lockPath, lockDocument, options);
      if (!installedByThisProcess) {
        throw conflict('Another generator won workspace lock installation', { path: lockPath });
      }
    }
    await releaseGuard();
  } catch (error) {
    if (installedByThisProcess) await unlink(lockPath).catch(() => {});
    await releaseGuard().catch(() => {});
    throw error;
  }

  let released = false;
  let releasing = false;
  return async () => {
    if (released) return;
    try {
      if (releasing) throw conflict('Generator lock release is already in progress', { path: lockPath });
      releasing = true;
      injectPersistenceFault('lock-release', lockPath);
      let current;
      try {
        current = await readRegularJson(lockPath, 'generator lock');
      } catch (error) {
        if (error.code === 'ENOENT') {
          released = true;
          return;
        }
        throw integrityFailure('Cannot safely release generator lock', {
          path: lockPath,
          reason: error.message,
        });
      }
      if (canonicalDigest(current) !== canonicalDigest(lockDocument)) {
        throw conflict('Generator lock changed while held; refusing to remove it', { path: lockPath });
      }
      await unlink(lockPath);
      released = true;
    } finally {
      releasing = false;
    }
  };
}

export async function removeOwnedArtifacts(stage, requestDigest, relativePaths) {
  await assertOwnedDirectory(stage, requestDigest);
  for (const relativePath of relativePaths) {
    if (
      !OWNED_ARTIFACTS.has(relativePath)
      || relativePath.includes('/')
      || relativePath.includes('\\')
      || path.isAbsolute(relativePath)
      || relativePath.split(/[\\/]/).some((segment) => segment === '..')
    ) {
      throw unsafeDestination('Refusing to remove an unsafe artifact path', { relativePath });
    }
    const target = path.join(stage, relativePath);
    await rm(target, { force: true, recursive: true });
  }
}

export async function removeOwnedAtomicTemporaryArtifacts(stage, requestDigest) {
  await assertOwnedDirectory(stage, requestDigest);
  const removed = [];
  for (const entry of await readdir(stage, { withFileTypes: true })) {
    const base = [...ATOMIC_ARTIFACTS].find((name) => entry.name.startsWith(`${name}.tmp-`));
    if (!base) continue;
    const suffix = entry.name.slice(`${base}.tmp-`.length);
    if (!/^[1-9][0-9]*-[1-9][0-9]*$/.test(suffix)) continue;
    if (!entry.isFile() || entry.isSymbolicLink()) {
      throw unsafeDestination('Owned atomic temporary artifact changed type', { artifact: entry.name });
    }
    await unlink(path.join(stage, entry.name));
    removed.push(entry.name);
  }
  if (removed.length > 0) await syncDirectory(stage, 'atomic-temporary-cleanup-sync');
  return { removed: removed.sort() };
}

export async function assertWorkspaceArtifactAllowlist(stage, requestDigest, options = {}) {
  await assertOwnedDirectory(stage, requestDigest);
  const allowed = new Set([OWNER_FILENAME, ...(options.allowed ?? OWNED_ARTIFACTS)]);
  const required = new Set([OWNER_FILENAME, ...(options.required ?? [])]);
  const entries = await readdir(stage, { withFileTypes: true });
  const present = new Set();
  for (const entry of entries) {
    present.add(entry.name);
    if (entry.isSymbolicLink()) {
      throw unsafeDestination('Workspace contains a symbolic-link artifact', { artifact: entry.name });
    }
    if (!allowed.has(entry.name)) {
      throw unsafeDestination('Workspace contains an unknown artifact', { artifact: entry.name });
    }
  }
  for (const name of required) {
    if (!present.has(name)) throw integrityFailure('Workspace is missing a required artifact', { artifact: name });
  }
  return { artifacts: [...present].sort() };
}

/**
 * Remove a stage left behind after a durable publication, but only when its
 * complete tree is still the hard-linked twin of the deeply verified
 * destination. This is deliberately stricter than ownership-marker checking:
 * content added to either tree after publication makes reconciliation a safe
 * no-op failure for the caller to report as a post-commit warning.
 */
export async function reconcileCompletedOwnedStage(stage, destination, requestDigest, budget) {
  budget?.checkRuntime('completed-stage-reconciliation');
  const metadata = await lstat(stage).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!metadata) return false;
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw unsafeDestination('Completed fixture stage is not a real directory', { path: stage });
  }

  await assertOwnedDirectory(stage, requestDigest);
  await assertWorkspaceArtifactAllowlist(stage, requestDigest);
  await assertLinkedPublicationSubset(stage, destination, budget);
  await assertLinkedPublicationSubset(destination, stage, budget);
  injectPersistenceFault('completed-stage-reconciliation-remove', stage);
  await rm(stage, { recursive: true });
  await syncDirectory(path.dirname(stage), 'completed-stage-reconciliation-sync');
  budget?.checkRuntime('completed-stage-reconciliation');
  return true;
}

async function assertLinkedPublicationSubset(stage, destination, budget) {
  const visit = async (sourceDirectory, publishedDirectory) => {
    for (const entry of await readdir(publishedDirectory, { withFileTypes: true })) {
      budget?.checkRuntime('publication-recovery');
      if (entry.isSymbolicLink()) {
        throw unsafeDestination('Incomplete publication contains a symbolic link', {
          artifact: path.relative(destination, path.join(publishedDirectory, entry.name)),
        });
      }
      const source = path.join(sourceDirectory, entry.name);
      const published = path.join(publishedDirectory, entry.name);
      const sourceMetadata = await lstat(source, { bigint: true }).catch((error) => {
        throw unsafeDestination('Incomplete publication contains an unknown artifact', {
          artifact: path.relative(destination, published),
          code: error.code,
        });
      });
      const publishedMetadata = await lstat(published, { bigint: true });
      if (entry.isDirectory()) {
        if (!sourceMetadata.isDirectory() || sourceMetadata.isSymbolicLink()) {
          throw unsafeDestination('Incomplete publication directory differs from its owned stage', {
            artifact: path.relative(destination, published),
          });
        }
        await visit(source, published);
      } else if (entry.isFile()) {
        if (
          !sourceMetadata.isFile()
          || sourceMetadata.isSymbolicLink()
          || sourceMetadata.dev !== publishedMetadata.dev
          || sourceMetadata.ino !== publishedMetadata.ino
          || sourceMetadata.size !== publishedMetadata.size
        ) {
          throw unsafeDestination('Incomplete publication file is not linked to its owned stage', {
            artifact: path.relative(destination, published),
          });
        }
      } else {
        throw unsafeDestination('Incomplete publication contains an unsupported filesystem entry', {
          artifact: path.relative(destination, published),
        });
      }
    }
  };
  await visit(stage, destination);
}

async function linkRegularArtifact(source, target, boundary, budget) {
  budget?.checkRuntime('publication-link');
  injectPersistenceFault(boundary, target);
  try {
    await link(source, target);
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw unsafeDestination('Publication target appeared unexpectedly', { path: target });
    }
    if (['EACCES', 'EMLINK', 'ENOTSUP', 'EOPNOTSUPP', 'EPERM', 'EROFS', 'EXDEV'].includes(error.code)) {
      throw unsafeDestination('Filesystem cannot provide required same-filesystem hard-link publication', {
        code: error.code,
        path: target,
      });
    }
    throw error;
  }
  const [sourceIdentity, targetIdentity] = await Promise.all([
    pathIdentity(source, 'file'),
    pathIdentity(target, 'file'),
  ]);
  if (sourceIdentity.dev !== targetIdentity.dev || sourceIdentity.ino !== targetIdentity.ino) {
    throw unsafeDestination('Published artifact is not linked to the verified stage', { path: target });
  }
}

async function linkDirectoryTree(source, target, directories, budget) {
  budget?.checkRuntime('publication-tree');
  try {
    await mkdir(target, { mode: 0o700 });
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw unsafeDestination('Publication tree target appeared unexpectedly', { path: target });
    }
    throw error;
  }
  directories.push(target);
  const entries = await readdir(source, { withFileTypes: true });
  entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  for (const entry of entries) {
    budget?.checkRuntime('publication-tree');
    if (entry.isSymbolicLink()) {
      throw unsafeDestination('Verified stage contains a symbolic link', { path: path.join(source, entry.name) });
    }
    const sourcePath = path.join(source, entry.name);
    const targetPath = path.join(target, entry.name);
    if (entry.isDirectory()) await linkDirectoryTree(sourcePath, targetPath, directories, budget);
    else if (entry.isFile()) {
      await linkRegularArtifact(sourcePath, targetPath, 'publish-tree-link', budget);
    }
    else throw unsafeDestination('Verified stage contains an unsupported filesystem entry', { path: sourcePath });
  }
}

async function removeIncompletePublication(stage, destination, destinationIdentity, budget) {
  const metadata = await lstat(destination).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!metadata) return;
  await assertSameIdentity(destination, destinationIdentity, 'directory');
  await assertLinkedPublicationSubset(stage, destination, budget);
  await rm(destination, { recursive: true });
  await syncDirectory(path.dirname(destination), 'publish-abort-parent-sync');
}

async function removeEmptyPublicationReservation(destination) {
  const metadata = await lstat(destination).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!metadata) return;
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw unsafeDestination('New publication reservation changed type before ownership linkage', {
      path: destination,
    });
  }
  if ((await readdir(destination)).length !== 0) {
    throw unsafeDestination('New publication reservation gained content before ownership linkage', {
      path: destination,
    });
  }
  await rmdir(destination);
  await syncDirectory(path.dirname(destination), 'publish-abort-parent-sync');
}

export async function publishWorkspace(stage, destination, requestDigest, options = {}) {
  options.budget?.checkRuntime('publication');
  const workspacePaths = deriveWorkspacePaths(destination, requestDigest);
  const publicationReceipt = publicationReservationDocument(workspacePaths, requestDigest);
  await assertOwnedDirectory(stage, requestDigest);
  if (!Array.isArray(options.expectedArtifacts)) {
    throw new TypeError('Publication requires the exact expected artifact list');
  }
  await assertWorkspaceArtifactAllowlist(stage, requestDigest, {
    allowed: options.expectedArtifacts,
    required: options.expectedArtifacts,
  });
  await rejectSymlinkChain(destination, options.budget);
  if (options.parentIdentity) await assertSameIdentity(path.dirname(destination), options.parentIdentity, 'directory');
  if (options.parentRealpath && await realpath(path.dirname(destination)) !== options.parentRealpath) {
    throw unsafeDestination('Workspace parent real path changed during generation');
  }
  if (options.stageIdentity) await assertSameIdentity(stage, options.stageIdentity, 'directory');
  if (await exists(destination)) {
    throw unsafeDestination('Destination appeared during generation; publication refused', {
      path: destination,
    });
  }
  await syncDirectory(stage, 'stage-sync');
  if (options.stageIdentity) await assertSameIdentity(stage, options.stageIdentity, 'directory');
  options.budget?.checkRuntime('publication-reservation');

  // This internal hook makes the check/reservation boundary deterministic in
  // tests. Production callers do not supply it; mkdir('...') remains the
  // no-replace operation that decides ownership of the destination name.
  await options.beforeDestinationReservation?.();

  const owner = OWNER_FILENAME;
  const manifest = 'manifest.json';
  const nonManifestArtifacts = options.expectedArtifacts
    .filter((name) => name !== owner && name !== manifest)
    .sort();
  const linkedDirectories = [];
  let destinationCreated = false;
  let destinationIdentity;
  let publishedRealpath;
  let manifestLinked = false;
  let committed = false;
  let publicationReceiptInstalled = false;
  try {
    await installControlReceipt(
      workspacePaths.publicationReservation,
      publicationReceipt,
      'Publication reservation receipt',
      { artifact: PUBLICATION_RESERVATION_ARTIFACT, budget: options.budget },
    );
    publicationReceiptInstalled = true;
    injectPersistenceFault('publish-mkdir', destination);
    try {
      await mkdir(destination, { mode: 0o700 });
      destinationCreated = true;
    } catch (error) {
      if (error.code === 'EEXIST') {
        throw unsafeDestination('Destination appeared during generation; publication refused', {
          path: destination,
        });
      }
      throw error;
    }
    if (options.env?.OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_DESTINATION_CREATE === '1') {
      process.exit(99);
    }
    destinationIdentity = await pathIdentity(destination, 'directory');
    // Resolve every value needed for the successful result before the manifest
    // commit. No fallible path lookup may convert a durable commit into failure.
    publishedRealpath = await realpath(destination);
    await linkRegularArtifact(
      path.join(stage, owner),
      path.join(destination, owner),
      'publish-owner-link',
      options.budget,
    );
    // The receipt is the positive proof for the ownerless mkdir window. Once
    // the linked owner and its directory entry are durable, that stronger
    // in-directory proof takes over and the sibling receipt can be retired.
    await syncDirectory(destination, 'publish-owner-sync');
    await syncDirectory(path.dirname(destination), 'publish-owner-parent-sync');
    await removeControlReceipt(
      workspacePaths.publicationReservation,
      PUBLICATION_RESERVATION_ARTIFACT,
      'publication-reservation-commit-sync',
      options.budget,
    );
    publicationReceiptInstalled = false;
    for (const artifact of nonManifestArtifacts) {
      options.budget?.checkRuntime('publication-artifacts');
      const source = path.join(stage, artifact);
      const target = path.join(destination, artifact);
      const metadata = await lstat(source);
      if (metadata.isSymbolicLink()) {
        throw unsafeDestination('Verified stage artifact became a symbolic link', { artifact });
      }
      if (metadata.isDirectory()) {
        await linkDirectoryTree(source, target, linkedDirectories, options.budget);
      } else if (metadata.isFile()) {
        await linkRegularArtifact(source, target, 'publish-artifact-link', options.budget);
      }
      else throw unsafeDestination('Verified stage artifact changed type', { artifact });
    }
    for (const directory of linkedDirectories.sort((left, right) => right.length - left.length)) {
      options.budget?.checkRuntime('publication-directory-sync');
      await syncDirectory(directory, 'publish-tree-sync');
    }
    await assertWorkspaceArtifactAllowlist(destination, requestDigest, {
      allowed: options.expectedArtifacts,
      required: options.expectedArtifacts.filter((name) => name !== manifest),
    });
    await syncDirectory(destination, 'publish-precommit-sync');
    await syncDirectory(path.dirname(destination), 'publish-parent-sync');
    if (options.parentIdentity) await assertSameIdentity(path.dirname(destination), options.parentIdentity, 'directory');
    if (options.stageIdentity) await assertSameIdentity(stage, options.stageIdentity, 'directory');
    await assertSameIdentity(destination, destinationIdentity, 'directory');
    options.budget?.checkRuntime('publication-commit');

    try {
      await linkRegularArtifact(
        path.join(stage, manifest),
        path.join(destination, manifest),
        'publish-manifest-link',
        options.budget,
      );
      manifestLinked = true;
      await assertWorkspaceArtifactAllowlist(destination, requestDigest, {
        allowed: options.expectedArtifacts,
        required: options.expectedArtifacts,
      });
      await syncDirectory(destination, 'publish-commit-sync');
    } catch (error) {
      if (manifestLinked) {
        await unlink(path.join(destination, manifest));
        manifestLinked = false;
        await syncDirectory(destination, 'publish-rollback-sync');
      }
      throw error;
    }
    committed = true;
  } catch (error) {
    if (!committed && destinationCreated) {
      const cleanup = destinationIdentity
        ? removeIncompletePublication(
          stage,
          destination,
          destinationIdentity,
          options.budget,
        )
        : removeEmptyPublicationReservation(destination);
      await cleanup.catch((cleanupError) => {
        error.publicationCleanup = cleanupError.message;
      });
    }
    if (!committed && publicationReceiptInstalled) {
      await removeControlReceipt(
        workspacePaths.publicationReservation,
        PUBLICATION_RESERVATION_ARTIFACT,
        'publication-reservation-abort-sync',
        options.budget,
      ).catch((cleanupError) => {
        error.publicationReceiptCleanup = cleanupError.message;
      });
    }
    throw error;
  }

  // Publication is committed once manifest linkage and destination fsync
  // succeed. Stage cleanup cannot turn that committed result into an error.
  try {
    injectPersistenceFault('publish-stage-cleanup-remove', stage);
    await rm(stage, { recursive: true });
    await syncDirectory(path.dirname(stage), 'publish-stage-cleanup-sync');
  } catch (error) {
    options.postCommitDiagnostics?.push({
      code: typeof error?.code === 'string' ? error.code : 'POST_COMMIT_ERROR',
      phase: 'stage-cleanup',
    });
  }
  return publishedRealpath;
}

export { OWNER_FILENAME };
