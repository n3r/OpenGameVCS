export const CONTRACT_VERSION = '1.0.0';
export const SCHEMA_VERSION = 'ogvcs.path/contract-manifest/v1';
export const UNICODE_VERSION = '16.0.0';
export const CASE_FOLDING_SHA256 = '6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb';
export const UNICODE_LICENSE_SHA256 = 'e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96';

const entry = (code, name, description, extra = {}) => ({ code, name, description, ...extra });

export const caseModes = Object.freeze([
  entry(1, 'case-sensitive', 'Repository path collision uses exact NFC segment bytes.', { fold: 'identity' }),
  entry(2, 'case-folded', 'Repository path collision uses Unicode 16.0 full default case folding.', { fold: 'unicode-default-full-16.0.0' }),
]);

const commonLimits = Object.freeze({ depth: 256, joinedUtf8Bytes: 4096, joinedUtf16Units: 4096, segmentUtf8Bytes: 255, segmentUtf16Units: 255 });

export const platformProfiles = Object.freeze([
  entry(1, 'portable', 'Conservative Windows, macOS, and Linux intersection.', {
    profile: 'path.opengamevcs/portable@1', state: 'ratified', owner: 'OGVCS-004',
    platforms: ['linux', 'macos', 'windows'], limits: commonLimits,
    rules: { macosColon: true, platformCaseFold: true, symlink: 'internal-relative-capability', windowsNames: true },
  }),
  entry(2, 'windows', 'Conservative Win32/NTFS materialization profile.', {
    profile: 'path.opengamevcs/windows@1', state: 'ratified', owner: 'OGVCS-004',
    platforms: ['windows'], limits: commonLimits,
    rules: { macosColon: false, platformCaseFold: true, symlink: 'internal-relative-capability', windowsNames: true },
  }),
  entry(3, 'macos', 'Conservative APFS profile valid on both case variants.', {
    profile: 'path.opengamevcs/macos@1', state: 'ratified', owner: 'OGVCS-004',
    platforms: ['macos'], limits: commonLimits,
    rules: { macosColon: true, platformCaseFold: true, symlink: 'internal-relative-capability', windowsNames: false },
  }),
  entry(4, 'linux', 'Linux byte-name profile with the OGVCS operational control exclusion.', {
    profile: 'path.opengamevcs/linux@1', state: 'ratified', owner: 'OGVCS-004',
    platforms: ['linux'], limits: commonLimits,
    rules: { macosColon: false, platformCaseFold: false, symlink: 'internal-relative-capability', windowsNames: false },
  }),
]);

export const errors = Object.freeze([
  entry(1, 'PATH_INPUT_INVALID', 'Path input is not a nonempty relative sequence of canonical segments.'),
  entry(2, 'PATH_NOT_NFC', 'A segment is not already Unicode NFC.'),
  entry(3, 'PATH_LIMIT_EXCEEDED', 'A segment, path, or depth exceeds the selected profile or core maximum.'),
  entry(4, 'PATH_PROFILE_UNKNOWN', 'The selected path/platform profile is not ratified by this contract.'),
  entry(5, 'PATH_PLATFORM_FORBIDDEN', 'A platform profile forbids a segment or reserved workspace name.'),
  entry(6, 'PATH_COLLISION', 'Two paths collide under repository or supported-platform comparison.'),
  entry(7, 'CASE_MODE_INVALID', 'Repository case mode is not a frozen v1 assignment.'),
  entry(8, 'ENTRY_INVALID', 'A materialization entry has invalid kind, mode, hierarchy, or fields.'),
  entry(9, 'CAPABILITY_UNAVAILABLE', 'The host lacks a capability required by the preflighted plan.'),
  entry(10, 'SYMLINK_FORBIDDEN', 'A symlink target or policy is unsafe or unsupported.'),
  entry(11, 'UNSAFE_TARGET', 'A target escapes the root or traverses a link, junction, or reparse point.'),
  entry(12, 'TARGET_CHANGED', 'A filesystem identity changed during a confined operation.'),
  entry(13, 'TARGET_BUSY', 'A bounded replace was blocked by an open handle or interference.'),
  entry(14, 'ATOMIC_REPLACE_FAILED', 'A staged atomic replacement failed without becoming trusted.'),
  entry(15, 'CRASH_REMNANT', 'An incomplete owner-bound transaction requires explicit recovery.'),
  entry(16, 'RENAME_CONFLICT', 'A rename plan has duplicate, colliding, or ambiguous endpoints.'),
  entry(17, 'WATCH_STATE_INVALID', 'Watcher state, cursor, session, or generation is malformed.'),
  entry(18, 'WATCH_GAP', 'The persisted and delivered watcher cursors are not contiguous.'),
  entry(19, 'WATCH_OVERFLOW', 'The watcher reported dropped or overflowed events.'),
  entry(20, 'WATCH_UNCLEAN_SHUTDOWN', 'A prior watcher session did not close cleanly.'),
  entry(21, 'RECONCILIATION_REQUIRED', 'Authoritative clean status is forbidden until reconciliation completes.'),
  entry(22, 'LIMIT_EXCEEDED', 'A configured count, byte, memory, retry, or time ceiling was exceeded.'),
  entry(23, 'IO_ERROR', 'A bounded filesystem operation failed with privacy-safe context.'),
]);

export const operationOutcomes = Object.freeze([
  entry(1, 'case-only-rename', 'Stage to an owner-bound temporary, then publish the exact new spelling.', { outcome: 'two-phase-preserve-fileid' }),
  entry(2, 'rename-cycle', 'Stage every source under the transaction namespace, then publish in deterministic destination order.', { outcome: 'two-phase-preserve-fileids' }),
  entry(3, 'directory-file-replacement', 'Fully stage the new kind before removing the verified prior target.', { outcome: 'recoverable-transaction' }),
  entry(4, 'delete-modify', 'Reject when observed identity or digest differs from the preflighted base.', { outcome: 'TARGET_CHANGED' }),
  entry(5, 'junction-reparse-point', 'Reject every existing ancestor or target reparse point.', { outcome: 'UNSAFE_TARGET' }),
  entry(6, 'sparse-file', 'Preserve logical bytes and digest; sparse allocation is an optional nonidentity optimization.', { outcome: 'logical-bytes-authoritative' }),
  entry(7, 'locked-open-file', 'Retry only within the configured bound, then leave recoverable staging and report busy.', { outcome: 'TARGET_BUSY' }),
  entry(8, 'antivirus-interference', 'Treat replacement interference like a bounded busy target; never fall back to unsafe copy.', { outcome: 'TARGET_BUSY' }),
  entry(9, 'symlink-materialization', 'Create only an internal relative link after capability preflight and never follow it while writing.', { outcome: 'capability-or-SYMLINK_FORBIDDEN' }),
  entry(10, 'executable-intent', 'Preserve portable executable intent; apply a native bit only when supported.', { outcome: 'portable-intent-authoritative' }),
]);

export const pathCases = Object.freeze([
  { id: 'ascii', input: 'Game/Characters/Hero.uasset', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'unicode-nfc', input: 'Game/Café/日本語/🎮.uasset', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'unicode-decomposed', input: 'Game/Cafe\u0301/file', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'empty', input: '', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'absolute', input: '/Game/file', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'empty-segment', input: 'Game//file', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'dot', input: 'Game/./file', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'dotdot', input: 'Game/../file', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'backslash', input: 'Game\\file', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'reserved-control-root', input: '.ogvcs/state', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'reserved-control-root-case-variant', input: '.OGVCS/state', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'windows-con', input: 'Game/CON', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'windows-nul-extension', input: 'Game/nul.txt', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'windows-superscript', input: 'Game/COM¹.log', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'windows-trailing-dot', input: 'Game/name.', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'windows-trailing-space', input: 'Game/name ', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'windows-colon', input: 'Game/name:stream', profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'linux-colon', input: 'Game/name:stream', profile: 'path.opengamevcs/linux@1', caseMode: 'case-sensitive' },
  { id: 'macos-colon', input: 'Game/name:stream', profile: 'path.opengamevcs/macos@1', caseMode: 'case-sensitive' },
  { id: 'segment-max', input: `Game/${'a'.repeat(255)}`, profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'segment-max-plus-one', input: `Game/${'a'.repeat(256)}`, profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'depth-max', input: Array.from({ length: 256 }, (_, index) => `p${index}`).join('/'), profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'depth-max-plus-one', input: Array.from({ length: 257 }, (_, index) => `p${index}`).join('/'), profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive' },
  { id: 'unknown-profile', input: 'Game/file', profile: 'path.opengamevcs/unknown@1', caseMode: 'case-sensitive' },
  { id: 'invalid-case-mode', input: 'Game/file', profile: 'path.opengamevcs/portable@1', caseMode: 'native' },
]);

export const foldCases = Object.freeze([
  { id: 'ascii', input: 'Hero.TXT' },
  { id: 'sharp-s', input: 'Straße' },
  { id: 'kelvin', input: 'Kelvin' },
  { id: 'greek-sigma', input: 'Σσς' },
  { id: 'dotted-i-default', input: 'İstanbul' },
  { id: 'cherokee', input: 'ꭰᎠ' },
  { id: 'emoji-invariant', input: '🎮Asset' },
]);

export const collisionCases = Object.freeze([
  { id: 'ascii-folded', caseMode: 'case-folded', profile: 'path.opengamevcs/linux@1', paths: ['Game/Hero', 'game/hero'] },
  { id: 'ascii-sensitive-linux', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', paths: ['Game/Hero', 'game/hero'] },
  { id: 'ascii-sensitive-windows', caseMode: 'case-sensitive', profile: 'path.opengamevcs/windows@1', paths: ['Game/Hero', 'game/hero'] },
  { id: 'sharp-s-folded', caseMode: 'case-folded', profile: 'path.opengamevcs/linux@1', paths: ['Game/Straße', 'Game/STRASSE'] },
  { id: 'different-parent', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', paths: ['A/file', 'B/file'] },
  { id: 'duplicate-exact', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', paths: ['A/file', 'A/file'] },
  { id: 'invalid-before-collision', caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1', paths: ['Game/CON', 'game/con'] },
]);

const baseCapabilities = Object.freeze({ atomicReplace: true, executableBit: true, symlink: true });

export const preflightCases = Object.freeze([
  {
    id: 'portable-tree', caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [
      { id: 'd', path: 'Game', kind: 'directory', mode: 'directory' },
      { id: 'f', path: 'Game/Hero.uasset', kind: 'regular', mode: 'regular-file' },
      { id: 'x', path: 'Game/Build.sh', kind: 'executable', mode: 'executable-file' },
      { id: 'l', path: 'Game/current', kind: 'symlink', mode: 'symlink', symlinkTarget: 'Hero.uasset' },
    ],
  },
  {
    id: 'symlink-capability-missing', caseMode: 'case-sensitive', profile: 'path.opengamevcs/portable@1', platform: 'windows', capabilities: { ...baseCapabilities, symlink: false },
    entries: [{ id: 'l', path: 'current', kind: 'symlink', mode: 'symlink', symlinkTarget: 'target' }],
  },
  {
    id: 'symlink-escape', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [{ id: 'l', path: 'current', kind: 'symlink', mode: 'symlink', symlinkTarget: '../outside' }],
  },
  {
    id: 'nested-relative-symlink', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [
      { id: 'l', path: 'Game/current', kind: 'symlink', mode: 'symlink', symlinkTarget: '../Shared' },
      { id: 'd', path: 'Game', kind: 'directory', mode: 'directory' },
      { id: 'f', path: 'Shared', kind: 'regular', mode: 'regular-file' },
    ],
  },
  {
    id: 'symlink-drive-absolute', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [{ id: 'l', path: 'current', kind: 'symlink', mode: 'symlink', symlinkTarget: 'C:/outside' }],
  },
  {
    id: 'mode-kind-mismatch', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [{ id: 'f', path: 'file', kind: 'regular', mode: 'executable-file' }],
  },
  {
    id: 'parent-missing', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [{ id: 'f', path: 'Game/file', kind: 'regular', mode: 'regular-file' }],
  },
  {
    id: 'child-before-parent', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [
      { id: 'f', path: 'Game/file', kind: 'regular', mode: 'regular-file' },
      { id: 'd', path: 'Game', kind: 'directory', mode: 'directory' },
    ],
  },
  {
    id: 'diagnostic-id-unsafe', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [{ id: 'private/path', path: 'file', kind: 'regular', mode: 'regular-file' }],
  },
  {
    id: 'case-collision', caseMode: 'case-folded', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [
      { id: 'a', path: 'Hero', kind: 'regular', mode: 'regular-file' },
      { id: 'b', path: 'hero', kind: 'regular', mode: 'regular-file' },
    ],
  },
  {
    id: 'atomic-missing', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', platform: 'linux', capabilities: { ...baseCapabilities, atomicReplace: false },
    entries: [],
  },
  {
    id: 'wrong-platform', caseMode: 'case-sensitive', profile: 'path.opengamevcs/windows@1', platform: 'linux', capabilities: baseCapabilities,
    entries: [],
  },
]);

const idA = '11111111111111111111111111111111';
const idB = '22222222222222222222222222222222';
export const renameCases = Object.freeze([
  { id: 'case-only', caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1', renames: [{ from: 'Game/Hero', to: 'Game/hero', fileId: idA }] },
  { id: 'two-cycle', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', renames: [{ from: 'A', to: 'B', fileId: idA }, { from: 'B', to: 'A', fileId: idB }] },
  { id: 'two-cycle-reversed', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', renames: [{ from: 'B', to: 'A', fileId: idB }, { from: 'A', to: 'B', fileId: idA }] },
  { id: 'ordinary', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', renames: [{ from: 'Old', to: 'New', fileId: idA }] },
  { id: 'duplicate-destination', caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1', renames: [{ from: 'A', to: 'C', fileId: idA }, { from: 'B', to: 'C', fileId: idB }] },
  { id: 'colliding-source', caseMode: 'case-folded', profile: 'path.opengamevcs/linux@1', renames: [{ from: 'A', to: 'C', fileId: idA }, { from: 'a', to: 'D', fileId: idB }] },
]);

export const watcherCases = Object.freeze([
  { id: 'initial-reconcile', events: [{ type: 'reconcile', cursor: 'c0', generation: 1 }] },
  { id: 'clean-batch', events: [{ type: 'reconcile', cursor: 'c0', generation: 1 }, { type: 'start', session: 's1' }, { type: 'batch', session: 's1', fromCursor: 'c0', toCursor: 'c1', overflow: false, indexUpdated: true }, { type: 'stop', session: 's1', resumeSupported: true }] },
  { id: 'cursor-gap', events: [{ type: 'reconcile', cursor: 'c0', generation: 1 }, { type: 'start', session: 's1' }, { type: 'batch', session: 's1', fromCursor: 'wrong', toCursor: 'c2', overflow: false, indexUpdated: true }] },
  { id: 'overflow', events: [{ type: 'reconcile', cursor: 'c0', generation: 1 }, { type: 'start', session: 's1' }, { type: 'batch', session: 's1', fromCursor: 'c0', toCursor: 'c2', overflow: true, indexUpdated: false }] },
  { id: 'unclean-restart', events: [{ type: 'reconcile', cursor: 'c0', generation: 1 }, { type: 'start', session: 's1' }, { type: 'restart' }] },
  { id: 'stop-dirty', events: [{ type: 'reconcile', cursor: 'c0', generation: 1 }, { type: 'start', session: 's1' }, { type: 'batch', session: 's1', fromCursor: 'c0', toCursor: 'c1', overflow: false, indexUpdated: false }, { type: 'stop', session: 's1' }] },
]);
