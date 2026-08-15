import { createHash } from 'node:crypto';

function stableToken(seed, ...parts) {
  return createHash('sha256')
    .update('ogvcs.fixture/semantic-token/v2\0')
    .update(seed)
    .update('\0')
    .update(parts.join('\0'))
    .digest('hex');
}

function json(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function yamlHeader() {
  return '%YAML 1.1\n%TAG !u! tag:unity3d.com,2011:\n';
}

/** Build a small, valid, profile-specific artifact version. */
export function semanticBytes({
  index,
  logicalPath,
  profileId,
  role,
  seed,
  syntheticGuid,
  version = 0,
}) {
  const token = stableToken(seed, profileId, String(index), role);
  const name = logicalPath.split('/').at(-1).replace(/[^A-Za-z0-9_]/g, '_');

  if (profileId === 'code-heavy') {
    if (logicalPath.endsWith('.json') || role === 'configuration') {
      return json({ enabled: true, fixture: 'ogvcs-v2', revision: version, token: token.slice(0, 16) });
    }
    if (logicalPath.endsWith('.md') || role === 'documentation') {
      return Buffer.from(`# ${name}\n\nSynthetic fixture revision ${version}.\n\nToken: \`${token.slice(0, 16)}\`\n`, 'utf8');
    }
    if (logicalPath.endsWith('.py')) {
      return Buffer.from(`#!/usr/bin/env python3\n\ndef fixture_${index}():\n    return ${version}\n`, 'utf8');
    }
    if (logicalPath.endsWith('.sh')) {
      return Buffer.from(`#!/bin/sh\n# synthetic fixture\nprintf '%s\\n' '${version}'\n`, 'utf8');
    }
    if (logicalPath.endsWith('.rs')) {
      return Buffer.from(`// synthetic fixture\npub fn fixture_${index}() -> u32 { ${version} }\n`, 'utf8');
    }
    if (logicalPath.endsWith('.h')) {
      return Buffer.from(`#pragma once\n// synthetic fixture revision ${version}\nint fixture_${index}(void);\n`, 'utf8');
    }
    return Buffer.from(`// synthetic fixture\nint fixture_${index}(void) { return ${version}; }\n`, 'utf8');
  }

  if (profileId === 'unreal-like') {
    if (role === 'source') {
      return Buffer.from(`// Synthetic Unreal-style source\nint Fixture_${index}() { return ${version}; }\n`, 'utf8');
    }
    if (role === 'header') {
      return Buffer.from(`#pragma once\nint Fixture_${index}(); // revision ${version}\n`, 'utf8');
    }
    if (role === 'configuration') {
      if (logicalPath.endsWith('.json')) return json({ fixtureRevision: version, package: name, token: token.slice(0, 16) });
      return Buffer.from(`[Fixture.Package.${index}]\nRevision=${version}\nToken=${token.slice(0, 16)}\n`, 'utf8');
    }
    const magic = role === 'map' ? 'OGVCS-UMAP-V2\0' : role === 'sidecar' ? 'OGVCS-UBULK-V2\0' : 'OGVCS-UASSET-V2\0';
    return Buffer.concat([
      Buffer.from(magic, 'ascii'),
      json({ object: name, revision: version, synthetic: true, token: token.slice(0, 24) }),
    ]);
  }

  if (profileId === 'unity-like') {
    if (role === 'meta') {
      return Buffer.from(
        `fileFormatVersion: 2\nguid: ${syntheticGuid}\nSyntheticImporter:\n  revision: ${version}\n  token: ${token.slice(0, 16)}\n`,
        'utf8',
      );
    }
    if (role === 'scene') {
      return Buffer.from(`${yamlHeader()}--- !u!1 &1000\nGameObject:\n  m_Name: Scene_${index}\n  m_Revision: ${version}\n`, 'utf8');
    }
    if (role === 'prefab' || role === 'asset') {
      return Buffer.from(`${yamlHeader()}--- !u!114 &11400000\nMonoBehaviour:\n  m_Name: Asset_${index}\n  revision: ${version}\n`, 'utf8');
    }
    if (role === 'binary-import') {
      return Buffer.concat([
        Buffer.from('OGVCS-UNITY-IMPORT-V2\0', 'ascii'),
        Buffer.from([version]),
        Buffer.from(token, 'hex'),
      ]);
    }
    return json({ evidence: 'intentionally-no-meta-sidecar', revision: version, target: name });
  }

  if (profileId === 'global-studio') {
    if (role === 'source') return Buffer.from(`// global studio source\nint fixture_${index} = ${version};\n`, 'utf8');
    if (role === 'configuration') return json({ region: index % 3, revision: version, token: token.slice(0, 16) });
    if (role === 'review-input') return Buffer.from(`Change: synthetic-${index}\nRevision: ${version}\n`, 'utf8');
    return Buffer.concat([Buffer.from('OGVCS-STUDIO-ASSET-V2\0', 'ascii'), Buffer.from(token, 'hex'), Buffer.from([version])]);
  }

  return Buffer.concat([Buffer.from('OGVCS-BINARY-SNAPSHOT-V2\0', 'ascii'), Buffer.from(token, 'hex'), Buffer.from([version])]);
}

export function mediaTypeFor(profileId, role, logicalPath) {
  if (role === 'configuration' && logicalPath.endsWith('.json')) return 'application/json';
  if (role === 'configuration') return 'text/plain';
  if (role === 'scene' || role === 'prefab' || role === 'asset' || role === 'meta') return 'application/yaml';
  if (['source', 'header', 'script', 'documentation', 'review-input'].includes(role)) return 'text/plain';
  if (profileId === 'unreal-like') return 'application/x-ogvcs-unreal-package';
  if (role === 'binary-import') return 'application/x-ogvcs-unity-import';
  return 'application/octet-stream';
}

export function semanticVersionCount(request, role) {
  if (request.profile.id === 'code-heavy' && request.featureFlags['text-edits'] === false) return 1;
  if (role === 'negative-evidence') return 1;
  return 2;
}
