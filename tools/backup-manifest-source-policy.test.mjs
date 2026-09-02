import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const cargoPath = new URL('../core/backup-manifest/rust/Cargo.toml', import.meta.url);
const sourcePath = new URL('../core/backup-manifest/rust/src/lib.rs', import.meta.url);
const readmePath = new URL('../core/backup-manifest/rust/README.md', import.meta.url);
const reviewPath = new URL('../docs/reviews/OGVCS-018-backup-completeness-manifest-review.md', import.meta.url);
const prdPath = new URL('../prd/todo/OGVCS-018-backup-restore-retention-gc.md', import.meta.url);

test('private backup manifest composes OGVCS-002 without storage or mutation authority', async () => {
  const [cargo, source] = await Promise.all([
    readFile(cargoPath, 'utf8'),
    readFile(sourcePath, 'utf8'),
  ]);
  assert.match(cargo, /publish = false/);
  assert.match(cargo, /ogvcs-object-model = \{ path = "\.\.\/\.\.\/object-model\/rust", version = "0\.1\.0" \}/);
  assert.doesNotMatch(cargo, /tokio|reqwest|axum|sqlx|aws-sdk|aws_sdk/);

  assert.match(source, /ObjectRef/);
  assert.match(source, /BACKUP_MANIFEST_VERSION: u16 = 1/);
  assert.match(source, /hard_limit_maximum\("chunk-payload-bytes"\)/);
  assert.match(source, /hard_limit_maximum\("metadata-payload-bytes"\)/);
  assert.match(source, /ExactSizeIterator/);
  assert.match(source, /reachability_proof/);
  assert.match(source, /integrity_verification/);
  assert.match(source, /verification_receipt/);
  assert.match(source, /retention_proof/);
  assert.match(source, /source_storage == capture\.target\.target/);
  assert.match(source, /source_credential_scope == capture\.target\.credential_scope/);
  assert.match(source, /required_roots\.remove/);
  assert.match(source, /pub declared_object_count: u64/);
  assert.match(source, /pub object_count: u64/);
  assert.match(source, /expected_tail = expected\.next\(\)/);
  assert.match(source, /copy_tail = copies\.next\(\)/);
  assert.doesNotMatch(source, /expected\.zip\(copies\)/);
  assert.match(source, /checked_add/);
  assert.match(source, /BACKUP_CANCELLED/);
  assert.doesNotMatch(source, /std::fs|std::net|TcpStream|UdpSocket|tokio|reqwest|axum|sqlx/);
  assert.doesNotMatch(source, /pub\s+(?:async\s+)?fn\s+(?:restore|activate|quarantine|delete|sweep|authorize|publish)/);

  const manifest = source.match(/pub struct BackupManifest \{(?<body>[\s\S]*?)\n\}/u)?.groups?.body;
  assert.ok(manifest, 'BackupManifest declaration is present');
  assert.doesNotMatch(manifest, /Vec<u8>|payload|content_bytes|secret|credential_token/);
});

test('documentation and PRD preserve the unwired Todo boundary', async () => {
  const [readme, review, prd] = await Promise.all([
    readFile(readmePath, 'utf8'),
    readFile(reviewPath, 'utf8'),
    readFile(prdPath, 'utf8'),
  ]);
  for (const text of [readme, review]) {
    assert.match(text, /unwired/i);
    assert.match(text, /does not prove credential separation/i);
    assert.match(text, /does not prove.*(?:hiding|privacy)|does not prove[\s\S]*hiding/i);
    assert.match(text, /restore/i);
    assert.match(text, /garbage collection|GC/i);
    assert.match(text, /hosted/i);
    assert.match(text, /OGVCS-018 remains Todo/);
  }
  assert.match(prd, /^\*\*Status:\*\* Todo\s*$/m);
  for (let criterion = 1; criterion <= 7; criterion += 1) {
    assert.match(prd, new RegExp(`\\*\\*OGVCS-018-AC-0${criterion}:\\*\\*`));
  }
  assert.match(prd, /bounded private candidate relevance only/i);
  assert.match(prd, /No acceptance\s+criterion is closed/i);
});
