import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const cargoPath = new URL('../core/integrity-verifier/rust/Cargo.toml', import.meta.url);
const libPath = new URL('../core/integrity-verifier/rust/src/lib.rs', import.meta.url);
const readmePath = new URL('../core/integrity-verifier/rust/README.md', import.meta.url);
const reviewPath = new URL('../docs/reviews/OGVCS-017-read-only-integrity-verifier-review.md', import.meta.url);
const prdPath = new URL('../prd/todo/OGVCS-017-integrity-verification-repair.md', import.meta.url);

test('private verifier composes the frozen object and chunk contracts', async () => {
  const cargo = await readFile(cargoPath, 'utf8');
  assert.match(cargo, /publish = false/);
  assert.match(cargo, /ogvcs-object-model = \{ path = "\.\.\/\.\.\/object-model\/rust", version = "0\.1\.0" \}/);
  assert.match(cargo, /ogvcs-chunking-manifest = \{ path = "\.\.\/\.\.\/chunking-manifest\/rust", version = "0\.1\.0" \}/);
  assert.doesNotMatch(cargo, /tokio|reqwest|axum|sqlx|aws-sdk|aws_sdk/);

  const source = await readFile(libPath, 'utf8');
  assert.match(source, /opaque_object_digest/);
  assert.match(source, /scan_metadata/);
  assert.match(source, /validate_metadata_schema_with_limits/);
  assert.match(source, /verify_manifest/);
  assert.match(source, /max_page_source_bytes/);
  assert.match(source, /max_page_work_units/);
  assert.match(source, /max_charged_memory_bytes/);
  assert.match(source, /GenerationChanged/);
  assert.match(source, /ManifestRestartRequired/);
  assert.match(source, /FindingsTruncated/);
  assert.match(source, /CoverageOverflow/);
  assert.match(source, /checked_logical_file_bytes/);
  assert.match(source, /active_manifest_reservation/);
  assert.match(source, /OperationControl::with_cancellation\(control\.cancellation_flag\(\), None\)/);
  assert.match(source, /ManifestRestartRecovery::ManifestIndex/);
  assert.match(source, /ManifestRestartRecovery::ManifestLedger/);
  assert.match(source, /ManifestRestartRecovery::DecodeWorking/);
  assert.match(source, /ManifestRestartRecovery::PageTransferBytes/);
  assert.match(source, /ManifestRestartRecovery::ObjectBytes/);
  assert.match(source, /ManifestRestartRecovery::FragmentWorkUnits/);
  assert.match(source, /bytes\.capacity\(\)/);
  assert.match(source, /observed_bytes > maximum_bytes \|\| observed_capacity > maximum_bytes/);
  assert.match(source, /preflight_work/);
  assert.doesNotMatch(source, /pub\s+(?:async\s+)?fn\s+(?:repair|quarantine|authorize|delete|publish)/);
  assert.doesNotMatch(source, /std::net|TcpStream|UdpSocket|tokio|reqwest|axum|sqlx/);

  const report = source.match(/pub struct VerificationReport \{(?<body>[\s\S]*?)\n\}/u)?.groups?.body;
  assert.ok(report, 'VerificationReport declaration is present');
  assert.doesNotMatch(report, /Vec<u8>|bytes:\s*Vec|payload|content/);
});

test('review and README retain the explicit unwired residual boundary', async () => {
  const [readme, review] = await Promise.all([
    readFile(readmePath, 'utf8'),
    readFile(reviewPath, 'utf8'),
  ]);
  for (const text of [readme, review]) {
    assert.match(text, /unwired/i);
    assert.match(text, /repair/i);
    assert.match(text, /quarantine/i);
    assert.match(text, /hosted\s+cross-OS/i);
    assert.match(text, /scale/i);
    assert.match(text, /OGVCS-017 remains Todo/);
    assert.match(text, /not (?:evidence for )?AC-?04 full-scrub resumability/i);
  }
});

test('PRD status and acceptance criteria remain unchanged while evidence is bounded', async () => {
  const prd = await readFile(prdPath, 'utf8');
  assert.match(prd, /^\*\*Status:\*\* Todo\s*$/m);
  const criteria = [
    '**OGVCS-017-AC-01:** The fault corpus corrupts snapshot, tree, manifest, chunk framing, chunk bytes, and storage metadata; each case yields the expected typed finding and no valid read.',
    '**OGVCS-017-AC-02:** With one corrupt and one good copy, reads avoid the corrupt copy and repair restores two independently verified copies without changing object ID.',
    '**OGVCS-017-AC-03:** With all copies missing/corrupt, affected snapshots are reported as degraded and no automated action fabricates data.',
    '**OGVCS-017-AC-04:** Full scrub can stop, restart, and complete with exact object/byte coverage for the captured generation while concurrent commits continue safely.',
    '**OGVCS-017-AC-05:** Verification of the reference large repository completes within the declared resource envelope and does not breach API latency/error SLOs.',
  ];
  for (const criterion of criteria) assert.ok(prd.includes(criterion));
  assert.match(prd, /Bounded candidate relevance only/);
  assert.match(prd, /replicas, quarantine, repair/i);
  assert.match(prd, /hosted cross-OS/i);
});
