import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private deployment preflight stays pure, fixed-shape, and unwired', async () => {
  const [cargo, source] = await Promise.all([
    read('core/deployment-preflight/rust/Cargo.toml'),
    read('core/deployment-preflight/rust/src/lib.rs'),
  ]);

  assert.match(cargo, /publish = false/u);
  assert.match(cargo, /rust-version = "1\.82"/u);
  assert.match(cargo, /sha2 = "=0\.10\.9"/u);
  assert.doesNotMatch(cargo, /tokio|reqwest|axum|sqlx|postgres|rusqlite|tonic|aws-sdk|aws_sdk|docker|kube/iu);

  assert.match(source, /pub const LISTENER_COUNT: usize = 3;/u);
  assert.match(source, /pub const SECRET_COUNT: usize = 4;/u);
  assert.match(source, /pub const SERVICE_ACCOUNT_COUNT: usize = 3;/u);
  assert.match(source, /pub const DEPENDENCY_COUNT: usize = 7;/u);
  assert.match(source, /pub const WORK_UNITS_HARD_MAXIMUM: u64 = 19;/u);
  assert.match(source, /pub const RETAINED_BYTES_HARD_MAXIMUM: u64 = 640;/u);
  assert.match(source, /pub const OBSERVATION_AGE_SECONDS_HARD_MAXIMUM: u64 = 300;/u);
  assert.match(source, /config: &DeploymentConfig,\s+observation: &PreflightObservation,\s+evaluation: PreflightEvaluation/u);
  assert.match(source, /validate_input_shapes\(config, observation\)\?;[\s\S]*?WORK_UNITS_WITHOUT_BACKUP_GATE[\s\S]*?if work_units > limits\.max_work_units[\s\S]*?validate_config\(config\)\?;/u);
  assert.match(source, /let mut reason_buffer = \[SafeReasonCode::ProcessNotLive; DEPENDENCY_COUNT \+ 1\];/u);
  assert.match(source, /if retained_bytes > limits\.max_retained_bytes[\s\S]*?&reason_buffer\[\.\.reason_count\][\s\S]*?reasons\.to_vec\(\)/u);
  assert.match(source, /checkpoint\(CancellationStage::BeforeResultAllocation\);\s+control\.check\(\)\?;\s+let reasons = reasons\.to_vec\(\);/u);
  assert.match(source, /MigrationClass::Irreversible/u);
  assert.match(source, /BackupGateEvidence/u);
  assert.match(source, /backup\.source_schema != observation\.migration\.current_schema/u);
  assert.match(source, /backup\.verified_backup_manifest != backup\.backup_manifest/u);
  assert.match(source, /backup\.retention_until_unix_seconds <= evaluation\.evaluated_at_unix_seconds/u);
  assert.match(source, /backup\.source_storage == backup\.target_storage/u);
  assert.match(source, /backup\.source_credential_scope == backup\.target_credential_scope/u);
  assert.match(source, /valid_reason_shape\(self\.live, &self\.reasons\)/u);
  assert.match(source, /DEPLOYMENT_BACKUP_GATE_INVALID/u);
  assert.match(source, /DEPLOYMENT_OBSERVATION_TIME_INVALID/u);
  assert.doesNotMatch(source, /mutation_ready/u);
  assert.doesNotMatch(source, /BTreeSet|HashSet/u);
  assert.doesNotMatch(source, /std::(?:fs|net|process)|TcpListener|TcpStream|UdpSocket|SystemTime|Instant|Command::|tokio|reqwest|axum|sqlx|postgres|rusqlite/iu);
  assert.doesNotMatch(source, /pub\s+(?:async\s+)?fn\s+(?:install|bootstrap|migrate|backup|restore|serve|listen|authorize|publish|uninstall)/u);

  for (const name of ['SecretBinding', 'ServiceAccount', 'DependencyObservation']) {
    const body = source.match(new RegExp(`pub struct ${name} \\{(?<body>[\\s\\S]*?)\\n\\}`, 'u'))?.groups?.body;
    assert.ok(body, `${name} declaration is present`);
    assert.doesNotMatch(body, /String|Vec<u8>|secret_bytes|password|token/iu);
  }
  for (const name of [
    'ListenerConfig', 'SecretBinding', 'ServiceAccount', 'DeploymentConfig',
    'DependencyObservation', 'BackupGateEvidence', 'PreflightObservation',
    'DeploymentPreflightReport',
  ]) {
    assert.doesNotMatch(
      source,
      new RegExp(`#\\[derive\\([^\\]]*Debug[^\\]]*\\)\\]\\s*pub struct ${name}\\b`, 'u'),
    );
  }
  assert.match(source, /field\("configuration", &"<redacted>"\)/u);
  assert.match(source, /field\("observation", &"<redacted>"\)/u);
  assert.match(source, /field\("evidence", &"<redacted>"\)/u);
});

test('safe defaults, readiness classes, and report-local checksum remain explicit', async () => {
  const source = await read('core/deployment-preflight/rust/src/lib.rs');
  for (const kind of ['Metadata', 'ObjectStorage', 'Identity', 'Verifier', 'Backup', 'Capacity', 'Schema']) {
    assert.match(source, new RegExp(`DependencyKind::${kind}|K::${kind}`, 'u'));
  }
  assert.match(source, /config\.telemetry_enabled_by_default/u);
  assert.match(source, /config\.vendor_check_in_required/u);
  assert.match(source, /DurableDataPolicy::PreserveByDefault/u);
  assert.match(source, /listener\.exposure != Exposure::Loopback && !listener\.tls/u);
  assert.match(source, /listener\.role != ListenerRole::Api && listener\.exposure != Exposure::Loopback/u);
  assert.match(source, /let live = observation\.process_alive;/u);
  assert.match(source, /let ready = live && reasons\.is_empty\(\);/u);
  assert.match(source, /Reconstructs only the report's structural checksum/u);
  assert.match(source, /self\.ready == \(self\.live && self\.reasons\.is_empty\(\)\)/u);

  const configDigest = source.match(/fn digest_configuration\([\s\S]*?\n\}/u)?.[0];
  const observationDigest = source.match(/fn digest_observation\([\s\S]*?\n\}/u)?.[0];
  const reportDigest = source.match(/fn digest_report_fields\([\s\S]*?\n\}/u)?.[0];
  assert.ok(configDigest);
  assert.ok(observationDigest);
  assert.ok(reportDigest);
  for (const field of [
    'version', 'deployment', 'artifact_set', 'compatibility_set',
    'configuration_generation', 'telemetry_enabled_by_default',
    'vendor_check_in_required', 'durable_data_policy', 'listeners', 'role',
    'exposure', 'port', 'tls', 'secrets', 'purpose', 'provider',
    'reference_commitment', 'access_restricted', 'embedded_in_public_config',
    'included_in_diagnostics', 'service_accounts', 'principal_commitment',
    'privileged_root', 'interactive_login',
  ]) assert.match(configDigest, new RegExp(`\\.${field}\\b`, 'u'));
  for (const field of [
    'captured_at_unix_seconds', 'process_alive', 'compatibility_set',
    'configuration_generation', 'dependencies', 'kind', 'state',
    'generation_commitment', 'migration', 'current_schema', 'target_schema',
    'class', 'backup_gate', 'backup_manifest', 'verification_report',
    'retention_until_unix_seconds', 'deployment', 'source_schema',
    'metadata_generation', 'object_storage_generation', 'verifier_generation',
    'backup_generation', 'schema_generation', 'verified_backup_manifest',
    'source_storage', 'source_credential_scope', 'target_storage',
    'target_credential_scope', 'retention_policy', 'encryption_policy',
  ]) assert.match(observationDigest, new RegExp(`\\.${field}\\b`, 'u'));
  for (const field of [
    'version', 'configuration_digest', 'observation_digest',
    'observation_captured_at_unix_seconds', 'evaluated_at_unix_seconds',
    'maximum_observation_age_seconds', 'live', 'ready',
    'backup_gate_evidence_present', 'reasons', 'reason_count', 'work_units',
    'retained_bytes',
  ]) assert.match(reportDigest, new RegExp(`\\b${field}\\b`, 'u'));
});

test('README and review retain supplied-fact and nonclaim boundaries', async () => {
  const [readme, review] = await Promise.all([
    read('core/deployment-preflight/rust/README.md'),
    read('docs/reviews/OGVCS-021-deployment-preflight-boundary-review.md'),
  ]);
  for (const text of [readme, review]) {
    assert.match(text, /unwired/iu);
    assert.match(text, /supplied fact|supplied-fact/iu);
    assert.match(text, /not a signature|not authentication/iu);
    assert.match(text, /first-admin bootstrap/iu);
    assert.match(text, /install/iu);
    assert.match(text, /backup\/restore/iu);
    assert.match(text, /300|observation-age|observation age/iu);
    assert.match(text, /conservative/iu);
    assert.match(text, /hosted cross-OS/iu);
    assert.match(text, /scale\/SLO|scale.*SLO/isu);
    assert.match(text, /OGVCS-021 remains\s+Todo/u);
  }
});

test('OGVCS-021 remains Todo with every acceptance criterion open', async () => {
  const [prd, packageValue] = await Promise.all([
    read('prd/todo/OGVCS-021-starter-deployment-admin-bootstrap.md'),
    read('package.json').then(JSON.parse),
  ]);
  assert.match(prd, /^\*\*Status:\*\* Todo\s*$/mu);
  const criteria = [
    '**OGVCS-021-AC-01:** Fresh supported hosts complete automated install, identity/storage bootstrap, repository creation, backup, clean restore, and full metadata/content/configuration verification without undocumented access.',
    '**OGVCS-021-AC-02:** Invalid TLS, credentials, permissions, schema, database, object store, capacity, and clock configurations fail preflight with no partial durable mutation.',
    '**OGVCS-021-AC-03:** Dependency failure matrix produces correct liveness/readiness and prevents mutation readiness whenever metadata, object storage, identity, schema, capacity, verifier, or backup prerequisites are unsafe.',
    '**OGVCS-021-AC-04:** Security review finds no shipped default credential, world-readable secret, undeclared listener, mandatory vendor egress, or unredacted diagnostic secret.',
    '**OGVCS-021-AC-05:** Uninstall/reinstall preserves named data by default and the recovery runbook restores service without private engineering intervention.',
  ];
  for (const criterion of criteria) assert.ok(prd.includes(criterion));
  assert.match(prd, /Bounded candidate relevance only/u);
  assert.match(prd, /all five\s+acceptance criteria remain open/iu);
  assert.equal(packageValue.scripts['test:deployment-preflight'], 'node --test tools/deployment-preflight-source-policy.test.mjs');
  assert.match(packageValue.scripts.test, /npm run test:deployment-preflight/u);
});
