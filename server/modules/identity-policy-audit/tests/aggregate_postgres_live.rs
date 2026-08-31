use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use ogvcs_identity_policy_audit_postgres::{
    run_migrations, AggregatePlanRequest, AggregateReceiptConsumptionRequest,
    AggregateResourceDigestProjection, AggregateSigningKeyRegistration, AuthorizationResource,
    CredentialScope, HmacSha256KeyRing, MigrationRunOptions, ParticipantErrorCode, PolicyDocument,
    PolicyRule, PostgresAggregateAuthorizationParticipant, RepositoryContractBindingRequest,
    RuleSubjects,
};
use postgres::fallible_iterator::FallibleIterator;
use postgres::{Client, NoTls};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TENANT: &str = "aggregate-studio";
const REPOSITORY: &str = "aggregate-game";
const PRESENTATION: &str = "aggregate.live.credential.presentation";
const METADATA_TENANT: &str = "11111111-1111-4111-8111-111111111111";
const METADATA_REPOSITORY: &str = "22222222-2222-4222-8222-222222222222";
const KEY_REFERENCE: &str = "kms://identity/aggregate/key-1";
const CREDENTIAL_DOMAIN: &[u8] = b"OGVCS-IDENTITY-CREDENTIAL-V1\0";
const SUBJECT_DOMAIN: &[u8] = b"OGVCS-IDENTITY-SUBJECT-V1\0";

fn canonical_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_value).collect()),
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonical_value(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        value => value,
    }
}

fn digest_json<T: Serialize>(value: &T) -> Vec<u8> {
    let value = serde_json::to_value(value).expect("fixture serializes");
    let bytes = serde_json::to_vec(&canonical_value(value)).expect("fixture canonicalizes");
    Sha256::digest(bytes).to_vec()
}

fn digest_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().to_vec()
}

fn policy(generation: u64) -> PolicyDocument {
    PolicyDocument {
        schema_version: "ogvcs.identity-policy/policy/v1".to_owned(),
        id: "aggregate.policy".to_owned(),
        version: format!("v{generation}"),
        generation,
        authority_epoch: 1,
        path_profile: "path.opengamevcs/portable@1".to_owned(),
        case_mode: "case-folded".to_owned(),
        default_effect: "deny".to_owned(),
        composition: "deny-overrides-v1".to_owned(),
        rules: vec![
            PolicyRule {
                id: "allow.aggregate.paths".to_owned(),
                effect: "allow".to_owned(),
                subjects: RuleSubjects {
                    identities: vec!["aggregate.artist".to_owned()],
                    groups: vec!["aggregate-artists".to_owned()],
                    actor_classes: vec!["human".to_owned()],
                },
                tenant: TENANT.to_owned(),
                repository: REPOSITORY.to_owned(),
                references: vec!["main".to_owned()],
                path_prefixes: vec!["Game".to_owned()],
                resource_types: vec!["path".to_owned()],
                permissions: vec!["metadata.read".to_owned()],
            },
            PolicyRule {
                id: "deny.aggregate.paths".to_owned(),
                effect: "deny".to_owned(),
                subjects: RuleSubjects {
                    identities: vec![],
                    groups: vec![],
                    actor_classes: vec![],
                },
                tenant: TENANT.to_owned(),
                repository: REPOSITORY.to_owned(),
                references: vec!["main".to_owned()],
                path_prefixes: vec![
                    "Game/A-Denied.asset".to_owned(),
                    "Game/M-Denied.asset".to_owned(),
                    "Game/Z-Denied.asset".to_owned(),
                ],
                resource_types: vec!["path".to_owned()],
                permissions: vec!["metadata.read".to_owned()],
            },
        ],
    }
}

fn resource(path: &str) -> AuthorizationResource {
    AuthorizationResource {
        resource_type: "path".to_owned(),
        path: Some(path.to_owned()),
        file_id: None,
        object_id: None,
        name: None,
    }
}

fn reconstruct_resource_digest_projection(client: &mut Client, plan_id: &str) -> String {
    let mut projection = AggregateResourceDigestProjection::new();
    {
        let mut rows = client
            .query_raw(
                "SELECT resource_digest
                 FROM ogvcs_identity.aggregate_plan_resources
                 WHERE plan_id=$1 ORDER BY item_ordinal",
                [&plan_id],
            )
            .expect("open ordered resource digest stream");
        while let Some(row) = rows.next().expect("stream resource digest") {
            let digest: Vec<u8> = row.get(0);
            projection
                .push(&digest)
                .expect("append exact 32-byte digest");
        }
    }
    projection.finish().expect("finish nonempty projection")
}

fn plan_request<'a>() -> AggregatePlanRequest<'a> {
    AggregatePlanRequest {
        credential_presentation: PRESENTATION,
        tenant: TENANT,
        repository: REPOSITORY,
        permission: "metadata.read",
        capability: "aggregate.read",
        reference: Some("main"),
        snapshot: Some("snapshot.aggregate.1"),
        reason: None,
        ttl_seconds: 300,
    }
}

fn seed(client: &mut Client) {
    client
        .batch_execute(
            "CREATE SCHEMA IF NOT EXISTS ogvcs_metadata;
             CREATE TABLE IF NOT EXISTS ogvcs_metadata.repositories (
                 repository_id uuid PRIMARY KEY,
                 tenant_id uuid NOT NULL);
             CREATE TABLE IF NOT EXISTS ogvcs_metadata.repository_settings (
                 repository_id uuid PRIMARY KEY REFERENCES ogvcs_metadata.repositories(repository_id),
                 settings_generation bigint NOT NULL,
                 descriptor_digest bytea NOT NULL,
                 path_profile text NOT NULL,
                 case_mode text NOT NULL);",
        )
        .expect("create authoritative metadata fixture");
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repositories (repository_id, tenant_id)
             VALUES (CAST($1::text AS uuid), CAST($2::text AS uuid)) ON CONFLICT DO NOTHING",
            &[&METADATA_REPOSITORY, &METADATA_TENANT],
        )
        .expect("seed metadata repository");
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repository_settings
             (repository_id, settings_generation, descriptor_digest,
              path_profile, case_mode)
             VALUES (CAST($1::text AS uuid), 1, $2,
                     'path.opengamevcs/portable@1', 'case-folded')
             ON CONFLICT DO NOTHING",
            &[&METADATA_REPOSITORY, &&[9_u8; 32][..]],
        )
        .expect("seed immutable metadata settings");

    let scope = CredentialScope {
        tenants: vec![TENANT.to_owned()],
        repositories: vec![REPOSITORY.to_owned()],
        references: vec!["main".to_owned()],
        path_prefixes: vec!["Game".to_owned()],
        permissions: vec!["metadata.read".to_owned()],
    };
    let current_policy = policy(1);
    let presentation_digest = digest_parts(&[CREDENTIAL_DOMAIN, PRESENTATION.as_bytes()]);
    let subject_digest = digest_parts(&[SUBJECT_DOMAIN, b"aggregate.artist"]);
    client
        .execute(
            "INSERT INTO ogvcs_identity.authority_states
             (tenant_id, authority_epoch, key_generation) VALUES ($1, 1, 1)
             ON CONFLICT DO NOTHING",
            &[&TENANT],
        )
        .expect("seed authority");
    client
        .execute(
            "INSERT INTO ogvcs_identity.credentials
             (tenant_id, credential_id, credential_generation,
              presentation_digest, subject_id, subject_digest, actor_class,
              credential_class, groups_json, authority_epoch, issued_at,
              expires_at, state, scope_json, scope_digest)
             VALUES ($1, 'aggregate-credential', 1, $2, 'aggregate.artist', $3,
                     'human', 'session', $4, 1,
                     clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '1 hour', 'active', $5, $6)
             ON CONFLICT DO NOTHING",
            &[
                &TENANT,
                &presentation_digest,
                &subject_digest,
                &json!(["aggregate-artists"]),
                &serde_json::to_value(&scope).unwrap(),
                &digest_json(&scope),
            ],
        )
        .expect("seed durable credential");
    client
        .execute(
            "INSERT INTO ogvcs_identity.policy_versions
             (tenant_id, repository_id, policy_generation, authority_epoch,
              policy_id, policy_version, path_profile, case_mode,
              policy_json, policy_digest)
             VALUES ($1, $2, 1, 1, $3, $4, $5, $6, $7, $8)
             ON CONFLICT DO NOTHING",
            &[
                &TENANT,
                &REPOSITORY,
                &current_policy.id,
                &current_policy.version,
                &current_policy.path_profile,
                &current_policy.case_mode,
                &serde_json::to_value(&current_policy).unwrap(),
                &digest_json(&current_policy),
            ],
        )
        .expect("seed policy");
    client
        .execute(
            "INSERT INTO ogvcs_identity.current_policies
             (tenant_id, repository_id, policy_generation) VALUES ($1, $2, 1)
             ON CONFLICT DO NOTHING",
            &[&TENANT, &REPOSITORY],
        )
        .expect("seed current policy");
}

/// Self-skips outside the guarded PostgreSQL lane. Exact 100,000 counting and
/// streaming construction are covered by the bounded unit proof; this live
/// test deliberately uses small chunks while exercising the same SQL path.
#[test]
fn aggregate_plans_are_sealed_current_set_based_and_one_use() {
    let Ok(database_url) = std::env::var("OGVCS_IDENTITY_POLICY_DATABASE_URL") else {
        return;
    };
    let mut client = Client::connect(&database_url, NoTls).expect("connect disposable postgres");
    run_migrations(
        &mut client,
        MigrationRunOptions {
            application_version: env!("CARGO_PKG_VERSION"),
            compatibility_fence_open: true,
        },
    )
    .expect("apply v1-v3 migrations");
    seed(&mut client);
    let initial_commitment_count: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.aggregate_decision_commitments
             WHERE tenant_id=$1",
            &[&TENANT],
        )
        .unwrap()
        .get(0);

    let provider = Arc::new(
        HmacSha256KeyRing::new([(KEY_REFERENCE.to_owned(), [0x5a; 32])])
            .expect("construct test key ring"),
    );
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    {
        let mut transaction = client.transaction().unwrap();
        participant
            .bind_repository_contract(
                &mut transaction,
                &RepositoryContractBindingRequest {
                    tenant: TENANT,
                    repository: REPOSITORY,
                    metadata_tenant_id: METADATA_TENANT,
                    metadata_repository_id: METADATA_REPOSITORY,
                },
            )
            .expect("bind exact immutable repository settings");
        participant
            .register_signing_key(
                &mut transaction,
                &AggregateSigningKeyRegistration {
                    tenant: TENANT,
                    key_generation: 1,
                    authority_epoch: 1,
                    key_reference: KEY_REFERENCE,
                },
            )
            .expect("register external HMAC reference");
        participant
            .compile_current_policy(&mut transaction, TENANT, REPOSITORY)
            .expect("compile normalized current policy");
        transaction.commit().unwrap();
    }

    // The same exact plan survives transaction and participant reconstruction.
    let handle = {
        let mut transaction = client.transaction().unwrap();
        let handle = participant
            .begin_plan(&mut transaction, &plan_request())
            .expect("begin aggregate plan");
        transaction.commit().unwrap();
        handle
    };
    {
        let resources = vec![
            resource("Game/Alpha.asset"),
            resource("Game/Straße.asset"),
            resource("Game/Yankee.asset"),
        ];
        let mut transaction = client.transaction().unwrap();
        let progress = participant
            .append_chunk(&mut transaction, &handle, &resources)
            .expect("append canonical bounded chunk");
        assert_eq!(progress.item_count(), 3);
        assert_eq!(progress.chunk_count(), 1);
        transaction.commit().unwrap();
    }
    let receipt = {
        let mut transaction = client.transaction().unwrap();
        let receipt = participant
            .authorize_plan(&mut transaction, &handle)
            .expect("authorize complete set");
        assert_eq!(receipt.resource_count(), 3);
        assert_eq!(receipt.policy_generation(), 1);
        assert_eq!(receipt.policy_digest().len(), 64);
        assert_eq!(receipt.metadata_tenant_id(), METADATA_TENANT);
        assert_eq!(receipt.metadata_repository_id(), METADATA_REPOSITORY);
        assert_eq!(receipt.settings_generation(), 1);
        assert_eq!(receipt.settings_descriptor_digest(), "09".repeat(32));
        assert_eq!(receipt.resource_digest_projection_digest().len(), 64);
        transaction.commit().unwrap();
        receipt
    };
    assert_eq!(
        reconstruct_resource_digest_projection(&mut client, receipt.plan_id()),
        receipt.resource_digest_projection_digest()
    );
    // A ring that resolves the same opaque reference to different secret
    // material cannot verify or consume the receipt.
    {
        let wrong_provider =
            Arc::new(HmacSha256KeyRing::new([(KEY_REFERENCE.to_owned(), [0x6b; 32])]).unwrap());
        let wrong_participant = PostgresAggregateAuthorizationParticipant::new(wrong_provider);
        let mut transaction = client.transaction().unwrap();
        let error = wrong_participant
            .consume_receipt(
                &mut transaction,
                &receipt,
                &AggregateReceiptConsumptionRequest {
                    consumption_id: "aggregate.consume.wrong-key",
                    operation_digest: &"ab".repeat(32),
                },
            )
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::EpochStale);
        transaction.rollback().unwrap();
    }

    // Two reconstructed participants race the same one-use receipt. The plan
    // row lock and unique evidence permit exactly one commit.
    let barrier = Arc::new(Barrier::new(3));
    let mut consumers = Vec::new();
    for index in 0..2 {
        let database_url = database_url.clone();
        let provider = provider.clone();
        let receipt = receipt.clone();
        let barrier = barrier.clone();
        consumers.push(thread::spawn(move || {
            let mut client = Client::connect(&database_url, NoTls).unwrap();
            let restarted = PostgresAggregateAuthorizationParticipant::new(provider);
            let mut transaction = client.transaction().unwrap();
            barrier.wait();
            let consumption_id = format!("aggregate.consume.concurrent-{index}");
            match restarted.consume_receipt(
                &mut transaction,
                &receipt,
                &AggregateReceiptConsumptionRequest {
                    consumption_id: &consumption_id,
                    operation_digest: &"ab".repeat(32),
                },
            ) {
                Ok(consumed) => {
                    assert_eq!(consumed.plan_id(), receipt.plan_id());
                    assert_eq!(
                        consumed.authorization().policy_digest(),
                        receipt.policy_digest()
                    );
                    assert_eq!(
                        consumed.authorization().settings_descriptor_digest(),
                        receipt.settings_descriptor_digest()
                    );
                    transaction.commit().unwrap();
                    Ok(())
                }
                Err(error) => {
                    transaction.rollback().unwrap();
                    Err(error.code())
                }
            }
        }));
    }
    barrier.wait();
    let outcomes = consumers
        .into_iter()
        .map(|consumer| consumer.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Err(ParticipantErrorCode::StateConflict))
            .count(),
        1
    );

    let restarted = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    {
        let mut transaction = client.transaction().unwrap();
        let error = restarted
            .consume_receipt(
                &mut transaction,
                &receipt,
                &AggregateReceiptConsumptionRequest {
                    consumption_id: "aggregate.consume.replay",
                    operation_digest: &"ab".repeat(32),
                },
            )
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::StateConflict);
        transaction.rollback().unwrap();
    }

    // Denial position does not change the public error or emit any aggregate
    // commitment. Each failed transaction is rolled back after poison.
    for (probe, paths) in [
        (
            "early",
            vec!["Game/A-Denied.asset", "Game/B.asset", "Game/C.asset"],
        ),
        (
            "middle",
            vec!["Game/L.asset", "Game/M-Denied.asset", "Game/N.asset"],
        ),
        (
            "last",
            vec!["Game/X.asset", "Game/Y.asset", "Game/Z-Denied.asset"],
        ),
    ] {
        let denied_handle = {
            let mut transaction = client.transaction().unwrap();
            let handle = participant
                .begin_plan(&mut transaction, &plan_request())
                .unwrap();
            transaction.commit().unwrap();
            handle
        };
        {
            let resources = paths.into_iter().map(resource).collect::<Vec<_>>();
            let mut transaction = client.transaction().unwrap();
            participant
                .append_chunk(&mut transaction, &denied_handle, &resources)
                .unwrap();
            transaction.commit().unwrap();
        }
        let mut transaction = client.transaction().unwrap();
        let error = participant
            .authorize_plan(&mut transaction, &denied_handle)
            .unwrap_err();
        assert_eq!(
            error.code(),
            ParticipantErrorCode::AuthenticationDenied,
            "{probe}"
        );
        transaction.rollback().unwrap();
        let commitments: i64 = client
            .query_one(
                "SELECT count(*) FROM ogvcs_identity.aggregate_decision_commitments
                 WHERE plan_id=$1",
                &[&denied_handle.plan_id()],
            )
            .unwrap()
            .get(0);
        assert_eq!(commitments, 0, "{probe}");
    }

    // Every mutable authority input is re-read under lock immediately before
    // set evaluation. None of these stale probes emits a commitment.
    let stale_handle = {
        let mut transaction = client.transaction().unwrap();
        let handle = participant
            .begin_plan(&mut transaction, &plan_request())
            .unwrap();
        transaction.commit().unwrap();
        let mut transaction = client.transaction().unwrap();
        participant
            .append_chunk(
                &mut transaction,
                &handle,
                &[resource("Game/Currentness.asset")],
            )
            .unwrap();
        transaction.commit().unwrap();
        handle
    };
    {
        let mut transaction = client.transaction().unwrap();
        transaction
            .execute(
                "UPDATE ogvcs_identity.credentials
                 SET state='revoked', revoked_at=clock_timestamp()
                 WHERE tenant_id=$1 AND credential_id='aggregate-credential'
                   AND credential_generation=1",
                &[&TENANT],
            )
            .unwrap();
        let error = participant
            .authorize_plan(&mut transaction, &stale_handle)
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::AuthenticationDenied);
        transaction.rollback().unwrap();
    }
    {
        let mut transaction = client.transaction().unwrap();
        transaction
            .execute(
                "UPDATE ogvcs_identity.authority_states
                 SET authority_epoch=2, key_generation=2,
                     updated_at=clock_timestamp() WHERE tenant_id=$1",
                &[&TENANT],
            )
            .unwrap();
        let error = participant
            .authorize_plan(&mut transaction, &stale_handle)
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::EpochStale);
        transaction.rollback().unwrap();
    }
    {
        let next_policy = policy(2);
        let mut transaction = client.transaction().unwrap();
        transaction
            .execute(
                "INSERT INTO ogvcs_identity.policy_versions
                 (tenant_id, repository_id, policy_generation, authority_epoch,
                  policy_id, policy_version, path_profile, case_mode,
                  policy_json, policy_digest)
                 VALUES ($1, $2, 2, 1, $3, $4, $5, $6, $7, $8)",
                &[
                    &TENANT,
                    &REPOSITORY,
                    &next_policy.id,
                    &next_policy.version,
                    &next_policy.path_profile,
                    &next_policy.case_mode,
                    &serde_json::to_value(&next_policy).unwrap(),
                    &digest_json(&next_policy),
                ],
            )
            .unwrap();
        transaction
            .execute(
                "UPDATE ogvcs_identity.current_policies
                 SET policy_generation=2, updated_at=clock_timestamp()
                 WHERE tenant_id=$1 AND repository_id=$2",
                &[&TENANT, &REPOSITORY],
            )
            .unwrap();
        let error = participant
            .authorize_plan(&mut transaction, &stale_handle)
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::PolicyGenerationMismatch);
        transaction.rollback().unwrap();
    }

    // Repository settings are an append-only, generation-versioned handoff.
    // Promoting settings makes every plan sealed to the prior descriptor stale.
    {
        let mut transaction = client.transaction().unwrap();
        transaction
            .execute(
                "UPDATE ogvcs_metadata.repository_settings
                 SET settings_generation=2, descriptor_digest=$2
                 WHERE repository_id=CAST($1::text AS uuid)",
                &[&METADATA_REPOSITORY, &&[0x0a_u8; 32][..]],
            )
            .unwrap();
        let binding = participant
            .bind_repository_contract(
                &mut transaction,
                &RepositoryContractBindingRequest {
                    tenant: TENANT,
                    repository: REPOSITORY,
                    metadata_tenant_id: METADATA_TENANT,
                    metadata_repository_id: METADATA_REPOSITORY,
                },
            )
            .unwrap();
        assert_eq!(binding.settings_generation(), 2);
        transaction.commit().unwrap();
    }
    {
        let mut transaction = client.transaction().unwrap();
        let error = participant
            .authorize_plan(&mut transaction, &stale_handle)
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::PolicyGenerationMismatch);
        transaction.rollback().unwrap();
    }

    // Expiry is checked from PostgreSQL time on every participant entry.
    let expiring_handle = {
        let mut request = plan_request();
        request.ttl_seconds = 1;
        let mut transaction = client.transaction().unwrap();
        let handle = participant.begin_plan(&mut transaction, &request).unwrap();
        transaction.commit().unwrap();
        handle
    };
    thread::sleep(Duration::from_millis(1_100));
    {
        let mut transaction = client.transaction().unwrap();
        let error = participant
            .append_chunk(
                &mut transaction,
                &expiring_handle,
                &[resource("Game/Expired.asset")],
            )
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::AuthenticationDenied);
        transaction.rollback().unwrap();
    }

    // Same-count projection mutations and source-policy mutation are rejected
    // by v3 immutable guards, so count parity cannot mask changed authority.
    for statement in [
        "UPDATE ogvcs_identity.compiled_policy_rules SET effect='deny'
         WHERE tenant_id='aggregate-studio' AND repository_id='aggregate-game'
           AND policy_generation=1 AND rule_id='allow.aggregate.paths'",
        "UPDATE ogvcs_identity.compiled_policy_subjects SET subject_value='other.artist'
         WHERE tenant_id='aggregate-studio' AND repository_id='aggregate-game'
           AND policy_generation=1 AND subject_kind='identity'",
        "UPDATE ogvcs_identity.compiled_policy_path_prefixes SET lower_inclusive='forged'
         WHERE tenant_id='aggregate-studio' AND repository_id='aggregate-game'
           AND policy_generation=1",
        "UPDATE ogvcs_identity.policy_versions SET policy_digest=decode(repeat('00',32),'hex')
         WHERE tenant_id='aggregate-studio' AND repository_id='aggregate-game'
           AND policy_generation=1",
    ] {
        let mut transaction = client.transaction().unwrap();
        assert!(transaction.batch_execute(statement).is_err());
        transaction.rollback().unwrap();
    }

    // Sealed policy/plan facts, the commitment, key binding, and consumption
    // evidence stay immutable even to direct SQL through the application role.
    for statement in [
        format!(
            "DELETE FROM ogvcs_identity.aggregate_plans WHERE plan_id='{}'",
            receipt.plan_id()
        ),
        format!(
            "DELETE FROM ogvcs_identity.aggregate_plan_chunks WHERE plan_id='{}'",
            receipt.plan_id()
        ),
        format!(
            "UPDATE ogvcs_identity.aggregate_decision_commitments
             SET policy_digest=decode(repeat('00',32),'hex') WHERE plan_id='{}'",
            receipt.plan_id()
        ),
        "UPDATE ogvcs_identity.aggregate_signing_keys
         SET state='retired', retired_at=clock_timestamp()
         WHERE tenant_id='aggregate-studio' AND key_generation=1"
            .to_owned(),
        "INSERT INTO ogvcs_identity.compiled_policy_rules
         (tenant_id, repository_id, policy_generation, rule_ordinal, rule_id, effect)
         VALUES ('aggregate-studio','aggregate-game',1,99,'forged.rule','allow')"
            .to_owned(),
        format!(
            "INSERT INTO ogvcs_identity.aggregate_plan_resources
             (plan_id, item_ordinal, resource_type, canonical_resource,
              canonical_resource_key, resource_digest, path_key)
             SELECT plan_id, 99, resource_type, canonical_resource,
                    canonical_resource_key, resource_digest, path_key
             FROM ogvcs_identity.aggregate_plan_resources
             WHERE plan_id='{}' LIMIT 1",
            receipt.plan_id()
        ),
    ] {
        let mut transaction = client.transaction().unwrap();
        assert!(
            transaction.batch_execute(&statement).is_err(),
            "{statement}"
        );
        transaction.rollback().unwrap();
    }

    // Row and chunk byte ceilings are database-enforced as a second line of
    // defense. The participant's bounded preparation rejects them earlier.
    let bounds_handle = {
        let mut transaction = client.transaction().unwrap();
        let handle = participant
            .begin_plan(&mut transaction, &plan_request())
            .unwrap();
        transaction.commit().unwrap();
        handle
    };
    {
        let mut transaction = client.transaction().unwrap();
        let result = transaction.execute(
            "INSERT INTO ogvcs_identity.aggregate_plan_chunks
             (plan_id, chunk_ordinal, first_item_ordinal, item_count,
              encoded_bytes, chunk_digest)
             VALUES ($1, 0, 0, 1, 1048577, decode(repeat('00',32),'hex'))",
            &[&bounds_handle.plan_id()],
        );
        assert!(result.is_err());
        transaction.rollback().unwrap();
    }
    {
        let mut transaction = client.transaction().unwrap();
        let result = transaction.execute(
            "INSERT INTO ogvcs_identity.aggregate_plan_resources
             (plan_id, item_ordinal, resource_type, canonical_resource,
              canonical_resource_key, resource_digest, path_key)
             VALUES ($1, 0, 'path',
               '{\"type\":\"path\",\"path\":\"Game/X.asset\",\"fileId\":null,\"objectId\":null,\"name\":null}'::jsonb,
               decode(repeat('aa',16385),'hex'), decode(repeat('00',32),'hex'), NULL)",
            &[&bounds_handle.plan_id()],
        );
        assert!(result.is_err());
        transaction.rollback().unwrap();
    }

    let commitment_count: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.aggregate_decision_commitments
             WHERE tenant_id=$1",
            &[&TENANT],
        )
        .unwrap()
        .get(0);
    let consumption_count: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.aggregate_plan_consumptions
             WHERE plan_id=$1",
            &[&receipt.plan_id()],
        )
        .unwrap()
        .get(0);
    assert_eq!(commitment_count, initial_commitment_count + 1);
    assert_eq!(consumption_count, 1);
}

/// Opt-in exact ceiling proof. It never retains more than one 1,000-item
/// caller batch, and it exercises the production PostgreSQL set evaluator.
/// Run alone with `--ignored --exact exact_hundred_thousand` against a fresh
/// disposable database; ordinary hosted CI deliberately remains bounded.
#[test]
#[ignore = "opt-in exact 100,000-resource PostgreSQL proof"]
fn exact_hundred_thousand_resources_stream_and_authorize() {
    let database_url = std::env::var("OGVCS_IDENTITY_POLICY_DATABASE_URL")
        .expect("exact aggregate proof requires a disposable PostgreSQL URL");
    let mut client = Client::connect(&database_url, NoTls).expect("connect disposable postgres");
    run_migrations(
        &mut client,
        MigrationRunOptions {
            application_version: env!("CARGO_PKG_VERSION"),
            compatibility_fence_open: true,
        },
    )
    .expect("apply v1-v3 migrations");
    seed(&mut client);
    let provider = Arc::new(
        HmacSha256KeyRing::new([(KEY_REFERENCE.to_owned(), [0x5a; 32])])
            .expect("construct test key ring"),
    );
    let participant = PostgresAggregateAuthorizationParticipant::new(provider);
    {
        let mut transaction = client.transaction().unwrap();
        participant
            .bind_repository_contract(
                &mut transaction,
                &RepositoryContractBindingRequest {
                    tenant: TENANT,
                    repository: REPOSITORY,
                    metadata_tenant_id: METADATA_TENANT,
                    metadata_repository_id: METADATA_REPOSITORY,
                },
            )
            .unwrap();
        participant
            .register_signing_key(
                &mut transaction,
                &AggregateSigningKeyRegistration {
                    tenant: TENANT,
                    key_generation: 1,
                    authority_epoch: 1,
                    key_reference: KEY_REFERENCE,
                },
            )
            .unwrap();
        participant
            .compile_current_policy(&mut transaction, TENANT, REPOSITORY)
            .unwrap();
        transaction.commit().unwrap();
    }
    let handle = {
        let mut transaction = client.transaction().unwrap();
        let handle = participant
            .begin_plan(&mut transaction, &plan_request())
            .unwrap();
        transaction.commit().unwrap();
        handle
    };
    for chunk in 0..100 {
        let first = chunk * 1_000;
        let resources = (first..first + 1_000)
            .map(|index| resource(&format!("Game/Scale/{index:06}.asset")))
            .collect::<Vec<_>>();
        let mut transaction = client.transaction().unwrap();
        let progress = participant
            .append_chunk(&mut transaction, &handle, &resources)
            .unwrap();
        assert_eq!(progress.item_count(), first + 1_000);
        transaction.commit().unwrap();
    }
    {
        let mut transaction = client.transaction().unwrap();
        let error = participant
            .append_chunk(
                &mut transaction,
                &handle,
                &[resource("Game/Scale/100000.asset")],
            )
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::LimitExceeded);
        transaction.rollback().unwrap();
    }
    let receipt = {
        let mut transaction = client.transaction().unwrap();
        let receipt = participant
            .authorize_plan(&mut transaction, &handle)
            .expect("authorize the complete exact resource set");
        transaction.commit().unwrap();
        receipt
    };
    assert_eq!(receipt.resource_count(), 100_000);
    assert_eq!(receipt.metadata_tenant_id(), METADATA_TENANT);
    assert_eq!(
        reconstruct_resource_digest_projection(&mut client, receipt.plan_id()),
        receipt.resource_digest_projection_digest()
    );
    let stored_count: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.aggregate_plan_resources
             WHERE plan_id=$1",
            &[&receipt.plan_id()],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored_count, 100_000);
}
