use std::collections::BTreeMap;

use ogvcs_identity_policy_audit_postgres::{
    run_migrations, verify_schema_compatibility, AuthorizationResource, CredentialScope,
    DecisionCommitmentRequest, MigrationRunOptions, PolicyDocument, PolicyRule,
    PostgresTransactionAuthorizationParticipant, RuleSubjects, TransactionAuthorizationParticipant,
    TransactionAuthorizationRequest, TransactionBatchRecheck,
};
use postgres::{Client, NoTls};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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

fn policy() -> PolicyDocument {
    PolicyDocument {
        schema_version: "ogvcs.identity-policy/policy/v1".to_owned(),
        id: "studio.policy".to_owned(),
        version: "v1".to_owned(),
        generation: 1,
        authority_epoch: 2,
        path_profile: "path.opengamevcs/portable@1".to_owned(),
        case_mode: "case-sensitive".to_owned(),
        default_effect: "deny".to_owned(),
        composition: "deny-overrides-v1".to_owned(),
        rules: vec![PolicyRule {
            id: "allow.artist".to_owned(),
            effect: "allow".to_owned(),
            subjects: RuleSubjects {
                identities: vec![],
                groups: vec!["artists".to_owned()],
                actor_classes: vec!["human".to_owned()],
            },
            tenant: "studio".to_owned(),
            repository: "game".to_owned(),
            references: vec!["main".to_owned()],
            path_prefixes: vec!["Game".to_owned()],
            resource_types: vec!["path".to_owned()],
            permissions: vec!["metadata.read".to_owned()],
        }],
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

fn seed_current_authority(client: &mut Client, presentation: &str) {
    let scope = CredentialScope {
        tenants: vec!["studio".to_owned()],
        repositories: vec!["game".to_owned()],
        references: vec!["main".to_owned()],
        path_prefixes: vec!["Game".to_owned()],
        permissions: vec!["metadata.read".to_owned()],
    };
    let policy = policy();
    let scope_json = serde_json::to_value(&scope).expect("scope serializes");
    let policy_json = serde_json::to_value(&policy).expect("policy serializes");
    let presentation_digest = digest_parts(&[CREDENTIAL_DOMAIN, presentation.as_bytes()]);
    let subject_digest = digest_parts(&[SUBJECT_DOMAIN, b"artist.user"]);
    let scope_digest = digest_json(&scope);
    let policy_digest = digest_json(&policy);

    client
        .execute(
            "INSERT INTO ogvcs_identity.authority_states
             (tenant_id, authority_epoch, key_generation) VALUES ($1, 2, 4)",
            &[&"studio"],
        )
        .expect("seed authority state");
    client
        .execute(
            "INSERT INTO ogvcs_identity.credentials
             (tenant_id, credential_id, credential_generation, presentation_digest,
              subject_id, subject_digest, actor_class, credential_class, groups_json,
              authority_epoch, issued_at, expires_at, state, scope_json, scope_digest)
             VALUES ($1, $2, 1, $3, $4, $5, 'human', 'session', $6, 2,
                     clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '1 hour', 'active', $7, $8)",
            &[
                &"studio",
                &"credential",
                &presentation_digest,
                &"artist.user",
                &subject_digest,
                &json!(["artists"]),
                &scope_json,
                &scope_digest,
            ],
        )
        .expect("seed current credential");
    client
        .execute(
            "INSERT INTO ogvcs_identity.policy_versions
             (tenant_id, repository_id, policy_generation, authority_epoch, policy_id,
              policy_version, path_profile, case_mode, policy_json, policy_digest)
             VALUES ($1, $2, 1, 2, $3, $4, $5, $6, $7, $8)",
            &[
                &"studio",
                &"game",
                &policy.id,
                &policy.version,
                &policy.path_profile,
                &policy.case_mode,
                &policy_json,
                &policy_digest,
            ],
        )
        .expect("seed current policy version");
    client
        .execute(
            "INSERT INTO ogvcs_identity.current_policies
             (tenant_id, repository_id, policy_generation) VALUES ($1, $2, 1)",
            &[&"studio", &"game"],
        )
        .expect("seed current policy pointer");
}

fn authorization_request<'a>(
    presentation: &'a str,
    resource: &'a AuthorizationResource,
) -> TransactionAuthorizationRequest<'a> {
    TransactionAuthorizationRequest {
        request_id: "request.metadata.1",
        credential_presentation: presentation,
        tenant: "studio",
        repository: "game",
        permission: "metadata.read",
        reason: None,
        resource,
        reference: Some("main"),
        snapshot: None,
    }
}

/// This self-skips without a disposable PostgreSQL URL. CI supplies PostgreSQL
/// 15 and proves migrations plus the real authorization participant boundary.
#[test]
fn checked_migrations_and_same_transaction_participant_work_on_postgres_15() {
    let Ok(database_url) = std::env::var("OGVCS_IDENTITY_POLICY_DATABASE_URL") else {
        return;
    };
    let mut client = Client::connect(&database_url, NoTls).expect("connect disposable postgres");
    let options = MigrationRunOptions {
        application_version: env!("CARGO_PKG_VERSION"),
        compatibility_fence_open: true,
    };
    let first = run_migrations(&mut client, options).expect("apply checksummed migrations");
    assert_eq!(first.applied, 3);
    let second = run_migrations(&mut client, options).expect("restartable migration replay");
    assert_eq!(second.applied, 0);
    assert_eq!(second.already_applied, 3);
    verify_schema_compatibility(&mut client).expect("schema compatibility fence");

    let presentation = "live.credential.presentation";
    seed_current_authority(&mut client, presentation);
    let participant = PostgresTransactionAuthorizationParticipant::new().expect("participant entropy");
    let alpha = resource("Game/Alpha.asset");
    let zeta = resource("Game/Zeta.asset");
    let resources = vec![zeta.clone(), alpha.clone()];

    {
        let mut transaction = client.transaction().expect("begin current transaction");
        let view = participant
            .authorize(&mut transaction, &authorization_request(presentation, &alpha))
            .expect("authorize current credential and policy");
        let batch = participant
            .recheck_batch(
                &mut transaction,
                &view,
                &TransactionBatchRecheck {
                    tenant: "studio",
                    repository: "game",
                    permission: "metadata.read",
                    resources: &resources,
                },
            )
            .expect("recheck canonical resource batch");
        let batch_json = serde_json::to_value(&batch).expect("batch serializes");
        assert_eq!(
            batch_json["schemaVersion"],
            "ogvcs.identity-policy/authorized-resource-batch/v1"
        );
        assert_eq!(batch_json["items"].as_array().unwrap().len(), 2);
        let commitment = participant
            .append_decision_commitment(
                &mut transaction,
                &view,
                &DecisionCommitmentRequest {
                    correlation_id: "correlation.live.1",
                    tenant: "studio",
                    repository: "game",
                    permission: "metadata.read",
                    resources: &resources,
                    result: &json!({ "outcome": "published" }),
                },
            )
            .expect("append ordinary decision commitment");
        assert_eq!(commitment.sequence(), 1);
        transaction.commit().expect("commit participant work");
    }
    {
        let mut transaction = client.transaction().expect("begin chain verification");
        assert_eq!(
            participant
                .verify_decision_chain(&mut transaction, "studio", 10)
                .expect("verify committed decision chain")
                .records(),
            1
        );
        transaction.commit().expect("commit verification read");
    }

    let mut other_client = Client::connect(&database_url, NoTls).expect("connect second transaction");
    let source_view = {
        let mut source = client.transaction().expect("begin source transaction");
        let view = participant
            .authorize(&mut source, &authorization_request(presentation, &alpha))
            .expect("authorize source view");
        let mut other = other_client.transaction().expect("begin wrong transaction");
        assert!(participant
            .recheck_batch(
                &mut other,
                &view,
                &TransactionBatchRecheck {
                    tenant: "studio",
                    repository: "game",
                    permission: "metadata.read",
                    resources: std::slice::from_ref(&alpha),
                },
            )
            .is_err());
        assert!(other.simple_query("SELECT 1").is_err());
        view
    };
    assert!(!source_view.transaction_id().is_empty());

    {
        let mut transaction = client.transaction().expect("begin poison transaction");
        let view = participant
            .authorize(&mut transaction, &authorization_request(presentation, &alpha))
            .expect("authorize poison fixture");
        let duplicate = vec![alpha.clone(), alpha.clone()];
        assert!(participant
            .recheck_batch(
                &mut transaction,
                &view,
                &TransactionBatchRecheck {
                    tenant: "studio",
                    repository: "game",
                    permission: "metadata.read",
                    resources: &duplicate,
                },
            )
            .is_err());
        assert!(transaction.simple_query("SELECT 1").is_err());
    }
}
