use std::collections::HashSet;

use ogvcs_path_contract::{CaseMode, PathProfile};
use serde_json::json;

use crate::canonical::{
    digest_json, hex, path_in_prefixes, valid_id, valid_opaque, valid_safe_text, validate_path,
};
use crate::{
    AuthorizationResource, CredentialScope, ParticipantError, ParticipantErrorCode, PolicyDocument,
    PolicyRule, Result,
};

const PERMISSIONS: &[&str] = &[
    "discover",
    "metadata.read",
    "content.materialize",
    "content.upload",
    "lock.create",
    "submit",
    "review",
    "export",
    "policy.administer",
    "lock.force-unlock",
    "repair",
    "retention.delete",
    "audit.read",
    "impersonate",
];

const PRIVILEGED_PERMISSIONS: &[&str] = &[
    "export",
    "policy.administer",
    "lock.force-unlock",
    "repair",
    "retention.delete",
    "audit.read",
    "impersonate",
];

const RESOURCE_TYPES: &[&str] = &[
    "repository",
    "reference",
    "snapshot",
    "tree",
    "path",
    "object",
    "content",
    "lock",
    "review",
    "search",
    "event",
    "cache-entry",
    "export",
    "policy",
    "audit",
    "retention",
    "repair-job",
    "sandbox-job",
];

const ACTOR_CLASSES: &[&str] = &[
    "anonymous",
    "human",
    "service",
    "administrator",
    "cache",
    "sandbox-worker",
];

#[derive(Clone, Debug)]
pub(crate) struct ActorFacts {
    pub id: String,
    pub class: String,
    pub groups: Vec<String>,
    pub credential_class: String,
    pub credential_generation: u64,
    pub authority_epoch: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct RequestFacts<'a> {
    pub request_id: &'a str,
    pub tenant: &'a str,
    pub repository: &'a str,
    pub permission: &'a str,
    pub reason: Option<&'a str>,
    pub resource: &'a AuthorizationResource,
    pub reference: Option<&'a str>,
    pub snapshot: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub(crate) struct AllowDecision {
    pub request_fingerprint: String,
    pub decision_digest: String,
}

pub(crate) fn validate_scope(
    scope: &CredentialScope,
    path_profile: PathProfile,
    case_mode: CaseMode,
) -> Result<()> {
    validate_id_list(&scope.tenants, 1, 16)?;
    validate_id_list(&scope.repositories, 1, 128)?;
    validate_id_list(&scope.references, 0, 128)?;
    validate_assignment_list(&scope.permissions, 1, 64, PERMISSIONS)?;
    validate_paths(&scope.path_prefixes, path_profile, case_mode, 128)?;
    Ok(())
}

pub(crate) fn validate_policy(policy: &PolicyDocument) -> Result<()> {
    let invalid = || ParticipantError::new(ParticipantErrorCode::PolicyUnavailable);
    if policy.schema_version != "ogvcs.identity-policy/policy/v1"
        || !valid_id(&policy.id)
        || !valid_id(&policy.version)
        || policy.generation == 0
        || policy.authority_epoch == 0
        || policy.default_effect != "deny"
        || policy.composition != "deny-overrides-v1"
        || policy.rules.is_empty()
        || policy.rules.len() > 1_024
    {
        return Err(invalid());
    }
    let path_profile = PathProfile::parse(&policy.path_profile).map_err(|_| invalid())?;
    let case_mode = CaseMode::parse(&policy.case_mode).map_err(|_| invalid())?;
    let mut rule_ids = HashSet::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        if !valid_id(&rule.id) || !rule_ids.insert(&rule.id) {
            return Err(invalid());
        }
        validate_rule(rule, path_profile, case_mode).map_err(|_| invalid())?;
    }
    Ok(())
}

fn validate_rule(rule: &PolicyRule, path_profile: PathProfile, case_mode: CaseMode) -> Result<()> {
    if !matches!(rule.effect.as_str(), "allow" | "deny")
        || !valid_id(&rule.tenant)
        || !valid_id(&rule.repository)
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        ));
    }
    validate_id_list(&rule.subjects.identities, 0, 128)?;
    validate_id_list(&rule.subjects.groups, 0, 128)?;
    validate_assignment_list(&rule.subjects.actor_classes, 0, 32, ACTOR_CLASSES)?;
    validate_id_list(&rule.references, 0, 128)?;
    validate_paths(&rule.path_prefixes, path_profile, case_mode, 128)?;
    validate_assignment_list(&rule.resource_types, 1, 64, RESOURCE_TYPES)?;
    validate_assignment_list(&rule.permissions, 1, 64, PERMISSIONS)
}

fn validate_paths(
    paths: &[String],
    path_profile: PathProfile,
    case_mode: CaseMode,
    maximum: usize,
) -> Result<()> {
    if paths.len() > maximum || !unique(paths) {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    for path in paths {
        validate_path(path, path_profile, case_mode, true)?;
    }
    Ok(())
}

fn validate_id_list(values: &[String], minimum: usize, maximum: usize) -> Result<()> {
    if values.len() < minimum
        || values.len() > maximum
        || !unique(values)
        || values.iter().any(|value| !valid_id(value))
    {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    Ok(())
}

fn validate_assignment_list(
    values: &[String],
    minimum: usize,
    maximum: usize,
    assignments: &[&str],
) -> Result<()> {
    validate_id_list(values, minimum, maximum)?;
    if values
        .iter()
        .any(|value| !assignments.contains(&value.as_str()))
    {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    Ok(())
}

fn unique(values: &[String]) -> bool {
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().all(|value| seen.insert(value))
}

pub(crate) fn validate_resource(
    resource: &AuthorizationResource,
    path_profile: PathProfile,
    case_mode: CaseMode,
) -> Result<()> {
    if !RESOURCE_TYPES.contains(&resource.resource_type.as_str()) {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    if let Some(path) = resource.path.as_deref() {
        validate_path(path, path_profile, case_mode, false)?;
    }
    if resource.file_id.as_deref().is_some_and(|value| {
        value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    if resource.object_id.as_deref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 160
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-')
            })
    }) {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    if resource
        .name
        .as_deref()
        .is_some_and(|value| !valid_safe_text(value))
    {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    Ok(())
}

pub(crate) fn validate_request_surface(
    request: RequestFacts<'_>,
    path_profile: PathProfile,
    case_mode: CaseMode,
) -> Result<()> {
    if !valid_opaque(request.request_id)
        || !valid_id(request.tenant)
        || !valid_id(request.repository)
        || !PERMISSIONS.contains(&request.permission)
        || request
            .reason
            .is_some_and(|reason| !valid_safe_text(reason))
        || request
            .reference
            .is_some_and(|reference| !valid_id(reference))
        || request
            .snapshot
            .is_some_and(|snapshot| !valid_opaque(snapshot))
    {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    validate_resource(request.resource, path_profile, case_mode)
}

pub(crate) fn evaluate_allow(
    policy: &PolicyDocument,
    actor: &ActorFacts,
    scope: &CredentialScope,
    request: RequestFacts<'_>,
    allow_unbound_transaction_scope: bool,
) -> Result<AllowDecision> {
    let path_profile = PathProfile::parse(&policy.path_profile)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let case_mode = CaseMode::parse(&policy.case_mode)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    validate_request_surface(request, path_profile, case_mode)?;
    validate_scope(scope, path_profile, case_mode)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    if !scope.tenants.iter().any(|value| value == request.tenant)
        || !scope
            .repositories
            .iter()
            .any(|value| value == request.repository)
        || !scope
            .permissions
            .iter()
            .any(|value| value == request.permission)
        || (!scope.references.is_empty()
            && request
                .reference
                .map_or(!allow_unbound_transaction_scope, |reference| {
                    !scope.references.iter().any(|value| value == reference)
                }))
        || (!allow_unbound_transaction_scope
            && request.resource.resource_type == "path"
            && !path_in_prefixes(
                request.resource.path.as_deref(),
                &scope.path_prefixes,
                path_profile,
                case_mode,
            )?)
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    if PRIVILEGED_PERMISSIONS.contains(&request.permission)
        && request.reason.is_none_or(|reason| reason.trim().is_empty())
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }

    let mut allowed = false;
    for rule in &policy.rules {
        if rule_matches(rule, actor, request, path_profile, case_mode)? {
            if rule.effect == "deny" {
                return Err(ParticipantError::new(
                    ParticipantErrorCode::AuthenticationDenied,
                ));
            }
            allowed = true;
        }
    }
    if !allowed {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }

    let request_value = json!({
        "schemaVersion": "ogvcs.authorization/request/v1",
        "requestId": request.request_id,
        "actor": {
            "id": actor.id,
            "class": actor.class,
            "groups": actor.groups,
            "credentialClass": actor.credential_class,
            "credentialGeneration": actor.credential_generation,
            "credentialStatus": "active",
            "authorityEpoch": actor.authority_epoch,
        },
        "tenant": request.tenant,
        "repository": request.repository,
        "permission": request.permission,
        "reason": request.reason,
        "resource": request.resource,
        "context": {
            "reference": request.reference,
            "snapshot": request.snapshot,
            "policyGeneration": policy.generation,
            "authorityEpoch": policy.authority_epoch,
        },
    });
    let fingerprint = hex(&digest_json(&json!({
        "policy": {
            "id": policy.id,
            "version": policy.version,
            "generation": policy.generation,
            "authorityEpoch": policy.authority_epoch,
        },
        "request": request_value,
    }))?);
    let decision_digest = hex(&digest_json(&json!({
        "schemaVersion": "ogvcs.authorization/decision/v1",
        "requestId": request.request_id,
        "allowed": true,
        "code": "ALLOW_EXPLICIT",
        "policyVersion": format!("{}.{}", policy.id, policy.version),
        "policyGeneration": policy.generation,
        "decisionFingerprint": fingerprint,
    }))?);
    Ok(AllowDecision {
        request_fingerprint: fingerprint,
        decision_digest,
    })
}
fn rule_matches(
    rule: &PolicyRule,
    actor: &ActorFacts,
    request: RequestFacts<'_>,
    path_profile: PathProfile,
    case_mode: CaseMode,
) -> Result<bool> {
    if !rule.subjects.identities.is_empty()
        && !rule
            .subjects
            .identities
            .iter()
            .any(|value| value == &actor.id)
    {
        return Ok(false);
    }
    if !rule.subjects.groups.is_empty()
        && !rule
            .subjects
            .groups
            .iter()
            .any(|value| actor.groups.iter().any(|group| group == value))
    {
        return Ok(false);
    }
    if !rule.subjects.actor_classes.is_empty()
        && !rule
            .subjects
            .actor_classes
            .iter()
            .any(|value| value == &actor.class)
    {
        return Ok(false);
    }
    if rule.tenant != request.tenant
        || rule.repository != request.repository
        || (!rule.references.is_empty()
            && request
                .reference
                .is_none_or(|reference| !rule.references.iter().any(|value| value == reference)))
        || !rule
            .resource_types
            .iter()
            .any(|value| value == &request.resource.resource_type)
        || !rule
            .permissions
            .iter()
            .any(|value| value == request.permission)
    {
        return Ok(false);
    }
    path_in_prefixes(
        request.resource.path.as_deref(),
        &rule.path_prefixes,
        path_profile,
        case_mode,
    )
}

#[cfg(test)]
mod tests {
    use super::{evaluate_allow, validate_policy, ActorFacts, RequestFacts};
    use crate::{
        AuthorizationResource, CredentialScope, ParticipantErrorCode, PolicyDocument, PolicyRule,
        RuleSubjects,
    };

    fn policy(profile: &str, case_mode: &str, prefix: &str) -> PolicyDocument {
        PolicyDocument {
            schema_version: "ogvcs.identity-policy/policy/v1".to_owned(),
            id: "studio.policy".to_owned(),
            version: "v1".to_owned(),
            generation: 1,
            authority_epoch: 1,
            path_profile: profile.to_owned(),
            case_mode: case_mode.to_owned(),
            default_effect: "deny".to_owned(),
            composition: "deny-overrides-v1".to_owned(),
            rules: vec![PolicyRule {
                id: "allow.path".to_owned(),
                effect: "allow".to_owned(),
                subjects: RuleSubjects {
                    identities: vec!["artist.user".to_owned()],
                    groups: vec![],
                    actor_classes: vec!["human".to_owned()],
                },
                tenant: "studio".to_owned(),
                repository: "game".to_owned(),
                references: vec!["main".to_owned()],
                path_prefixes: vec![prefix.to_owned()],
                resource_types: vec!["path".to_owned()],
                permissions: vec!["metadata.read".to_owned()],
            }],
        }
    }

    fn actor() -> ActorFacts {
        ActorFacts {
            id: "artist.user".to_owned(),
            class: "human".to_owned(),
            groups: vec![],
            credential_class: "session".to_owned(),
            credential_generation: 1,
            authority_epoch: 1,
        }
    }

    fn scope() -> CredentialScope {
        CredentialScope {
            tenants: vec!["studio".to_owned()],
            repositories: vec!["game".to_owned()],
            references: vec!["main".to_owned()],
            path_prefixes: vec![String::new()],
            permissions: vec!["metadata.read".to_owned()],
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

    fn evaluate(policy: &PolicyDocument, path: &str) -> crate::Result<()> {
        let actor = actor();
        let scope = scope();
        let resource = resource(path);
        evaluate_allow(
            policy,
            &actor,
            &scope,
            RequestFacts {
                request_id: "request.1",
                tenant: "studio",
                repository: "game",
                permission: "metadata.read",
                reason: None,
                resource: &resource,
                reference: Some("main"),
                snapshot: None,
            },
            false,
        )
        .map(|_| ())
    }

    #[test]
    fn all_ratified_profiles_and_case_modes_validate() {
        for profile in [
            "path.opengamevcs/portable@1",
            "path.opengamevcs/windows@1",
            "path.opengamevcs/macos@1",
            "path.opengamevcs/linux@1",
        ] {
            for case_mode in ["case-sensitive", "case-folded"] {
                validate_policy(&policy(profile, case_mode, "Game"))
                    .expect("ratified OGVCS-004 policy options validate");
            }
        }
        assert_eq!(
            validate_policy(&policy(
                "path.opengamevcs/unknown@1",
                "case-sensitive",
                "Game"
            ))
            .unwrap_err()
            .code(),
            ParticipantErrorCode::PolicyUnavailable
        );
    }

    #[test]
    fn direct_evaluator_applies_the_selected_profile_and_case_mode() {
        let linux = policy(
            "path.opengamevcs/linux@1",
            "case-sensitive",
            "Game:Assets/Hero",
        );
        validate_policy(&linux).expect("Linux permits a colon inside a path component");
        evaluate(&linux, "Game:Assets/Hero/asset")
            .expect("the evaluator uses the selected Linux profile");

        assert_eq!(
            validate_policy(&policy(
                "path.opengamevcs/portable@1",
                "case-sensitive",
                "Game:Assets/Hero",
            ))
            .unwrap_err()
            .code(),
            ParticipantErrorCode::PolicyUnavailable
        );

        let sensitive = policy("path.opengamevcs/linux@1", "case-sensitive", "Game/Hero");
        assert_eq!(
            evaluate(&sensitive, "game/hero/asset").unwrap_err().code(),
            ParticipantErrorCode::AuthenticationDenied
        );
    }

    #[test]
    fn direct_evaluator_uses_full_unicode_16_fold_and_component_prefixes() {
        let folded = policy(
            "path.opengamevcs/linux@1",
            "case-folded",
            "Game/Straße/Σ/İ/ꭰ",
        );
        evaluate(&folded, "game/STRASSE/ς/i\u{307}/Ꭰ/child")
            .expect("sharp-s, sigma, dotted-I, and Cherokee use the pinned full fold");

        let separated = policy("path.opengamevcs/linux@1", "case-folded", "Game/Hero");
        assert_eq!(
            evaluate(&separated, "game/Heroic/asset")
                .unwrap_err()
                .code(),
            ParticipantErrorCode::AuthenticationDenied
        );
    }

    #[test]
    fn non_nfc_and_reserved_namespace_fail_closed_without_repair() {
        let source = policy("path.opengamevcs/linux@1", "case-folded", "Game");
        assert_eq!(
            evaluate(&source, "Game/Cafe\u{301}/asset")
                .unwrap_err()
                .code(),
            ParticipantErrorCode::InputInvalid
        );
        for profile in [
            "path.opengamevcs/portable@1",
            "path.opengamevcs/windows@1",
            "path.opengamevcs/macos@1",
            "path.opengamevcs/linux@1",
        ] {
            assert_eq!(
                validate_policy(&policy(profile, "case-sensitive", ".OGVCS/state"))
                    .unwrap_err()
                    .code(),
                ParticipantErrorCode::PolicyUnavailable
            );
        }
    }
}
