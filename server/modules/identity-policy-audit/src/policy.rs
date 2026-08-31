use std::collections::HashSet;

use serde_json::json;

use crate::canonical::{
    canonical_path, digest_json, hex, path_in_prefixes, valid_id, valid_opaque, valid_safe_text,
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

pub(crate) fn validate_scope(scope: &CredentialScope, case_mode: &str) -> Result<()> {
    validate_id_list(&scope.tenants, 1, 16)?;
    validate_id_list(&scope.repositories, 1, 128)?;
    validate_id_list(&scope.references, 0, 128)?;
    validate_assignment_list(&scope.permissions, 1, 64, PERMISSIONS)?;
    validate_paths(&scope.path_prefixes, case_mode, 128)?;
    Ok(())
}

pub(crate) fn validate_policy(policy: &PolicyDocument) -> Result<()> {
    let invalid = || ParticipantError::new(ParticipantErrorCode::PolicyUnavailable);
    if policy.schema_version != "ogvcs.identity-policy/policy/v1"
        || !valid_id(&policy.id)
        || !valid_id(&policy.version)
        || policy.generation == 0
        || policy.authority_epoch == 0
        || policy.path_profile != "path.opengamevcs/portable@1"
        || !matches!(policy.case_mode.as_str(), "case-sensitive" | "case-folded")
        || policy.default_effect != "deny"
        || policy.composition != "deny-overrides-v1"
        || policy.rules.is_empty()
        || policy.rules.len() > 1_024
    {
        return Err(invalid());
    }
    let mut rule_ids = HashSet::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        if !valid_id(&rule.id) || !rule_ids.insert(&rule.id) {
            return Err(invalid());
        }
        validate_rule(rule, &policy.case_mode).map_err(|_| invalid())?;
    }
    Ok(())
}

fn validate_rule(rule: &PolicyRule, case_mode: &str) -> Result<()> {
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
    validate_paths(&rule.path_prefixes, case_mode, 128)?;
    validate_assignment_list(&rule.resource_types, 1, 64, RESOURCE_TYPES)?;
    validate_assignment_list(&rule.permissions, 1, 64, PERMISSIONS)
}

fn validate_paths(paths: &[String], case_mode: &str, maximum: usize) -> Result<()> {
    if paths.len() > maximum || !unique(paths) {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    for path in paths {
        canonical_path(path, case_mode, true)?;
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

pub(crate) fn validate_resource(resource: &AuthorizationResource, case_mode: &str) -> Result<()> {
    if !RESOURCE_TYPES.contains(&resource.resource_type.as_str()) {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    if let Some(path) = resource.path.as_deref() {
        canonical_path(path, case_mode, false)?;
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

pub(crate) fn validate_request_surface(request: RequestFacts<'_>, case_mode: &str) -> Result<()> {
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
    validate_resource(request.resource, case_mode)
}

pub(crate) fn evaluate_allow(
    policy: &PolicyDocument,
    actor: &ActorFacts,
    scope: &CredentialScope,
    request: RequestFacts<'_>,
) -> Result<AllowDecision> {
    validate_request_surface(request, &policy.case_mode)?;
    validate_scope(scope, &policy.case_mode)
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
                .is_none_or(|reference| !scope.references.iter().any(|value| value == reference)))
        || !path_in_prefixes(
            request.resource.path.as_deref(),
            &scope.path_prefixes,
            &policy.case_mode,
        )?
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
        if rule_matches(rule, policy, actor, request)? {
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
    policy: &PolicyDocument,
    actor: &ActorFacts,
    request: RequestFacts<'_>,
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
        &policy.case_mode,
    )
}
