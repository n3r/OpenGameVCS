#![allow(dead_code)]

use ogvcs_hard_lock_model::*;
use ogvcs_object_model::{FileId, ObjectKind, ObjectRef};
use ogvcs_path_contract::{CaseMode, PathProfile};

pub fn bytes16(value: u8) -> [u8; 16] {
    [value; 16]
}

pub fn bytes32(value: u8) -> [u8; 32] {
    [value; 32]
}

pub fn repository(value: u8) -> RepositoryId {
    RepositoryId::new(bytes16(value)).unwrap()
}

pub fn subject(value: u8) -> SubjectId {
    SubjectId::new(bytes32(value)).unwrap()
}

pub fn workspace(value: u8) -> WorkspaceId {
    WorkspaceId::new(bytes32(value)).unwrap()
}

pub fn key(value: u8) -> IdempotencyKey {
    IdempotencyKey::new(bytes16(value)).unwrap()
}

pub fn file(value: u8) -> FileId {
    FileId::new(bytes16(value)).unwrap()
}

pub fn file_number(value: u16) -> FileId {
    let mut bytes = [0_u8; 16];
    bytes[..2].copy_from_slice(&value.to_be_bytes());
    FileId::new(bytes).unwrap()
}

pub fn snapshot(value: u8) -> ObjectRef {
    ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: bytes32(value),
    }
}

pub fn scope() -> ScopeBinding {
    ScopeBinding {
        repository_id: repository(1),
        domain_digest: bytes32(2),
    }
}

pub fn model_with(case_mode: CaseMode, limits: ModelLimits) -> LockModel {
    LockModel::new(LockModelConfig {
        scope: scope(),
        authority_epoch: 7,
        initial_server_time: 100,
        path_profile: PathProfile::parse("path.opengamevcs/portable@1").unwrap(),
        case_mode,
        limits,
    })
    .unwrap()
}

pub fn model() -> LockModel {
    model_with(CaseMode::Sensitive, ModelLimits::default())
}

pub fn permission(
    actor: SubjectId,
    assignment: PermissionAssignment,
    affirmed: bool,
) -> SuppliedPermissionFact {
    SuppliedPermissionFact {
        permission: assignment,
        decision: if affirmed {
            SuppliedDecision::Affirmed
        } else {
            SuppliedDecision::NotAffirmed
        },
        authority_epoch: 7,
        policy_generation: 3,
        subject: actor,
        scope_commitment: scope().commitment(),
        decision_digest: bytes32(99),
    }
}

pub fn meta(key_value: u8, actor: SubjectId, assignment: PermissionAssignment) -> RequestMeta {
    RequestMeta {
        idempotency_key: key(key_value),
        scope: scope(),
        permission: permission(actor, assignment, true),
    }
}

pub fn file_target(file_id: FileId, path: &str, generation: u64) -> TargetInput {
    TargetInput {
        target: LockTarget::File(file_id),
        expansion: TargetExpansion {
            schema_version: TARGET_EXPANSION_VERSION,
            view_generation: generation,
            policy_version: 0,
            policy_digest: [0; 32],
            members: vec![ExpandedMember {
                file_id,
                canonical_path: path.to_owned(),
            }],
        },
    }
}

pub fn prefix_target(path: &str, members: &[(FileId, &str)], generation: u64) -> TargetInput {
    TargetInput {
        target: LockTarget::Prefix(path.to_owned()),
        expansion: TargetExpansion {
            schema_version: TARGET_EXPANSION_VERSION,
            view_generation: generation,
            policy_version: 0,
            policy_digest: [0; 32],
            members: members
                .iter()
                .map(|(file_id, path)| ExpandedMember {
                    file_id: *file_id,
                    canonical_path: (*path).to_owned(),
                })
                .collect(),
        },
    }
}

pub fn group_target(
    group_value: u8,
    policy_version: u32,
    members: Vec<ExpandedMember>,
) -> TargetInput {
    TargetInput {
        target: LockTarget::AssetGroup {
            group_id: AssetGroupId::new(bytes16(group_value)).unwrap(),
            policy_version,
        },
        expansion: TargetExpansion {
            schema_version: TARGET_EXPANSION_VERSION,
            view_generation: 8,
            policy_version,
            policy_digest: bytes32(44),
            members,
        },
    }
}

pub fn acquire(
    key_value: u8,
    actor: SubjectId,
    workspace_id: WorkspaceId,
    target: TargetInput,
) -> Command {
    Command::Acquire(AcquireRequest {
        meta: meta(key_value, actor, PermissionAssignment::LockCreate),
        owner: actor,
        workspace: workspace_id,
        base_snapshot: snapshot(10),
        target,
        lease_ticks: 20,
    })
}

pub fn advisory(
    key_value: u8,
    actor: SubjectId,
    workspace_id: WorkspaceId,
    target: TargetInput,
) -> Command {
    Command::BeginAdvisory(BeginAdvisoryRequest {
        meta: meta(key_value, actor, PermissionAssignment::LockCreate),
        owner: actor,
        workspace: workspace_id,
        base_snapshot: snapshot(10),
        target,
        lease_ticks: 20,
    })
}

pub fn context(time: u64) -> TransitionContext {
    TransitionContext {
        authority_epoch: 7,
        server_time: time,
        control: TransitionControl::default(),
    }
}

pub fn recorded(receipt: &BatchReceipt, index: usize) -> OperationReceipt {
    match receipt.results[index] {
        OperationResult::Recorded { receipt, .. } => receipt,
        OperationResult::KeyReuse => panic!("expected recorded result"),
    }
}
