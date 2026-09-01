use ogvcs_local_cli::production::{
    create_verified_workspace, list_staged_intents, list_verified_workspaces,
    open_verified_workspace, recover_verified_workspace, remove_verified_workspace,
    remove_verified_workspace_with_progress, revert_staged_intent, stage_add, stage_delete,
    stage_move, AuthenticationRequest, AuthenticationSession, AuthenticationTransport,
    Cancellation, CancellationToken, CapabilityOffer, CapabilitySelection, DiscardProgress,
    FileIdAllocationReceipt, IntentKind, NeverCancelled, OperationPhase, OsCredentialProvider,
    OsCredentialStore, PresentedFileIdAllocation, ProgressEvent, ProgressSink,
    RemoveWorkspaceOptions, RepositoryDiscovery, RepositoryDiscoveryRequest,
    RepositoryPublicRoutes, RevertIntentRequest, SecretMaterial, SecureCredentialProvider,
    StageAddRequest, StageDeleteRequest, StageMoveRequest, UnavailablePublicRoutes,
    VerifiedBinding, WorkspaceConfigureRequest, WorkspaceCreateRequest, AUTHORIZATION_CONTRACT,
    AUTHORIZATION_REGISTRY_SHA256, EVENT_VERSION, FILE_ID_ALLOCATION_SCHEMA,
    MESSAGE_SCHEMA_VERSION, PATH_CONTRACT, PATH_REGISTRY_SHA256, PROTOCOL_REGISTRY_SET_SHA256,
    PROTOCOL_VERSION, REPOSITORY_FORMAT, REPOSITORY_REGISTRY_SHA256, REQUIRED_PROTOCOL_FEATURES,
    TRANSFER_PROFILE,
};
use ogvcs_local_cli::{CliError, CredentialStatus};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::process::Command;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "ogvcs011-production-{}-{}-{}",
            label,
            std::process::id(),
            nonce
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(not(windows))]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        #[cfg(windows)]
        protect_test_directory(&path);
        Self(path)
    }
}

#[cfg(windows)]
fn protect_test_directory(path: &Path) {
    let identity = String::from_utf8(
        Command::new("whoami")
            .output()
            .expect("query Windows test identity")
            .stdout,
    )
    .expect("Windows identity is text")
    .trim()
    .to_owned();
    assert!(!identity.is_empty());
    let owner_status = Command::new("icacls")
        .arg(path)
        .args(["/setowner", &identity])
        .status()
        .expect("set Windows test directory owner");
    assert!(owner_status.success());
    let status = Command::new("icacls")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("{identity}:(OI)(CI)F"),
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .status()
        .expect("protect Windows test directory DACL");
    assert!(status.success());
}

#[cfg(windows)]
fn protect_test_file(path: &Path) {
    let identity = String::from_utf8(
        Command::new("whoami")
            .output()
            .expect("query Windows test identity")
            .stdout,
    )
    .expect("Windows identity is text")
    .trim()
    .to_owned();
    let owner_status = Command::new("icacls")
        .arg(path)
        .args(["/setowner", &identity])
        .status()
        .expect("set Windows test file owner");
    assert!(owner_status.success());
    let status = Command::new("icacls")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("{identity}:F"),
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
        ])
        .status()
        .expect("protect Windows test file DACL");
    assert!(status.success());
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FixedStore;

impl OsCredentialStore for FixedStore {
    fn load(&self, _: &str) -> Result<SecretMaterial, CliError> {
        SecretMaterial::new(b"test-only-secret-material".to_vec())
    }
}

#[derive(Default)]
struct MockRoutes {
    capability_skew: bool,
    reject_authentication: bool,
    authentication_calls: usize,
    discovery_calls: usize,
    negotiation_calls: usize,
    binding_calls: usize,
    file_id_calls: usize,
    lose_preallocated_file_id_response: bool,
}

impl AuthenticationTransport for MockRoutes {
    fn authenticate(
        &mut self,
        request: &AuthenticationRequest,
        secret: &SecretMaterial,
        _: &dyn Cancellation,
    ) -> Result<AuthenticationSession, CliError> {
        self.authentication_calls += 1;
        assert_eq!(request.endpoint, "https://service.example");
        assert_eq!(secret.expose_to_transport(), b"test-only-secret-material");
        if self.reject_authentication {
            return SecretMaterial::new(Vec::new()).map(|_| unreachable!());
        }
        Ok(AuthenticationSession {
            subject_digest: "1".repeat(64),
            session_digest: "2".repeat(64),
            authority_epoch: 7,
            security_epoch: 9,
            expires_at_unix_ms: now_ms() + 3_600_000,
        })
    }
}

impl RepositoryPublicRoutes for MockRoutes {
    fn authentication_transport(&mut self) -> &mut dyn AuthenticationTransport {
        self
    }

    fn discover_repository(
        &mut self,
        _: &AuthenticationSession,
        request: &RepositoryDiscoveryRequest,
        _: &dyn Cancellation,
        _: &mut dyn ProgressSink,
    ) -> Result<RepositoryDiscovery, CliError> {
        self.discovery_calls += 1;
        Ok(RepositoryDiscovery {
            repository_id_hex: "00000000000040008000000000000002".to_owned(),
            branch: request.branch.clone(),
            baseline: format!("ogvcs:v1:snapshot:sha256:{}", "4".repeat(64)),
            case_mode: "case-folded".to_owned(),
            path_profile: "path.opengamevcs/portable@1".to_owned(),
            repository_settings_digest: "5".repeat(64),
        })
    }

    fn negotiate_capabilities(
        &mut self,
        _: &AuthenticationSession,
        discovery: &RepositoryDiscovery,
        offer: &CapabilityOffer,
        _: &dyn Cancellation,
        _: &mut dyn ProgressSink,
    ) -> Result<CapabilitySelection, CliError> {
        self.negotiation_calls += 1;
        assert_eq!(offer.protocol_version, PROTOCOL_VERSION);
        assert_eq!(offer.required_features, REQUIRED_PROTOCOL_FEATURES);
        Ok(selection(&discovery.path_profile, self.capability_skew))
    }

    fn validate_binding(
        &mut self,
        session: &AuthenticationSession,
        binding: &VerifiedBinding,
        _: &dyn Cancellation,
    ) -> Result<(), CliError> {
        self.binding_calls += 1;
        assert_eq!(session.authority_epoch, binding.authority_epoch);
        assert_eq!(binding.verification, "public-service-verified");
        Ok(())
    }

    fn present_preallocated_file_id(
        &mut self,
        session: &AuthenticationSession,
        binding: &VerifiedBinding,
        repository_path_key: &str,
        cancellation: &dyn Cancellation,
    ) -> Result<PresentedFileIdAllocation, CliError> {
        self.file_id_calls += 1;
        assert!(repository_path_key.starts_with("ogvcs-path-key-v1:"));
        if self.lose_preallocated_file_id_response {
            return UnavailablePublicRoutes.present_preallocated_file_id(
                session,
                binding,
                repository_path_key,
                cancellation,
            );
        }
        Ok(PresentedFileIdAllocation {
            allocation_schema_version: FILE_ID_ALLOCATION_SCHEMA.to_owned(),
            repository_id: "00000000-0000-4000-8000-000000000002".to_owned(),
            repository_path_key: repository_path_key.to_owned(),
            file_id: "fid:00000000000000000000000000000001".to_owned(),
            allocation_receipt: FileIdAllocationReceipt::new(format!("far1.{}", "A".repeat(43)))
                .unwrap(),
            allocation_idempotency_key_sha256: "6".repeat(64),
            expires_at_unix_ms: now_ms() + 3_600_000,
        })
    }

    fn resolve_file_id(
        &mut self,
        _: &AuthenticationSession,
        _: &VerifiedBinding,
        repository_path_key: &str,
        _: &dyn Cancellation,
    ) -> Result<String, CliError> {
        self.file_id_calls += 1;
        assert!(repository_path_key.starts_with("ogvcs-path-key-v1:"));
        Ok("fid:00000000000000000000000000000002".to_owned())
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn selection(path_profile: &str, skew: bool) -> CapabilitySelection {
    CapabilitySelection {
        protocol_version: if skew {
            "ogvcs.control.https-json@99".to_owned()
        } else {
            PROTOCOL_VERSION.to_owned()
        },
        message_schema_version: MESSAGE_SCHEMA_VERSION.to_owned(),
        repository_format: REPOSITORY_FORMAT.to_owned(),
        authorization_contract: AUTHORIZATION_CONTRACT.to_owned(),
        authorization_registry_sha256: AUTHORIZATION_REGISTRY_SHA256.to_owned(),
        path_contract: PATH_CONTRACT.to_owned(),
        path_profile: path_profile.to_owned(),
        path_registry_sha256: PATH_REGISTRY_SHA256.to_owned(),
        event_version: EVENT_VERSION.to_owned(),
        transfer_profile: TRANSFER_PROFILE.to_owned(),
        protocol_registry_set_sha256: PROTOCOL_REGISTRY_SET_SHA256.to_owned(),
        repository_registry_sha256: REPOSITORY_REGISTRY_SHA256.to_owned(),
        required_features: REQUIRED_PROTOCOL_FEATURES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        receipt_sha256: "a".repeat(64),
        expires_at_unix_ms: now_ms() + 3_600_000,
    }
}

fn authentication() -> AuthenticationRequest {
    AuthenticationRequest {
        endpoint: "https://service.example".to_owned(),
        profile: "test-profile".to_owned(),
        non_interactive: true,
    }
}

fn rewrite_intent_state(root: &Path, intent_id: &str, state: &str) -> serde_json::Value {
    let path = root.join(".ogvcs/staging-v1.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let intent = value["intents"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|intent| intent["intentId"] == intent_id)
        .unwrap();
    intent["state"] = serde_json::Value::String(state.to_owned());
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    value
}

fn create(root: &Path, branch: &str, routes: &mut MockRoutes) {
    let provider = OsCredentialProvider::new(&FixedStore);
    let mut progress = DiscardProgress;
    create_verified_workspace(
        &WorkspaceCreateRequest {
            root: root.to_path_buf(),
            repository_locator: "repo:test".to_owned(),
            branch: branch.to_owned(),
            authentication: authentication(),
        },
        &provider,
        routes,
        &NeverCancelled,
        &mut progress,
    )
    .unwrap();
}

#[test]
fn verified_workspace_lifecycle_and_confined_staging_are_complete_and_redacted() {
    let directory = TestDirectory::new("lifecycle");
    fs::create_dir(directory.0.join("Game")).unwrap();
    fs::write(directory.0.join("Game/new.bin"), b"new").unwrap();
    fs::write(directory.0.join("Game/old.bin"), b"old").unwrap();
    fs::write(directory.0.join("Game/delete.bin"), b"delete").unwrap();
    let mut routes = MockRoutes::default();
    create(&directory.0, "main", &mut routes);

    let opened = open_verified_workspace(&directory.0).unwrap();
    assert_eq!(opened.binding_verification, "public-service-verified");
    assert_eq!(opened.staged_intents, 0);
    assert!(!serde_json::to_string(&opened)
        .unwrap()
        .contains(&directory.0.to_string_lossy().to_string()));
    assert_eq!(
        list_verified_workspaces(&[directory.0.clone()])
            .unwrap()
            .len(),
        1
    );

    let provider = OsCredentialProvider::new(&FixedStore);
    let mut progress = DiscardProgress;
    let configured = ogvcs_local_cli::production::configure_verified_workspace(
        &WorkspaceConfigureRequest {
            root: directory.0.clone(),
            repository_locator: "repo:test".to_owned(),
            branch: "dev".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut progress,
    )
    .unwrap();
    assert_eq!(configured.branch_digest.len(), 64);
    assert!(!serde_json::to_string(&configured)
        .unwrap()
        .contains("test-only-secret-material"));
    assert!(
        !serde_json::to_string(&list_verified_workspaces(&[directory.0.clone()]).unwrap())
            .unwrap()
            .contains("test-only-secret-material")
    );

    let add = stage_add(
        &StageAddRequest {
            root: directory.0.clone(),
            repository_path: "Game/new.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut progress,
    )
    .unwrap();
    assert_eq!(add.kind, IntentKind::Add);
    assert!(!add.uploads_started && !add.submit_started);
    assert_eq!(add.remote_durable_state, "unchanged");
    assert!(add.allocation_receipt_digest.is_some());
    let allocation_key_digest = "6".repeat(64);
    assert_eq!(
        add.allocation_idempotency_key_digest.as_deref(),
        Some(allocation_key_digest.as_str())
    );
    let rendered_add = serde_json::to_string(&add).unwrap();
    assert!(!rendered_add.contains("far1."));
    let private_staging = fs::read_to_string(directory.0.join(".ogvcs/staging-v1.json")).unwrap();
    assert!(private_staging.contains(&format!("far1.{}", "A".repeat(43))));
    assert!(
        !serde_json::to_string(&list_staged_intents(&directory.0).unwrap())
            .unwrap()
            .contains("far1.")
    );

    let moved = stage_move(
        &StageMoveRequest {
            root: directory.0.clone(),
            source_repository_path: "Game/old.bin".to_owned(),
            destination_repository_path: "Game/moved.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut progress,
    )
    .unwrap();
    assert!(!directory.0.join("Game/old.bin").exists());
    assert!(directory.0.join("Game/moved.bin").exists());

    let deleted = stage_delete(
        &StageDeleteRequest {
            root: directory.0.clone(),
            repository_path: "Game/delete.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut progress,
    )
    .unwrap();
    assert!(!directory.0.join("Game/delete.bin").exists());
    assert_eq!(list_staged_intents(&directory.0).unwrap().len(), 3);

    for intent in [&deleted, &moved, &add] {
        revert_staged_intent(
            &RevertIntentRequest {
                root: directory.0.clone(),
                intent_id: intent.intent_id.clone(),
                authentication: authentication(),
            },
            &provider,
            &mut routes,
            &NeverCancelled,
            &mut progress,
        )
        .unwrap();
    }
    assert!(directory.0.join("Game/old.bin").exists());
    assert!(directory.0.join("Game/delete.bin").exists());
    assert!(list_staged_intents(&directory.0).unwrap().is_empty());
    assert!(
        !fs::read_to_string(directory.0.join(".ogvcs/staging-v1.json"))
            .unwrap()
            .contains("far1.")
    );

    let removed = remove_verified_workspace(
        &directory.0,
        RemoveWorkspaceOptions {
            confirmed: true,
            non_interactive: true,
        },
        &NeverCancelled,
    )
    .unwrap();
    assert!(removed.removed);
    assert!(!serde_json::to_string(&removed)
        .unwrap()
        .contains("test-only-secret-material"));
    assert!(!directory.0.join(".ogvcs").exists());
    assert_eq!(routes.file_id_calls, 3);
}

#[test]
fn lost_preallocated_file_id_handoff_never_publishes_a_local_intent() {
    let directory = TestDirectory::new("file-id-lost-response");
    fs::create_dir(directory.0.join("Game")).unwrap();
    fs::write(directory.0.join("Game/new.bin"), b"new").unwrap();
    let mut routes = MockRoutes::default();
    create(&directory.0, "main", &mut routes);
    routes.lose_preallocated_file_id_response = true;
    let staging_path = directory.0.join(".ogvcs/staging-v1.json");
    let before = fs::read(&staging_path).unwrap();

    let error = stage_add(
        &StageAddRequest {
            root: directory.0.clone(),
            repository_path: "Game/new.bin".to_owned(),
            authentication: authentication(),
        },
        &OsCredentialProvider::new(&FixedStore),
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();

    assert_eq!(error.code, "FILE_ID_ALLOCATION_HANDOFF_UNAVAILABLE");
    assert_eq!(error.data["mutationStarted"], false);
    assert_eq!(
        error.data["remoteDurableState"],
        "unchanged-by-this-command"
    );
    assert_eq!(fs::read(&staging_path).unwrap(), before);
    assert!(list_staged_intents(&directory.0).unwrap().is_empty());
}

#[test]
fn recovery_handles_each_prepared_mutated_and_reverting_intent_boundary() {
    let directory = TestDirectory::new("intent-crash-phases");
    fs::create_dir(directory.0.join("Game")).unwrap();
    fs::write(directory.0.join("Game/move.bin"), b"move").unwrap();
    fs::write(directory.0.join("Game/delete.bin"), b"delete").unwrap();
    let mut routes = MockRoutes::default();
    create(&directory.0, "main", &mut routes);
    let provider = OsCredentialProvider::new(&FixedStore);

    let moved = stage_move(
        &StageMoveRequest {
            root: directory.0.clone(),
            source_repository_path: "Game/move.bin".to_owned(),
            destination_repository_path: "Game/moved.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap();
    rewrite_intent_state(&directory.0, &moved.intent_id, "prepared");
    recover_verified_workspace(&directory.0, &mut DiscardProgress).unwrap();
    assert!(directory.0.join("Game/moved.bin").is_file());
    rewrite_intent_state(&directory.0, &moved.intent_id, "reverting");
    recover_verified_workspace(&directory.0, &mut DiscardProgress).unwrap();
    assert!(directory.0.join("Game/move.bin").is_file());
    assert!(!directory.0.join("Game/moved.bin").exists());

    let moved_again = stage_move(
        &StageMoveRequest {
            root: directory.0.clone(),
            source_repository_path: "Game/move.bin".to_owned(),
            destination_repository_path: "Game/moved-again.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap();
    rewrite_intent_state(&directory.0, &moved_again.intent_id, "reverting");
    fs::rename(
        directory.0.join("Game/moved-again.bin"),
        directory.0.join("Game/move.bin"),
    )
    .unwrap();
    recover_verified_workspace(&directory.0, &mut DiscardProgress).unwrap();
    assert!(directory.0.join("Game/move.bin").is_file());

    let deleted = stage_delete(
        &StageDeleteRequest {
            root: directory.0.clone(),
            repository_path: "Game/delete.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap();
    let state = rewrite_intent_state(&directory.0, &deleted.intent_id, "prepared");
    let deleted_intent = state["intents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|intent| intent["intentId"] == deleted.intent_id)
        .unwrap();
    let trash_name = deleted_intent["trashName"].as_str().unwrap().to_owned();
    recover_verified_workspace(&directory.0, &mut DiscardProgress).unwrap();
    rewrite_intent_state(&directory.0, &deleted.intent_id, "reverting");
    fs::rename(
        directory.0.join(".ogvcs/trash-v1").join(trash_name),
        directory.0.join("Game/delete.bin"),
    )
    .unwrap();
    recover_verified_workspace(&directory.0, &mut DiscardProgress).unwrap();
    assert!(directory.0.join("Game/delete.bin").is_file());
    assert!(list_staged_intents(&directory.0).unwrap().is_empty());
}

#[test]
fn verified_diagnostics_are_explicit_private_and_exclude_sensitive_material() {
    let directory = TestDirectory::new("diagnostics");
    let mut routes = MockRoutes::default();
    create(&directory.0, "main", &mut routes);
    let provider = OsCredentialProvider::new(&FixedStore);
    let endpoint = "https://private-service.example/tenant/secret";
    let preview = ogvcs_local_cli::production::preview_verified_diagnostics(
        &directory.0,
        endpoint,
        &provider,
    )
    .unwrap();
    assert!(preview.preview && !preview.written);
    assert!(!directory.0.join(".ogvcs/diagnostics-v2").exists());
    let rendered = serde_json::to_string(&preview).unwrap();
    for forbidden in [
        directory.0.to_string_lossy().as_ref(),
        endpoint,
        "test-only-secret-material",
        "repo:test",
    ] {
        assert!(!rendered.contains(forbidden));
    }

    let created = ogvcs_local_cli::production::create_verified_diagnostics(
        &directory.0,
        "support.json",
        endpoint,
        &provider,
    )
    .unwrap();
    assert!(!created.preview && created.written);
    assert_eq!(created.artifact_name.as_deref(), Some("support.json"));
    assert_eq!(created.artifact_digest.as_deref().unwrap().len(), 64);
    let artifact =
        fs::read_to_string(directory.0.join(".ogvcs/diagnostics-v2/support.json")).unwrap();
    for forbidden in [
        directory.0.to_string_lossy().as_ref(),
        endpoint,
        "test-only-secret-material",
        "repo:test",
    ] {
        assert!(!artifact.contains(forbidden));
    }
}

struct CancelOnPhase {
    phase: OperationPhase,
    token: CancellationToken,
}

struct PanicOnPhase(OperationPhase);

impl ProgressSink for PanicOnPhase {
    fn emit(&mut self, event: &ProgressEvent) -> Result<(), CliError> {
        assert_ne!(event.resume_token.as_deref(), Some("raw-local-path"));
        if event.phase == self.0 {
            panic!("simulated process crash at durable phase")
        }
        Ok(())
    }
}

struct BlockOnPhase {
    phase: OperationPhase,
    reached: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
}

impl ProgressSink for BlockOnPhase {
    fn emit(&mut self, event: &ProgressEvent) -> Result<(), CliError> {
        if event.phase == self.phase {
            self.reached.wait();
            self.release.wait();
        }
        Ok(())
    }
}

impl ProgressSink for CancelOnPhase {
    fn emit(&mut self, event: &ProgressEvent) -> Result<(), CliError> {
        if event.phase == self.phase {
            self.token.cancel();
        }
        Ok(())
    }
}

#[test]
fn cancellation_cleans_unpublished_create_and_recovers_published_intent_journals() {
    let early = TestDirectory::new("cancel-create");
    let provider = OsCredentialProvider::new(&FixedStore);
    let mut routes = MockRoutes::default();
    let token = CancellationToken::default();
    let mut progress = CancelOnPhase {
        phase: OperationPhase::Preflight,
        token: token.clone(),
    };
    let error = create_verified_workspace(
        &WorkspaceCreateRequest {
            root: early.0.clone(),
            repository_locator: "repo:test".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &token,
        &mut progress,
    )
    .unwrap_err();
    assert_eq!(error.code, "OPERATION_CANCELLED");
    assert_eq!(
        error.data["remoteDurableState"],
        "unchanged-after-preflight"
    );
    assert!(!early.0.join(".ogvcs").exists());
    assert!(fs::read_dir(&early.0).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".ogvcs-init")));

    let published = TestDirectory::new("cancel-published-create");
    let mut routes = MockRoutes::default();
    let token = CancellationToken::default();
    let mut progress = CancelOnPhase {
        phase: OperationPhase::Journal,
        token: token.clone(),
    };
    let error = create_verified_workspace(
        &WorkspaceCreateRequest {
            root: published.0.clone(),
            repository_locator: "repo:test".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &token,
        &mut progress,
    )
    .unwrap_err();
    assert_eq!(error.code, "OPERATION_CANCELLED");
    assert_eq!(
        error.data["remoteDurableState"],
        "unchanged-after-preflight"
    );
    assert!(error.data["resumeToken"].as_str().is_some());
    assert_eq!(
        open_verified_workspace(&published.0).unwrap_err().code,
        "WORKSPACE_RECOVERY_REQUIRED"
    );
    recover_verified_workspace(&published.0, &mut DiscardProgress).unwrap();
    assert_eq!(
        open_verified_workspace(&published.0).unwrap().state,
        "ready"
    );
    let control = published.0.join(".ogvcs");
    fs::copy(
        control.join("workspace-v2.json"),
        control.join("pending-workspace-v2.json"),
    )
    .unwrap();
    #[cfg(not(windows))]
    fs::set_permissions(
        control.join("pending-workspace-v2.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    #[cfg(windows)]
    protect_test_file(&control.join("pending-workspace-v2.json"));
    assert_eq!(
        open_verified_workspace(&published.0).unwrap_err().code,
        "WORKSPACE_RECOVERY_REQUIRED"
    );
    recover_verified_workspace(&published.0, &mut DiscardProgress).unwrap();
    assert!(!control.join("pending-workspace-v2.json").exists());

    let configured = TestDirectory::new("cancel-configure");
    let mut routes = MockRoutes::default();
    create(&configured.0, "main", &mut routes);
    let main_branch_digest = open_verified_workspace(&configured.0)
        .unwrap()
        .branch_digest;
    let token = CancellationToken::default();
    let mut progress = CancelOnPhase {
        phase: OperationPhase::Journal,
        token: token.clone(),
    };
    let error = ogvcs_local_cli::production::configure_verified_workspace(
        &WorkspaceConfigureRequest {
            root: configured.0.clone(),
            repository_locator: "repo:test".to_owned(),
            branch: "dev".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &token,
        &mut progress,
    )
    .unwrap_err();
    assert_eq!(error.code, "OPERATION_CANCELLED");
    assert_eq!(
        error.data["remoteDurableState"],
        "unchanged-after-preflight"
    );
    assert_eq!(
        open_verified_workspace(&configured.0).unwrap_err().code,
        "WORKSPACE_RECOVERY_REQUIRED"
    );
    recover_verified_workspace(&configured.0, &mut DiscardProgress).unwrap();
    let recovered = open_verified_workspace(&configured.0).unwrap();
    assert_ne!(recovered.branch_digest, main_branch_digest);

    let staged = TestDirectory::new("cancel-stage");
    fs::create_dir(staged.0.join("Game")).unwrap();
    fs::write(staged.0.join("Game/add.bin"), b"payload").unwrap();
    let mut routes = MockRoutes::default();
    create(&staged.0, "main", &mut routes);
    let token = CancellationToken::default();
    let mut progress = CancelOnPhase {
        phase: OperationPhase::Journal,
        token: token.clone(),
    };
    let error = stage_add(
        &StageAddRequest {
            root: staged.0.clone(),
            repository_path: "Game/add.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &token,
        &mut progress,
    )
    .unwrap_err();
    assert_eq!(error.code, "OPERATION_CANCELLED");
    assert_eq!(
        error.data["remoteDurableState"],
        "unchanged-after-preflight"
    );
    assert_eq!(
        open_verified_workspace(&staged.0).unwrap_err().code,
        "WORKSPACE_RECOVERY_REQUIRED"
    );
    recover_verified_workspace(&staged.0, &mut DiscardProgress).unwrap();
    assert_eq!(list_staged_intents(&staged.0).unwrap().len(), 1);
}

#[test]
fn capability_skew_and_auth_failure_happen_before_local_mutation_without_secret_leak() {
    let skewed = TestDirectory::new("skew");
    let provider = OsCredentialProvider::new(&FixedStore);
    let mut routes = MockRoutes {
        capability_skew: true,
        ..MockRoutes::default()
    };
    let error = create_verified_workspace(
        &WorkspaceCreateRequest {
            root: skewed.0.clone(),
            repository_locator: "repo:test".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "CAPABILITY_SKEW");
    assert!(!skewed.0.join(".ogvcs").exists());

    let rejected = TestDirectory::new("secret-redaction");
    let mut routes = MockRoutes {
        reject_authentication: true,
        ..MockRoutes::default()
    };
    let error = create_verified_workspace(
        &WorkspaceCreateRequest {
            root: rejected.0.clone(),
            repository_locator: "repo:test".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    let rendered = format!("{} {} {}", error.code, error.message, error.data);
    assert!(!rendered.contains("test-only-secret-material"));
    assert!(!rejected.0.join(".ogvcs").exists());
}

#[cfg(not(windows))]
#[test]
fn unsafe_permissions_and_symlink_ancestors_fail_closed() {
    use std::os::unix::fs::symlink;

    let unsafe_root = TestDirectory::new("permissions");
    fs::set_permissions(&unsafe_root.0, fs::Permissions::from_mode(0o755)).unwrap();
    let mut routes = MockRoutes::default();
    let provider = OsCredentialProvider::new(&FixedStore);
    let error = create_verified_workspace(
        &WorkspaceCreateRequest {
            root: unsafe_root.0.clone(),
            repository_locator: "repo:test".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "UNSAFE_WORKSPACE");

    let workspace = TestDirectory::new("symlink");
    let outside = TestDirectory::new("outside");
    fs::write(outside.0.join("secret.bin"), b"outside").unwrap();
    create(&workspace.0, "main", &mut routes);
    symlink(&outside.0, workspace.0.join("Linked")).unwrap();
    let error = stage_add(
        &StageAddRequest {
            root: workspace.0.clone(),
            repository_path: "Linked/secret.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "UNSAFE_WORKSPACE_PATH");
    assert_eq!(fs::read(outside.0.join("secret.bin")).unwrap(), b"outside");

    let locked = TestDirectory::new("lock-symlink");
    fs::create_dir(locked.0.join("Game")).unwrap();
    fs::write(locked.0.join("Game/add.bin"), b"payload").unwrap();
    create(&locked.0, "main", &mut routes);
    fs::remove_file(locked.0.join(".ogvcs-mutation-v2.lock")).unwrap();
    let outside_lock = outside.0.join("outside-lock");
    fs::write(&outside_lock, b"must-not-change").unwrap();
    fs::set_permissions(&outside_lock, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&outside_lock, locked.0.join(".ogvcs-mutation-v2.lock")).unwrap();
    let error = stage_add(
        &StageAddRequest {
            root: locked.0.clone(),
            repository_path: "Game/add.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "WORKSPACE_WRITE_UNAVAILABLE");
    assert_eq!(fs::read(&outside_lock).unwrap(), b"must-not-change");
    assert_eq!(
        fs::metadata(&outside_lock).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_file(locked.0.join(".ogvcs-mutation-v2.lock")).unwrap();

    let hardlink_workspace = TestDirectory::new("lock-hardlink");
    fs::create_dir(hardlink_workspace.0.join("Game")).unwrap();
    fs::write(hardlink_workspace.0.join("Game/add.bin"), b"payload").unwrap();
    create(&hardlink_workspace.0, "main", &mut routes);
    fs::remove_file(hardlink_workspace.0.join(".ogvcs-mutation-v2.lock")).unwrap();
    let outside_hardlink = outside.0.join("outside-hardlink");
    fs::write(&outside_hardlink, b"hardlink-must-not-change").unwrap();
    fs::set_permissions(&outside_hardlink, fs::Permissions::from_mode(0o640)).unwrap();
    fs::hard_link(
        &outside_hardlink,
        hardlink_workspace.0.join(".ogvcs-mutation-v2.lock"),
    )
    .unwrap();
    let error = stage_add(
        &StageAddRequest {
            root: hardlink_workspace.0.clone(),
            repository_path: "Game/add.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "UNSAFE_WORKSPACE_PATH");
    assert_eq!(
        fs::read(&outside_hardlink).unwrap(),
        b"hardlink-must-not-change"
    );
    assert_eq!(
        fs::metadata(&outside_hardlink)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );

    let outside_record = outside.0.join("outside-removal-record");
    fs::write(&outside_record, b"must-not-change").unwrap();
    fs::set_permissions(&outside_record, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&outside_record, locked.0.join(".ogvcs-remove-v2.json")).unwrap();
    let error = remove_verified_workspace(
        &locked.0,
        RemoveWorkspaceOptions {
            confirmed: true,
            non_interactive: true,
        },
        &NeverCancelled,
    )
    .unwrap_err();
    assert_eq!(error.code, "WORKSPACE_RECOVERY_CONFLICT");
    assert_eq!(fs::read(&outside_record).unwrap(), b"must-not-change");
}

#[cfg(windows)]
#[test]
fn windows_junction_and_broad_dacl_fail_closed() {
    let workspace = TestDirectory::new("junction");
    let outside = TestDirectory::new("outside");
    fs::write(outside.0.join("secret.bin"), b"outside").unwrap();
    let mut routes = MockRoutes::default();
    create(&workspace.0, "main", &mut routes);
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(workspace.0.join("Linked"))
        .arg(&outside.0)
        .status()
        .unwrap();
    assert!(status.success());
    let provider = OsCredentialProvider::new(&FixedStore);
    let error = stage_add(
        &StageAddRequest {
            root: workspace.0.clone(),
            repository_path: "Linked/secret.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "UNSAFE_WORKSPACE_PATH");

    let broad = TestDirectory::new("broad-dacl");
    let status = Command::new("icacls")
        .arg(&broad.0)
        .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
        .status()
        .unwrap();
    assert!(status.success());
    let error = create_verified_workspace(
        &WorkspaceCreateRequest {
            root: broad.0.clone(),
            repository_locator: "repo:test".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "UNSAFE_WORKSPACE");

    let inherited_parent = TestDirectory::new("inherited-parent");
    let inherited_root = inherited_parent.0.join("inherited-child");
    fs::create_dir(&inherited_root).unwrap();
    let error = create_verified_workspace(
        &WorkspaceCreateRequest {
            root: inherited_root,
            repository_locator: "repo:test".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "UNSAFE_WORKSPACE");

    let locked = TestDirectory::new("lock-hardlink");
    fs::create_dir(locked.0.join("Game")).unwrap();
    fs::write(locked.0.join("Game/add.bin"), b"payload").unwrap();
    create(&locked.0, "main", &mut routes);
    fs::remove_file(locked.0.join(".ogvcs-mutation-v2.lock")).unwrap();
    let external = TestDirectory::new("lock-external");
    let external_lock = external.0.join("outside-lock");
    fs::write(&external_lock, b"must-not-change").unwrap();
    fs::hard_link(&external_lock, locked.0.join(".ogvcs-mutation-v2.lock")).unwrap();
    let error = stage_add(
        &StageAddRequest {
            root: locked.0.clone(),
            repository_path: "Game/add.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut routes,
        &NeverCancelled,
        &mut DiscardProgress,
    )
    .unwrap_err();
    assert_eq!(error.code, "WORKSPACE_WRITE_UNAVAILABLE");
    assert_eq!(fs::read(external_lock).unwrap(), b"must-not-change");
    fs::remove_file(locked.0.join(".ogvcs-mutation-v2.lock")).unwrap();

    let removal_outside = TestDirectory::new("removal-junction-outside");
    let removal_link = locked.0.join(".ogvcs-removed-v2");
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&removal_link)
        .arg(&removal_outside.0)
        .status()
        .unwrap();
    assert!(status.success());
    let error = recover_verified_workspace(&locked.0, &mut DiscardProgress).unwrap_err();
    assert_eq!(error.code, "WORKSPACE_RECOVERY_CONFLICT");
}

#[test]
fn removal_requires_explicit_confirmation_even_noninteractive() {
    let directory = TestDirectory::new("remove-confirm");
    let mut routes = MockRoutes::default();
    create(&directory.0, "main", &mut routes);
    let error = remove_verified_workspace(
        &directory.0,
        RemoveWorkspaceOptions {
            confirmed: false,
            non_interactive: true,
        },
        &NeverCancelled,
    )
    .unwrap_err();
    assert_eq!(error.code, "DESTRUCTIVE_CONFIRMATION_REQUIRED");
    assert_eq!(error.data["prompted"], false);
    assert!(directory.0.join(".ogvcs").exists());
}

#[test]
fn removal_crash_is_reconciled_from_a_deterministic_root_bound_record() {
    let directory = TestDirectory::new("remove-crash");
    let mut routes = MockRoutes::default();
    create(&directory.0, "main", &mut routes);
    let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        remove_verified_workspace_with_progress(
            &directory.0,
            RemoveWorkspaceOptions {
                confirmed: true,
                non_interactive: true,
            },
            &NeverCancelled,
            &mut PanicOnPhase(OperationPhase::Mutation),
        )
        .unwrap();
    }));
    assert!(crash.is_err());
    assert!(!directory.0.join(".ogvcs").exists());
    assert!(directory.0.join(".ogvcs-removed-v2").is_dir());
    assert!(directory.0.join(".ogvcs-remove-v2.json").is_file());
    let recovered = recover_verified_workspace(&directory.0, &mut DiscardProgress).unwrap_err();
    assert_eq!(recovered.code, "WORKSPACE_REMOVED");
    assert_eq!(recovered.data["removed"], true);
    assert!(!directory.0.join(".ogvcs-removed-v2").exists());
    assert!(!directory.0.join(".ogvcs-remove-v2.json").exists());

    create(&directory.0, "main", &mut routes);
    let token = CancellationToken::default();
    let removed = remove_verified_workspace_with_progress(
        &directory.0,
        RemoveWorkspaceOptions {
            confirmed: true,
            non_interactive: true,
        },
        &token,
        &mut CancelOnPhase {
            phase: OperationPhase::Mutation,
            token: token.clone(),
        },
    )
    .unwrap();
    assert!(removed.removed);
    assert!(token.is_cancelled());
    assert!(!directory.0.join(".ogvcs-remove-v2.json").exists());
}

#[test]
fn root_scoped_lock_serializes_remove_against_concurrent_recovery() {
    let directory = TestDirectory::new("remove-race");
    let mut routes = MockRoutes::default();
    create(&directory.0, "main", &mut routes);
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_root = directory.0.clone();
    let worker_reached = reached.clone();
    let worker_release = release.clone();
    let worker = std::thread::spawn(move || {
        remove_verified_workspace_with_progress(
            &worker_root,
            RemoveWorkspaceOptions {
                confirmed: true,
                non_interactive: true,
            },
            &NeverCancelled,
            &mut BlockOnPhase {
                phase: OperationPhase::Mutation,
                reached: worker_reached,
                release: worker_release,
            },
        )
    });
    reached.wait();
    let concurrent = recover_verified_workspace(&directory.0, &mut DiscardProgress).unwrap_err();
    assert_eq!(concurrent.code, "WORKSPACE_BUSY");
    release.wait();
    assert!(worker.join().unwrap().unwrap().removed);
    assert!(!directory.0.join(".ogvcs").exists());
    assert!(!directory.0.join(".ogvcs-remove-v2.json").exists());
    assert!(!directory.0.join(".ogvcs-removed-v2").exists());
}

#[test]
fn credential_provider_status_is_nonsecret() {
    let provider = OsCredentialProvider::new(&FixedStore);
    assert_eq!(provider.kind(), "os-credential-store");
    assert_eq!(provider.status(), CredentialStatus::Available);
}

#[test]
fn generic_cancellation_does_not_invent_remote_durable_state() {
    let token = CancellationToken::default();
    token.cancel();
    let error = token.check("ambiguous-route-boundary").unwrap_err();
    assert_eq!(error.code, "OPERATION_CANCELLED");
    assert_eq!(error.data["phase"], "ambiguous-route-boundary");
    assert!(error.data.get("remoteDurableState").is_none());
}
