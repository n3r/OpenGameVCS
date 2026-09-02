use ogvcs_local_agent_ipc::*;

fn digest(value: u64) -> Digest32 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xa5;
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Digest32::from_bytes(bytes)
}

fn file_id(value: u64) -> FileId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x5a;
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    FileId::new(bytes).expect("nonzero FileId")
}

fn all_capabilities() -> Vec<Capability> {
    vec![
        Capability::ReadStatus,
        Capability::SyncMaterialize,
        Capability::StartEditLockFact,
        Capability::CheckpointHandoff,
        Capability::RevertHandoff,
        Capability::JobProgress,
        Capability::WorkspaceEvents,
        Capability::TrustedClientHandoff,
    ]
}

fn offer(versions: Vec<ProtocolVersion>, capabilities: Vec<Capability>) -> NegotiationOffer {
    NegotiationOffer {
        versions,
        required_capabilities: vec![Capability::ReadStatus],
        optional_capabilities: capabilities
            .into_iter()
            .filter(|capability| *capability != Capability::ReadStatus)
            .collect(),
        public_protocol_manifest: public_protocol_manifest_commitment()
            .expect("generated protocol pin"),
    }
}

fn capability_wire_name(capability: Capability) -> &'static str {
    match capability {
        Capability::ReadStatus => "read-status",
        Capability::SyncMaterialize => "sync-materialize",
        Capability::StartEditLockFact => "start-edit-lock-fact",
        Capability::CheckpointHandoff => "checkpoint-handoff",
        Capability::RevertHandoff => "revert-handoff",
        Capability::JobProgress => "job-progress",
        Capability::WorkspaceEvents => "workspace-events",
        Capability::TrustedClientHandoff => "trusted-client-handoff",
    }
}

fn json_capabilities(capabilities: &[Capability]) -> String {
    capabilities
        .iter()
        .map(|capability| format!("\"{}\"", capability_wire_name(*capability)))
        .collect::<Vec<_>>()
        .join(",")
}

fn client_hello_frame(offer: &NegotiationOffer, client_challenge: [u8; 32]) -> Vec<u8> {
    let versions = offer
        .versions
        .iter()
        .map(|version| {
            format!(
                "{{\"major\":{},\"minor\":{}}}",
                version.major, version.minor
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schemaVersion\":\"{CLIENT_HELLO_SCHEMA_V1}\",\"publicProtocolManifestSha256\":\"{}\",\"versions\":[{versions}],\"requiredCapabilities\":[{}],\"optionalCapabilities\":[{}],\"clientChallengeHex\":\"{}\"}}",
        offer.public_protocol_manifest.to_lower_hex(),
        json_capabilities(&offer.required_capabilities),
        json_capabilities(&offer.optional_capabilities),
        Digest32::from_bytes(client_challenge).to_lower_hex(),
    )
    .into_bytes()
}

fn default_client_hello() -> Vec<u8> {
    client_hello_frame(
        &offer(vec![ProtocolVersion::new(1, 0)], all_capabilities()),
        *digest(100).as_bytes(),
    )
}

fn make_installation(generation: u64, id: u64) -> InstallationIdentity {
    InstallationIdentity {
        id: InstallationId::new(digest(id)),
        generation,
        identity_commitment: digest(id + 1_000),
    }
}

fn make_endpoint(
    installation: &InstallationIdentity,
    generation: u64,
    id: u64,
) -> EndpointIdentity {
    EndpointIdentity {
        id: EndpointId::new(digest(id)),
        installation_id: installation.id,
        installation_generation: installation.generation,
        endpoint_generation: generation,
        os_locality: ExternalVerdict::Verified,
        restrictive_access: ExternalVerdict::Verified,
        adapter_facts_commitment: digest(id + 1_000),
    }
}

fn make_integration(installation: &InstallationIdentity, id: u64) -> IntegrationIdentity {
    IntegrationIdentity {
        id: IntegrationId::new(digest(id)),
        installation_id: installation.id,
        manifest_commitment: digest(id + 1_000),
        registration_generation: 1,
        external_registration: ExternalVerdict::Verified,
    }
}

fn context(repository_id: RepositoryId) -> ScopeContext {
    ScopeContext {
        repository_id,
        path_profile: PathProfile::parse("path.opengamevcs/portable@1").expect("portable profile"),
        case_mode: CaseMode::Sensitive,
    }
}

fn scope(context: ScopeContext, inputs: &[PathScopeInput<'_>], label: &'static [u8]) -> PathScope {
    PathScope::new(context, inputs, &RawFrame::new(label), &NeverCancel).expect("valid scope")
}

fn handshake_verification(
    installation: &InstallationIdentity,
    endpoint: &EndpointIdentity,
    integration: &IntegrationIdentity,
    session_id: SessionId,
    issued_at_ms: u64,
    raw: &RawFrame<'_>,
) -> HandshakeVerificationFacts {
    HandshakeVerificationFacts {
        session_id,
        installation: installation.clone(),
        endpoint: endpoint.clone(),
        integration: integration.clone(),
        agent_challenge: *digest(101).as_bytes(),
        verifier_key_generation: 1,
        issued_at_ms,
        expires_at_ms: issued_at_ms + SESSION_TTL_MAXIMUM_MS,
        challenge_response: ExternalVerdict::Verified,
        transcript_signature: ExternalVerdict::Verified,
        anti_downgrade: ExternalVerdict::Verified,
        verified_client_frame_commitment: raw.commitment().expect("bounded client hello"),
        crypto_adapter_commitment: digest(102),
    }
}

struct Fixture {
    ledger: LocalAgentLedger,
    installation: InstallationIdentity,
    integration: IntegrationIdentity,
    session_id: SessionId,
    consent_id: ConsentId,
    workspace_id: WorkspaceId,
    repository_id: RepositoryId,
    context: ScopeContext,
    grant_scope: PathScope,
    session_receipt: SessionReceipt,
    consent_receipt: ConsentReceipt,
}

fn fixture_with_grant(grant_prefix: &str, capabilities: Vec<Capability>) -> Fixture {
    fixture_with_scope_inputs(&[PathScopeInput::Prefix(grant_prefix)], capabilities)
}

fn fixture_with_scope_inputs(
    grant_inputs: &[PathScopeInput<'_>],
    capabilities: Vec<Capability>,
) -> Fixture {
    let installation = make_installation(1, 1);
    let endpoint = make_endpoint(&installation, 1, 2);
    let integration = make_integration(&installation, 3);
    let session_id = SessionId::new(digest(4));
    let consent_id = ConsentId::new(digest(5));
    let workspace_id = WorkspaceId::new(digest(6));
    let repository_id = RepositoryId::new(digest(7));
    let context = context(repository_id);
    let grant_scope = scope(context, grant_inputs, b"grant-scope");
    let mut ledger = LocalAgentLedger::new(
        installation.clone(),
        endpoint.clone(),
        1,
        offer(vec![ProtocolVersion::new(1, 0)], all_capabilities()),
        1_000,
        &RawFrame::new(b"ledger-new"),
        &NeverCancel,
    )
    .expect("ledger");
    let hello = default_client_hello();
    let raw_hello = RawFrame::new(&hello);
    let session_receipt = ledger
        .establish_session(
            handshake_verification(
                &installation,
                &endpoint,
                &integration,
                session_id,
                1_000,
                &raw_hello,
            ),
            1_000,
            &raw_hello,
            &NeverCancel,
        )
        .expect("session");
    let consent_receipt = ledger
        .register_consent(
            ConsentGrantFacts {
                consent_id,
                session_id,
                integration_id: integration.id,
                workspace_id,
                repository_id,
                generation: 1,
                capabilities,
                scope: grant_scope.clone(),
                issued_at_ms: 1_001,
                expires_at_ms: 100_000,
                confirmation: ConsentConfirmation::ExplicitUser,
                external_consent_proof: ExternalVerdict::Verified,
                consent_proof_commitment: digest(8),
            },
            1_001,
            &RawFrame::new(b"consent-frame"),
            &NeverCancel,
        )
        .expect("consent");
    Fixture {
        ledger,
        installation,
        integration,
        session_id,
        consent_id,
        workspace_id,
        repository_id,
        context,
        grant_scope,
        session_receipt,
        consent_receipt,
    }
}

fn subscription_caller(fixture: &Fixture) -> SubscriptionCallerFacts {
    SubscriptionCallerFacts {
        session_id: fixture.session_id,
        session_transcript_commitment: fixture.session_receipt.transcript_commitment,
        consent_id: fixture.consent_id,
        consent_generation: fixture.consent_receipt.generation,
        consent_grant_commitment: fixture.consent_receipt.grant_commitment,
        integration_id: fixture.integration.id,
        workspace_id: fixture.workspace_id,
        repository_id: fixture.repository_id,
        request_authentication: ExternalVerdict::Verified,
        request_authenticator_commitment: digest(9_000_000),
    }
}

fn fresh(now_ms: u64, value: u64) -> FreshStateFacts {
    FreshStateFacts {
        base: BaselineCommitment::new(digest(value)),
        current: StateCommitment::new(digest(value + 1)),
        generation: value,
        observed_at_ms: now_ms,
        valid_through_ms: now_ms + FRESHNESS_FUTURE_MAXIMUM_MS,
    }
}

fn operation(
    fixture: &Fixture,
    operation: OperationKind,
    request_scope: PathScope,
    key: u64,
    now_ms: u64,
    lock_knowledge: Option<LockKnowledge>,
) -> OperationFacts {
    OperationFacts {
        session_id: fixture.session_id,
        consent_id: fixture.consent_id,
        integration_id: fixture.integration.id,
        workspace_id: fixture.workspace_id,
        repository_id: fixture.repository_id,
        operation,
        scope: request_scope,
        fresh_state: fresh(now_ms, key + 100),
        idempotency_key: IdempotencyKey::new(digest(key)),
        confirmation_policy: ConfirmationPolicy::None,
        lock_knowledge,
        deadline_ms: now_ms + DEADLINE_HORIZON_MAXIMUM_MS,
        idempotency_expires_at_ms: now_ms + IDEMPOTENCY_TTL_MAXIMUM_MS,
    }
}

#[test]
fn negotiation_is_order_independent_bounded_and_pinned() {
    let client = offer(
        vec![ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 2)],
        vec![
            Capability::WorkspaceEvents,
            Capability::ReadStatus,
            Capability::JobProgress,
        ],
    );
    let agent = offer(
        vec![ProtocolVersion::new(1, 2), ProtocolVersion::new(1, 1)],
        vec![
            Capability::JobProgress,
            Capability::ReadStatus,
            Capability::WorkspaceEvents,
        ],
    );
    let installation = make_installation(1, 430);
    let endpoint = make_endpoint(&installation, 1, 431);
    let integration = make_integration(&installation, 432);
    let hello = client_hello_frame(&client, *digest(100).as_bytes());
    let raw_hello = RawFrame::new(&hello);
    let mut ledger = LocalAgentLedger::new(
        installation.clone(),
        endpoint.clone(),
        1,
        agent,
        1_000,
        &RawFrame::new(b"negotiation-ledger"),
        &NeverCancel,
    )
    .expect("ledger");
    let selected = ledger
        .establish_session(
            handshake_verification(
                &installation,
                &endpoint,
                &integration,
                SessionId::new(digest(433)),
                1_000,
                &raw_hello,
            ),
            1_000,
            &raw_hello,
            &NeverCancel,
        )
        .expect("session")
        .selection;
    assert_eq!(selected.version, ProtocolVersion::new(1, 2));
    assert_eq!(
        selected.capabilities,
        vec![
            Capability::ReadStatus,
            Capability::JobProgress,
            Capability::WorkspaceEvents
        ]
    );
    assert_eq!(
        selected.selection_commitment.to_lower_hex(),
        "390e64ff2881afb6a978fec50720edd0beaed6dfb5407ff60177581c12d6835a"
    );

    let versions: Vec<_> = (0..VERSION_ITEMS_MAXIMUM)
        .map(|minor| ProtocolVersion::new(1, minor as u16))
        .collect();
    let maximum = offer(versions.clone(), vec![Capability::ReadStatus]);
    let maximum_frame = client_hello_frame(&maximum, *digest(434).as_bytes());
    assert_eq!(
        decode_client_hello(&RawFrame::new(&maximum_frame), &NeverCancel)
            .expect("exact version maximum")
            .offer()
            .versions
            .len(),
        VERSION_ITEMS_MAXIMUM
    );
    let mut too_many_versions = versions;
    too_many_versions.push(ProtocolVersion::new(1, VERSION_ITEMS_MAXIMUM as u16));
    let too_many = offer(too_many_versions, vec![Capability::ReadStatus]);
    assert_eq!(
        decode_client_hello(
            &RawFrame::new(&client_hello_frame(&too_many, *digest(435).as_bytes())),
            &NeverCancel,
        )
        .expect_err("version maximum + 1")
        .code(),
        ErrorCode::ItemLimit
    );
    let mut exact_frame = maximum_frame;
    exact_frame.resize(CLIENT_HELLO_BYTES_MAXIMUM, b' ');
    decode_client_hello(&RawFrame::new(&exact_frame), &NeverCancel)
        .expect("exact client-hello byte maximum");
    exact_frame.push(b' ');
    assert_eq!(
        decode_client_hello(&RawFrame::new(&exact_frame), &NeverCancel)
            .expect_err("client-hello byte maximum + 1")
            .code(),
        ErrorCode::InputTooLarge
    );
}

#[test]
fn configured_agent_offer_external_verdicts_and_error_precedence_fail_closed() {
    let installation = make_installation(1, 450);
    let endpoint = make_endpoint(&installation, 1, 451);
    let integration = make_integration(&installation, 452);
    let session_id = SessionId::new(digest(453));
    let mut ledger = LocalAgentLedger::new(
        installation.clone(),
        endpoint.clone(),
        1,
        offer(vec![ProtocolVersion::new(1, 0)], all_capabilities()),
        1_000,
        &RawFrame::new(b"new-configured"),
        &NeverCancel,
    )
    .expect("ledger");
    let baseline = ledger.snapshot();

    let hello = default_client_hello();
    let raw_hello = RawFrame::new(&hello);
    let substituted_bytes = format!(
        "{{\"agentOffer\":{{}},{}",
        std::str::from_utf8(&hello).expect("UTF-8 client hello")[1..].to_owned()
    )
    .into_bytes();
    let substituted_raw = RawFrame::new(&substituted_bytes);
    assert_eq!(
        ledger
            .establish_session(
                handshake_verification(
                    &installation,
                    &endpoint,
                    &integration,
                    session_id,
                    1_000,
                    &substituted_raw,
                ),
                1_000,
                &substituted_raw,
                &NeverCancel,
            )
            .expect_err("the frame cannot supply an agent offer")
            .code(),
        ErrorCode::FrameInvalid
    );
    assert_eq!(ledger.snapshot(), baseline);

    let mut unverified = handshake_verification(
        &installation,
        &endpoint,
        &integration,
        session_id,
        1_000,
        &raw_hello,
    );
    unverified.transcript_signature = ExternalVerdict::NotEvaluated;
    assert_eq!(
        ledger
            .establish_session(unverified, 1_000, &raw_hello, &NeverCancel,)
            .expect_err("unverified transcript")
            .code(),
        ErrorCode::TranscriptUnverified
    );
    assert_eq!(ledger.snapshot(), baseline);

    let mut excessive_ttl = handshake_verification(
        &installation,
        &endpoint,
        &integration,
        session_id,
        1_000,
        &raw_hello,
    );
    excessive_ttl.expires_at_ms += 1;
    assert_eq!(
        ledger
            .establish_session(excessive_ttl, 1_000, &raw_hello, &NeverCancel,)
            .expect_err("session ttl maximum + 1")
            .code(),
        ErrorCode::InvalidFact
    );
    assert_eq!(ledger.snapshot(), baseline);

    let oversized = vec![0u8; CLIENT_HELLO_BYTES_MAXIMUM + 1];
    let oversized_raw = RawFrame::new(&oversized);
    assert_eq!(
        ledger
            .establish_session(
                handshake_verification(
                    &installation,
                    &endpoint,
                    &integration,
                    session_id,
                    1_000,
                    &oversized_raw,
                ),
                999,
                &oversized_raw,
                &NeverCancel,
            )
            .expect_err("raw bound precedes reordered time")
            .code(),
        ErrorCode::InputTooLarge
    );
    assert_eq!(ledger.snapshot(), baseline);
    assert_eq!(
        ledger
            .establish_session(
                handshake_verification(
                    &installation,
                    &endpoint,
                    &integration,
                    session_id,
                    1_000,
                    &raw_hello,
                ),
                999,
                &raw_hello,
                &NeverCancel,
            )
            .expect_err("reordered time")
            .code(),
        ErrorCode::TimeReordered
    );
    assert_eq!(ledger.snapshot(), baseline);
}

#[test]
fn path_scope_normalizes_duplicates_ancestors_and_exact_maximum() {
    let context = context(RepositoryId::new(digest(500)));
    let group = AssetGroupCommitment::new(digest(501));
    let file = file_id(1);
    let normalized = PathScope::new(
        context,
        &[
            PathScopeInput::Exact("Assets/Hero/model.uasset"),
            PathScopeInput::Prefix("Assets/Hero"),
            PathScopeInput::Prefix(""),
            PathScopeInput::File(file),
            PathScopeInput::File(file),
            PathScopeInput::AssetGroup(group),
            PathScopeInput::AssetGroup(group),
        ],
        &RawFrame::new(b"normalize"),
        &NeverCancel,
    )
    .expect("normalized scope");
    assert_eq!(normalized.selector_count(), 3);

    let folded_context = ScopeContext {
        repository_id: context.repository_id,
        path_profile: context.path_profile,
        case_mode: CaseMode::Folded,
    };
    let folded_left = PathScope::new(
        folded_context,
        &[
            PathScopeInput::Prefix("assets/hero"),
            PathScopeInput::Prefix("Assets/Hero"),
        ],
        &RawFrame::new(b"folded-left"),
        &NeverCancel,
    )
    .expect("case-equivalent prefixes normalize");
    let folded_right = PathScope::new(
        folded_context,
        &[
            PathScopeInput::Prefix("Assets/Hero"),
            PathScopeInput::Prefix("assets/hero"),
        ],
        &RawFrame::new(b"folded-right"),
        &NeverCancel,
    )
    .expect("reverse case-equivalent prefixes normalize");
    assert_eq!(folded_left.selector_count(), 1);
    assert_eq!(folded_left.commitment(), folded_right.commitment());

    let folded_exact_left = scope(
        folded_context,
        &[
            PathScopeInput::Exact("Assets/Hero/model.uasset"),
            PathScopeInput::Exact("assets/hero/MODEL.uasset"),
        ],
        b"folded-exact-left",
    );
    let folded_exact_right = scope(
        folded_context,
        &[
            PathScopeInput::Exact("assets/hero/MODEL.uasset"),
            PathScopeInput::Exact("Assets/Hero/model.uasset"),
        ],
        b"folded-exact-right",
    );
    assert_eq!(folded_exact_left.selector_count(), 1);
    assert_eq!(
        folded_exact_left.commitment(),
        folded_exact_right.commitment()
    );

    let assets = scope(
        context,
        &[PathScopeInput::Prefix("Assets")],
        b"assets-prefix",
    );
    let nested = scope(
        context,
        &[
            PathScopeInput::Exact("Assets/Hero/model.uasset"),
            PathScopeInput::Prefix("Assets/Props"),
        ],
        b"nested",
    );
    let outside = scope(
        context,
        &[PathScopeInput::Exact("Config/game.ini")],
        b"outside",
    );
    assert!(nested.is_narrower_than(&assets).expect("bounded subset"));
    assert!(!outside.is_narrower_than(&assets).expect("bounded subset"));

    let maximum = vec![PathScopeInput::File(file); PATH_SELECTORS_MAXIMUM];
    assert_eq!(
        PathScope::new(
            context,
            &maximum,
            &RawFrame::new(b"selector-max"),
            &NeverCancel
        )
        .expect("exact selector maximum")
        .selector_count(),
        1
    );
    let too_many = vec![PathScopeInput::File(file); PATH_SELECTORS_MAXIMUM + 1];
    assert_eq!(
        PathScope::new(
            context,
            &too_many,
            &RawFrame::new(b"selector-max-plus-one"),
            &NeverCancel
        )
        .expect_err("selector maximum + 1")
        .code(),
        ErrorCode::ItemLimit
    );

    let long_path = (0..16)
        .map(|segment| format!("segment-{segment:02}-{}", "x".repeat(225)))
        .collect::<Vec<_>>()
        .join("/");
    let duplicate_long_inputs = vec![PathScopeInput::Exact(&long_path); PATH_SELECTORS_MAXIMUM];
    assert_eq!(
        PathScope::new(
            context,
            &duplicate_long_inputs,
            &RawFrame::new(b"typed-scope-over"),
            &NeverCancel,
        )
        .expect_err("supplied typed scope bytes are capped before deduplication")
        .code(),
        ErrorCode::InputTooLarge
    );
}

#[test]
fn debug_output_redacts_paths_challenges_file_ids_and_digests() {
    let repository_id = RepositoryId::new(digest(550));
    let context = context(repository_id);
    let sensitive_path = "Assets/Secret/never-log-this.uasset";
    let path = ValidatedScopePath::new(context, sensitive_path).expect("sensitive path");
    let file = file_id(551);
    let item = StatusItemFact {
        file_id: file,
        path: path.clone(),
        state: StatusItemState::Modified,
        item_state_commitment: StateCommitment::new(digest(552)),
    };
    let input_debug = format!("{:?}", PathScopeInput::Exact(sensitive_path));
    let path_debug = format!("{path:?}");
    let item_debug = format!("{item:?}");
    assert!(!input_debug.contains(sensitive_path));
    assert!(!path_debug.contains(sensitive_path));
    assert!(!item_debug.contains(sensitive_path));
    assert!(!item_debug.contains(&format!("{file:?}")));

    let installation = make_installation(1, 553);
    let endpoint = make_endpoint(&installation, 1, 554);
    let integration = make_integration(&installation, 555);
    let hello = default_client_hello();
    let raw_hello = RawFrame::new(&hello);
    let mut facts = handshake_verification(
        &installation,
        &endpoint,
        &integration,
        SessionId::new(digest(556)),
        1_000,
        &raw_hello,
    );
    facts.agent_challenge = [222; 32];
    let handshake_debug = format!("{facts:?}");
    assert!(!handshake_debug.contains("222, 222"));
    assert!(handshake_debug.contains("<redacted>"));
    let decoded = decode_client_hello(&raw_hello, &NeverCancel).expect("decoded client hello");
    let decoded_debug = format!("{decoded:?}");
    assert!(!decoded_debug.contains(&digest(100).to_lower_hex()));
    assert!(decoded_debug.contains("<redacted>"));
    assert_eq!(format!("{:?}", digest(557)), "Digest32(<redacted>)");
}

#[test]
fn handshake_replay_reordered_time_rotation_and_retained_limits_fail_closed() {
    let installation = make_installation(1, 600);
    let endpoint = make_endpoint(&installation, 1, 601);
    let integration = make_integration(&installation, 602);
    let session_id = SessionId::new(digest(603));
    let mut ledger = LocalAgentLedger::new(
        installation.clone(),
        endpoint.clone(),
        1,
        offer(vec![ProtocolVersion::new(1, 0)], all_capabilities()),
        10_000,
        &RawFrame::new(b"new"),
        &NeverCancel,
    )
    .expect("ledger");
    let hello = default_client_hello();
    let raw_hello = RawFrame::new(&hello);
    let facts = handshake_verification(
        &installation,
        &endpoint,
        &integration,
        session_id,
        10_000,
        &raw_hello,
    );
    let receipt = ledger
        .establish_session(facts.clone(), 10_000, &raw_hello, &NeverCancel)
        .expect("session");
    assert_eq!(
        receipt.transcript_commitment.to_lower_hex(),
        "aac3285c13b07d9c5fa195d4574c5e24f562495fe19d376fa61bcb49cb4e3803"
    );
    let before_replay = ledger.snapshot();
    assert_eq!(
        ledger
            .establish_session(facts.clone(), 10_001, &raw_hello, &NeverCancel,)
            .expect_err("transcript replay")
            .code(),
        ErrorCode::ReplayRejected
    );
    assert_eq!(ledger.snapshot(), before_replay);
    assert_eq!(
        ledger
            .establish_session(
                facts.clone(),
                10_001,
                &raw_hello,
                &CancelAt(CancellationPoint::BeforeCommit),
            )
            .expect_err("replay admission precedes the final cancellation fence")
            .code(),
        ErrorCode::ReplayRejected
    );
    assert_eq!(ledger.snapshot(), before_replay);
    let mut different_frame = hello.clone();
    different_frame.push(b' ');
    let different_raw = RawFrame::new(&different_frame);
    let mut replayed_challenges = facts;
    replayed_challenges.session_id = SessionId::new(digest(699));
    replayed_challenges.issued_at_ms = 10_001;
    replayed_challenges.expires_at_ms = 10_001 + SESSION_TTL_MAXIMUM_MS;
    replayed_challenges.verified_client_frame_commitment = different_raw
        .commitment()
        .expect("bounded alternate client hello");
    assert_eq!(
        ledger
            .establish_session(replayed_challenges, 10_001, &different_raw, &NeverCancel,)
            .expect_err("challenge pair replay with a distinct transcript")
            .code(),
        ErrorCode::ReplayRejected
    );
    assert_eq!(ledger.snapshot(), before_replay);
    assert_eq!(
        ledger
            .reap_expired(9_999, &RawFrame::new(b"time-back"), &NeverCancel)
            .expect_err("time reorder")
            .code(),
        ErrorCode::TimeReordered
    );
    assert_eq!(ledger.snapshot(), before_replay);

    let replacement = InstallationIdentity {
        id: installation.id,
        generation: 2,
        identity_commitment: digest(604),
    };
    let replacement_endpoint = make_endpoint(&replacement, 2, 601);
    let replaced_endpoint_identity = make_endpoint(&replacement, 2, 605);
    let jumped_endpoint = make_endpoint(&replacement, 3, 617);
    let before_jump = ledger.snapshot();
    assert_eq!(
        ledger
            .rotate_installation(
                RotationFacts {
                    expected_installation: installation.clone(),
                    replacement_installation: replacement.clone(),
                    replacement_endpoint: jumped_endpoint,
                    expected_verifier_key_generation: 1,
                    replacement_verifier_key_generation: 2,
                    rotation_verification: ExternalVerdict::Verified,
                    rotation_commitment: digest(618),
                    effective_at_ms: 10_002,
                },
                10_002,
                &RawFrame::new(b"rotate-endpoint-jump"),
                &NeverCancel,
            )
            .expect_err("endpoint generation must advance exactly once")
            .code(),
        ErrorCode::StaleGeneration
    );
    assert_eq!(ledger.snapshot(), before_jump);
    assert_eq!(
        ledger
            .rotate_installation(
                RotationFacts {
                    expected_installation: installation.clone(),
                    replacement_installation: replacement.clone(),
                    replacement_endpoint: replaced_endpoint_identity,
                    expected_verifier_key_generation: 1,
                    replacement_verifier_key_generation: 2,
                    rotation_verification: ExternalVerdict::Verified,
                    rotation_commitment: digest(619),
                    effective_at_ms: 10_002,
                },
                10_002,
                &RawFrame::new(b"rotate-endpoint-identity"),
                &NeverCancel,
            )
            .expect_err("endpoint generation cannot substitute its stable identity")
            .code(),
        ErrorCode::StaleGeneration
    );
    assert_eq!(ledger.snapshot(), before_jump);
    ledger
        .rotate_installation(
            RotationFacts {
                expected_installation: installation,
                replacement_installation: replacement.clone(),
                replacement_endpoint: replacement_endpoint.clone(),
                expected_verifier_key_generation: 1,
                replacement_verifier_key_generation: 2,
                rotation_verification: ExternalVerdict::Verified,
                rotation_commitment: digest(606),
                effective_at_ms: 10_002,
            },
            10_002,
            &RawFrame::new(b"rotate"),
            &NeverCancel,
        )
        .expect("rotation");
    assert_eq!(ledger.installation(), &replacement);
    assert_eq!(ledger.endpoint(), &replacement_endpoint);
    assert_eq!(ledger.verifier_key_generation(), 2);
    let repository_id = RepositoryId::new(digest(607));
    let old_session_scope = scope(
        context(repository_id),
        &[PathScopeInput::Prefix("")],
        b"old-session-scope",
    );
    let after_rotation = ledger.snapshot();
    assert_eq!(
        ledger
            .register_consent(
                ConsentGrantFacts {
                    consent_id: ConsentId::new(digest(608)),
                    session_id,
                    integration_id: integration.id,
                    workspace_id: WorkspaceId::new(digest(609)),
                    repository_id,
                    generation: 1,
                    capabilities: vec![Capability::ReadStatus],
                    scope: old_session_scope,
                    issued_at_ms: 10_003,
                    expires_at_ms: 20_000,
                    confirmation: ConsentConfirmation::ExplicitUser,
                    external_consent_proof: ExternalVerdict::Verified,
                    consent_proof_commitment: digest(610),
                },
                10_003,
                &RawFrame::new(b"old-session-after-rotation"),
                &NeverCancel,
            )
            .expect_err("old session is generation fenced")
            .code(),
        ErrorCode::StaleGeneration
    );
    assert_eq!(ledger.snapshot(), after_rotation);

    assert_eq!(
        LedgerLimits::narrowed(RETAINED_LOGICAL_BYTES_MAXIMUM + 1, RETAINED_RECORDS_MAXIMUM,)
            .expect_err("retained byte hard maximum + 1")
            .code(),
        ErrorCode::InvalidFact
    );
    assert_eq!(
        LedgerLimits::narrowed(RETAINED_LOGICAL_BYTES_MAXIMUM, RETAINED_RECORDS_MAXIMUM + 1,)
            .expect_err("retained record hard maximum + 1")
            .code(),
        ErrorCode::InvalidFact
    );
    let exact_session_retained = 512 + 1_056 + 96;
    let limits = LedgerLimits::narrowed(exact_session_retained, RETAINED_RECORDS_MAXIMUM)
        .expect("narrowed retained limit");
    assert_eq!(
        limits.retained_logical_bytes_maximum(),
        exact_session_retained
    );
    assert_eq!(limits.retained_records_maximum(), RETAINED_RECORDS_MAXIMUM);
    let installation = make_installation(1, 610);
    let endpoint = make_endpoint(&installation, 1, 611);
    let integration = make_integration(&installation, 612);
    let mut exact = LocalAgentLedger::new_with_limits(
        LedgerConfiguration {
            installation: installation.clone(),
            endpoint: endpoint.clone(),
            verifier_key_generation: 1,
            agent_support: offer(vec![ProtocolVersion::new(1, 0)], all_capabilities()),
            limits,
        },
        1,
        &RawFrame::new(b"exact-retained"),
        &NeverCancel,
    )
    .expect("ledger");
    let first_hello = default_client_hello();
    let first_raw = RawFrame::new(&first_hello);
    exact
        .establish_session(
            handshake_verification(
                &installation,
                &endpoint,
                &integration,
                SessionId::new(digest(613)),
                1,
                &first_raw,
            ),
            1,
            &first_raw,
            &NeverCancel,
        )
        .expect("exact retained maximum");
    assert_eq!(
        exact.snapshot().retained_logical_bytes,
        exact_session_retained
    );
    let before_overflow = exact.snapshot();
    let second_hello = client_hello_frame(
        &offer(vec![ProtocolVersion::new(1, 0)], all_capabilities()),
        *digest(615).as_bytes(),
    );
    let second_raw = RawFrame::new(&second_hello);
    let mut second = handshake_verification(
        &installation,
        &endpoint,
        &integration,
        SessionId::new(digest(614)),
        2,
        &second_raw,
    );
    second.agent_challenge = *digest(616).as_bytes();
    assert_eq!(
        exact
            .establish_session(second, 2, &second_raw, &NeverCancel,)
            .expect_err("retained maximum + one record")
            .code(),
        ErrorCode::RetainedLimit
    );
    assert_eq!(exact.snapshot(), before_overflow);
}

#[test]
fn consent_narrows_operations_and_idempotency_preserves_original_receipt() {
    let mut fixture = fixture_with_grant("Assets", all_capabilities());
    let requested = scope(
        fixture.context,
        &[PathScopeInput::Exact("Assets/Hero/model.uasset")],
        b"requested",
    );
    let facts = operation(
        &fixture,
        OperationKind::ReadStatus,
        requested.clone(),
        700,
        2_000,
        None,
    );
    let admitted = fixture
        .ledger
        .admit_operation(
            facts.clone(),
            2_000,
            &RawFrame::new(b"operation-frame"),
            &NeverCancel,
        )
        .expect("admitted");
    assert_eq!(
        admitted.disposition,
        OperationAdmissionDisposition::Admitted
    );
    let replay = fixture
        .ledger
        .admit_operation(
            facts.clone(),
            2_001,
            &RawFrame::new(b"operation-frame"),
            &NeverCancel,
        )
        .expect("idempotent replay");
    assert_eq!(
        replay.disposition,
        OperationAdmissionDisposition::IdempotentReplay
    );
    assert_eq!(replay.receipt, admitted.receipt);

    let before_conflict = fixture.ledger.snapshot();
    let mut conflicting = facts.clone();
    conflicting.fresh_state.current = StateCommitment::new(digest(701));
    assert_eq!(
        fixture
            .ledger
            .admit_operation(
                conflicting,
                2_002,
                &RawFrame::new(b"operation-frame"),
                &NeverCancel,
            )
            .expect_err("same key, different request")
            .code(),
        ErrorCode::IdempotencyConflict
    );
    assert_eq!(fixture.ledger.snapshot(), before_conflict);

    for (key, label) in [(700, "retained"), (799, "absent")] {
        let mut unauthorized = facts.clone();
        unauthorized.consent_id = ConsentId::new(digest(798));
        unauthorized.idempotency_key = IdempotencyKey::new(digest(key));
        unauthorized.deadline_ms = 0;
        assert_eq!(
            fixture
                .ledger
                .admit_operation(
                    unauthorized,
                    2_002,
                    &RawFrame::new(b"idempotency-oracle"),
                    &NeverCancel,
                )
                .expect_err(label)
                .code(),
            ErrorCode::ConsentUnknown
        );
    }
    assert_eq!(fixture.ledger.snapshot(), before_conflict);

    let outside = scope(
        fixture.context,
        &[PathScopeInput::Exact("Config/game.ini")],
        b"outside-operation",
    );
    let before_scope = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .admit_operation(
                operation(
                    &fixture,
                    OperationKind::ReadStatus,
                    outside,
                    702,
                    2_003,
                    None,
                ),
                2_003,
                &RawFrame::new(b"outside"),
                &NeverCancel,
            )
            .expect_err("outside consent")
            .code(),
        ErrorCode::ScopeDenied
    );
    assert_eq!(fixture.ledger.snapshot(), before_scope);

    let before_cancel = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .admit_operation(
                operation(
                    &fixture,
                    OperationKind::ReadStatus,
                    requested,
                    703,
                    2_004,
                    None,
                ),
                2_004,
                &RawFrame::new(b"cancel"),
                &CancelAt(CancellationPoint::BeforeCommit),
            )
            .expect_err("cancelled before commit")
            .code(),
        ErrorCode::Cancelled
    );
    assert_eq!(fixture.ledger.snapshot(), before_cancel);
}

#[test]
fn exact_idempotent_replay_survives_original_freshness_and_deadline_windows() {
    let mut fixture = fixture_with_grant("Assets", all_capabilities());
    let request_scope = scope(
        fixture.context,
        &[PathScopeInput::Exact("Assets/Hero/replay.uasset")],
        b"replay-window-scope",
    );
    let mut facts = operation(
        &fixture,
        OperationKind::ReadStatus,
        request_scope,
        750,
        2_000,
        None,
    );
    facts.deadline_ms = 2_000;
    let admitted = fixture
        .ledger
        .admit_operation(
            facts.clone(),
            2_000,
            &RawFrame::new(b"replay-window-frame"),
            &NeverCancel,
        )
        .expect("initial admission");
    let replayed = fixture
        .ledger
        .admit_operation(
            facts,
            2_000 + FRESHNESS_FUTURE_MAXIMUM_MS + 1,
            &RawFrame::new(b"replay-window-frame"),
            &NeverCancel,
        )
        .expect("exact replay returns the stored result without re-execution");
    assert_eq!(
        replayed.disposition,
        OperationAdmissionDisposition::IdempotentReplay
    );
    assert_eq!(replayed.receipt, admitted.receipt);
}

#[test]
fn freshness_deadline_and_explicit_lock_states_have_exact_boundaries() {
    let mut fixture = fixture_with_grant("", all_capabilities());
    let request_scope = scope(
        fixture.context,
        &[PathScopeInput::Exact("Assets/lock.uasset")],
        b"lock-scope",
    );
    let now = 40_000;
    let states = vec![
        LockKnowledge::Denied {
            decision_commitment: LockProofCommitment::new(digest(800)),
        },
        LockKnowledge::Lost {
            last_generation: 4,
            transition_commitment: LockProofCommitment::new(digest(801)),
        },
        LockKnowledge::Unknown {
            last_generation: Some(4),
            cause_commitment: LockProofCommitment::new(digest(802)),
        },
        LockKnowledge::Recoverable {
            last_generation: Some(4),
            recovery_commitment: LockProofCommitment::new(digest(803)),
        },
        LockKnowledge::Granted {
            authority_epoch: 2,
            generation: 5,
            lease_expires_at_ms: now + 10,
            proof: LockProofCommitment::new(digest(804)),
        },
    ];
    for (index, lock) in states.into_iter().enumerate() {
        let mut facts = operation(
            &fixture,
            OperationKind::StartEditLockFact,
            request_scope.clone(),
            810 + index as u64,
            now + index as u64,
            Some(lock),
        );
        facts.fresh_state.observed_at_ms = facts
            .fresh_state
            .observed_at_ms
            .saturating_sub(FRESHNESS_AGE_MAXIMUM_MS);
        fixture
            .ledger
            .admit_operation(
                facts,
                now + index as u64,
                &RawFrame::new(b"lock-state"),
                &NeverCancel,
            )
            .expect("explicit lock state");
    }

    let current_now = now + 4;
    let mut stale = operation(
        &fixture,
        OperationKind::ReadStatus,
        request_scope.clone(),
        820,
        current_now,
        None,
    );
    stale.fresh_state.observed_at_ms = current_now - FRESHNESS_AGE_MAXIMUM_MS - 1;
    let before_stale = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .admit_operation(stale, current_now, &RawFrame::new(b"stale"), &NeverCancel,)
            .expect_err("freshness max + 1")
            .code(),
        ErrorCode::StaleState
    );
    assert_eq!(fixture.ledger.snapshot(), before_stale);

    let mut deadline = operation(
        &fixture,
        OperationKind::ReadStatus,
        request_scope,
        821,
        current_now,
        None,
    );
    deadline.deadline_ms = current_now + DEADLINE_HORIZON_MAXIMUM_MS + 1;
    assert_eq!(
        fixture
            .ledger
            .admit_operation(
                deadline,
                current_now,
                &RawFrame::new(b"deadline"),
                &NeverCancel,
            )
            .expect_err("deadline horizon max + 1")
            .code(),
        ErrorCode::InvalidFact
    );
}

#[test]
fn status_batches_are_bounded_scoped_and_do_not_accept_duplicate_items() {
    let mut fixture = fixture_with_grant("Assets", all_capabilities());
    let query_scope = scope(
        fixture.context,
        &[PathScopeInput::Prefix("Assets")],
        b"status-query",
    );
    let items = vec![
        StatusItemFact {
            file_id: file_id(900),
            path: ValidatedScopePath::new(fixture.context, "Assets/a.uasset").expect("path"),
            state: StatusItemState::Modified,
            item_state_commitment: StateCommitment::new(digest(901)),
        },
        StatusItemFact {
            file_id: file_id(902),
            path: ValidatedScopePath::new(fixture.context, "Assets/b.uasset").expect("path"),
            state: StatusItemState::Clean,
            item_state_commitment: StateCommitment::new(digest(903)),
        },
    ];
    let facts = StatusBatchFacts {
        session_id: fixture.session_id,
        consent_id: fixture.consent_id,
        integration_id: fixture.integration.id,
        workspace_id: fixture.workspace_id,
        repository_id: fixture.repository_id,
        query_scope: query_scope.clone(),
        fresh_state: fresh(3_000, 904),
        items: items.clone(),
        continuation: StatusContinuation::Complete,
    };
    let receipt = fixture
        .ledger
        .validate_status_batch(&facts, 3_000, &RawFrame::new(b"status-batch"), &NeverCancel)
        .expect("status batch");
    assert_eq!(receipt.item_count, 2);
    assert!(receipt.complete);

    let selected_file = file_id(905);
    let mut file_fixture =
        fixture_with_scope_inputs(&[PathScopeInput::File(selected_file)], all_capabilities());
    let file_receipt = file_fixture
        .ledger
        .validate_status_batch(
            &StatusBatchFacts {
                session_id: file_fixture.session_id,
                consent_id: file_fixture.consent_id,
                integration_id: file_fixture.integration.id,
                workspace_id: file_fixture.workspace_id,
                repository_id: file_fixture.repository_id,
                query_scope: scope(
                    file_fixture.context,
                    &[PathScopeInput::File(selected_file)],
                    b"file-status-query",
                ),
                fresh_state: fresh(3_000, 906),
                items: vec![StatusItemFact {
                    file_id: selected_file,
                    path: ValidatedScopePath::new(file_fixture.context, "Renamed/location.uasset")
                        .expect("renamed FileID path"),
                    state: StatusItemState::Modified,
                    item_state_commitment: StateCommitment::new(digest(907)),
                }],
                continuation: StatusContinuation::Complete,
            },
            3_000,
            &RawFrame::new(b"file-status-batch"),
            &NeverCancel,
        )
        .expect("a FileID selector authorizes the matching stable item");
    assert_eq!(file_receipt.item_count, 1);

    let mut duplicate = facts;
    duplicate.items[1].file_id = duplicate.items[0].file_id;
    let before = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .validate_status_batch(
                &duplicate,
                3_001,
                &RawFrame::new(b"status-duplicate"),
                &NeverCancel,
            )
            .expect_err("duplicate FileID")
            .code(),
        ErrorCode::ScopeDenied
    );
    assert_eq!(fixture.ledger.snapshot(), before);

    let maximum_items: Vec<_> = (0..STATUS_ITEMS_MAXIMUM)
        .map(|index| StatusItemFact {
            file_id: file_id(1_000 + index as u64),
            path: ValidatedScopePath::new(fixture.context, &format!("Assets/item-{index}.uasset"))
                .expect("path"),
            state: StatusItemState::Clean,
            item_state_commitment: StateCommitment::new(digest(2_000 + index as u64)),
        })
        .collect();
    let maximum = StatusBatchFacts {
        session_id: fixture.session_id,
        consent_id: fixture.consent_id,
        integration_id: fixture.integration.id,
        workspace_id: fixture.workspace_id,
        repository_id: fixture.repository_id,
        query_scope,
        fresh_state: fresh(3_002, 3_000),
        items: maximum_items.clone(),
        continuation: StatusContinuation::More {
            externally_scoped_cursor_commitment: digest(3_500),
        },
    };
    assert_eq!(
        fixture
            .ledger
            .validate_status_batch(
                &maximum,
                3_002,
                &RawFrame::new(b"status-maximum"),
                &NeverCancel,
            )
            .expect("status exact maximum")
            .item_count,
        STATUS_ITEMS_MAXIMUM
    );
    let mut over = maximum;
    over.items.push(StatusItemFact {
        file_id: file_id(9_999),
        path: ValidatedScopePath::new(fixture.context, "Assets/over.uasset").expect("path"),
        state: StatusItemState::Clean,
        item_state_commitment: StateCommitment::new(digest(9_999)),
    });
    assert_eq!(
        fixture
            .ledger
            .validate_status_batch(&over, 3_003, &RawFrame::new(b"status-over"), &NeverCancel,)
            .expect_err("status maximum + 1")
            .code(),
        ErrorCode::ItemLimit
    );

    let long_prefix = (0..16)
        .map(|segment| format!("segment-{segment:02}-{}", "x".repeat(225)))
        .collect::<Vec<_>>()
        .join("/");
    let oversized_items: Vec<_> = (0..STATUS_ITEMS_MAXIMUM)
        .map(|index| StatusItemFact {
            file_id: file_id(30_000 + index as u64),
            path: ValidatedScopePath::new(
                fixture.context,
                &format!("Assets/{long_prefix}/item-{index}"),
            )
            .expect("individually bounded long path"),
            state: StatusItemState::Clean,
            item_state_commitment: StateCommitment::new(digest(31_000 + index as u64)),
        })
        .collect();
    let oversized = StatusBatchFacts {
        session_id: fixture.session_id,
        consent_id: fixture.consent_id,
        integration_id: fixture.integration.id,
        workspace_id: fixture.workspace_id,
        repository_id: fixture.repository_id,
        query_scope: scope(
            fixture.context,
            &[PathScopeInput::Prefix("Assets")],
            b"status-oversized-query",
        ),
        fresh_state: fresh(3_004, 32_000),
        items: oversized_items,
        continuation: StatusContinuation::Complete,
    };
    let before_oversized = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .validate_status_batch(
                &oversized,
                3_004,
                &RawFrame::new(b"status-structured-over"),
                &NeverCancel,
            )
            .expect_err("aggregate typed status bytes exceed the entry-point ceiling")
            .code(),
        ErrorCode::InputTooLarge
    );
    assert_eq!(fixture.ledger.snapshot(), before_oversized);
}

#[test]
fn work_budget_accepts_exact_limit_and_rejects_one_charged_comparison_more() {
    let path_strings: Vec<_> = (0..STATUS_ITEMS_MAXIMUM)
        .map(|index| format!("Assets/work-{index}.uasset"))
        .collect();
    let query_inputs: Vec<_> = path_strings
        .iter()
        .map(|path| PathScopeInput::Exact(path))
        .collect();

    let mut exact_grants: Vec<_> = (0..254)
        .map(|index| PathScopeInput::File(file_id(20_000 + index)))
        .collect();
    exact_grants.push(PathScopeInput::Prefix(""));
    let mut exact = fixture_with_scope_inputs(&exact_grants, all_capabilities());
    assert_eq!(exact.grant_scope.selector_count(), 255);
    let exact_query = scope(exact.context, &query_inputs, b"work-query-exact");
    assert_eq!(exact_query.selector_count(), 256);
    let items: Vec<_> = path_strings
        .iter()
        .enumerate()
        .map(|(index, path)| StatusItemFact {
            file_id: file_id(21_000 + index as u64),
            path: ValidatedScopePath::new(exact.context, path).expect("path"),
            state: StatusItemState::Clean,
            item_state_commitment: StateCommitment::new(digest(22_000 + index as u64)),
        })
        .collect();
    let exact_facts = StatusBatchFacts {
        session_id: exact.session_id,
        consent_id: exact.consent_id,
        integration_id: exact.integration.id,
        workspace_id: exact.workspace_id,
        repository_id: exact.repository_id,
        query_scope: exact_query,
        fresh_state: fresh(8_000, 23_000),
        items: items.clone(),
        continuation: StatusContinuation::Complete,
    };
    assert_eq!(
        exact
            .ledger
            .validate_status_batch(
                &exact_facts,
                8_000,
                &RawFrame::new(b"work-exact"),
                &NeverCancel,
            )
            .expect("exact 131072 work units")
            .item_count,
        256
    );

    let mut over_grants: Vec<_> = (0..255)
        .map(|index| PathScopeInput::File(file_id(24_000 + index)))
        .collect();
    over_grants.push(PathScopeInput::Prefix(""));
    let mut over = fixture_with_scope_inputs(&over_grants, all_capabilities());
    assert_eq!(over.grant_scope.selector_count(), 256);
    let over_query = scope(over.context, &query_inputs, b"work-query-over");
    let over_facts = StatusBatchFacts {
        session_id: over.session_id,
        consent_id: over.consent_id,
        integration_id: over.integration.id,
        workspace_id: over.workspace_id,
        repository_id: over.repository_id,
        query_scope: over_query,
        fresh_state: fresh(8_000, 25_000),
        items,
        continuation: StatusContinuation::Complete,
    };
    let before = over.ledger.snapshot();
    assert_eq!(
        over.ledger
            .validate_status_batch(
                &over_facts,
                8_000,
                &RawFrame::new(b"work-over"),
                &NeverCancel,
            )
            .expect_err("one 256-comparison charge beyond work limit")
            .code(),
        ErrorCode::WorkLimit
    );
    assert_eq!(over.ledger.snapshot(), before);
}

fn event(_fixture: &Fixture, scope: &PathScope, sequence: u64, now_ms: u64) -> StatusEventFact {
    StatusEventFact {
        event_id: EventId::new(digest(4_000 + sequence)),
        sequence,
        scope: scope.clone(),
        kind: EventKind::WorkspaceStatus,
        fresh_state: fresh(now_ms, 4_100 + sequence),
        producer_commitment: digest(4_200 + sequence),
    }
}

#[test]
fn subscription_backpressure_cursor_ack_and_reorder_are_deterministic() {
    let mut fixture = fixture_with_grant("Assets", all_capabilities());
    let caller = subscription_caller(&fixture);
    let event_scope = scope(
        fixture.context,
        &[PathScopeInput::Prefix("Assets")],
        b"event-scope",
    );
    let subscription_id = SubscriptionId::new(digest(4_300));
    let opened = fixture
        .ledger
        .open_subscription(
            SubscriptionFacts {
                subscription_id,
                session_id: fixture.session_id,
                consent_id: fixture.consent_id,
                integration_id: fixture.integration.id,
                workspace_id: fixture.workspace_id,
                repository_id: fixture.repository_id,
                scope: event_scope.clone(),
                queue_capacity: 2,
                opened_at_ms: 5_000,
                expires_at_ms: 20_000,
                cursor_ttl_ms: 5_000,
                initial_state_commitment: StateCommitment::new(digest(4_301)),
            },
            5_000,
            &RawFrame::new(b"subscribe"),
            &NeverCancel,
        )
        .expect("subscription");
    let mut extended_cursor = opened.initial_cursor.clone();
    extended_cursor.expires_at_ms = 5_000 + 5_000 + 1;
    extended_cursor.cursor_commitment = extended_cursor.integrity_commitment();
    let before_extended_cursor = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .poll_events(
                &caller,
                &extended_cursor,
                1,
                5_000,
                &RawFrame::new(b"extended-cursor"),
                &NeverCancel,
            )
            .expect_err("recomputed cursor TTL maximum + 1")
            .code(),
        ErrorCode::CursorInvalid
    );
    assert_eq!(fixture.ledger.snapshot(), before_extended_cursor);
    let mut later_extended_cursor = opened.initial_cursor.clone();
    later_extended_cursor.expires_at_ms = 9_000 + 5_000;
    later_extended_cursor.cursor_commitment = later_extended_cursor.integrity_commitment();
    assert_eq!(
        fixture
            .ledger
            .poll_events(
                &caller,
                &later_extended_cursor,
                1,
                9_000,
                &RawFrame::new(b"later-extended-cursor"),
                &NeverCancel,
            )
            .expect_err("recomputed cursor cannot extend a ledger-issued expiry")
            .code(),
        ErrorCode::CursorInvalid
    );
    assert_eq!(fixture.ledger.snapshot(), before_extended_cursor);
    let mut first = event(&fixture, &event_scope, 1, 5_001);
    first.fresh_state.valid_through_ms = 5_002;
    let first_receipt = fixture
        .ledger
        .enqueue_event(
            &caller,
            subscription_id,
            first.clone(),
            5_001,
            &RawFrame::new(b"event-one"),
            &NeverCancel,
        )
        .expect("first event");
    assert_eq!(first_receipt.disposition, EventEnqueueDisposition::Enqueued);
    assert_eq!(
        fixture
            .ledger
            .enqueue_event(
                &caller,
                subscription_id,
                first,
                5_003,
                &RawFrame::new(b"event-one"),
                &NeverCancel,
            )
            .expect("exact duplicate after original freshness")
            .disposition,
        EventEnqueueDisposition::ExactDuplicate
    );
    fixture
        .ledger
        .enqueue_event(
            &caller,
            subscription_id,
            event(&fixture, &event_scope, 2, 5_003),
            5_003,
            &RawFrame::new(b"event-two"),
            &NeverCancel,
        )
        .expect("second event");
    let before_full = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .enqueue_event(
                &caller,
                subscription_id,
                event(&fixture, &event_scope, 3, 5_004),
                5_004,
                &RawFrame::new(b"event-three"),
                &NeverCancel,
            )
            .expect_err("queue full")
            .code(),
        ErrorCode::QueueFull
    );
    assert_eq!(fixture.ledger.snapshot(), before_full);

    let page = fixture
        .ledger
        .poll_events(
            &caller,
            &opened.initial_cursor,
            1,
            5_005,
            &RawFrame::new(b"poll-one"),
            &NeverCancel,
        )
        .expect("page");
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.next_cursor.position, 1);
    assert_eq!(
        fixture
            .ledger
            .acknowledge_events(
                &caller,
                &page.next_cursor,
                5_006,
                &RawFrame::new(b"ack-one"),
                &NeverCancel,
            )
            .expect("ack")
            .removed_items,
        1
    );
    assert_eq!(
        fixture
            .ledger
            .poll_events(
                &caller,
                &opened.initial_cursor,
                1,
                5_007,
                &RawFrame::new(b"old-cursor"),
                &NeverCancel,
            )
            .expect_err("acknowledged cursor gap")
            .code(),
        ErrorCode::CursorGap
    );
    fixture
        .ledger
        .enqueue_event(
            &caller,
            subscription_id,
            event(&fixture, &event_scope, 3, 5_008),
            5_008,
            &RawFrame::new(b"event-three"),
            &NeverCancel,
        )
        .expect("capacity returned after ack");
    let before_reorder = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .enqueue_event(
                &caller,
                subscription_id,
                event(&fixture, &event_scope, 2, 5_009),
                5_009,
                &RawFrame::new(b"reordered-event"),
                &NeverCancel,
            )
            .expect_err("reordered event")
            .code(),
        ErrorCode::SequenceInvalid
    );
    assert_eq!(fixture.ledger.snapshot(), before_reorder);
    assert_eq!(
        fixture
            .ledger
            .poll_events(
                &caller,
                &page.next_cursor,
                EVENT_PAGE_ITEMS_MAXIMUM + 1,
                5_010,
                &RawFrame::new(b"page-over"),
                &NeverCancel,
            )
            .expect_err("page maximum + 1")
            .code(),
        ErrorCode::ItemLimit
    );

    let delivered = fixture
        .ledger
        .poll_events(
            &caller,
            &page.next_cursor,
            2,
            5_011,
            &RawFrame::new(b"poll-two-and-three"),
            &NeverCancel,
        )
        .expect("two-event page");
    assert_eq!(delivered.next_cursor.position, 3);
    let mut unissued = EventCursor {
        subscription_id,
        subscription_generation: 1,
        position: 2,
        scope_commitment: event_scope.commitment(),
        state_commitment: StateCommitment::new(digest(4_103)),
        expires_at_ms: delivered.next_cursor.expires_at_ms,
        cursor_commitment: Digest32::ZERO,
    };
    unissued.cursor_commitment = unissued.integrity_commitment();
    let before_unissued = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .poll_events(
                &caller,
                &unissued,
                1,
                5_012,
                &RawFrame::new(b"unissued-intermediate"),
                &NeverCancel,
            )
            .expect_err("an intermediate event without an issued cursor is not authority")
            .code(),
        ErrorCode::CursorInvalid
    );
    assert_eq!(fixture.ledger.snapshot(), before_unissued);

    let mut unauthenticated = caller.clone();
    unauthenticated.request_authentication = ExternalVerdict::Rejected;
    assert_eq!(
        fixture
            .ledger
            .poll_events(
                &unauthenticated,
                &delivered.next_cursor,
                1,
                5_012,
                &RawFrame::new(b"stolen-cursor"),
                &NeverCancel,
            )
            .expect_err("an unkeyed cursor is not caller authentication")
            .code(),
        ErrorCode::TranscriptUnverified
    );
    assert_eq!(fixture.ledger.snapshot(), before_unissued);
}

#[test]
fn event_page_commitment_binds_the_complete_enqueued_event() {
    let page_commitment_for = |kind: EventKind| {
        let mut fixture = fixture_with_grant("Assets", all_capabilities());
        let caller = subscription_caller(&fixture);
        let event_scope = scope(
            fixture.context,
            &[PathScopeInput::Prefix("Assets")],
            b"page-binding-scope",
        );
        let subscription_id = SubscriptionId::new(digest(27_000));
        let opened = fixture
            .ledger
            .open_subscription(
                SubscriptionFacts {
                    subscription_id,
                    session_id: fixture.session_id,
                    consent_id: fixture.consent_id,
                    integration_id: fixture.integration.id,
                    workspace_id: fixture.workspace_id,
                    repository_id: fixture.repository_id,
                    scope: event_scope.clone(),
                    queue_capacity: 1,
                    opened_at_ms: 12_000,
                    expires_at_ms: 20_000,
                    cursor_ttl_ms: 5_000,
                    initial_state_commitment: StateCommitment::new(digest(27_001)),
                },
                12_000,
                &RawFrame::new(b"page-binding-subscribe"),
                &NeverCancel,
            )
            .expect("subscription");
        let mut queued = event(&fixture, &event_scope, 1, 12_001);
        queued.kind = kind;
        fixture
            .ledger
            .enqueue_event(
                &caller,
                subscription_id,
                queued,
                12_001,
                &RawFrame::new(b"page-binding-event"),
                &NeverCancel,
            )
            .expect("event");
        fixture
            .ledger
            .poll_events(
                &caller,
                &opened.initial_cursor,
                1,
                12_002,
                &RawFrame::new(b"page-binding-poll"),
                &NeverCancel,
            )
            .expect("page")
            .page_commitment
    };

    assert_ne!(
        page_commitment_for(EventKind::WorkspaceStatus),
        page_commitment_for(EventKind::JobProgress)
    );
}

#[test]
fn event_queue_accepts_exact_capacity_and_rejects_capacity_plus_one() {
    let mut fixture = fixture_with_grant("Assets", all_capabilities());
    let caller = subscription_caller(&fixture);
    let event_scope = scope(
        fixture.context,
        &[PathScopeInput::Prefix("Assets")],
        b"event-max-scope",
    );
    let subscription_id = SubscriptionId::new(digest(26_000));
    fixture
        .ledger
        .open_subscription(
            SubscriptionFacts {
                subscription_id,
                session_id: fixture.session_id,
                consent_id: fixture.consent_id,
                integration_id: fixture.integration.id,
                workspace_id: fixture.workspace_id,
                repository_id: fixture.repository_id,
                scope: event_scope.clone(),
                queue_capacity: EVENT_QUEUE_ITEMS_MAXIMUM,
                opened_at_ms: 9_000,
                expires_at_ms: 90_000,
                cursor_ttl_ms: CURSOR_TTL_MAXIMUM_MS,
                initial_state_commitment: StateCommitment::new(digest(26_001)),
            },
            9_000,
            &RawFrame::new(b"queue-max-subscribe"),
            &NeverCancel,
        )
        .expect("subscription at capacity maximum");
    for sequence in 1..=EVENT_QUEUE_ITEMS_MAXIMUM {
        let now_ms = 9_000 + sequence as u64;
        let queued = event(&fixture, &event_scope, sequence as u64, now_ms);
        fixture
            .ledger
            .enqueue_event(
                &caller,
                subscription_id,
                queued,
                now_ms,
                &RawFrame::new(b"queue-max-event"),
                &NeverCancel,
            )
            .expect("event through exact capacity");
    }
    assert_eq!(
        fixture.ledger.snapshot().queued_events,
        EVENT_QUEUE_ITEMS_MAXIMUM
    );
    let before = fixture.ledger.snapshot();
    let over_now = 9_000 + EVENT_QUEUE_ITEMS_MAXIMUM as u64 + 1;
    let over_event = event(
        &fixture,
        &event_scope,
        EVENT_QUEUE_ITEMS_MAXIMUM as u64 + 1,
        over_now,
    );
    assert_eq!(
        fixture
            .ledger
            .enqueue_event(
                &caller,
                subscription_id,
                over_event,
                over_now,
                &RawFrame::new(b"queue-max-plus-one"),
                &NeverCancel,
            )
            .expect_err("queue capacity + 1")
            .code(),
        ErrorCode::QueueFull
    );
    assert_eq!(fixture.ledger.snapshot(), before);
}

#[test]
fn trusted_handoff_is_exactly_scoped_and_single_use() {
    let mut fixture = fixture_with_grant("Assets", all_capabilities());
    let handoff_scope = scope(
        fixture.context,
        &[PathScopeInput::Exact("Assets/Hero/model.uasset")],
        b"handoff-scope",
    );
    let handoff_id = HandoffId::new(digest(5_000));
    let trusted_client_id = TrustedClientId::new(digest(5_001));
    let registered = fixture
        .ledger
        .register_trusted_handoff(
            TrustedHandoffFacts {
                handoff_id,
                session_id: fixture.session_id,
                consent_id: fixture.consent_id,
                integration_id: fixture.integration.id,
                installation_id: fixture.installation.id,
                workspace_id: fixture.workspace_id,
                repository_id: fixture.repository_id,
                trusted_client_id,
                action: HandoffAction::Submit,
                scope: handoff_scope,
                fresh_state: fresh(6_000, 5_002),
                verifier_key_generation: 1,
                issued_at_ms: 6_000,
                expires_at_ms: 6_000 + HANDOFF_TTL_MAXIMUM_MS,
                trusted_desktop_confirmation: ExternalVerdict::Verified,
                signature_verification: ExternalVerdict::Verified,
                confirmation_commitment: ConfirmationCommitment::new(digest(5_003)),
                signature_envelope_commitment: digest(5_004),
            },
            6_000,
            &RawFrame::new(b"handoff-register"),
            &NeverCancel,
        )
        .expect("handoff registered");
    let consumption = HandoffConsumptionFacts {
        handoff_id,
        trusted_client_id,
        expected_handoff_commitment: registered.handoff_commitment,
        trusted_client_verification: ExternalVerdict::Verified,
        consumer_adapter_commitment: digest(5_005),
    };
    fixture
        .ledger
        .consume_trusted_handoff(
            &consumption,
            6_001,
            &RawFrame::new(b"handoff-consume"),
            &NeverCancel,
        )
        .expect("single consume");
    let before_replay = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .consume_trusted_handoff(
                &consumption,
                6_002,
                &RawFrame::new(b"handoff-consume"),
                &NeverCancel,
            )
            .expect_err("second consume")
            .code(),
        ErrorCode::HandoffUsed
    );
    assert_eq!(fixture.ledger.snapshot(), before_replay);

    let stale_handoff_id = HandoffId::new(digest(5_100));
    let stale_registered = fixture
        .ledger
        .register_trusted_handoff(
            TrustedHandoffFacts {
                handoff_id: stale_handoff_id,
                session_id: fixture.session_id,
                consent_id: fixture.consent_id,
                integration_id: fixture.integration.id,
                installation_id: fixture.installation.id,
                workspace_id: fixture.workspace_id,
                repository_id: fixture.repository_id,
                trusted_client_id,
                action: HandoffAction::Review,
                scope: scope(
                    fixture.context,
                    &[PathScopeInput::Exact("Assets/Hero/model.uasset")],
                    b"stale-handoff-scope",
                ),
                fresh_state: fresh(7_000, 5_102),
                verifier_key_generation: 1,
                issued_at_ms: 7_000,
                expires_at_ms: 7_000 + HANDOFF_TTL_MAXIMUM_MS,
                trusted_desktop_confirmation: ExternalVerdict::Verified,
                signature_verification: ExternalVerdict::Verified,
                confirmation_commitment: ConfirmationCommitment::new(digest(5_103)),
                signature_envelope_commitment: digest(5_104),
            },
            7_000,
            &RawFrame::new(b"stale-handoff-register"),
            &NeverCancel,
        )
        .expect("longer-lived handoff registered");
    let before_stale = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .consume_trusted_handoff(
                &HandoffConsumptionFacts {
                    handoff_id: stale_handoff_id,
                    trusted_client_id,
                    expected_handoff_commitment: stale_registered.handoff_commitment,
                    trusted_client_verification: ExternalVerdict::Verified,
                    consumer_adapter_commitment: digest(5_105),
                },
                7_000 + FRESHNESS_AGE_MAXIMUM_MS + 1,
                &RawFrame::new(b"stale-handoff-consume"),
                &NeverCancel,
            )
            .expect_err("handoff state freshness elapsed before consumption")
            .code(),
        ErrorCode::StaleState
    );
    assert_eq!(fixture.ledger.snapshot(), before_stale);
}

#[test]
fn consent_generation_fences_operations_subscriptions_and_handoffs() {
    let mut fixture = fixture_with_grant("Assets", all_capabilities());
    let caller = subscription_caller(&fixture);
    let exact_scope = scope(
        fixture.context,
        &[PathScopeInput::Exact("Assets/Hero/generation.uasset")],
        b"generation-scope",
    );
    let operation_facts = operation(
        &fixture,
        OperationKind::ReadStatus,
        exact_scope.clone(),
        28_000,
        5_000,
        None,
    );
    fixture
        .ledger
        .admit_operation(
            operation_facts.clone(),
            5_000,
            &RawFrame::new(b"generation-operation"),
            &NeverCancel,
        )
        .expect("operation admitted under generation one");

    let subscription_id = SubscriptionId::new(digest(28_001));
    let subscription = fixture
        .ledger
        .open_subscription(
            SubscriptionFacts {
                subscription_id,
                session_id: fixture.session_id,
                consent_id: fixture.consent_id,
                integration_id: fixture.integration.id,
                workspace_id: fixture.workspace_id,
                repository_id: fixture.repository_id,
                scope: exact_scope.clone(),
                queue_capacity: 2,
                opened_at_ms: 5_001,
                expires_at_ms: 20_000,
                cursor_ttl_ms: 5_000,
                initial_state_commitment: StateCommitment::new(digest(28_002)),
            },
            5_001,
            &RawFrame::new(b"generation-subscription"),
            &NeverCancel,
        )
        .expect("subscription under generation one");

    let handoff_id = HandoffId::new(digest(28_003));
    let trusted_client_id = TrustedClientId::new(digest(28_004));
    let handoff = fixture
        .ledger
        .register_trusted_handoff(
            TrustedHandoffFacts {
                handoff_id,
                session_id: fixture.session_id,
                consent_id: fixture.consent_id,
                integration_id: fixture.integration.id,
                installation_id: fixture.installation.id,
                workspace_id: fixture.workspace_id,
                repository_id: fixture.repository_id,
                trusted_client_id,
                action: HandoffAction::Review,
                scope: exact_scope,
                fresh_state: fresh(5_002, 28_005),
                verifier_key_generation: 1,
                issued_at_ms: 5_002,
                expires_at_ms: 5_002 + HANDOFF_TTL_MAXIMUM_MS,
                trusted_desktop_confirmation: ExternalVerdict::Verified,
                signature_verification: ExternalVerdict::Verified,
                confirmation_commitment: ConfirmationCommitment::new(digest(28_006)),
                signature_envelope_commitment: digest(28_007),
            },
            5_002,
            &RawFrame::new(b"generation-handoff"),
            &NeverCancel,
        )
        .expect("handoff under generation one");

    fixture
        .ledger
        .replace_consent(
            ConsentGrantFacts {
                consent_id: fixture.consent_id,
                session_id: fixture.session_id,
                integration_id: fixture.integration.id,
                workspace_id: fixture.workspace_id,
                repository_id: fixture.repository_id,
                generation: 2,
                capabilities: all_capabilities(),
                scope: fixture.grant_scope.clone(),
                issued_at_ms: 5_003,
                expires_at_ms: 100_000,
                confirmation: ConsentConfirmation::ExplicitAdministrator,
                external_consent_proof: ExternalVerdict::Verified,
                consent_proof_commitment: digest(28_008),
            },
            fixture.consent_receipt.grant_commitment,
            5_003,
            &RawFrame::new(b"generation-replacement"),
            &NeverCancel,
        )
        .expect("explicit consent replacement");

    let after_replacement = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .admit_operation(
                operation_facts,
                5_004,
                &RawFrame::new(b"generation-operation"),
                &NeverCancel,
            )
            .expect_err("old idempotency record is generation fenced")
            .code(),
        ErrorCode::StaleGeneration
    );
    assert_eq!(fixture.ledger.snapshot(), after_replacement);
    assert_eq!(
        fixture
            .ledger
            .poll_events(
                &caller,
                &subscription.initial_cursor,
                1,
                5_004,
                &RawFrame::new(b"generation-poll"),
                &NeverCancel,
            )
            .expect_err("old subscription is generation fenced")
            .code(),
        ErrorCode::StaleGeneration
    );
    assert_eq!(fixture.ledger.snapshot(), after_replacement);
    assert_eq!(
        fixture
            .ledger
            .consume_trusted_handoff(
                &HandoffConsumptionFacts {
                    handoff_id,
                    trusted_client_id,
                    expected_handoff_commitment: handoff.handoff_commitment,
                    trusted_client_verification: ExternalVerdict::Verified,
                    consumer_adapter_commitment: digest(28_009),
                },
                5_004,
                &RawFrame::new(b"generation-consume"),
                &NeverCancel,
            )
            .expect_err("old handoff is generation fenced")
            .code(),
        ErrorCode::StaleGeneration
    );
    assert_eq!(fixture.ledger.snapshot(), after_replacement);
}

#[test]
fn consent_replacement_revocation_and_expiry_reap_are_generation_fenced() {
    let mut fixture = fixture_with_grant("Assets", all_capabilities());
    let replacement = ConsentGrantFacts {
        consent_id: fixture.consent_id,
        session_id: fixture.session_id,
        integration_id: fixture.integration.id,
        workspace_id: fixture.workspace_id,
        repository_id: fixture.repository_id,
        generation: 2,
        capabilities: all_capabilities(),
        scope: fixture.grant_scope.clone(),
        issued_at_ms: 7_000,
        expires_at_ms: 100_000,
        confirmation: ConsentConfirmation::ExplicitAdministrator,
        external_consent_proof: ExternalVerdict::Verified,
        consent_proof_commitment: digest(6_000),
    };
    let wrong = fixture.ledger.snapshot();
    assert_eq!(
        fixture
            .ledger
            .replace_consent(
                replacement.clone(),
                digest(6_001),
                7_000,
                &RawFrame::new(b"replace-wrong"),
                &NeverCancel,
            )
            .expect_err("wrong prior commitment")
            .code(),
        ErrorCode::StaleGeneration
    );
    assert_eq!(fixture.ledger.snapshot(), wrong);
    let replaced = fixture
        .ledger
        .replace_consent(
            replacement,
            fixture.consent_receipt.grant_commitment,
            7_000,
            &RawFrame::new(b"replace-correct"),
            &NeverCancel,
        )
        .expect("explicit replacement");
    assert_eq!(replaced.generation, 2);

    let revocation_before = fixture.ledger.snapshot();
    fixture
        .ledger
        .revoke_consent(
            ConsentRevocationFacts {
                consent_id: fixture.consent_id,
                expected_generation: 2,
                external_verification: ExternalVerdict::Verified,
                revocation_commitment: digest(6_003),
            },
            7_001,
            &RawFrame::new(b"revoke"),
            &NeverCancel,
        )
        .expect("revoke");
    assert_ne!(fixture.ledger.snapshot(), revocation_before);
    let request_scope = scope(
        fixture.context,
        &[PathScopeInput::Exact("Assets/revoked.uasset")],
        b"revoked-scope",
    );
    assert_eq!(
        fixture
            .ledger
            .admit_operation(
                operation(
                    &fixture,
                    OperationKind::ReadStatus,
                    request_scope,
                    6_004,
                    7_002,
                    None,
                ),
                7_002,
                &RawFrame::new(b"revoked-operation"),
                &NeverCancel,
            )
            .expect_err("revoked consent")
            .code(),
        ErrorCode::ConsentRevoked
    );
    let report = fixture
        .ledger
        .reap_expired(301_000, &RawFrame::new(b"reap-expired"), &NeverCancel)
        .expect("reap");
    assert_eq!(report.sessions, 1);
    assert_eq!(report.replays, 1);
    assert_eq!(report.consents, 1);
    assert_eq!(fixture.ledger.snapshot().session_records, 0);
}
