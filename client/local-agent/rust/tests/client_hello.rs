use ogvcs_local_agent_ipc::*;

fn digest(value: u64) -> Digest32 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xa5;
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Digest32::from_bytes(bytes)
}

fn manifest_hex() -> String {
    public_protocol_manifest_commitment()
        .expect("generated protocol pin")
        .to_lower_hex()
}

fn frame_with(
    schema: &str,
    manifest: &str,
    versions: &str,
    required: &str,
    optional: &str,
    challenge: &str,
) -> Vec<u8> {
    format!(
        "{{\"schemaVersion\":\"{schema}\",\"publicProtocolManifestSha256\":\"{manifest}\",\"versions\":{versions},\"requiredCapabilities\":{required},\"optionalCapabilities\":{optional},\"clientChallengeHex\":\"{challenge}\"}}"
    )
    .into_bytes()
}

fn valid_frame() -> Vec<u8> {
    frame_with(
        CLIENT_HELLO_SCHEMA_V1,
        &manifest_hex(),
        "[{\"major\":1,\"minor\":0}]",
        "[\"read-status\"]",
        "[\"workspace-events\",\"job-progress\"]",
        &digest(100).to_lower_hex(),
    )
}

fn installation() -> InstallationIdentity {
    InstallationIdentity {
        id: InstallationId::new(digest(1)),
        generation: 1,
        identity_commitment: digest(2),
    }
}

fn endpoint(installation: &InstallationIdentity) -> EndpointIdentity {
    EndpointIdentity {
        id: EndpointId::new(digest(3)),
        installation_id: installation.id,
        installation_generation: installation.generation,
        endpoint_generation: 1,
        os_locality: ExternalVerdict::Verified,
        restrictive_access: ExternalVerdict::Verified,
        adapter_facts_commitment: digest(4),
    }
}

fn integration(installation: &InstallationIdentity) -> IntegrationIdentity {
    IntegrationIdentity {
        id: IntegrationId::new(digest(5)),
        installation_id: installation.id,
        manifest_commitment: digest(6),
        registration_generation: 1,
        external_registration: ExternalVerdict::Verified,
    }
}

fn agent_offer() -> NegotiationOffer {
    NegotiationOffer {
        versions: vec![ProtocolVersion::new(1, 0)],
        required_capabilities: vec![Capability::ReadStatus],
        optional_capabilities: vec![Capability::JobProgress, Capability::WorkspaceEvents],
        public_protocol_manifest: public_protocol_manifest_commitment()
            .expect("generated protocol pin"),
    }
}

fn verification(
    installation: &InstallationIdentity,
    endpoint: &EndpointIdentity,
    integration: &IntegrationIdentity,
    session: u64,
    raw: &RawFrame<'_>,
) -> HandshakeVerificationFacts {
    HandshakeVerificationFacts {
        session_id: SessionId::new(digest(session)),
        installation: installation.clone(),
        endpoint: endpoint.clone(),
        integration: integration.clone(),
        agent_challenge: *digest(101).as_bytes(),
        verifier_key_generation: 1,
        issued_at_ms: 1_000,
        expires_at_ms: 1_000 + SESSION_TTL_MAXIMUM_MS,
        challenge_response: ExternalVerdict::Verified,
        transcript_signature: ExternalVerdict::Verified,
        anti_downgrade: ExternalVerdict::Verified,
        verified_client_frame_commitment: raw.commitment().expect("bounded frame"),
        crypto_adapter_commitment: digest(102),
    }
}

#[test]
fn client_hello_semantics_are_order_independent_while_raw_bytes_remain_bound() {
    let first = valid_frame();
    let reordered = format!(
        " {{ \"clientChallengeHex\" : \"{}\", \"optionalCapabilities\" : [\"workspace-events\",\"job-progress\"], \"requiredCapabilities\" : [\"read-status\"], \"versions\" : [{{\"minor\":0,\"major\":1}}], \"publicProtocolManifestSha256\" : \"{}\", \"schemaVersion\" : \"{}\" }} ",
        digest(100).to_lower_hex(),
        manifest_hex(),
        CLIENT_HELLO_SCHEMA_V1,
    )
    .into_bytes();

    let decoded_first =
        decode_client_hello(&RawFrame::new(&first), &NeverCancel).expect("first frame");
    let decoded_reordered =
        decode_client_hello(&RawFrame::new(&reordered), &NeverCancel).expect("reordered frame");
    assert_eq!(decoded_first.offer(), decoded_reordered.offer());
    assert_eq!(
        decoded_first.semantic_commitment(),
        decoded_reordered.semantic_commitment()
    );
    assert_ne!(
        decoded_first.raw_frame_commitment(),
        decoded_reordered.raw_frame_commitment()
    );
    assert_eq!(
        decode_client_hello(
            &RawFrame::new(&first),
            &CancelAt(CancellationPoint::Preflight),
        )
        .expect_err("preflight cancellation")
        .code(),
        ErrorCode::Cancelled
    );
    assert_eq!(
        decode_client_hello(
            &RawFrame::new(&first),
            &CancelAt(CancellationPoint::BeforeCommit),
        )
        .expect_err("final cancellation")
        .code(),
        ErrorCode::Cancelled
    );
}

#[test]
fn client_hello_rejects_closed_shape_schema_baseline_and_collection_attacks() {
    let manifest = manifest_hex();
    let challenge = digest(100).to_lower_hex();
    let cases: Vec<(&str, Vec<u8>, ErrorCode)> = vec![
        ("empty", b"{}".to_vec(), ErrorCode::FrameInvalid),
        ("invalid UTF-8", vec![0xff], ErrorCode::FrameInvalid),
        (
            "unknown field",
            format!(
                "{{\"unknown\":0,{}",
                std::str::from_utf8(&valid_frame()).expect("UTF-8 frame")[1..].to_owned()
            )
            .into_bytes(),
            ErrorCode::FrameInvalid,
        ),
        (
            "duplicate field",
            format!(
                "{{\"schemaVersion\":\"{CLIENT_HELLO_SCHEMA_V1}\",{}",
                std::str::from_utf8(&valid_frame()).expect("UTF-8 frame")[1..].to_owned()
            )
            .into_bytes(),
            ErrorCode::FrameInvalid,
        ),
        (
            "trailing token",
            [valid_frame(), b"x".to_vec()].concat(),
            ErrorCode::FrameInvalid,
        ),
        (
            "wrong schema",
            frame_with(
                "ogvcs.local-agent/client-hello/v2",
                &manifest,
                "[{\"major\":1,\"minor\":0}]",
                "[\"read-status\"]",
                "[]",
                &challenge,
            ),
            ErrorCode::UnsupportedVersion,
        ),
        (
            "uppercase manifest",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest.to_uppercase(),
                "[{\"major\":1,\"minor\":0}]",
                "[\"read-status\"]",
                "[]",
                &challenge,
            ),
            ErrorCode::FrameInvalid,
        ),
        (
            "other baseline",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &digest(999).to_lower_hex(),
                "[{\"major\":1,\"minor\":0}]",
                "[\"read-status\"]",
                "[]",
                &challenge,
            ),
            ErrorCode::BaselineMismatch,
        ),
        (
            "zero challenge",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":1,\"minor\":0}]",
                "[\"read-status\"]",
                "[]",
                &"0".repeat(64),
            ),
            ErrorCode::InvalidFact,
        ),
        (
            "zero major",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":0,\"minor\":0}]",
                "[\"read-status\"]",
                "[]",
                &challenge,
            ),
            ErrorCode::InvalidFact,
        ),
        (
            "duplicate version",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":1,\"minor\":0},{\"major\":1,\"minor\":0}]",
                "[\"read-status\"]",
                "[]",
                &challenge,
            ),
            ErrorCode::InvalidFact,
        ),
        (
            "duplicate capability",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":1,\"minor\":0}]",
                "[\"read-status\",\"read-status\"]",
                "[]",
                &challenge,
            ),
            ErrorCode::InvalidFact,
        ),
        (
            "cross-list capability",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":1,\"minor\":0}]",
                "[\"read-status\"]",
                "[\"read-status\"]",
                &challenge,
            ),
            ErrorCode::InvalidFact,
        ),
        (
            "unknown capability",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":1,\"minor\":0}]",
                "[\"read-status\"]",
                "[\"unregistered\"]",
                &challenge,
            ),
            ErrorCode::FrameInvalid,
        ),
        (
            "numeric overflow",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":65536,\"minor\":0}]",
                "[\"read-status\"]",
                "[]",
                &challenge,
            ),
            ErrorCode::FrameInvalid,
        ),
        (
            "duplicate version member",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":1,\"major\":1,\"minor\":0}]",
                "[\"read-status\"]",
                "[]",
                &challenge,
            ),
            ErrorCode::FrameInvalid,
        ),
        (
            "capability maximum plus one",
            frame_with(
                CLIENT_HELLO_SCHEMA_V1,
                &manifest,
                "[{\"major\":1,\"minor\":0}]",
                &format!(
                    "[{}]",
                    vec!["\"read-status\""; CAPABILITY_ITEMS_MAXIMUM + 1].join(",")
                ),
                "[]",
                &challenge,
            ),
            ErrorCode::ItemLimit,
        ),
    ];

    for (label, frame, expected) in cases {
        assert_eq!(
            decode_client_hello(&RawFrame::new(&frame), &NeverCancel)
                .expect_err(label)
                .code(),
            expected,
            "{label}"
        );
    }
}

#[test]
fn session_establishment_requires_the_exact_adapter_verified_client_frame() {
    let installation = installation();
    let endpoint = endpoint(&installation);
    let integration = integration(&installation);
    let first = valid_frame();
    let first_raw = RawFrame::new(&first);
    let mut alternate = first.clone();
    alternate.push(b' ');
    let alternate_raw = RawFrame::new(&alternate);
    let mut ledger = LocalAgentLedger::new(
        installation.clone(),
        endpoint.clone(),
        1,
        agent_offer(),
        1_000,
        &RawFrame::new(b"client-hello-ledger"),
        &NeverCancel,
    )
    .expect("ledger");
    let before = ledger.snapshot();

    assert_eq!(
        ledger
            .establish_session(
                verification(&installation, &endpoint, &integration, 7, &first_raw),
                1_000,
                &alternate_raw,
                &NeverCancel,
            )
            .expect_err("adapter facts name another raw frame")
            .code(),
        ErrorCode::TranscriptUnverified
    );
    assert_eq!(ledger.snapshot(), before);

    let receipt = ledger
        .establish_session(
            verification(&installation, &endpoint, &integration, 7, &alternate_raw),
            1_000,
            &alternate_raw,
            &NeverCancel,
        )
        .expect("exact verified frame");
    assert_eq!(receipt.selection.version, ProtocolVersion::new(1, 0));
    assert_eq!(
        receipt.selection.raw_frame_commitment,
        alternate_raw.commitment().unwrap()
    );
}
