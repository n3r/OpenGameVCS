// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.
use std::collections::BTreeSet;
use opengamevcs_protocol_v1::{capability_axes_fields, CapabilityAxes, CONTRACT_MANIFEST_SHA256, FIELD_DESCRIPTORS, MESSAGE_DESCRIPTORS};

#[test]
fn generated_types_and_assignments_are_usable() {
    let axes = CapabilityAxes {
        protocol_versions: vec!["ogvcs.control.https-json@1".into()],
        schema_versions: vec!["ogvcs.protocol.schema@1".into()],
        repository_formats: vec!["ogvcs.repository-format@1".into()],
        authorization_contracts: vec!["ogvcs.authorization@1".into()],
        path_contracts: vec!["ogvcs.path-filesystem@1".into()],
        path_profiles: vec!["path.opengamevcs/portable@1".into()],
        event_versions: vec!["ogvcs.events.base@1".into()],
        transfer_profiles: vec!["ogvcs.transfer.range-resume-probe@1".into()],
        extensions: vec![],
        required_capabilities: vec![],
    };
    assert_eq!(axes.protocol_versions.len(), 1);
    assert_eq!(capability_axes_fields::PROTOCOL_VERSIONS, 1);
    assert_eq!(CONTRACT_MANIFEST_SHA256.len(), 64);
    assert_eq!(MESSAGE_DESCRIPTORS.iter().map(|entry| entry.field_count).sum::<usize>(), FIELD_DESCRIPTORS.len());
    let mut seen = BTreeSet::new();
    for field in FIELD_DESCRIPTORS {
        let message = MESSAGE_DESCRIPTORS.iter().find(|entry| entry.code == field.message_code).expect("field message descriptor");
        assert_eq!(message.name, field.message_name);
        assert!(seen.insert((field.message_code, field.number)));
        assert_eq!(field.required, field.presence == "required");
        assert_eq!(field.reference.is_some(), field.normalized_type.contains("reference"));
    }
}
