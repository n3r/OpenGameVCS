use ogvcs_object_model::{
    decode_canonical, encode_canonical, hash_chunk, scan_metadata, scan_metadata_with_hard_limits,
    validate_metadata_schema, Error, ErrorCode, HardLimitCeilings, Limits, LogicalBundleBudget,
    LogicalBundleWriteLimits, LogicalBundleWriteOptions, LogicalBundleWritePlan,
    LogicalBundleWriter, Registry,
};

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{VECTOR_ROOT}/{relative}")).unwrap()
}

fn reduced(name: &'static str, maximum: u64) -> HardLimitCeilings {
    HardLimitCeilings::HARD.with_limit(name, maximum).unwrap()
}

fn schema_error(path: &str, name: &'static str, maximum: u64) -> Error {
    let object = scan_metadata(&read(path), Limits::METADATA)
        .unwrap()
        .constrained_by(reduced(name, maximum));
    match validate_metadata_schema(&object) {
        Ok(kind) => panic!("{name} reduced ceiling accepted by {kind:?}"),
        Err(error) => error,
    }
}

#[test]
fn reduced_framing_ceilings_stop_before_schema_or_allocation() {
    let descriptor = read("objects/06-repository-descriptor.cbor");
    for (name, maximum, code) in [
        (
            "metadata-payload-bytes",
            descriptor.len() as u64 - 1,
            ErrorCode::LimitMetadataBytes,
        ),
        (
            "generic-text-or-byte-value-bytes",
            0,
            ErrorCode::LimitValueBytes,
        ),
        ("cbor-nesting-depth", 0, ErrorCode::LimitNesting),
    ] {
        let error =
            scan_metadata_with_hard_limits(&descriptor, Limits::METADATA, reduced(name, maximum))
                .unwrap_err();
        assert_eq!((error.code, error.layer), (code, 1), "{name}");
    }

    let mut value = decode_canonical(&descriptor, Limits::METADATA).unwrap();
    let ogvcs_object_model::Cbor::Map(fields) = &mut value else {
        unreachable!()
    };
    fields.push((
        ogvcs_object_model::Cbor::UInt(3),
        ogvcs_object_model::Cbor::Map(vec![(
            ogvcs_object_model::Cbor::Text("extension.test/example@1".into()),
            ogvcs_object_model::Cbor::Bool(true),
        )]),
    ));
    let with_extension = encode_canonical(&value).unwrap();
    for (name, code) in [
        ("extensions-per-object", ErrorCode::LimitCount),
        (
            "extension-aggregate-bytes-per-object",
            ErrorCode::LimitExtensionBytes,
        ),
    ] {
        let error =
            scan_metadata_with_hard_limits(&with_extension, Limits::METADATA, reduced(name, 0))
                .unwrap_err();
        assert_eq!((error.code, error.layer), (code, 1), "{name}");
    }

    let error = hash_chunk(b"x", 0).unwrap_err();
    assert_eq!((error.code, error.layer), (ErrorCode::LimitChunkBytes, 1));
}

#[test]
fn reduced_known_schema_ceilings_cover_every_semantic_family() {
    let cases = [
        (
            "objects/02-content-manifest.cbor",
            "manifest-chunks",
            ErrorCode::LimitCount,
        ),
        (
            "objects/02-content-manifest.cbor",
            "chunk-payload-bytes",
            ErrorCode::ManifestChunkLengthInvalid,
        ),
        (
            "objects/02-content-manifest.cbor",
            "logical-file-bytes",
            ErrorCode::LimitLogicalBytes,
        ),
        (
            "objects/03-tree.cbor",
            "tree-entries",
            ErrorCode::LimitCount,
        ),
        (
            "scenarios/objects/transition-exact-result-mismatch/candidate-change.cbor",
            "change-set-operations",
            ErrorCode::LimitCount,
        ),
        (
            "scenarios/objects/transition-exact-result-mismatch/candidate-change.cbor",
            "path-segment-bytes",
            ErrorCode::PathCoreInvalid,
        ),
        (
            "scenarios/objects/transition-exact-result-mismatch/candidate-change.cbor",
            "path-segments",
            ErrorCode::PathCoreInvalid,
        ),
        (
            "scenarios/objects/transition-exact-result-mismatch/candidate-change.cbor",
            "path-bytes",
            ErrorCode::PathCoreInvalid,
        ),
        (
            "objects/05-asset-group-set.cbor",
            "asset-groups",
            ErrorCode::LimitCount,
        ),
        (
            "objects/05-asset-group-set.cbor",
            "asset-group-members",
            ErrorCode::LimitCount,
        ),
        (
            "scenarios/objects/history-one-parent/candidate.cbor",
            "snapshot-parents",
            ErrorCode::SnapshotParentCountInvalid,
        ),
        (
            "scenarios/objects/history-one-parent/candidate.cbor",
            "snapshot-message-bytes",
            ErrorCode::LimitValueBytes,
        ),
    ];
    for (path, name, code) in cases {
        let error = schema_error(path, name, 0);
        assert_eq!((error.code, error.layer), (code, 2), "{name}");
    }
}

fn writer_preflight_error(
    plan: LogicalBundleWritePlan,
    limits: LogicalBundleWriteLimits,
) -> (Error, Vec<u8>) {
    let registry = Registry::bundled();
    let mut output = Vec::new();
    let error = match LogicalBundleWriter::new(
        &mut output,
        plan,
        LogicalBundleWriteOptions {
            registry: &registry,
            limits,
            ..LogicalBundleWriteOptions::new(&registry)
        },
    ) {
        Ok(_) => panic!("reduced bundle ceiling accepted"),
        Err(error) => error,
    };
    (error, output)
}

#[test]
fn all_eight_bundle_families_fail_in_writer_preflight_without_partial_output() {
    let base = LogicalBundleWritePlan {
        object_count: 0,
        logical_record_count: 0,
        root_count: 0,
        budget: LogicalBundleBudget {
            sequence_bytes: 1_024,
            largest_item_bytes: 512,
            traversal_edges: 0,
            index_entries: 0,
        },
    };
    for (name, plan, limits) in [
        (
            "bundle-objects",
            LogicalBundleWritePlan {
                object_count: 1,
                budget: LogicalBundleBudget {
                    index_entries: 1,
                    ..base.budget
                },
                ..base
            },
            LogicalBundleWriteLimits {
                objects: 0,
                ..LogicalBundleWriteLimits::HARD
            },
        ),
        (
            "bundle-logical-records",
            LogicalBundleWritePlan {
                logical_record_count: 1,
                budget: LogicalBundleBudget {
                    index_entries: 1,
                    ..base.budget
                },
                ..base
            },
            LogicalBundleWriteLimits {
                logical_records: 0,
                ..LogicalBundleWriteLimits::HARD
            },
        ),
        (
            "bundle-roots",
            LogicalBundleWritePlan {
                root_count: 1,
                ..base
            },
            LogicalBundleWriteLimits {
                roots: 0,
                ..LogicalBundleWriteLimits::HARD
            },
        ),
        (
            "bundle-total-items",
            base,
            LogicalBundleWriteLimits {
                items: 1,
                ..LogicalBundleWriteLimits::HARD
            },
        ),
        (
            "bundle-sequence-bytes",
            base,
            LogicalBundleWriteLimits {
                sequence_bytes: base.budget.sequence_bytes - 1,
                ..LogicalBundleWriteLimits::HARD
            },
        ),
        (
            "bundle-largest-item-bytes",
            base,
            LogicalBundleWriteLimits {
                item_bytes: base.budget.largest_item_bytes - 1,
                ..LogicalBundleWriteLimits::HARD
            },
        ),
        (
            "bundle-traversal-edges",
            LogicalBundleWritePlan {
                budget: LogicalBundleBudget {
                    traversal_edges: 1,
                    ..base.budget
                },
                ..base
            },
            LogicalBundleWriteLimits {
                traversal_edges: 0,
                ..LogicalBundleWriteLimits::HARD
            },
        ),
        (
            "bundle-index-entries",
            LogicalBundleWritePlan {
                budget: LogicalBundleBudget {
                    index_entries: 1,
                    ..base.budget
                },
                ..base
            },
            LogicalBundleWriteLimits {
                index_entries: 0,
                ..LogicalBundleWriteLimits::HARD
            },
        ),
    ] {
        let (error, output) = writer_preflight_error(plan, limits);
        assert_eq!(
            (error.code, error.layer),
            (ErrorCode::BundleBudgetExceeded, 1),
            "{name}"
        );
        assert!(output.is_empty(), "{name} wrote trusted bytes");
    }
}
