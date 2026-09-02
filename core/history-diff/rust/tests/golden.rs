mod support;

use ogvcs_history_diff_kernel::{
    diff_page, DiffRequest, Limits, MoveHint, OperationControl, PresenceChange,
};
use ogvcs_path_contract::CaseMode;
use serde_json::{json, Value};
use support::{file_id, EntrySpec, Store};

const GOLDEN: &str = include_str!("golden.json");

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

#[test]
fn independent_golden_table_matches_order_and_all_projection_fields() {
    let authority: Value = serde_json::from_str(GOLDEN).unwrap();
    assert_eq!(
        authority["schemaVersion"],
        "ogvcs.history-diff/private-golden/v1"
    );
    let mut store = Store::new();
    let old = store.manifest(1, 10);
    let new = store.manifest(2, 20);
    let before_tree = store.tree(vec![
        EntrySpec::file("deleted.bin", file_id(3), old, 10),
        EntrySpec::file("old.txt", file_id(2), old, 10),
    ]);
    let after_tree = store.tree(vec![
        EntrySpec::file("added.bin", file_id(1), old, 10),
        EntrySpec::file("new.txt", file_id(2), new, 20),
    ]);
    let before = store.snapshot(1, vec![], before_tree);
    let after = store.snapshot(2, vec![], after_tree);
    let records = diff_page(
        &mut store.source(),
        DiffRequest {
            before_snapshot: before,
            after_snapshot: after,
            repository_descriptor: store.descriptor,
            case_mode: CaseMode::Sensitive,
        },
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap()
    .records;
    let actual = records
        .iter()
        .map(|record| {
            json!({
                "fileId": hex(record.file_id.as_bytes()),
                "presence": match record.presence {
                    PresenceChange::Added => "added",
                    PresenceChange::Deleted => "deleted",
                    PresenceChange::Retained => "retained",
                },
                "changes": record.changes.bits(),
                "moveHint": match record.move_hint {
                    MoveHint::None => "none",
                    MoveHint::Rename => "rename",
                    MoveHint::Move => "move",
                },
                "beforePath": record.before.as_ref().map(|entry| entry.path.as_str()),
                "afterPath": record.after.as_ref().map(|entry| entry.path.as_str()),
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(Value::Array(actual), authority["cases"]);
}
