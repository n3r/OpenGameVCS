use std::{
    fmt::Write as _,
    sync::{atomic::AtomicBool, Arc},
};

use ogvcs_history_diff_kernel::{
    merge_text_three_way, OperationControl, TextMergeAlgorithm, TextMergeConflictKind,
    TextMergeErrorKind, TextMergeInput, TextMergeInputErrorKind, TextMergeLimitKind,
    TextMergeOptions, TextMergeOutcome, TextMergeRequest, TextMergeSide,
    TEXT_MERGE_CONFLICTS_MAXIMUM, TEXT_MERGE_INPUT_BYTES_MAXIMUM, TEXT_MERGE_LCS_CELLS_MAXIMUM,
    TEXT_MERGE_LINES_PER_INPUT_MAXIMUM, TEXT_MERGE_LINE_BYTES_MAXIMUM,
};
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn request<'a>(base: &'a [u8], ours: &'a [u8], theirs: &'a [u8]) -> TextMergeRequest<'a> {
    TextMergeRequest {
        algorithm: TextMergeAlgorithm::LineDiff3V1,
        options: TextMergeOptions::default(),
        base: TextMergeInput {
            bytes: base,
            digest: digest(base),
        },
        ours: TextMergeInput {
            bytes: ours,
            digest: digest(ours),
        },
        theirs: TextMergeInput {
            bytes: theirs,
            digest: digest(theirs),
        },
    }
}

fn merge(base: &[u8], ours: &[u8], theirs: &[u8]) -> TextMergeOutcome {
    merge_text_three_way(request(base, ours, theirs), &OperationControl::default()).unwrap()
}

fn clean_output(outcome: TextMergeOutcome) -> Box<[u8]> {
    match outcome {
        TextMergeOutcome::Clean(clean) => clean.output().into(),
        TextMergeOutcome::Conflict(conflict) => {
            panic!("unexpected {}-span conflict", conflict.conflicts().len())
        }
    }
}

fn divergent_conflicts(count: usize) -> (String, String, String) {
    let mut base = String::new();
    let mut ours = String::new();
    let mut theirs = String::new();
    for index in 0..count {
        writeln!(&mut base, "base-{index:03}").unwrap();
        writeln!(&mut ours, "ours-{index:03}").unwrap();
        writeln!(&mut theirs, "theirs-{index:03}").unwrap();
        for value in [&mut base, &mut ours, &mut theirs] {
            writeln!(value, "common-{index:03}").unwrap();
        }
    }
    (base, ours, theirs)
}

#[test]
fn unchanged_side_and_identical_side_shortcuts_preserve_exact_bytes() {
    assert_eq!(
        &*clean_output(merge(b"base\n", b"base\n", b"theirs\n")),
        b"theirs\n"
    );
    assert_eq!(
        &*clean_output(merge(b"base\n", b"ours", b"base\n")),
        b"ours"
    );
    assert_eq!(
        &*clean_output(merge(b"base\n", b"same\n", b"same\n")),
        b"same\n"
    );
}

#[test]
fn adjacent_edits_unicode_and_final_newline_state_merge_cleanly() {
    let base = "alpha\nβeta\ngamma\ndelta\n".as_bytes();
    let ours = "ALPHA\nβeta\ngamma\ndelta\n".as_bytes();
    let theirs = "alpha\nΒETA\ngamma\ndelta\n".as_bytes();
    assert_eq!(
        &*clean_output(merge(base, ours, theirs)),
        "ALPHA\nΒETA\ngamma\ndelta\n".as_bytes()
    );

    assert_eq!(
        &*clean_output(merge(b"one\ntwo\n", b"one\ntwo", b"ONE\ntwo\n")),
        b"ONE\ntwo"
    );
}

#[test]
fn identical_overlap_is_applied_once_alongside_disjoint_edits() {
    let base = b"a\nb\nc\nd\n";
    let ours = b"A\nB\nc\nd\n";
    let theirs = b"a\nB\nc\nD\n";
    assert_eq!(&*clean_output(merge(base, ours, theirs)), b"A\nB\nc\nD\n");

    let base = b"a\nb\nc\n";
    let ours = b"A\nsame\nb\nc\n";
    let theirs = b"a\nsame\nb\nC\n";
    assert_eq!(
        &*clean_output(merge(base, ours, theirs)),
        b"A\nsame\nb\nC\n"
    );
}

#[test]
fn same_boundary_insertions_and_delete_modify_return_only_typed_commitments() {
    let insertion = merge(b"a\nb\n", b"a\nours\nb\n", b"a\ntheirs\nb\n");
    let TextMergeOutcome::Conflict(insertion) = insertion else {
        panic!("divergent insertions unexpectedly merged")
    };
    assert_eq!(insertion.conflicts().len(), 1);
    let span = &insertion.conflicts()[0];
    assert_eq!(span.kind(), TextMergeConflictKind::ConcurrentInsertion);
    assert_eq!((span.base_start_line(), span.base_end_line()), (1, 1));
    assert_eq!(span.base().byte_count(), 0);
    assert_eq!(span.ours().byte_count(), 5);
    assert_eq!(span.theirs().byte_count(), 7);
    assert_ne!(span.ours().digest(), span.theirs().digest());

    let delete_modify = merge(b"a\nb\nc\n", b"a\nc\n", b"a\nB\nc\n");
    let TextMergeOutcome::Conflict(delete_modify) = delete_modify else {
        panic!("delete/modify unexpectedly merged")
    };
    assert_eq!(delete_modify.conflicts().len(), 1);
    assert_eq!(
        delete_modify.conflicts()[0].kind(),
        TextMergeConflictKind::DeleteModify
    );
}

#[test]
fn input_digest_text_profile_and_cancellation_fail_closed() {
    let mut substituted = request(b"base\n", b"ours\n", b"theirs\n");
    substituted.ours.digest = digest(b"other\n");
    let error = merge_text_three_way(substituted, &OperationControl::default()).unwrap_err();
    assert_eq!(
        error.kind,
        TextMergeErrorKind::InvalidInput(TextMergeInputErrorKind::DigestMismatch)
    );
    assert_eq!(error.side, Some(TextMergeSide::Ours));

    for (bytes, expected) in [
        (&b"nul\0byte\n"[..], TextMergeInputErrorKind::BinaryControl),
        (
            &b"unicode-control\xc2\x85"[..],
            TextMergeInputErrorKind::BinaryControl,
        ),
        (
            &b"windows\r\n"[..],
            TextMergeInputErrorKind::CarriageReturnForbidden,
        ),
        (
            &b"bare\rreturn"[..],
            TextMergeInputErrorKind::CarriageReturnForbidden,
        ),
        (&b"bad\xff"[..], TextMergeInputErrorKind::InvalidUtf8),
    ] {
        let error = merge_text_three_way(
            request(bytes, b"ours\n", b"theirs\n"),
            &OperationControl::default(),
        )
        .unwrap_err();
        assert_eq!(error.kind, TextMergeErrorKind::InvalidInput(expected));
        assert_eq!(error.side, Some(TextMergeSide::Base));
    }

    let cancellation = Arc::new(AtomicBool::new(true));
    let control = OperationControl::with_cancellation(cancellation);
    assert_eq!(
        merge_text_three_way(request(b"a\n", b"b\n", b"c\n"), &control)
            .unwrap_err()
            .kind,
        TextMergeErrorKind::Cancelled
    );
}

#[test]
fn literal_input_line_lcs_and_conflict_bounds_accept_maximum_and_reject_next() {
    let at_max = format!("{}\n", "x".repeat(65_535)).repeat(16).into_bytes();
    assert_eq!(
        u64::try_from(at_max.len()).unwrap(),
        TEXT_MERGE_INPUT_BYTES_MAXIMUM
    );
    assert_eq!(
        &*clean_output(merge(&at_max, &at_max, b"replacement\n")),
        b"replacement\n"
    );
    let above_max = vec![b'x'; at_max.len() + 1];
    let error = merge_text_three_way(
        request(&above_max, b"ours\n", b"theirs\n"),
        &OperationControl::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        TextMergeErrorKind::Limit(TextMergeLimitKind::InputBytes)
    );
    assert_eq!(error.side, Some(TextMergeSide::Base));

    let line_at_max = vec![b'x'; usize::try_from(TEXT_MERGE_LINE_BYTES_MAXIMUM).unwrap()];
    assert_eq!(
        &*clean_output(merge(&line_at_max, &line_at_max, b"replacement\n")),
        b"replacement\n"
    );
    let line_above_max = vec![b'x'; line_at_max.len() + 1];
    let error = merge_text_three_way(
        request(&line_above_max, b"ours\n", b"theirs\n"),
        &OperationControl::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        TextMergeErrorKind::Limit(TextMergeLimitKind::LineBytes)
    );

    let maximum_lines = "x\n".repeat(usize::try_from(TEXT_MERGE_LINES_PER_INPUT_MAXIMUM).unwrap());
    assert!(matches!(
        merge(
            maximum_lines.as_bytes(),
            maximum_lines.as_bytes(),
            b"different\n"
        ),
        TextMergeOutcome::Clean(_)
    ));
    let above_lines = format!("{maximum_lines}x\n");
    let error = merge_text_three_way(
        request(above_lines.as_bytes(), b"ours\n", b"theirs\n"),
        &OperationControl::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        TextMergeErrorKind::Limit(TextMergeLimitKind::Lines)
    );

    let mut base = String::new();
    for index in 0..512 {
        writeln!(&mut base, "b{index:04}").unwrap();
    }
    let mut ours_lines = base.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut theirs_lines = ours_lines.clone();
    ours_lines[0] = "ours".to_owned();
    theirs_lines[511] = "theirs".to_owned();
    let ours = format!("{}\n", ours_lines.join("\n"));
    let theirs = format!("{}\n", theirs_lines.join("\n"));
    let outcome = merge(base.as_bytes(), ours.as_bytes(), theirs.as_bytes());
    let TextMergeOutcome::Clean(clean) = outcome else {
        panic!("boundary case conflicted")
    };
    assert_eq!(clean.ledger().lcs_cells, TEXT_MERGE_LCS_CELLS_MAXIMUM * 2);

    let base_above = format!("{base}extra\n");
    let error = merge_text_three_way(
        request(base_above.as_bytes(), ours.as_bytes(), theirs.as_bytes()),
        &OperationControl::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        TextMergeErrorKind::Limit(TextMergeLimitKind::LcsCells)
    );

    let (base, ours, theirs) =
        divergent_conflicts(usize::try_from(TEXT_MERGE_CONFLICTS_MAXIMUM).unwrap());
    let TextMergeOutcome::Conflict(conflicted) =
        merge(base.as_bytes(), ours.as_bytes(), theirs.as_bytes())
    else {
        panic!("exact conflict maximum unexpectedly merged")
    };
    assert_eq!(
        u64::try_from(conflicted.conflicts().len()).unwrap(),
        TEXT_MERGE_CONFLICTS_MAXIMUM
    );
    let (base, ours, theirs) =
        divergent_conflicts(usize::try_from(TEXT_MERGE_CONFLICTS_MAXIMUM).unwrap() + 1);
    let error = merge_text_three_way(
        request(base.as_bytes(), ours.as_bytes(), theirs.as_bytes()),
        &OperationControl::default(),
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        TextMergeErrorKind::Limit(TextMergeLimitKind::Conflicts)
    );
}

#[test]
fn replay_is_byte_and_commitment_deterministic_and_inputs_are_bound() {
    for seed in 0u32..64 {
        let base = format!("seed-{seed}\ncommon\ntail\n");
        let ours = format!("seed-{seed}\nours-{seed}\ntail\n");
        let theirs = format!("seed-{seed}\ncommon\ntheirs-{seed}\n");
        let first = merge(base.as_bytes(), ours.as_bytes(), theirs.as_bytes());
        let second = merge(base.as_bytes(), ours.as_bytes(), theirs.as_bytes());
        assert_eq!(first, second, "seed {seed}");
    }

    let first = merge(b"base\n", b"ours\n", b"theirs\n");
    let changed = merge(b"base\n", b"ours!\n", b"theirs\n");
    let (TextMergeOutcome::Conflict(first), TextMergeOutcome::Conflict(changed)) = (first, changed)
    else {
        panic!("expected conflicts")
    };
    assert_ne!(first.request_commitment(), changed.request_commitment());
    assert_ne!(first.conflict_commitment(), changed.conflict_commitment());
}
