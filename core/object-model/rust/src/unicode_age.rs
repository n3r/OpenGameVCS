use crate::unicode_age_table::UNICODE_15_INTERVALS;

/// Returns whether every scalar in `value` belongs to the Unicode 15.0 Age
/// repertoire frozen by repository-format-v1. Rust strings are already scalar
/// UTF-8, so this only needs the generated assigned-scalar lookup.
pub(crate) fn is_unicode_15(value: &str) -> bool {
    value.chars().all(|scalar| {
        let code = scalar as u32;
        UNICODE_15_INTERVALS
            .binary_search_by(|(start, end)| {
                if code < *start {
                    core::cmp::Ordering::Greater
                } else if code > *end {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Equal
                }
            })
            .is_ok()
    })
}
