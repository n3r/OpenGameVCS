use crate::{Error, ErrorCode, Result};

/// Validates the only claim carried by a format-v1 logical bundle.
///
/// Fidelity, projection, and export labels belong to later profiles and are
/// forbidden at this boundary.
pub fn validate_bundle_claim(claim: &str) -> Result<&'static str> {
    if claim.is_empty() {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    if claim != "supplied-closure" {
        return Err(Error::new(ErrorCode::BundleExportClaimForbidden));
    }
    Ok("supplied-closure")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplied_closure_is_the_only_claim() {
        assert_eq!(
            validate_bundle_claim("supplied-closure").unwrap(),
            "supplied-closure"
        );
        assert_eq!(
            validate_bundle_claim("fidelity-export").unwrap_err().code,
            ErrorCode::BundleExportClaimForbidden
        );
        assert_eq!(
            validate_bundle_claim("").unwrap_err().code,
            ErrorCode::SchemaFieldInvalid
        );
    }
}
