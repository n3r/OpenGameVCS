#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationPhase {
    Expand,
    Migrate,
    Contract,
}

impl MigrationPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Expand => "expand",
            Self::Migrate => "migrate",
            Self::Contract => "contract",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Migration {
    pub version: u64,
    pub phase: MigrationPhase,
    pub sql: &'static str,
    pub checksum_sha256: &'static str,
    pub restartable: bool,
    pub minimum_application_version: &'static str,
    pub maximum_application_version: &'static str,
    pub requires_compatibility_fence: bool,
}

pub const MIGRATIONS: [Migration; 6] = [
    Migration {
        version: 1,
        phase: MigrationPhase::Expand,
        sql: include_str!("../../../migrations/identity-policy-audit/000001_expand.sql"),
        checksum_sha256: "f31def32f2dc2a5da085187e345fa91ca0defe1035426c17fdeba719bd1df583",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: false,
    },
    Migration {
        version: 1,
        phase: MigrationPhase::Migrate,
        sql: include_str!("../../../migrations/identity-policy-audit/000001_migrate.sql"),
        checksum_sha256: "f1c122423a5e6dfddefc1918cc0f40b6dd10f05d0bdea1e5004b54758c5d0390",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: false,
    },
    Migration {
        version: 1,
        phase: MigrationPhase::Contract,
        sql: include_str!("../../../migrations/identity-policy-audit/000001_contract.sql"),
        checksum_sha256: "3b1c5d5e8254e7f4ebd3cafb74935e742796f871336f9fd677af6ead898b29c6",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: true,
    },
    Migration {
        version: 2,
        phase: MigrationPhase::Expand,
        sql: include_str!("../../../migrations/identity-policy-audit/000002_expand.sql"),
        checksum_sha256: "72e4a67a92de318f309e908e6b500b18ff74fa0ec8a13c010b8e19e3a77eec29",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: false,
    },
    Migration {
        version: 2,
        phase: MigrationPhase::Migrate,
        sql: include_str!("../../../migrations/identity-policy-audit/000002_migrate.sql"),
        checksum_sha256: "f7b8ceb2eebaa9efed250e9781c184a0d46aa3b1b796566552f25d804853f826",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: false,
    },
    Migration {
        version: 2,
        phase: MigrationPhase::Contract,
        sql: include_str!("../../../migrations/identity-policy-audit/000002_contract.sql"),
        checksum_sha256: "7705488d488bff2b6b8dd2355010c3b929bec2a8bd9f38bb071ec2cdf386555b",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: true,
    },
];
