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

pub const MIGRATIONS: [Migration; 3] = [
    Migration {
        version: 1,
        phase: MigrationPhase::Expand,
        sql: include_str!("../../../migrations/identity-policy-audit/000001_expand.sql"),
        checksum_sha256: "f84c690f2d173724af6bccfa248f656f97676e6236bc4aaa2f53f353cb19a378",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: false,
    },
    Migration {
        version: 1,
        phase: MigrationPhase::Migrate,
        sql: include_str!("../../../migrations/identity-policy-audit/000001_migrate.sql"),
        checksum_sha256: "7d00d5be1a2c9ce349656b372e9990ee31e94f731541aeaa3d13f66474c02451",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: false,
    },
    Migration {
        version: 1,
        phase: MigrationPhase::Contract,
        sql: include_str!("../../../migrations/identity-policy-audit/000001_contract.sql"),
        checksum_sha256: "7558ed51246621d58127d3a8525bb2b001327bfcafa9b2d5401be5b49e689512",
        restartable: true,
        minimum_application_version: "0.2.0",
        maximum_application_version: "0.2.x",
        requires_compatibility_fence: true,
    },
];

