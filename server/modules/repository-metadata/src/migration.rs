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
        sql: include_str!("../../../migrations/repository-metadata/000001_expand.sql"),
        checksum_sha256: "4a19863f82952c67108886fbb206b5ef0de8f947e7537518ca8e51eb872a0c39",
        restartable: true,
        minimum_application_version: "0.1.0",
        maximum_application_version: "0.1.x",
        requires_compatibility_fence: false,
    },
    Migration {
        version: 1,
        phase: MigrationPhase::Migrate,
        sql: include_str!("../../../migrations/repository-metadata/000001_migrate.sql"),
        checksum_sha256: "a9463826cf3d29c8ba21e3912e9d8ef766db728f0cbd71a090de32ad6186128d",
        restartable: true,
        minimum_application_version: "0.1.0",
        maximum_application_version: "0.1.x",
        requires_compatibility_fence: false,
    },
    Migration {
        version: 1,
        phase: MigrationPhase::Contract,
        sql: include_str!("../../../migrations/repository-metadata/000001_contract.sql"),
        checksum_sha256: "d48496191956898e9d2b6ded8a3baffe50a196a055c8afa59300d055673b5480",
        restartable: true,
        minimum_application_version: "0.1.0",
        maximum_application_version: "0.1.x",
        requires_compatibility_fence: true,
    },
];
