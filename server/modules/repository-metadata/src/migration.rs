#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationPhase {
    Expand,
    Migrate,
    Contract,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Migration {
    pub version: u64,
    pub phase: MigrationPhase,
    pub sql: &'static str,
    pub restartable: bool,
}

pub const MIGRATIONS: [Migration; 3] = [
    Migration {
        version: 1,
        phase: MigrationPhase::Expand,
        sql: include_str!("../../../migrations/repository-metadata/000001_expand.sql"),
        restartable: true,
    },
    Migration {
        version: 1,
        phase: MigrationPhase::Migrate,
        sql: include_str!("../../../migrations/repository-metadata/000001_migrate.sql"),
        restartable: true,
    },
    Migration {
        version: 1,
        phase: MigrationPhase::Contract,
        sql: include_str!("../../../migrations/repository-metadata/000001_contract.sql"),
        restartable: true,
    },
];
