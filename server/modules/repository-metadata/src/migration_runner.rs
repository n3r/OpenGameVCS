use postgres::Client;
use sha2::{Digest, Sha256};

use crate::{DomainError, DomainErrorCode, Result, MIGRATIONS};

const MIGRATION_LOCK: &str = "ogvcs-metadata-migrations-v1";
const MAXIMUM_SCHEMA_VERSION: i64 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationRunOptions {
    pub application_version: &'static str,
    pub compatibility_fence_open: bool,
}

impl Default for MigrationRunOptions {
    fn default() -> Self {
        Self {
            application_version: env!("CARGO_PKG_VERSION"),
            compatibility_fence_open: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MigrationRunReport {
    pub applied: usize,
    pub already_applied: usize,
}

pub fn run_migrations(
    client: &mut Client,
    options: MigrationRunOptions,
) -> Result<MigrationRunReport> {
    client
        .simple_query(&format!(
            "SELECT pg_advisory_lock(hashtextextended('{MIGRATION_LOCK}', 0))"
        ))
        .map_err(database_error)?;
    let result = run_locked(client, options);
    let unlock = client.simple_query(&format!(
        "SELECT pg_advisory_unlock(hashtextextended('{MIGRATION_LOCK}', 0))"
    ));
    match (result, unlock) {
        (Ok(report), Ok(_)) => Ok(report),
        (Err(error), _) => Err(error),
        (Ok(_), Err(_)) => Err(DomainError::new(DomainErrorCode::MigrationIncompatible)),
    }
}

/// Proves that every phase required by this binary is present, completed, and
/// byte-for-byte identical to the migration source bundled into the binary.
/// Mutation entry points call this before opening a database transaction.
pub fn verify_schema_compatibility(client: &mut Client) -> Result<()> {
    if !compatible(env!("CARGO_PKG_VERSION"), "0.1.0", "0.1.x") {
        return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
    }
    let ledger_exists: bool = client
        .query_one(
            "SELECT to_regclass('ogvcs_metadata.schema_migrations') IS NOT NULL",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    if !ledger_exists {
        return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
    }
    let newest: Option<i64> = client
        .query_one(
            "SELECT max(version) FROM ogvcs_metadata.schema_migrations",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    if newest.unwrap_or(0) > MAXIMUM_SCHEMA_VERSION {
        return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
    }

    for migration in MIGRATIONS {
        validate_source(migration)?;
        if !compatible(
            env!("CARGO_PKG_VERSION"),
            migration.minimum_application_version,
            migration.maximum_application_version,
        ) {
            return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
        }
        let row = client
            .query_opt(
                "SELECT checksum_sha256, state, minimum_application_version,
                        maximum_application_version
                 FROM ogvcs_metadata.schema_migrations
                 WHERE version = $1 AND phase = $2",
                &[&(migration.version as i64), &migration.phase.as_str()],
            )
            .map_err(database_error)?
            .ok_or_else(|| DomainError::new(DomainErrorCode::MigrationIncompatible))?;
        let checksum: String = row.get(0);
        let state: String = row.get(1);
        let minimum_application_version: String = row.get(2);
        let maximum_application_version: String = row.get(3);
        if checksum != migration.checksum_sha256 {
            return Err(DomainError::new(DomainErrorCode::MigrationChecksumMismatch));
        }
        if state != "completed" {
            return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
        }
        if minimum_application_version != migration.minimum_application_version
            || maximum_application_version != migration.maximum_application_version
        {
            return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
        }
    }
    Ok(())
}

fn run_locked(client: &mut Client, options: MigrationRunOptions) -> Result<MigrationRunReport> {
    if !compatible(options.application_version, "0.1.0", "0.1.x") {
        return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
    }

    let ledger_exists: bool = client
        .query_one(
            "SELECT to_regclass('ogvcs_metadata.schema_migrations') IS NOT NULL",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    if ledger_exists {
        let newest: Option<i64> = client
            .query_one(
                "SELECT max(version) FROM ogvcs_metadata.schema_migrations",
                &[],
            )
            .map_err(database_error)?
            .get(0);
        if newest.unwrap_or(0) > MAXIMUM_SCHEMA_VERSION {
            return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
        }
    }

    let mut report = MigrationRunReport::default();
    for migration in MIGRATIONS {
        validate_source(migration)?;
        if !compatible(
            options.application_version,
            migration.minimum_application_version,
            migration.maximum_application_version,
        ) {
            return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
        }
        let existing = if ledger_exists || report.applied > 0 {
            client
                .query_opt(
                    "SELECT checksum_sha256, state, minimum_application_version,
                            maximum_application_version
                     FROM ogvcs_metadata.schema_migrations WHERE version = $1 AND phase = $2",
                    &[&(migration.version as i64), &migration.phase.as_str()],
                )
                .map_err(database_error)?
        } else {
            None
        };
        if let Some(row) = existing {
            let checksum: String = row.get(0);
            let state: String = row.get(1);
            let minimum_application_version: String = row.get(2);
            let maximum_application_version: String = row.get(3);
            if checksum != migration.checksum_sha256 {
                return Err(DomainError::new(DomainErrorCode::MigrationChecksumMismatch));
            }
            if minimum_application_version != migration.minimum_application_version
                || maximum_application_version != migration.maximum_application_version
            {
                return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
            }
            if state == "completed" {
                report.already_applied += 1;
                continue;
            }
            if !migration.restartable {
                return Err(DomainError::new(DomainErrorCode::MigrationIncompatible));
            }
        }
        if migration.requires_compatibility_fence && !options.compatibility_fence_open {
            continue;
        }

        let body = transaction_body(migration.sql)?;
        let mut transaction = client.transaction().map_err(database_error)?;
        transaction.batch_execute(body).map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.schema_migrations
                 (version, phase, checksum_sha256, state, minimum_application_version,
                  maximum_application_version, started_at, completed_at)
                 VALUES ($1, $2, $3, 'completed', $4, $5, clock_timestamp(), clock_timestamp())
                 ON CONFLICT (version, phase) DO UPDATE SET
                    checksum_sha256 = EXCLUDED.checksum_sha256,
                    state = 'completed', completed_at = clock_timestamp()
                 WHERE ogvcs_metadata.schema_migrations.state = 'started'",
                &[
                    &(migration.version as i64),
                    &migration.phase.as_str(),
                    &migration.checksum_sha256,
                    &migration.minimum_application_version,
                    &migration.maximum_application_version,
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        report.applied += 1;
    }
    Ok(report)
}

fn validate_source(migration: crate::Migration) -> Result<()> {
    let actual = format!("{:x}", Sha256::digest(migration.sql.as_bytes()));
    if actual == migration.checksum_sha256 {
        Ok(())
    } else {
        Err(DomainError::new(DomainErrorCode::MigrationChecksumMismatch))
    }
}

fn transaction_body(sql: &str) -> Result<&str> {
    sql.strip_prefix("BEGIN;\n")
        .and_then(|body| body.strip_suffix("COMMIT;\n"))
        .ok_or_else(|| DomainError::new(DomainErrorCode::MigrationChecksumMismatch))
}

fn compatible(application: &str, minimum: &str, maximum: &str) -> bool {
    let Some(application) = version_triplet(application) else {
        return false;
    };
    let Some(minimum) = version_triplet(minimum) else {
        return false;
    };
    if application < minimum {
        return false;
    }
    if let Some(prefix) = maximum.strip_suffix(".x") {
        let mut parts = prefix.split('.');
        let major = parts.next().and_then(|value| value.parse::<u64>().ok());
        let minor = parts.next().and_then(|value| value.parse::<u64>().ok());
        return parts.next().is_none()
            && major == Some(application.0)
            && minor == Some(application.1);
    }
    version_triplet(maximum).is_some_and(|maximum| application <= maximum)
}

fn version_triplet(value: &str) -> Option<(u64, u64, u64)> {
    let core = value.split_once('-').map_or(value, |(core, _)| core);
    let mut parts = core.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(version)
}

fn database_error(_error: postgres::Error) -> DomainError {
    DomainError::new(DomainErrorCode::MigrationIncompatible)
}
