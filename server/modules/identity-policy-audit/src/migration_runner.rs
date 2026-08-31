use postgres::{Client, Transaction};
use sha2::{Digest, Sha256};

use crate::{Migration, ParticipantError, ParticipantErrorCode, Result, MIGRATIONS};

const MIGRATION_LOCK: &str = "ogvcs-identity-policy-migrations-v1";
const MAXIMUM_SCHEMA_VERSION: i64 = 3;

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
        (Ok(_), Err(_)) => Err(ParticipantError::new(
            ParticipantErrorCode::MigrationIncompatible,
        )),
    }
}

pub fn verify_schema_compatibility(client: &mut Client) -> Result<()> {
    verify_ledger(client)
}

pub(crate) fn verify_schema_in_transaction(transaction: &mut Transaction<'_>) -> Result<()> {
    let newest: Option<i64> = transaction
        .query_one(
            "SELECT max(version) FROM ogvcs_identity.schema_migrations",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    if newest.unwrap_or(0) > MAXIMUM_SCHEMA_VERSION {
        return Err(ParticipantError::new(
            ParticipantErrorCode::MigrationIncompatible,
        ));
    }
    for migration in MIGRATIONS {
        validate_source(migration)?;
        let row = transaction
            .query_opt(
                "SELECT checksum_sha256, state, minimum_application_version,
                        maximum_application_version
                 FROM ogvcs_identity.schema_migrations
                 WHERE version = $1 AND phase = $2",
                &[&(migration.version as i64), &migration.phase.as_str()],
            )
            .map_err(database_error)?
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::MigrationIncompatible))?;
        validate_ledger_row(row, migration)?;
    }
    Ok(())
}

fn verify_ledger(client: &mut Client) -> Result<()> {
    let ledger_exists: bool = client
        .query_one(
            "SELECT to_regclass('ogvcs_identity.schema_migrations') IS NOT NULL",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    if !ledger_exists {
        return Err(ParticipantError::new(
            ParticipantErrorCode::MigrationIncompatible,
        ));
    }
    let newest: Option<i64> = client
        .query_one(
            "SELECT max(version) FROM ogvcs_identity.schema_migrations",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    if newest.unwrap_or(0) > MAXIMUM_SCHEMA_VERSION {
        return Err(ParticipantError::new(
            ParticipantErrorCode::MigrationIncompatible,
        ));
    }
    for migration in MIGRATIONS {
        validate_source(migration)?;
        let row = client
            .query_opt(
                "SELECT checksum_sha256, state, minimum_application_version,
                        maximum_application_version
                 FROM ogvcs_identity.schema_migrations
                 WHERE version = $1 AND phase = $2",
                &[&(migration.version as i64), &migration.phase.as_str()],
            )
            .map_err(database_error)?
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::MigrationIncompatible))?;
        validate_ledger_row(row, migration)?;
    }
    Ok(())
}

fn validate_ledger_row(row: postgres::Row, migration: Migration) -> Result<()> {
    let checksum: String = row.get(0);
    let state: String = row.get(1);
    let minimum: String = row.get(2);
    let maximum: String = row.get(3);
    if checksum != migration.checksum_sha256 {
        return Err(ParticipantError::new(
            ParticipantErrorCode::MigrationChecksumMismatch,
        ));
    }
    if state != "completed"
        || minimum != migration.minimum_application_version
        || maximum != migration.maximum_application_version
        || !compatible(
            env!("CARGO_PKG_VERSION"),
            migration.minimum_application_version,
            migration.maximum_application_version,
        )
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::MigrationIncompatible,
        ));
    }
    Ok(())
}

fn run_locked(client: &mut Client, options: MigrationRunOptions) -> Result<MigrationRunReport> {
    if !compatible(options.application_version, "0.2.0", "0.2.x") {
        return Err(ParticipantError::new(
            ParticipantErrorCode::MigrationIncompatible,
        ));
    }
    let ledger_exists: bool = client
        .query_one(
            "SELECT to_regclass('ogvcs_identity.schema_migrations') IS NOT NULL",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    if ledger_exists {
        let newest: Option<i64> = client
            .query_one(
                "SELECT max(version) FROM ogvcs_identity.schema_migrations",
                &[],
            )
            .map_err(database_error)?
            .get(0);
        if newest.unwrap_or(0) > MAXIMUM_SCHEMA_VERSION {
            return Err(ParticipantError::new(
                ParticipantErrorCode::MigrationIncompatible,
            ));
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
            return Err(ParticipantError::new(
                ParticipantErrorCode::MigrationIncompatible,
            ));
        }
        let existing = if ledger_exists || report.applied > 0 {
            client
                .query_opt(
                    "SELECT checksum_sha256, state, minimum_application_version,
                            maximum_application_version
                     FROM ogvcs_identity.schema_migrations
                     WHERE version = $1 AND phase = $2",
                    &[&(migration.version as i64), &migration.phase.as_str()],
                )
                .map_err(database_error)?
        } else {
            None
        };
        if let Some(row) = existing {
            validate_ledger_row(row, migration)?;
            report.already_applied += 1;
            continue;
        }
        if migration.requires_compatibility_fence && !options.compatibility_fence_open {
            continue;
        }
        let body = transaction_body(migration.sql)?;
        let mut transaction = client.transaction().map_err(database_error)?;
        transaction.batch_execute(body).map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO ogvcs_identity.schema_migrations
                 (version, phase, checksum_sha256, state,
                  minimum_application_version, maximum_application_version,
                  started_at, completed_at)
                 VALUES ($1, $2, $3, 'completed', $4, $5,
                         clock_timestamp(), clock_timestamp())",
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

fn validate_source(migration: Migration) -> Result<()> {
    let actual = format!("{:x}", Sha256::digest(migration.sql.as_bytes()));
    if actual == migration.checksum_sha256 {
        Ok(())
    } else {
        Err(ParticipantError::new(
            ParticipantErrorCode::MigrationChecksumMismatch,
        ))
    }
}

fn transaction_body(sql: &str) -> Result<&str> {
    sql.strip_prefix("BEGIN;\n")
        .and_then(|body| body.strip_suffix("COMMIT;\n"))
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::MigrationChecksumMismatch))
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

fn database_error(_error: postgres::Error) -> ParticipantError {
    ParticipantError::new(ParticipantErrorCode::MigrationIncompatible)
}
