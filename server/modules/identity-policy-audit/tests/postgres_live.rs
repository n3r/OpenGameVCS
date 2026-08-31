use ogvcs_identity_policy_audit_postgres::{
    run_migrations, verify_schema_compatibility, MigrationRunOptions,
};
use postgres::{Client, NoTls};

/// This is intentionally self-skipping for ordinary local `cargo test` runs.
/// CI supplies a disposable PostgreSQL 15 service, so the same test proves
/// that checksummed Expand/Migrate/Contract phases are restartable and the
/// schema fence is consumable from a real connection.
#[test]
fn checked_migrations_and_fail_closed_function_work_on_postgres_15() {
    let Ok(database_url) = std::env::var("OGVCS_IDENTITY_POLICY_DATABASE_URL") else {
        return;
    };
    let mut client = Client::connect(&database_url, NoTls).expect("connect disposable postgres");
    let options = MigrationRunOptions {
        application_version: env!("CARGO_PKG_VERSION"),
        compatibility_fence_open: true,
    };
    let first = run_migrations(&mut client, options).expect("apply checksummed migrations");
    assert_eq!(first.applied, 3);
    let second = run_migrations(&mut client, options).expect("restartable migration replay");
    assert_eq!(second.applied, 0);
    assert_eq!(second.already_applied, 3);
    verify_schema_compatibility(&mut client).expect("schema compatibility fence");

    let mut transaction = client.transaction().expect("begin poison check");
    assert!(transaction
        .simple_query("SELECT ogvcs_identity.poison_transaction()")
        .is_err());
    assert!(transaction.simple_query("SELECT 1").is_err());
}
