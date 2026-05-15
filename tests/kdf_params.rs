// Regression test for the KDF strength advertised in the README.
//
// keepass-rs interprets `KdfConfig::Argon2id.memory` as BYTES (it divides by
// 1024 internally to get `mem_cost` in KiB). Previously this code passed
// `1024 * 1024`, intending 1 GiB-as-KiB, but actually getting 1 MiB. The fix
// passes 1 GiB in bytes. This test asserts the persisted KDF config matches
// the README's "1 GiB" claim so a future cleanup cannot quietly weaken it.

mod common;

use keepass::config::KdfConfig;
use keepass::{Database, DatabaseKey};

#[test]
fn init_persists_strong_argon2id_params() {
    let dir = common::scratch_dir("kdf-params");
    let path = common::init_db(&dir, "kdf.kdbx", "test-pw-123");

    let mut f = std::fs::File::open(&path).expect("reopen db");
    let key = DatabaseKey::new().with_password("test-pw-123");
    let db = Database::open(&mut f, key).expect("decrypt with correct password");

    match db.config.kdf_config {
        KdfConfig::Argon2id {
            iterations,
            memory,
            parallelism,
            ..
        } => {
            // Lower bounds, not exact equality — the test guards against
            // regressions toward weaker params, not against future hardening.
            assert!(iterations >= 50, "iterations too low: {iterations}");
            assert!(
                memory >= 1024 * 1024 * 1024,
                "argon2 memory must be at least 1 GiB in bytes; got {memory}"
            );
            assert!(parallelism >= 4, "parallelism too low: {parallelism}");
        }
        other => panic!("expected Argon2id, got {other:?}"),
    }
}
