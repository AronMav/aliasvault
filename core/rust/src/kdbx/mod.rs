//! KDBX (KeePass database) parsing.
//!
//! Decrypts a KDBX database with a master password and maps its entries into a
//! neutral model that any AliasVault client can consume. Both KDBX 4 and the
//! older 3.1 are read, because KeePassXC still writes 3.1.
//!
//! Only the master password is supported. Key files and challenge-response
//! tokens are out of scope, and the format does not record which of them a
//! database was protected with.

use keepass::db::{Database, DatabaseOpenError};
use keepass::error::{CryptographyError, DatabaseKeyError};
use keepass::DatabaseKey;

#[cfg(all(test, feature = "kdbx-testing"))]
pub(crate) mod fixtures;
mod mapping;
mod session;
mod types;

pub use mapping::map_database;
pub use session::{close_session, open_session, take_attachment};
pub use types::{KdbxAttachmentMeta, KdbxCustomField, KdbxImportResult, KdbxItem, KdbxSkipped};

/// Errors that can occur while opening a KDBX database.
#[derive(Debug, thiserror::Error)]
pub enum KdbxError {
    /// The master password did not decrypt the database. A key file, which is
    /// not supported, produces the same failure and cannot be distinguished.
    #[error("invalid password or the database requires a key file")]
    InvalidPassword,

    /// The file is not a readable KDBX database.
    #[error("could not read the database: {0}")]
    Malformed(String),
}

/// Opens a KDBX database using a master password only.
pub fn open_database(bytes: &[u8], password: &str) -> Result<Database, KdbxError> {
    let key = DatabaseKey::new().with_password(password);
    Database::parse(bytes, key).map_err(classify_open_error)
}

/// Classifies why a database failed to open.
///
/// Matches on the variant, never on the message text. A key mismatch and a
/// structurally broken file must not be confused: telling someone to retype a
/// password that was already correct sends them into a loop they cannot exit,
/// and calling their database corrupt when they merely mistyped sends them
/// looking for a backup they do not need.
///
/// The two formats report a wrong key differently. KDBX 4 authenticates the
/// header with an HMAC and fails as `IncorrectKey` before decrypting anything.
/// KDBX 3.1 has no such check: it decrypts first, so a wrong key almost always
/// fails while stripping the block padding, and only reaches the check that
/// would report `IncorrectKey` on the rare occasion the padding happens to
/// come out valid. A padding failure is therefore also a wrong key, which
/// matters because KeePassXC still writes 3.1 databases.
fn classify_open_error(err: DatabaseOpenError) -> KdbxError {
    match err {
        DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey)
        | DatabaseOpenError::Cryptography(CryptographyError::InvalidPadding(_)) => {
            KdbxError::InvalidPassword
        }
        other => KdbxError::Malformed(other.to_string()),
    }
}

#[cfg(all(test, feature = "kdbx-testing"))]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct horse";

    #[test]
    fn opens_database_with_correct_password() {
        let bytes = fixtures::entry_with_all_fields(PASSWORD);
        let db = open_database(&bytes, PASSWORD).expect("database must open");

        assert_eq!(db.root().entry_ids().count(), 1);
    }

    #[test]
    fn rejects_wrong_password() {
        let bytes = fixtures::entry_with_all_fields(PASSWORD);

        let err = open_database(&bytes, "wrong").unwrap_err();

        assert!(matches!(err, KdbxError::InvalidPassword));
    }

    #[test]
    fn parses_a_database_produced_by_the_real_keepassxc() {
        // The fixtures above are written by the same crate that reads them, so on
        // their own they only prove the reader agrees with the writer. This database
        // came out of KeePassXC 2.7.12, attachment included. See testdata/README.md.
        let bytes = include_bytes!("testdata/real_keepassxc.kdbx");

        let db = open_database(bytes, "testkdbxpass123").expect("real database must open");
        let (items, _, blobs) = crate::kdbx::map_database(&db);

        let entry = items
            .iter()
            .find(|item| item.title == "Example")
            .expect("the entry written by keepassxc-cli must be mapped");

        assert_eq!(entry.username.as_deref(), Some("alice"));
        assert_eq!(entry.urls, vec!["https://example.com/"]);
        assert_eq!(entry.attachments.len(), 1);
        assert_eq!(entry.attachments[0].filename, "notes.txt");
        assert_eq!(entry.attachments[0].size, 5);
        assert_eq!(blobs[0], b"hello");
    }

    #[test]
    fn rejects_wrong_password_on_a_database_produced_by_the_real_keepassxc() {
        // The fixtures are KDBX 4, which reports a wrong key outright. The database
        // KeePassXC wrote is 3.1, where a wrong key surfaces as a padding failure
        // instead, so only this file covers the path a real user hits after a typo.
        let bytes = include_bytes!("testdata/real_keepassxc.kdbx");

        let err = open_database(bytes, "not the password").unwrap_err();

        assert!(matches!(err, KdbxError::InvalidPassword));
    }

    /// Writes databases of increasing attachment volume, for measuring where the browser
    /// stops being able to save the resulting vault.
    ///
    /// Ignored by default; run with `cargo test --features kdbx-testing -- --ignored`.
    #[test]
    #[ignore]
    fn write_large_fixture_for_manual_testing() {
        // Attachment volume in megabytes per generated file.
        for total_mb in [20usize, 30, 40, 60] {
            let attachment_count = 20;
            let per_attachment = total_mb * 1024 * 1024 / attachment_count;
            let bytes = fixtures::large_database("testkdbxpass123", 200, per_attachment);

            let name = format!("large_test_{}mb.kdbx", total_mb);
            std::fs::write(&name, &bytes).expect("must write fixture");
            println!("wrote {}: {} bytes on disk", name, bytes.len());
        }
    }

    #[test]
    fn reports_a_broken_file_as_malformed_not_as_a_bad_password() {
        // Garbage must never be reported as a wrong password: the user would
        // retype a password that was never the problem.
        let err = open_database(b"this is not a database at all", PASSWORD).unwrap_err();

        assert!(matches!(err, KdbxError::Malformed(_)));
    }
}
