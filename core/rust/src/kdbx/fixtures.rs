//! In-memory KDBX fixtures for tests. Compiled only with the kdbx-testing feature.
//!
//! Fixtures built by our own writer keep the mapping tests readable and reviewable,
//! but they cannot prove compatibility with the real format: that is what the
//! end-to-end test with a database produced by KeePassXC is for.

use keepass::db::{Database, Value};
use keepass::DatabaseKey;

fn serialize(db: &Database, password: &str) -> Vec<u8> {
    let mut out = Vec::new();
    db.save(&mut out, DatabaseKey::new().with_password(password))
        .expect("fixture must serialize");
    out
}

/// A single entry that fills every field the mapping has a slot for.
pub fn entry_with_all_fields(password: &str) -> Vec<u8> {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Example");
        entry.set_unprotected("UserName", "alice");
        entry.set_protected("Password", "s3cret");
        entry.set_unprotected("URL", "https://example.com/");
        entry.set_unprotected("Notes", "a note");
        entry.set_protected("otp", "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP");
        entry.tags = vec!["work".to_string()];
    }
    serialize(&db, password)
}

/// An entry whose additional URLs use all four naming conventions found in the wild.
pub fn entry_with_additional_urls(password: &str) -> Vec<u8> {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Example");
        entry.set_unprotected("URL", "https://example.com/");
        entry.set_unprotected("KP2A_URL", "https://login.example.com/");
        entry.set_unprotected("KP2A_URL_1", "https://a.example.com/");
        entry.set_unprotected("URL_2", "https://b.example.com/");
        entry.set_unprotected("URL3", "https://c.example.com/");
    }
    serialize(&db, password)
}

/// An entry carrying one protected and one plain user defined field.
pub fn entry_with_protected_field(password: &str) -> Vec<u8> {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Example");
        entry.set_protected("Recovery code", "12345");
        entry.set_unprotected("Account", "ACC-1");
    }
    serialize(&db, password)
}

/// An entry two levels below the root, to exercise folder path building.
pub fn entry_in_nested_group(password: &str) -> Vec<u8> {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut work = root.add_group();
        work.name = "Work".to_string();

        let mut servers = work.add_group();
        servers.name = "Servers".to_string();

        let mut entry = servers.add_entry();
        entry.set_unprotected("Title", "Example");
    }
    serialize(&db, password)
}

/// An entry that lives in the recycle bin and must not be imported.
pub fn entry_in_recycle_bin(password: &str) -> Vec<u8> {
    let mut db = Database::new();
    let bin_uuid;
    {
        let mut root = db.root_mut();
        let mut bin = root.add_group();
        // Deliberately not named "Recycle Bin": the name is translated, and the
        // mapping must find the group through the metadata UUID instead.
        bin.name = "Papierkorb".to_string();
        bin_uuid = bin.id().uuid();

        let mut entry = bin.add_entry();
        entry.set_unprotected("Title", "Deleted");
    }
    db.meta.recyclebin_uuid = Some(bin_uuid);
    db.meta.recyclebin_enabled = Some(true);
    serialize(&db, password)
}

/// An entry with two historical versions, which must be counted and skipped.
pub fn entry_with_history(password: &str) -> Vec<u8> {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Example");

        let mut first = entry.as_ref().clone();
        first.fields.insert(
            "Password".to_string(),
            Value::unprotected("old-one".to_string()),
        );
        let mut second = entry.as_ref().clone();
        second.fields.insert(
            "Password".to_string(),
            Value::unprotected("old-two".to_string()),
        );

        let history = entry.history.get_or_insert_with(Default::default);
        history.add_entry(first);
        history.add_entry(second);
    }
    serialize(&db, password)
}

/// A database with many entries and several attachments, for load testing.
pub fn large_database(password: &str, entries: usize, attachment_bytes: usize) -> Vec<u8> {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        for i in 0..entries {
            let mut entry = root.add_entry();
            entry.set_unprotected("Title", format!("Service {}", i));
            entry.set_unprotected("UserName", format!("user{}@example.com", i));
            entry.set_protected("Password", format!("p4ssw0rd-{}-xyzzy", i));
            entry.set_unprotected("URL", format!("https://service{}.example.com/", i));
            entry.set_unprotected("Notes", "generated for load testing");

            if i % 10 == 0 {
                entry.add_attachment(
                    format!("blob{}.bin", i),
                    Value::unprotected(vec![b'x'; attachment_bytes]),
                );
            }
        }
    }
    serialize(&db, password)
}

/// An entry with one small attachment.
pub fn entry_with_attachment(password: &str) -> Vec<u8> {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "Example");
        entry.add_attachment("notes.txt", Value::unprotected(b"hello".to_vec()));
    }
    serialize(&db, password)
}
