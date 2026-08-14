//! Session storage for a parsed database.
//!
//! Attachment blobs stay here after parsing and are handed out one at a time, so
//! that a large database is never held twice in memory across the wasm boundary.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::kdbx::mapping::map_database;
use crate::kdbx::types::KdbxImportResult;
use crate::kdbx::{open_database, KdbxError};

/// Maximum total size of all attachment blobs, in bytes.
///
/// A single KDBX file can hold gigabytes of attachments while the file itself
/// stays small (the inner XML is compressed). Without a cap, a crafted database
/// exhausts the WASM heap (256 MB) during import and aborts the browser tab.
/// 50 MB leaves headroom for the vault itself and the WASM runtime.
const MAX_TOTAL_ATTACHMENT_BYTES: usize = 50 * 1024 * 1024;

thread_local! {
    static SESSIONS: RefCell<HashMap<String, Vec<Option<Vec<u8>>>>> =
        RefCell::new(HashMap::new());
    static NEXT_SESSION: RefCell<u64> = const { RefCell::new(0) };
}

/// Opens a database and keeps its attachment blobs for later retrieval.
///
/// A failure leaves nothing behind: the session is only registered once the
/// database has been parsed and mapped successfully.
pub fn open_session(bytes: &[u8], password: &str) -> Result<KdbxImportResult, KdbxError> {
    let db = open_database(bytes, password)?;
    let (items, skipped, blobs) = map_database(&db);

    // Reject databases whose attachments alone would exhaust the WASM heap.
    let total_blob_bytes: usize = blobs.iter().map(|b| b.len()).sum();
    if total_blob_bytes > MAX_TOTAL_ATTACHMENT_BYTES {
        return Err(KdbxError::TooLarge(format!(
            "attachments total {} MB exceeds the {} MB limit",
            total_blob_bytes / 1024 / 1024,
            MAX_TOTAL_ATTACHMENT_BYTES / 1024 / 1024
        )));
    }

    let session_id = NEXT_SESSION.with(|counter| {
        let mut counter = counter.borrow_mut();
        *counter += 1;
        format!("kdbx-{}", *counter)
    });

    SESSIONS.with(|sessions| {
        sessions
            .borrow_mut()
            .insert(session_id.clone(), blobs.into_iter().map(Some).collect());
    });

    Ok(KdbxImportResult {
        session_id,
        items,
        skipped,
    })
}

/// Hands out one attachment blob and releases it from the session.
///
/// Returns None when the session is unknown, the id is out of range, or the blob
/// has already been taken.
pub fn take_attachment(session_id: &str, attachment_id: &str) -> Option<Vec<u8>> {
    let index: usize = attachment_id.parse().ok()?;

    SESSIONS.with(|sessions| {
        sessions
            .borrow_mut()
            .get_mut(session_id)?
            .get_mut(index)?
            .take()
    })
}

/// Drops a session and every blob it still holds.
pub fn close_session(session_id: &str) {
    SESSIONS.with(|sessions| {
        sessions.borrow_mut().remove(session_id);
    });
}

#[cfg(all(test, feature = "kdbx-testing"))]
mod tests {
    use crate::kdbx::fixtures;
    use crate::kdbx::session::{close_session, open_session, take_attachment};

    const PASSWORD: &str = "fixture-pass";

    #[test]
    fn take_attachment_returns_blob_once() {
        let result = open_session(&fixtures::entry_with_attachment(PASSWORD), PASSWORD).unwrap();
        let id = result.items[0].attachments[0].id.clone();

        assert_eq!(
            take_attachment(&result.session_id, &id).unwrap(),
            b"hello".to_vec()
        );
        // Taking is destructive: the blob is released so a large import does not
        // hold every attachment twice.
        assert!(take_attachment(&result.session_id, &id).is_none());

        close_session(&result.session_id);
    }

    #[test]
    fn close_session_drops_remaining_blobs() {
        let result = open_session(&fixtures::entry_with_attachment(PASSWORD), PASSWORD).unwrap();
        let id = result.items[0].attachments[0].id.clone();

        close_session(&result.session_id);

        assert!(take_attachment(&result.session_id, &id).is_none());
    }

    #[test]
    fn sessions_are_independent() {
        let a = open_session(&fixtures::entry_with_attachment(PASSWORD), PASSWORD).unwrap();
        let b = open_session(&fixtures::entry_with_attachment(PASSWORD), PASSWORD).unwrap();

        assert_ne!(a.session_id, b.session_id);

        close_session(&a.session_id);

        let b_id = b.items[0].attachments[0].id.clone();
        assert!(take_attachment(&b.session_id, &b_id).is_some());

        close_session(&b.session_id);
    }

    #[test]
    fn wrong_password_leaves_no_session_behind() {
        let bytes = fixtures::entry_with_attachment(PASSWORD);

        assert!(open_session(&bytes, "wrong").is_err());
        // Nothing to release, and nothing must linger in memory holding blobs.
        assert!(take_attachment("kdbx-does-not-exist", "0").is_none());
    }
}
