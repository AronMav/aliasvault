//! Neutral model returned to clients after parsing a KDBX database.
//!
//! The shape is deliberately independent of both KeePass and AliasVault so that
//! every platform can adapt it to its own import model.

use serde::{Deserialize, Serialize};

/// Result of opening and mapping a KDBX database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbxImportResult {
    /// Handle used to fetch attachment blobs and to release the session.
    pub session_id: String,
    /// The mapped entries.
    pub items: Vec<KdbxItem>,
    /// Counts of deliberately ignored content.
    pub skipped: KdbxSkipped,
}

/// A single mapped KeePass entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KdbxItem {
    /// Entry title.
    pub title: String,
    /// Username field.
    pub username: Option<String>,
    /// Password field.
    pub password: Option<String>,
    /// Notes field.
    pub notes: Option<String>,
    /// TOTP value, passed through verbatim (usually an otpauth:// URI).
    pub totp: Option<String>,
    /// Slash separated path of the containing group, root excluded.
    pub folder_path: Option<String>,
    /// Primary URL followed by any additional URLs.
    pub urls: Vec<String>,
    /// Entry tags.
    pub tags: Vec<String>,
    /// Creation time, ISO 8601 in UTC.
    pub created_at: Option<String>,
    /// Last modification time, ISO 8601 in UTC.
    pub updated_at: Option<String>,
    /// Remaining user defined fields.
    pub custom_fields: Vec<KdbxCustomField>,
    /// Metadata of the entry's attachments; blobs are fetched separately.
    pub attachments: Vec<KdbxAttachmentMeta>,
}

/// A user defined field that has no dedicated slot in the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbxCustomField {
    /// Field name as shown in KeePass.
    pub name: String,
    /// Field value.
    pub value: String,
    /// Whether KeePass stored the value as a protected field.
    pub is_protected: bool,
}

/// Attachment metadata. The blob is fetched with a separate call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdbxAttachmentMeta {
    /// Index of the blob within the session.
    pub id: String,
    /// Attachment file name.
    pub filename: String,
    /// Blob size in bytes.
    pub size: u64,
}

/// Content that was intentionally not imported.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KdbxSkipped {
    /// Entries that live in the recycle bin.
    pub recycle_bin: u32,
    /// Historical versions of entries.
    pub history: u32,
}
