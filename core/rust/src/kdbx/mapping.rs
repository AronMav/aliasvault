//! Maps a parsed KeePass database into the neutral model.

use chrono::NaiveDateTime;
use keepass::db::{Database, EntryRef, GroupId, GroupRef};

use crate::kdbx::types::{KdbxAttachmentMeta, KdbxCustomField, KdbxItem, KdbxSkipped};

/// Fields that always have a dedicated slot and must not reappear as custom fields.
const RESERVED_FIELDS: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

/// Field names that hold a TOTP value, in the order they are preferred.
const TOTP_FIELDS: [&str; 2] = ["otp", "TOTP Seed"];

/// Returns true for the field names used for additional URLs.
///
/// The ecosystem never agreed on one convention: KeePassXC and Keepass2Android
/// write KP2A_URL and KP2A_URL_<n>, KeePassDX writes URL_<n>, Strongbox writes
/// URL<n>. All four are accepted.
fn is_additional_url_field(name: &str) -> bool {
    if name == "KP2A_URL" {
        return true;
    }

    for prefix in ["KP2A_URL_", "URL_", "URL"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }

    false
}

/// Sort key for an additional URL field: the bare KP2A_URL carries no number and
/// sorts first among the extras, the rest sort by their trailing number.
fn additional_url_order(name: &str) -> u32 {
    let trailing_digits: String = name
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    trailing_digits.parse().unwrap_or(0)
}

/// Formats a KeePass timestamp as ISO 8601 in UTC. KeePass stores times in UTC
/// already, so no conversion is applied, only formatting.
fn format_time(time: Option<NaiveDateTime>) -> Option<String> {
    time.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty())
}

/// Maps every entry outside the recycle bin into the neutral model.
///
/// Returns the items, the counts of skipped content, and the attachment blobs.
/// A `KdbxAttachmentMeta::id` is the blob's index in the returned vector.
pub fn map_database(db: &Database) -> (Vec<KdbxItem>, KdbxSkipped, Vec<Vec<u8>>) {
    let mut items = Vec::new();
    let mut skipped = KdbxSkipped::default();
    let mut blobs = Vec::new();

    // The recycle bin is identified through the metadata UUID, never by group
    // name: the name is translated and differs per interface language.
    let recycle_bin_id = db.recycle_bin().map(|group| group.id());

    visit_group(
        db.root(),
        recycle_bin_id,
        &[],
        &mut items,
        &mut skipped,
        &mut blobs,
    );

    (items, skipped, blobs)
}

fn visit_group(
    group: GroupRef<'_>,
    recycle_bin_id: Option<GroupId>,
    ancestors: &[String],
    items: &mut Vec<KdbxItem>,
    skipped: &mut KdbxSkipped,
    blobs: &mut Vec<Vec<u8>>,
) {
    if recycle_bin_id == Some(group.id()) {
        skipped.recycle_bin += count_entries(&group);
        return;
    }

    let folder_path = if ancestors.is_empty() {
        None
    } else {
        Some(ancestors.join("/"))
    };

    for entry in group.entries() {
        items.push(map_entry(&entry, folder_path.clone(), skipped, blobs));
    }

    for child in group.groups() {
        let mut path = ancestors.to_vec();
        path.push(child.name.clone());
        visit_group(child, recycle_bin_id, &path, items, skipped, blobs);
    }
}

/// Counts every entry in a subtree, used to report how much the recycle bin held.
fn count_entries(group: &GroupRef<'_>) -> u32 {
    let mut count = group.entry_ids().count() as u32;

    for child in group.groups() {
        count += count_entries(&child);
    }

    count
}

fn map_entry(
    entry: &EntryRef<'_>,
    folder_path: Option<String>,
    skipped: &mut KdbxSkipped,
    blobs: &mut Vec<Vec<u8>>,
) -> KdbxItem {
    if let Some(history) = &entry.history {
        skipped.history += history.get_entries().len() as u32;
    }

    // The field that supplied the TOTP value is tracked by name so that it is
    // excluded from the custom fields without hiding the other TOTP field when
    // both are present.
    let totp_field = TOTP_FIELDS
        .iter()
        .find(|name| non_empty(entry.get(name)).is_some());
    let totp = totp_field.and_then(|name| entry.get(name)).map(String::from);

    let mut urls = Vec::new();
    if let Some(url) = non_empty(entry.get_url()) {
        urls.push(url.to_string());
    }

    let mut additional: Vec<(&str, &str)> = entry
        .fields
        .iter()
        .filter(|(name, _)| is_additional_url_field(name))
        .filter_map(|(name, value)| {
            non_empty(Some(value.get().as_str())).map(|v| (name.as_str(), v))
        })
        .collect();
    // Sorted by number and then by name: the fields come out of a HashMap, so ties on the
    // number alone would leave the order down to chance and reshuffle the preview between
    // imports of the same file. KP2A_URL and URL0 both carry the number zero.
    additional.sort_by(|(left, _), (right, _)| {
        additional_url_order(left)
            .cmp(&additional_url_order(right))
            .then_with(|| left.cmp(right))
    });
    urls.extend(additional.into_iter().map(|(_, value)| value.to_string()));

    // HashMap iteration order is not stable, so custom fields are sorted by name.
    // Without this the preview would reshuffle between imports of the same file.
    let mut custom_fields: Vec<KdbxCustomField> = entry
        .fields
        .iter()
        .filter(|(name, _)| {
            !RESERVED_FIELDS.contains(&name.as_str())
                && !is_additional_url_field(name)
                && Some(&name.as_str()) != totp_field
        })
        .map(|(name, value)| KdbxCustomField {
            name: name.clone(),
            value: value.get().clone(),
            is_protected: value.is_protected(),
        })
        .collect();
    custom_fields.sort_by(|a, b| a.name.cmp(&b.name));

    let mut named_attachments: Vec<_> = entry.attachments_named().collect();
    named_attachments.sort_by_key(|(name, _)| *name);

    let mut attachments = Vec::new();
    for (name, attachment) in named_attachments {
        let data = attachment.get().clone();

        attachments.push(KdbxAttachmentMeta {
            id: blobs.len().to_string(),
            filename: name.to_string(),
            size: data.len() as u64,
        });
        blobs.push(data);
    }

    KdbxItem {
        title: entry.get_title().unwrap_or_default().to_string(),
        username: non_empty(entry.get_username()).map(String::from),
        password: non_empty(entry.get_password()).map(String::from),
        notes: non_empty(entry.get("Notes")).map(String::from),
        totp,
        folder_path,
        urls,
        tags: entry.tags.clone(),
        created_at: format_time(entry.times.creation),
        updated_at: format_time(entry.times.last_modification),
        custom_fields,
        attachments,
    }
}

#[cfg(all(test, feature = "kdbx-testing"))]
mod tests {
    use crate::kdbx::fixtures;
    use crate::kdbx::mapping::map_database;
    use crate::kdbx::open_database;

    const PASSWORD: &str = "fixture-pass";

    #[test]
    fn maps_standard_fields() {
        let db = open_database(&fixtures::entry_with_all_fields(PASSWORD), PASSWORD).unwrap();
        let (items, _, _) = map_database(&db);

        let item = &items[0];
        assert_eq!(item.title, "Example");
        assert_eq!(item.username.as_deref(), Some("alice"));
        assert_eq!(item.password.as_deref(), Some("s3cret"));
        assert_eq!(item.notes.as_deref(), Some("a note"));
        assert_eq!(
            item.totp.as_deref(),
            Some("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
        );
        assert_eq!(item.tags, vec!["work".to_string()]);
        assert!(item.folder_path.is_none());
    }

    #[test]
    fn collects_additional_urls_in_all_four_conventions() {
        let db = open_database(&fixtures::entry_with_additional_urls(PASSWORD), PASSWORD).unwrap();
        let (items, _, _) = map_database(&db);

        assert_eq!(
            items[0].urls,
            vec![
                "https://example.com/",
                "https://login.example.com/",
                "https://a.example.com/",
                "https://b.example.com/",
                "https://c.example.com/",
            ]
        );
    }

    #[test]
    fn url_fields_are_not_repeated_as_custom_fields() {
        let db = open_database(&fixtures::entry_with_additional_urls(PASSWORD), PASSWORD).unwrap();
        let (items, _, _) = map_database(&db);

        assert!(items[0]
            .custom_fields
            .iter()
            .all(|f| !f.name.contains("URL")));
    }

    #[test]
    fn keeps_protected_flag_on_custom_fields() {
        let db = open_database(&fixtures::entry_with_protected_field(PASSWORD), PASSWORD).unwrap();
        let (items, _, _) = map_database(&db);

        let protected = items[0]
            .custom_fields
            .iter()
            .find(|f| f.name == "Recovery code")
            .expect("protected custom field must be mapped");
        let plain = items[0]
            .custom_fields
            .iter()
            .find(|f| f.name == "Account")
            .expect("plain custom field must be mapped");

        assert_eq!(protected.value, "12345");
        assert!(protected.is_protected);
        assert_eq!(plain.value, "ACC-1");
        assert!(!plain.is_protected);
    }

    #[test]
    fn builds_nested_folder_path_without_root() {
        let db = open_database(&fixtures::entry_in_nested_group(PASSWORD), PASSWORD).unwrap();
        let (items, _, _) = map_database(&db);

        assert_eq!(items[0].folder_path.as_deref(), Some("Work/Servers"));
    }

    #[test]
    fn skips_recycle_bin_entries_by_uuid() {
        let db = open_database(&fixtures::entry_in_recycle_bin(PASSWORD), PASSWORD).unwrap();
        let (items, skipped, _) = map_database(&db);

        assert!(items.is_empty());
        assert_eq!(skipped.recycle_bin, 1);
    }

    #[test]
    fn skips_history_versions() {
        let db = open_database(&fixtures::entry_with_history(PASSWORD), PASSWORD).unwrap();
        let (items, skipped, _) = map_database(&db);

        assert_eq!(items.len(), 1);
        assert_eq!(skipped.history, 2);
    }

    #[test]
    fn exposes_attachments_as_metadata_and_blobs() {
        let db = open_database(&fixtures::entry_with_attachment(PASSWORD), PASSWORD).unwrap();
        let (items, _, blobs) = map_database(&db);

        let meta = &items[0].attachments[0];
        assert_eq!(meta.filename, "notes.txt");
        assert_eq!(meta.size, 5);
        assert_eq!(blobs[meta.id.parse::<usize>().unwrap()], b"hello");
    }
}
