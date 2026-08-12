//! Public Suffix List lookups used to find the registrable part of a domain.
//!
//! Credential matching treats two hosts as the same site when they share a
//! registrable domain. Deriving that boundary by simply taking the last two
//! labels breaks on shared hosting suffixes: `alice.github.io` and
//! `mallory.github.io` would both reduce to `github.io`, so credentials saved
//! by one tenant would be offered on a site owned by anyone else who can
//! register a name under the same suffix.
//!
//! The rule data lives in `public_suffix_list.dat` and is refreshed by
//! `scripts/refresh-external-dependencies.sh`.

use std::collections::HashSet;
use std::sync::OnceLock;

/// The Public Suffix List rules, embedded at compile time.
static PUBLIC_SUFFIX_LIST: &str = include_str!("public_suffix_list.dat");

/// The three kinds of rule the list defines.
struct Rules {
    /// Ordinary rules, e.g. `com` or `co.uk`.
    normal: HashSet<&'static str>,
    /// Wildcard rules, stored without the leading `*.` — e.g. `*.ck` is held as `ck`.
    wildcard: HashSet<&'static str>,
    /// Exception rules, stored without the leading `!` — e.g. `!www.ck` is held as `www.ck`.
    exception: HashSet<&'static str>,
}

/// Parses the embedded list once on first use.
fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut normal = HashSet::new();
        let mut wildcard = HashSet::new();
        let mut exception = HashSet::new();

        for line in PUBLIC_SUFFIX_LIST.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            if let Some(rest) = line.strip_prefix('!') {
                exception.insert(rest);
            } else if let Some(rest) = line.strip_prefix("*.") {
                wildcard.insert(rest);
            } else {
                normal.insert(line);
            }
        }

        Rules {
            normal,
            wildcard,
            exception,
        }
    })
}

/// Returns the registrable domain of `domain`: its public suffix plus the label
/// to the left of it.
///
/// Returns `None` when the input has no registrable domain — a single label such
/// as `localhost`, or a name that is itself a public suffix such as `github.io`.
///
/// Follows the matching algorithm published at <https://publicsuffix.org/list/>:
/// an exception rule wins outright, otherwise the matching rule with the most
/// labels prevails, and an unlisted name falls back to the implicit `*` rule.
pub fn registrable_domain(domain: &str) -> Option<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| label.is_empty()) {
        return None;
    }

    let rules = rules();

    // An exception rule removes its own leftmost label from the public suffix.
    for i in 0..labels.len() {
        if rules.exception.contains(labels[i..].join(".").as_str()) {
            return join_from(&labels, i);
        }
    }

    // Otherwise the longest matching rule wins. `suffix_labels` counts the
    // labels the public suffix occupies; 1 is the implicit `*` default.
    let mut suffix_labels = 1;
    for i in 0..labels.len() {
        let candidate_len = labels.len() - i;
        if candidate_len <= suffix_labels {
            continue;
        }

        let matched = rules.normal.contains(labels[i..].join(".").as_str())
            || (i + 1 < labels.len() && rules.wildcard.contains(labels[i + 1..].join(".").as_str()));

        if matched {
            suffix_labels = candidate_len;
        }
    }

    if labels.len() <= suffix_labels {
        return None;
    }

    join_from(&labels, labels.len() - suffix_labels - 1)
}

/// Joins `labels` from `start` to the end, or `None` if the range is empty.
fn join_from(labels: &[&str], start: usize) -> Option<String> {
    if start >= labels.len() {
        return None;
    }
    Some(labels[start..].join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordinary_domains() {
        assert_eq!(registrable_domain("example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("sub.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable_domain("a.b.c.example.com").as_deref(), Some("example.com"));
    }

    #[test]
    fn test_multi_label_suffixes() {
        assert_eq!(registrable_domain("example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("sub.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable_domain("sub.example.com.au").as_deref(), Some("example.com.au"));
    }

    #[test]
    fn test_shared_hosting_suffixes() {
        assert_eq!(registrable_domain("alice.github.io").as_deref(), Some("alice.github.io"));
        assert_eq!(registrable_domain("blog.alice.github.io").as_deref(), Some("alice.github.io"));
        assert_eq!(registrable_domain("myapp.pages.dev").as_deref(), Some("myapp.pages.dev"));
    }

    #[test]
    fn test_wildcard_rules() {
        // `*.compute.amazonaws.com` makes each region a suffix of its own.
        assert_eq!(
            registrable_domain("host.eu-west-1.compute.amazonaws.com").as_deref(),
            Some("host.eu-west-1.compute.amazonaws.com")
        );
    }

    #[test]
    fn test_exception_rules() {
        // `*.ck` with the `!www.ck` exception.
        assert_eq!(registrable_domain("www.ck").as_deref(), Some("www.ck"));
        assert_eq!(registrable_domain("site.www.ck").as_deref(), Some("www.ck"));
    }

    #[test]
    fn test_no_registrable_domain() {
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain("com"), None);
        assert_eq!(registrable_domain("github.io"), None);
        assert_eq!(registrable_domain(""), None);
    }

    #[test]
    fn test_unlisted_suffix_falls_back_to_last_two_labels() {
        // Internal names keep the pre-existing behaviour.
        assert_eq!(registrable_domain("server.internal").as_deref(), Some("server.internal"));
        assert_eq!(registrable_domain("box.home.internal").as_deref(), Some("home.internal"));
    }

    #[test]
    fn test_list_parsed() {
        let rules = rules();
        assert!(rules.normal.contains("com"));
        assert!(rules.normal.contains("co.uk"));
        assert!(rules.normal.contains("github.io"));
        assert!(rules.wildcard.contains("ck"));
        assert!(rules.exception.contains("www.ck"));
        assert!(rules.normal.len() > 5000);
    }
}
