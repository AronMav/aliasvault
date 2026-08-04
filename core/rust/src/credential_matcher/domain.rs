//! Domain extraction and matching utilities.

use std::collections::HashSet;

/// Common top-level domains (TLDs) used for app package name detection.
/// When a search string starts with one of these TLDs followed by a dot (e.g., "com.coolblue.app"),
/// it's identified as a reversed domain name (app package name) rather than a regular URL.
static COMMON_TLDS: &[&str] = &[
    // Generic TLDs
    "com", "net", "org", "edu", "gov", "mil", "int",
    // Country code TLDs
    "nl", "de", "uk", "fr", "it", "es", "pl", "be", "ch", "at", "se", "no", "dk", "fi",
    "pt", "gr", "cz", "hu", "ro", "bg", "hr", "sk", "si", "lt", "lv", "ee", "ie", "lu",
    "us", "ca", "mx", "br", "ar", "cl", "co", "ve", "pe", "ec",
    "au", "nz", "jp", "cn", "in", "kr", "tw", "hk", "sg", "my", "th", "id", "ph", "vn",
    "za", "eg", "ng", "ke", "ug", "tz", "ma",
    "ru", "ua", "by", "kz", "il", "tr", "sa", "ae", "qa", "kw",
    // New gTLDs (common ones)
    "app", "dev", "io", "ai", "tech", "shop", "store", "online", "site", "website",
    "blog", "news", "media", "tv", "video", "music", "pro", "info", "biz", "name",
];


/// Check if a string is likely an app package name (reversed domain).
/// Package names start with TLD followed by dot (e.g., "com.example", "nl.app").
pub fn is_app_package_name(text: &str) -> bool {
    // Must contain a dot
    if !text.contains('.') {
        return false;
    }

    // Must not have protocol
    if text.starts_with("http://") || text.starts_with("https://") {
        return false;
    }

    // Extract first part before first dot
    let first_part = text.split('.').next().unwrap_or("").to_lowercase();

    // Check if first part is a common TLD - indicates reversed domain (package name)
    let tld_set: HashSet<&str> = COMMON_TLDS.iter().copied().collect();
    tld_set.contains(first_part.as_str())
}

/// Result of domain extraction containing both the domain and optional port.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainWithPort {
    pub domain: String,
    pub port: Option<String>,
}

impl DomainWithPort {
    /// Returns the domain with port if present (e.g., "example.com:8080")
    pub fn with_port(&self) -> String {
        match &self.port {
            Some(p) => format!("{}:{}", self.domain, p),
            None => self.domain.clone(),
        }
    }
}

/// Extract domain and port from URL, handling both full URLs and partial domains.
/// Returns DomainWithPort with empty domain if not a valid URL/domain.
pub fn extract_domain_with_port(url: &str) -> DomainWithPort {
    if url.is_empty() {
        return DomainWithPort {
            domain: String::new(),
            port: None,
        };
    }

    let mut domain = url.to_lowercase();

    // Check if it has a protocol - this is important for allowing single-word hostnames
    // like "http://plex" or "https://nas" which are common in self-hosted/homelab setups
    let has_protocol = domain.starts_with("http://") || domain.starts_with("https://");

    // If no protocol and starts with TLD + dot, it's likely an app package name
    if !has_protocol && is_app_package_name(&domain) {
        return DomainWithPort {
            domain: String::new(),
            port: None,
        };
    }

    // Remove protocol if present
    if let Some(stripped) = domain.strip_prefix("https://") {
        domain = stripped.to_string();
    } else if let Some(stripped) = domain.strip_prefix("http://") {
        domain = stripped.to_string();
    }

    // Remove www. prefix
    if let Some(stripped) = domain.strip_prefix("www.") {
        domain = stripped.to_string();
    }

    // Remove path, query, and fragment first (before extracting port)
    if let Some(pos) = domain.find('/') {
        domain = domain[..pos].to_string();
    }
    if let Some(pos) = domain.find('?') {
        domain = domain[..pos].to_string();
    }
    if let Some(pos) = domain.find('#') {
        domain = domain[..pos].to_string();
    }

    // Extract port number if present (e.g., :8080, :1234)
    let port = if let Some(pos) = domain.find(':') {
        let port_str = domain[pos + 1..].to_string();
        domain = domain[..pos].to_string();
        // Validate port is numeric
        if port_str.chars().all(|c| c.is_ascii_digit()) && !port_str.is_empty() {
            Some(port_str)
        } else {
            None
        }
    } else {
        None
    };

    // Domain validation:
    // - If URL had a protocol (http:// or https://), allow single-word hostnames
    //   like "localhost", "plex", "nas", "router" - common in self-hosted/homelab setups
    // - If no protocol, require at least one dot to distinguish from random text
    if !domain.contains('.') && !has_protocol {
        return DomainWithPort {
            domain: String::new(),
            port: None,
        };
    }

    // Check for valid domain characters (alphanumeric, dots, hyphens)
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return DomainWithPort {
            domain: String::new(),
            port: None,
        };
    }

    // Ensure valid domain structure (no leading/trailing dots, no consecutive dots)
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return DomainWithPort {
            domain: String::new(),
            port: None,
        };
    }

    // Ensure domain is not empty after all processing
    if domain.is_empty() {
        return DomainWithPort {
            domain: String::new(),
            port: None,
        };
    }

    DomainWithPort { domain, port }
}

/// Extract domain from URL, handling both full URLs and partial domains.
/// Returns empty string if not a valid URL/domain.
/// Note: This strips port numbers. Use extract_domain_with_port() to preserve port info.
pub fn extract_domain(url: &str) -> String {
    extract_domain_with_port(url).domain
}

/// Extract root domain from a domain string.
/// E.g., "sub.example.com" -> "example.com"
/// E.g., "sub.example.com.au" -> "example.com.au"
/// E.g., "sub.example.co.uk" -> "example.co.uk"
/// E.g., "alice.github.io" -> "alice.github.io" (shared hosting suffix)
pub fn extract_root_domain(domain: &str) -> String {
    // An IP address has no domain hierarchy to reduce.
    if is_ip_address(domain) {
        return domain.to_string();
    }

    super::public_suffix::registrable_domain(domain).unwrap_or_else(|| domain.to_string())
}

/// Check whether the given host is a literal IP address rather than a domain name.
fn is_ip_address(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Check if two domains match, supporting subdomain matching.
/// Note: Both parameters should be pre-extracted domains (without protocol, www, path, etc.)
pub fn domains_match(domain1: &str, domain2: &str) -> bool {
    if domain1.is_empty() || domain2.is_empty() {
        return false;
    }

    // Exact match
    if domain1 == domain2 {
        return true;
    }

    // IP addresses have no subdomain or registrable-domain structure, so anything
    // other than an exact match would group unrelated hosts together.
    if is_ip_address(domain1) || is_ip_address(domain2) {
        return false;
    }

    // Check subdomain relationship (must end with ".domain" not just contain it)
    // e.g., "sub.example.com" is a subdomain of "example.com"
    // but "another-example.com" is NOT related to "example.com"
    if is_subdomain_of(domain1, domain2) || is_subdomain_of(domain2, domain1) {
        return true;
    }

    // Check root domain match
    let d1_root = extract_root_domain(domain1);
    let d2_root = extract_root_domain(domain2);

    d1_root == d2_root
}

/// Check if domain1 is a subdomain of domain2.
/// e.g., "sub.example.com" is a subdomain of "example.com"
/// but "another-example.com" is NOT a subdomain of "example.com"
fn is_subdomain_of(domain1: &str, domain2: &str) -> bool {
    // domain1 must be longer and end with ".domain2"
    if domain1.len() <= domain2.len() {
        return false;
    }

    // Check if domain1 ends with ".domain2" (proper subdomain boundary)
    domain1.ends_with(&format!(".{}", domain2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_app_package_name() {
        assert!(is_app_package_name("com.coolblue.app"));
        assert!(is_app_package_name("nl.marktplaats.android"));
        assert!(is_app_package_name("org.example.app"));

        assert!(!is_app_package_name("https://example.com"));
        assert!(!is_app_package_name("example.com"));
        assert!(!is_app_package_name("coolblue.nl"));
        assert!(!is_app_package_name("nodot"));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://www.example.com/path"), "example.com");
        assert_eq!(extract_domain("http://example.com"), "example.com");
        assert_eq!(extract_domain("example.com"), "example.com");
        assert_eq!(extract_domain("www.example.com"), "example.com");
        assert_eq!(extract_domain("https://example.com?query=1"), "example.com");
        assert_eq!(extract_domain("https://example.com#fragment"), "example.com");

        // Package names should return empty
        assert_eq!(extract_domain("com.coolblue.app"), "");

        // Invalid domains
        assert_eq!(extract_domain(""), "");
        assert_eq!(extract_domain("nodot"), "");

        // Single-word hostnames WITH protocol should be supported
        // (common in self-hosted/homelab setups with local DNS or /etc/hosts)
        assert_eq!(extract_domain("http://localhost"), "localhost");
        assert_eq!(extract_domain("https://localhost"), "localhost");
        assert_eq!(extract_domain("http://localhost/path"), "localhost");
        assert_eq!(extract_domain("http://localhost?query=1"), "localhost");
        assert_eq!(extract_domain("http://plex"), "plex");
        assert_eq!(extract_domain("https://nas"), "nas");
        assert_eq!(extract_domain("http://router"), "router");
        assert_eq!(extract_domain("http://homeassistant"), "homeassistant");
        assert_eq!(extract_domain("http://pihole/admin"), "pihole");

        // Single-word hostnames WITHOUT protocol should NOT be accepted
        // (to avoid matching random text as domains)
        assert_eq!(extract_domain("localhost"), "");
        assert_eq!(extract_domain("plex"), "");
        assert_eq!(extract_domain("randomword"), "");
    }

    #[test]
    fn test_extract_domain_single_word_hostname_with_port() {
        // Single-word hostnames with port (common for self-hosted services)
        assert_eq!(extract_domain("http://localhost:8080"), "localhost");
        assert_eq!(extract_domain("http://localhost:81"), "localhost");
        assert_eq!(extract_domain("http://localhost:3000/path"), "localhost");
        assert_eq!(extract_domain("http://plex:32400"), "plex");
        assert_eq!(extract_domain("https://nas:5001"), "nas");
        assert_eq!(extract_domain("http://router:8080/admin"), "router");

        // Without protocol - should NOT work (could be ambiguous)
        assert_eq!(extract_domain("localhost:8080"), "");
        assert_eq!(extract_domain("plex:32400"), "");

        // Test DomainWithPort struct with localhost
        let result = extract_domain_with_port("http://localhost:81");
        assert_eq!(result.domain, "localhost");
        assert_eq!(result.port, Some("81".to_string()));
        assert_eq!(result.with_port(), "localhost:81");

        let result = extract_domain_with_port("http://localhost:8080/path");
        assert_eq!(result.domain, "localhost");
        assert_eq!(result.port, Some("8080".to_string()));

        let result = extract_domain_with_port("http://localhost/path");
        assert_eq!(result.domain, "localhost");
        assert_eq!(result.port, None);

        // Test with other single-word hostnames
        let result = extract_domain_with_port("http://plex:32400");
        assert_eq!(result.domain, "plex");
        assert_eq!(result.port, Some("32400".to_string()));

        let result = extract_domain_with_port("https://nas:5001/files");
        assert_eq!(result.domain, "nas");
        assert_eq!(result.port, Some("5001".to_string()));
    }

    #[test]
    fn test_extract_domain_with_port() {
        // Port numbers should be stripped from extract_domain
        assert_eq!(extract_domain("https://example.com:8080"), "example.com");
        assert_eq!(extract_domain("https://example.com:8080/path"), "example.com");
        assert_eq!(extract_domain("https://blabla.asd.com:1234"), "blabla.asd.com");
        assert_eq!(extract_domain("https://www.example.com:443/login"), "example.com");
        assert_eq!(extract_domain("example.com:8080"), "example.com");
        assert_eq!(extract_domain("sub.domain.example.com:9000/path?query=1"), "sub.domain.example.com");
    }

    #[test]
    fn test_extract_domain_with_port_struct() {
        // Test the DomainWithPort struct
        let result = extract_domain_with_port("https://example.com:8080/path");
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.port, Some("8080".to_string()));
        assert_eq!(result.with_port(), "example.com:8080");

        let result = extract_domain_with_port("https://example.com/path");
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.port, None);
        assert_eq!(result.with_port(), "example.com");

        let result = extract_domain_with_port("https://www.myserver.local:9443/dashboard");
        assert_eq!(result.domain, "myserver.local");
        assert_eq!(result.port, Some("9443".to_string()));

        let result = extract_domain_with_port("myserver.local:8123");
        assert_eq!(result.domain, "myserver.local");
        assert_eq!(result.port, Some("8123".to_string()));

        // Test that ports are validated as numeric
        let result = extract_domain_with_port("https://example.com:abc/path");
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.port, None); // Invalid port should be None
    }

    #[test]
    fn test_extract_root_domain() {
        assert_eq!(extract_root_domain("sub.example.com"), "example.com");
        assert_eq!(extract_root_domain("example.com"), "example.com");
        assert_eq!(extract_root_domain("sub.example.co.uk"), "example.co.uk");
        assert_eq!(extract_root_domain("example.co.uk"), "example.co.uk");
        assert_eq!(extract_root_domain("sub.example.com.au"), "example.com.au");
    }

    #[test]
    fn test_extract_root_domain_shared_hosting_suffixes() {
        // Tenants on a shared hosting suffix each own their own registrable domain.
        // Collapsing them to the suffix would make unrelated tenants look like one site.
        assert_eq!(extract_root_domain("alice.github.io"), "alice.github.io");
        assert_eq!(extract_root_domain("myapp.pages.dev"), "myapp.pages.dev");
        assert_eq!(extract_root_domain("shop.vercel.app"), "shop.vercel.app");
        assert_eq!(extract_root_domain("deep.sub.alice.github.io"), "alice.github.io");
    }

    #[test]
    fn test_domains_do_not_match_across_shared_hosting_tenants() {
        assert!(!domains_match("alice.github.io", "mallory.github.io"));
        assert!(!domains_match("myapp.pages.dev", "evil.pages.dev"));
        assert!(!domains_match("shop.vercel.app", "phish.vercel.app"));

        // Subdomains of the same tenant still match.
        assert!(domains_match("blog.alice.github.io", "alice.github.io"));
    }

    #[test]
    fn test_ip_addresses_are_not_collapsed() {
        // Two unrelated self-hosted servers must not be treated as the same site.
        assert_eq!(extract_root_domain("192.168.1.5"), "192.168.1.5");
        assert!(!domains_match("192.168.1.5", "10.0.1.5"));
        assert!(domains_match("192.168.1.5", "192.168.1.5"));
    }

    #[test]
    fn test_domains_match() {
        // Exact match
        assert!(domains_match("example.com", "example.com"));

        // Subdomain match
        assert!(domains_match("sub.example.com", "example.com"));
        assert!(domains_match("example.com", "sub.example.com"));

        // Root domain match
        assert!(domains_match("app.example.com", "www.example.com"));

        // No match
        assert!(!domains_match("example.com", "different.com"));
        assert!(!domains_match("coolblue.nl", "coolblue.be"));

        // CRITICAL: Substring match should NOT work (anti-phishing protection)
        // "another-example.com" contains "example.com" but is NOT a subdomain
        assert!(!domains_match("another-example.com", "example.com"));
        assert!(!domains_match("example.com", "another-example.com"));
        assert!(!domains_match("myexample.com", "example.com"));
        assert!(!domains_match("example.com.evil.com", "example.com"));
    }
}
