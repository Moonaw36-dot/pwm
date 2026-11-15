//! URL matching for the browser extension. Deliberately conservative: a
//! credential is only offered to pages served over HTTPS (or to localhost) and
//! whose host equals, or is a subdomain of, the host saved on the entry.
//! Bare public suffixes never match, and loopback entries compare ports.

/// Lower-cased host of `url` without userinfo, port or trailing dot. A URL
/// without a scheme is treated as a bare `host/path`.
pub fn host_of(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    let host = if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal: keep everything up to the closing bracket.
        let end = stripped.find(']')?;
        &authority[..end + 2]
    } else {
        authority.split(':').next()?
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn scheme_of(url: &str) -> Option<String> {
    url.trim()
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
}

/// Explicit port of `url`, if it names one.
pub fn port_of(url: &str) -> Option<u16> {
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let tail = if let Some(end) = authority.find(']') {
        authority[end + 1..].strip_prefix(':')?
    } else {
        authority.split_once(':')?.1
    };
    tail.parse().ok()
}

/// Port the page is actually served on.
fn effective_port(url: &str) -> Option<u16> {
    port_of(url).or_else(|| match scheme_of(url).as_deref() {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    })
}

/// Loopback ports must agree. An entry without a port only fits a page on a
/// default port, so one dev server can't read another's logins.
fn loopback_ports_match(entry_url: &str, page_url: &str) -> bool {
    let page = effective_port(page_url);
    match port_of(entry_url) {
        Some(port) => Some(port) == page,
        None => matches!(page, Some(80 | 443)),
    }
}

/// Multi-label public suffixes that commonly host unrelated tenants. Single
/// label hosts (bare TLDs) are rejected separately.
const PUBLIC_SUFFIXES: &[&str] = &[
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "co.nz",
    "org.nz",
    "co.jp",
    "or.jp",
    "ne.jp",
    "co.in",
    "net.in",
    "org.in",
    "co.za",
    "com.br",
    "com.cn",
    "com.mx",
    "com.tr",
    "com.sg",
    "com.hk",
    "com.tw",
    "co.kr",
    "co.il",
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "pages.dev",
    "workers.dev",
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "appspot.com",
    "blogspot.com",
    "azurewebsites.net",
    "cloudfront.net",
    "onrender.com",
    "fly.dev",
    "glitch.me",
    "repl.co",
    "surge.sh",
    "s3.amazonaws.com",
    "amazonaws.com",
    "myshopify.com",
    "wordpress.com",
    "000webhostapp.com",
    "ngrok.io",
    "ngrok-free.app",
];

/// True for hosts nobody should be able to claim as a whole: single-label
/// names (bare TLDs) and the suffixes above. `localhost` is allowed.
pub fn is_public_suffix(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host == "localhost" || is_ip_literal(&host) {
        return false;
    }
    !host.contains('.') || PUBLIC_SUFFIXES.contains(&host.as_str())
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host.ends_with(".localhost")
}

fn is_ip_literal(host: &str) -> bool {
    host.starts_with('[')
        || (!host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

/// True for pages where secrets may be filled: HTTPS, or HTTP on loopback.
pub fn is_secure_page(url: &str) -> bool {
    match (scheme_of(url).as_deref(), host_of(url)) {
        (Some("https"), Some(_)) => true,
        (Some("http"), Some(host)) => is_loopback(&host),
        _ => false,
    }
}

fn strip_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

/// Does a credential saved for `entry_url` belong on `page_url`? Subdomains
/// of the saved host match; use `url_matches_exact` where that is too loose.
pub fn url_matches(entry_url: &str, page_url: &str) -> bool {
    matches_with(entry_url, page_url, false)
}

/// Same host only (a leading `www.` is ignored). This is what unattended
/// autofill and password updates require.
pub fn url_matches_exact(entry_url: &str, page_url: &str) -> bool {
    matches_with(entry_url, page_url, true)
}

fn matches_with(entry_url: &str, page_url: &str, exact: bool) -> bool {
    if !is_secure_page(page_url) {
        return false;
    }
    let (Some(entry_host), Some(page_host)) = (host_of(entry_url), host_of(page_url)) else {
        return false;
    };
    let entry_host = strip_www(&entry_host);
    let page_host = strip_www(&page_host);
    if is_public_suffix(entry_host) || is_public_suffix(page_host) {
        return false;
    }
    if is_loopback(page_host) && !loopback_ports_match(entry_url, page_url) {
        return false;
    }
    if entry_host == page_host {
        return true;
    }
    // Never for IP literals, and loopback names stay exact.
    !exact
        && !is_ip_literal(entry_host)
        && !is_loopback(entry_host)
        && page_host.ends_with(&format!(".{entry_host}"))
}

/// Is `rp_id` a legal WebAuthn relying-party id for a page at `origin`?
/// The rp id must be the page's host or a parent domain of it, and not a
/// public suffix.
pub fn rp_id_valid_for_origin(rp_id: &str, origin: &str) -> bool {
    if !is_secure_page(origin) {
        return false;
    }
    let Some(host) = host_of(origin) else {
        return false;
    };
    let rp_id = rp_id.trim().to_ascii_lowercase();
    if rp_id.is_empty() || rp_id != rp_id.trim_matches('.') || is_ip_literal(&rp_id) {
        return false;
    }
    if is_public_suffix(&rp_id) {
        return false;
    }
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hosts() {
        assert_eq!(
            host_of("https://Example.com/login").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host_of("https://user:pw@example.com:8443/x?y#z").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("example.com/path").as_deref(), Some("example.com"));
        assert_eq!(
            host_of("https://example.com./").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("http://[::1]:3000/a").as_deref(), Some("[::1]"));
        assert_eq!(host_of("https://").as_deref(), None);
        assert_eq!(host_of("").as_deref(), None);
    }

    #[test]
    fn only_fills_secure_pages() {
        assert!(is_secure_page("https://example.com"));
        assert!(is_secure_page("http://localhost:8080/login"));
        assert!(is_secure_page("http://127.0.0.1/"));
        assert!(!is_secure_page("http://example.com"));
        assert!(!is_secure_page("ftp://example.com"));
        assert!(!is_secure_page("example.com"));
        assert!(!is_secure_page("file:///etc/passwd"));
    }

    #[test]
    fn matches_same_and_sub_domains() {
        assert!(url_matches(
            "https://example.com/login",
            "https://example.com/other"
        ));
        assert!(url_matches("example.com", "https://www.example.com/"));
        assert!(url_matches(
            "https://www.example.com",
            "https://example.com/"
        ));
        assert!(url_matches(
            "https://example.com",
            "https://accounts.example.com/"
        ));
        assert!(url_matches("http://example.com", "https://example.com/"));
    }

    #[test]
    fn rejects_lookalikes_and_insecure_pages() {
        assert!(!url_matches(
            "https://example.com",
            "https://evil-example.com/"
        ));
        assert!(!url_matches(
            "https://example.com",
            "https://example.com.evil.net/"
        ));
        assert!(!url_matches(
            "https://accounts.example.com",
            "https://example.com/"
        ));
        assert!(!url_matches("https://example.com", "http://example.com/"));
        assert!(!url_matches("https://com", "https://example.com/"));
        assert!(!url_matches("https://co.uk", "https://evil.co.uk/"));
        assert!(!url_matches(
            "https://github.io",
            "https://alice.github.io/"
        ));
        assert!(!url_matches("https://github.io", "https://github.io/"));
        assert!(url_matches(
            "https://alice.github.io",
            "https://alice.github.io/"
        ));
        assert!(!url_matches("https://10.0.0.1", "https://1.10.0.0.1/"));
        assert!(!url_matches("", "https://example.com/"));
    }

    #[test]
    fn exact_matching_ignores_only_www() {
        assert!(url_matches_exact("example.com", "https://www.example.com/"));
        assert!(url_matches_exact(
            "https://www.example.com",
            "https://example.com/"
        ));
        assert!(!url_matches_exact(
            "https://example.com",
            "https://accounts.example.com/"
        ));
        assert!(!url_matches_exact(
            "https://example.com",
            "http://example.com/"
        ));
    }

    #[test]
    fn loopback_entries_compare_ports() {
        assert!(url_matches(
            "http://localhost:3000",
            "http://localhost:3000/x"
        ));
        assert!(!url_matches(
            "http://localhost:3000",
            "http://localhost:4000/"
        ));
        assert!(!url_matches("http://localhost", "http://localhost:3000/"));
        assert!(url_matches("http://localhost", "http://localhost/"));
        assert!(!url_matches("http://localhost:3000", "http://localhost/"));
        assert_eq!(port_of("http://[::1]:3000/a"), Some(3000));
        assert_eq!(port_of("https://user@example.com:8443"), Some(8443));
        assert_eq!(port_of("https://example.com/a:b"), None);
    }

    #[test]
    fn public_suffixes_are_flagged() {
        for host in [
            "com",
            "co.uk",
            "github.io",
            "herokuapp.com",
            "intranet",
            "Pages.Dev",
        ] {
            assert!(is_public_suffix(host), "{host}");
        }
        for host in [
            "example.com",
            "alice.github.io",
            "localhost",
            "127.0.0.1",
            "foo.co.uk",
        ] {
            assert!(!is_public_suffix(host), "{host}");
        }
    }

    #[test]
    fn rp_id_must_be_a_parent_of_the_origin_host() {
        assert!(rp_id_valid_for_origin("example.com", "https://example.com"));
        assert!(rp_id_valid_for_origin(
            "example.com",
            "https://login.example.com/x"
        ));
        assert!(rp_id_valid_for_origin("localhost", "http://localhost:3000"));
        assert!(!rp_id_valid_for_origin(
            "login.example.com",
            "https://example.com"
        ));
        assert!(!rp_id_valid_for_origin("com", "https://example.com"));
        assert!(!rp_id_valid_for_origin(
            "github.io",
            "https://alice.github.io"
        ));
        assert!(!rp_id_valid_for_origin("co.uk", "https://example.co.uk"));
        assert!(rp_id_valid_for_origin(
            "alice.github.io",
            "https://alice.github.io"
        ));
        assert!(!rp_id_valid_for_origin("evil.com", "https://example.com"));
        assert!(!rp_id_valid_for_origin("example.com", "http://example.com"));
        assert!(!rp_id_valid_for_origin("1.1", "https://1.1"));
        assert!(!rp_id_valid_for_origin("ample.com", "https://example.com"));
    }
}
