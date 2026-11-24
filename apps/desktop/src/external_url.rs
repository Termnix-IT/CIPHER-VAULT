//! Opens an entry's URL in the default browser. The screen names the entry, never the URL, and the
//! core hands over the URL stored in it; this module decides whether it may be opened. Only web
//! addresses are opened, so a stored `file:`, `javascript:` or custom scheme can never start a
//! program, and nothing from the entry (login ID, password) is ever added to the address.

use tauri::Url;

/// Longer addresses are not web pages someone signs in to, and some programs cut them short.
const MAX_URL_BYTES: usize = 2048;

pub const REFUSED: &str = "開けるのは http:// か https:// で始まるWebのURLだけです";

/// The address to open for `text`, or None when it is not a web address. A URL typed without a
/// scheme, such as `example.com/login`, is read as https, as a browser's address bar reads it. Text
/// that names any other scheme is refused rather than guessed at.
pub fn launchable(text: &str) -> Option<Url> {
    let text = text.trim();
    // Spaces and control characters have no place in an address; a browser would read them differently than this check.
    // A backslash is read as a slash by the URL parser, so a Windows path would turn into an address.
    if text.is_empty() || text.chars().any(|character| character.is_whitespace() || character.is_control() || character == '\\') {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let candidate = if lower.starts_with("http://") || lower.starts_with("https://") {
        text.to_string()
    } else if has_scheme(&lower) {
        return None;
    } else {
        format!("https://{text}")
    };
    // The parser skips extra slashes (`https:///x` becomes the host `x`), which the user did not write.
    if candidate.split_once("://").is_some_and(|(_, rest)| rest.starts_with('/')) {
        return None;
    }
    let url = Url::parse(&candidate).ok()?;
    // A user name or password in the address would be sent to the site, so such an address is not opened.
    let web = matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(plain_host);
    // The parser escapes quotes and spaces everywhere but in the host, which plain_host has checked. The
    // shell may put the address inside quotes on the browser's command line, so none may remain.
    let safe = url.as_str().len() <= MAX_URL_BYTES && url.as_str().chars().all(|character| character.is_ascii_graphic() && !matches!(character, '"' | '<' | '>' | '`'));
    (web && safe && url.username().is_empty() && url.password().is_none()).then_some(url)
}

/// A host name of letters, digits, hyphens, underscores and dots, an IPv4 address, or an IPv6 address
/// in brackets (which the parser has already checked). The parser turns international names into this
/// form (xn--) and percent-decodes the rest, so `%22` cannot hide a quote in the host.
fn plain_host(host: &str) -> bool {
    let ipv6 = host.starts_with('[') && host.ends_with(']') && host[1..host.len() - 1].chars().all(|character| character.is_ascii_hexdigit() || matches!(character, ':' | '.'));
    ipv6 || (!host.is_empty() && host.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')))
}

/// Whether the text starts with `scheme:` and is not a host with a port, such as `localhost:8080`.
fn has_scheme(lower: &str) -> bool {
    let Some((scheme, rest)) = lower.split_once(':') else { return false };
    let is_scheme = scheme.starts_with(|character: char| character.is_ascii_alphabetic())
        && scheme.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.'));
    let is_port = rest.chars().take_while(char::is_ascii_digit).count() > 0 && rest.trim_start_matches(|character: char| character.is_ascii_digit()).chars().next().is_none_or(|next| next == '/');
    is_scheme && !is_port
}

/// Hands a checked address to the shell, which opens it in the default browser.
#[cfg(not(feature = "e2e"))]
pub fn open(url: &Url) -> Result<(), String> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::{HSTRING, w};
    let result = unsafe { ShellExecuteW(None, w!("open"), &HSTRING::from(url.as_str()), None, None, SW_SHOWNORMAL) };
    // ShellExecuteW reports success with a value above 32.
    if result.0 as isize > 32 { Ok(()) } else { Err("ブラウザでURLを開けませんでした".to_string()) }
}

/// The automated checks never open a browser. They see the address that would have been opened.
#[cfg(feature = "e2e")]
pub fn open(url: &Url) -> Result<(), String> {
    crate::trace(&format!("url-opened {url}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_addresses_open_and_a_missing_scheme_means_https() {
        for (text, opened) in [
            ("https://example.test/login", "https://example.test/login"),
            ("  http://example.test  ", "http://example.test/"),
            ("HTTPS://Example.test/a?b=c#d", "https://example.test/a?b=c#d"),
            ("example.test", "https://example.test/"),
            ("example.test/sign-in?next=/", "https://example.test/sign-in?next=/"),
            ("localhost:8080", "https://localhost:8080/"),
            ("localhost:8080/path", "https://localhost:8080/path"),
            ("192.0.2.1", "https://192.0.2.1/"),
        ] {
            assert_eq!(launchable(text).map(|url| url.to_string()).as_deref(), Some(opened), "{text}");
        }
        assert_eq!(launchable("https://[2001:db8::1]/").map(|url| url.to_string()).as_deref(), Some("https://[2001:db8::1]/"));
        // Quotes in the path and query are escaped by the parser, so they are opened escaped.
        assert_eq!(launchable("https://example.test/a\"b?c=\"d\"").map(|url| url.to_string()).as_deref(), Some("https://example.test/a%22b?c=%22d%22"));
        assert!(launchable(&format!("https://example.test/{}", "a".repeat(MAX_URL_BYTES))).is_none(), "a very long address");
        let international = launchable("日本語.example").unwrap();
        assert!(international.host_str().unwrap().starts_with("xn--"), "the host is sent in its ASCII form");
    }

    #[test]
    fn other_schemes_credentials_and_odd_text_are_refused() {
        for text in [
            "",
            "   ",
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "file:///C:/Windows/System32/calc.exe",
            "file:C:/x",
            "data:text/html,x",
            "mailto:someone@example.test",
            "ms-settings:privacy",
            "vbscript:x",
            "ftp://example.test",
            "\\\\server\\share",
            "C:\\Windows\\notepad.exe",
            "https://user:secret@example.test",
            "https://user@example.test",
            "example.test/a b",
            "https://example.test/\nnext",
            "https://",
            "https:///path",
            "http://[::1",
            "https://a%22b.example.test/",
            "https://a\"b.example.test/",
            "https://a%3Cb.example.test/",
            "https://a!b.example.test/",
        ] {
            assert!(launchable(text).is_none(), "{text:?}");
        }
    }
}
