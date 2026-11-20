//! Minimal RFC 3986 URL handling and percent/form encoding for Portal
//! redirects.
//!
//! The firmware only matched the literal text `Location: http://`
//! (docs/05 §5.2, cleanroom/07 §1 "302 多跳/相对 Location 处理 — 原固件脆弱");
//! this module instead resolves relative references (RFC 3986 §5.2), keeps
//! explicit ports, lower-cases scheme and host, strips userinfo and
//! fragments, and percent-encodes each component so that a hostile
//! `Location` cannot inject spaces, CR/LF or extra query parameters.

use std::fmt;

/// Error parsing or resolving a URL. Messages are user-facing (Chinese).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UrlError {
    Empty,
    /// No `scheme:` prefix on what must be an absolute URL.
    NoScheme(String),
    /// `scheme:` without `//authority`, or an empty host.
    NoHost(String),
    BadPort(String),
    BadHost(String),
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlError::Empty => f.write_str("地址为空"),
            UrlError::NoScheme(u) => write!(f, "地址缺少协议头: {:?}", u),
            UrlError::NoHost(u) => write!(f, "地址缺少主机: {:?}", u),
            UrlError::BadPort(u) => write!(f, "地址端口无效: {:?}", u),
            UrlError::BadHost(u) => write!(f, "地址主机名无效: {:?}", u),
        }
    }
}

impl std::error::Error for UrlError {}

/// An absolute hierarchical URL (`scheme://host[:port]/path[?query]`).
///
/// Invariants: `scheme` and `host` are lower case; `port` is `None` when
/// absent or equal to the scheme default; `path` starts with `/` and has no
/// dot segments; `path` and `query` contain only RFC 3986 characters
/// (anything else was percent-encoded on parse).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

/// Length of a leading `scheme:` (RFC 3986 §3.1), without the colon.
fn scheme_len(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if !bytes.first()?.is_ascii_alphabetic() {
        return None;
    }
    for (i, &b) in bytes.iter().enumerate().skip(1) {
        match b {
            b':' => return Some(i),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'-' | b'.' => {}
            _ => return None,
        }
    }
    None
}

fn strip_fragment(s: &str) -> &str {
    s.split_once('#').map_or(s, |(a, _)| a)
}

impl Url {
    /// Parses an absolute URL. Surrounding whitespace and the fragment are
    /// dropped, userinfo is discarded, the path is normalized.
    pub fn parse(input: &str) -> Result<Url, UrlError> {
        let s = strip_fragment(input.trim());
        if s.is_empty() {
            return Err(UrlError::Empty);
        }
        let n = scheme_len(s).ok_or_else(|| UrlError::NoScheme(input.to_string()))?;
        let scheme = s[..n].to_ascii_lowercase();
        let rest = s[n + 1..].strip_prefix("//").ok_or_else(|| UrlError::NoHost(input.to_string()))?;
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let (host, port) = split_authority(authority, input)?;
        let port = port.filter(|p| Some(*p) != default_port(&scheme));
        let (path, query) = match tail.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (tail, None),
        };
        let path = if path.is_empty() { "/".to_string() } else { remove_dot_segments(&encode_path(path)) };
        Ok(Url { scheme, host, port, path, query: query.map(encode_query) })
    }

    /// Resolves `reference` (absolute, network-path, absolute-path or
    /// relative-path, RFC 3986 §5.2.2) against this base.
    pub fn join(&self, reference: &str) -> Result<Url, UrlError> {
        let r = strip_fragment(reference.trim());
        if scheme_len(r).is_some() {
            return Url::parse(r);
        }
        if r.starts_with("//") {
            return Url::parse(&format!("{}:{}", self.scheme, r));
        }
        let (rpath, rquery) = match r.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (r, None),
        };
        let (path, query) = if rpath.is_empty() {
            (self.path.clone(), rquery.map(encode_query).or_else(|| self.query.clone()))
        } else if rpath.starts_with('/') {
            (remove_dot_segments(&encode_path(rpath)), rquery.map(encode_query))
        } else {
            let base_dir = &self.path[..self.path.rfind('/').map_or(0, |i| i + 1)];
            (remove_dot_segments(&format!("{}{}", base_dir, encode_path(rpath))), rquery.map(encode_query))
        };
        Ok(Url { scheme: self.scheme.clone(), host: self.host.clone(), port: self.port, path, query })
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Lower-case host; IPv6 literals keep their brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Explicit non-default port.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Raw (still percent-encoded) query, without `?`.
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    pub fn is_http(&self) -> bool {
        self.scheme == "http"
    }

    /// `host[:port]`, port only when not the scheme default.
    pub fn authority(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        }
    }

    /// `(name, value)` pairs of the query, still percent-encoded.
    pub fn raw_query_pairs(&self) -> Vec<(&str, &str)> {
        self.query
            .as_deref()
            .unwrap_or("")
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once('=').unwrap_or((p, "")))
            .collect()
    }

    /// First query value whose name equals `name` (ASCII case-insensitive,
    /// whole name: `userip` never matches `wlanuserip`), still encoded.
    pub fn raw_query_value(&self, name: &str) -> Option<&str> {
        self.raw_query_pairs()
            .into_iter()
            .find(|(k, _)| form_decode_lossy(k).eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.authority(), self.path)?;
        if let Some(q) = &self.query {
            write!(f, "?{}", q)?;
        }
        Ok(())
    }
}

fn split_authority(authority: &str, input: &str) -> Result<(String, Option<u16>), UrlError> {
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']').ok_or_else(|| UrlError::BadHost(input.to_string()))?;
        let host = &authority[..=close];
        let inner = &host[1..host.len() - 1];
        if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.') {
            return Err(UrlError::BadHost(input.to_string()));
        }
        let tail = &authority[close + 1..];
        let port = match tail {
            "" => None,
            t => Some(t.strip_prefix(':').ok_or_else(|| UrlError::BadHost(input.to_string()))?),
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(UrlError::NoHost(input.to_string()));
    }
    let valid = |b: u8| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=%[]:".contains(&b);
    if !host.bytes().all(valid) {
        return Err(UrlError::BadHost(input.to_string()));
    }
    let port = match port {
        None | Some("") => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => {
            Some(p.parse::<u16>().map_err(|_| UrlError::BadPort(input.to_string()))?)
        }
        Some(_) => return Err(UrlError::BadPort(input.to_string())),
    };
    if port == Some(0) {
        return Err(UrlError::BadPort(input.to_string()));
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// RFC 3986 §5.2.4, verbatim.
fn remove_dot_segments(path: &str) -> String {
    fn pop_last(output: &mut String) {
        match output.rfind('/') {
            Some(i) => output.truncate(i),
            None => output.clear(),
        }
    }
    let mut input = path.to_string();
    let mut output = String::with_capacity(path.len());
    while !input.is_empty() {
        if input.starts_with("../") {
            input.drain(..3);
        } else if input.starts_with("./") {
            input.drain(..2);
        } else if input.starts_with("/./") {
            input.replace_range(..3, "/");
        } else if input == "/." {
            input = "/".into();
        } else if input.starts_with("/../") {
            input.replace_range(..4, "/");
            pop_last(&mut output);
        } else if input == "/.." {
            input = "/".into();
            pop_last(&mut output);
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..].find('/').map_or(input.len(), |i| i + start);
            output.push_str(&input[..end]);
            input.drain(..end);
        }
    }
    if output.is_empty() {
        output.push('/');
    }
    output
}

fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Percent-encodes every byte that is not allowed raw, keeping valid
/// `%XX` escapes as they are.
fn encode_with(s: &str, allowed: impl Fn(u8) -> bool) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() && is_hex(bytes[i + 1]) && is_hex(bytes[i + 2]) {
            out.push_str(&s[i..i + 3]);
            i += 3;
            continue;
        }
        if b != b'%' && allowed(b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
        i += 1;
    }
    out
}

/// RFC 3986 `pchar` minus `%` (escapes are handled separately).
fn is_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b)
}

fn encode_path(s: &str) -> String {
    encode_with(s, |b| is_pchar(b) || b == b'/')
}

fn encode_query(s: &str) -> String {
    encode_with(s, |b| is_pchar(b) || b == b'/' || b == b'?')
}

/// Percent-encodes one query *value* for a URL built by this crate: RFC
/// 3986 query characters stay raw, except the ones that would change the
/// meaning under form decoding (`&`, `=`, `+`, `%`, `#`).
pub fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-._~!$'()*,;:@/?".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// `application/x-www-form-urlencoded` byte serializer (WHATWG URL
/// §5.2): ASCII alphanumerics and `*-._` stay, space becomes `+`, every
/// other byte is `%XX`.
pub fn form_encode(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for &b in value {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Serializes ordered pairs as a form body (`a=1&b=2`).
pub fn form_encode_pairs(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode(k.as_bytes()), form_encode(v.as_bytes())))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-decodes; `+` becomes a space when `plus_as_space` (form data).
/// Invalid escapes are kept literally.
pub fn percent_decode(s: &str, plus_as_space: bool) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() && is_hex(bytes[i + 1]) && is_hex(bytes[i + 2]) => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
                i += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

/// Form-decodes a query component into text (invalid UTF-8 replaced).
pub fn form_decode_lossy(s: &str) -> String {
    String::from_utf8_lossy(&percent_decode(s, true)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn parses_scheme_host_port_case() {
        let url = u("HTTP://Portal.Example.EDU:8080/a/b?x=1#frag");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host(), "portal.example.edu");
        assert_eq!(url.port(), Some(8080));
        assert_eq!(url.path(), "/a/b");
        assert_eq!(url.query(), Some("x=1"));
        assert_eq!(url.to_string(), "http://portal.example.edu:8080/a/b?x=1");
        // Default port is dropped, empty path becomes "/", userinfo removed.
        assert_eq!(u("http://user:pw@h:80").to_string(), "http://h/");
        assert_eq!(u("https://h:443/x").port(), None);
        assert_eq!(u("http://h:/x").port(), None);
        assert_eq!(u("http://[FE80::1]:8080/").host(), "[fe80::1]");
        assert_eq!(u("http://[::1]/").authority(), "[::1]");
        assert!(u("https://h/").scheme() == "https" && !u("https://h/").is_http());
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Url::parse("  "), Err(UrlError::Empty));
        assert!(matches!(Url::parse("/relative"), Err(UrlError::NoScheme(_))));
        assert!(matches!(Url::parse("mailto:x@y"), Err(UrlError::NoHost(_))));
        assert!(matches!(Url::parse("http:///x"), Err(UrlError::NoHost(_))));
        assert!(matches!(Url::parse("http://h:99999/"), Err(UrlError::BadPort(_))));
        assert!(matches!(Url::parse("http://h:8a/"), Err(UrlError::BadPort(_))));
        assert!(matches!(Url::parse("http://h:0/"), Err(UrlError::BadPort(_))));
        assert!(matches!(Url::parse("http://bad host/"), Err(UrlError::BadHost(_))));
        assert!(matches!(Url::parse("http://[zz]/"), Err(UrlError::BadHost(_))));
    }

    #[test]
    fn encodes_unsafe_bytes_on_parse() {
        let url = u("http://h/a b/\u{6e56}?q=a b&r=\"x\"\r\n");
        assert_eq!(url.path(), "/a%20b/%E6%B9%96");
        assert_eq!(url.query(), Some("q=a%20b&r=%22x%22"));
        // Existing escapes are kept, stray '%' is escaped.
        assert_eq!(u("http://h/?a=%41%2&b=%zz").query(), Some("a=%41%252&b=%25zz"));
    }

    /// RFC 3986 §5.4.1 normal examples (subset relevant to HTTP).
    #[test]
    fn rfc3986_reference_resolution() {
        let base = u("http://a/b/c/d;p?q");
        let cases = [
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            ("//g", "http://g/"),
            ("?y", "http://a/b/c/d;p?y"),
            ("g?y", "http://a/b/c/g?y"),
            ("#s", "http://a/b/c/d;p?q"),
            ("g#s", "http://a/b/c/g"),
            (";x", "http://a/b/c/;x"),
            ("", "http://a/b/c/d;p?q"),
            (".", "http://a/b/c/"),
            ("./", "http://a/b/c/"),
            ("..", "http://a/b/"),
            ("../", "http://a/b/"),
            ("../g", "http://a/b/g"),
            ("../..", "http://a/"),
            ("../../", "http://a/"),
            ("../../g", "http://a/g"),
            ("../../../g", "http://a/g"),
            ("/./g", "http://a/g"),
            ("/../g", "http://a/g"),
            ("g.", "http://a/b/c/g."),
            ("..g", "http://a/b/c/..g"),
            ("./g/.", "http://a/b/c/g/"),
            ("g/./h", "http://a/b/c/g/h"),
            ("g/../h", "http://a/b/c/h"),
            ("HTTPS://Other:8443/x", "https://other:8443/x"),
        ];
        for (reference, expected) in cases {
            assert_eq!(base.join(reference).unwrap().to_string(), expected, "{}", reference);
        }
        // Network-path references keep the base scheme and take their own port.
        assert_eq!(u("http://a:81/x").join("//b:8080/y").unwrap().to_string(), "http://b:8080/y");
        // Relative references keep the base port.
        assert_eq!(u("http://a:81/x/y").join("z?k=v").unwrap().to_string(), "http://a:81/x/z?k=v");
    }

    #[test]
    fn query_lookup_is_whole_name_and_case_insensitive() {
        let url = u("http://h/?wlanuserip=1.1.1.1&UserIP=10.0.0.2&usermac=02%3A00&e=&flag");
        assert_eq!(url.raw_query_value("userip"), Some("10.0.0.2"));
        assert_eq!(url.raw_query_value("wlanuserip"), Some("1.1.1.1"));
        assert_eq!(url.raw_query_value("usermac"), Some("02%3A00"));
        assert_eq!(url.raw_query_value("e"), Some(""));
        assert_eq!(url.raw_query_value("flag"), Some(""));
        assert_eq!(url.raw_query_value("nasip"), None);
    }

    #[test]
    fn form_encoding_matches_whatwg() {
        assert_eq!(form_encode(b"!^Mdsc0user@x"), "%21%5EMdsc0user%40x");
        assert_eq!(form_encode(b"a b+c&d=e*-._~"), "a+b%2Bc%26d%3De*-._%7E");
        assert_eq!(form_encode("湖".as_bytes()), "%E6%B9%96");
        assert_eq!(form_encode_pairs(&[("a", "1"), ("b c", "http://x/")]), "a=1&b+c=http%3A%2F%2Fx%2F");
        assert_eq!(encode_query_value("02:00:00:00:00:01"), "02:00:00:00:00:01");
        assert_eq!(encode_query_value("a&b=c+d e%#"), "a%26b%3Dc%2Bd%20e%25%23");
    }

    #[test]
    fn decoding() {
        assert_eq!(percent_decode("%21%5e+x%", true), b"!^ x%");
        assert_eq!(percent_decode("a+b%2", false), b"a+b%2");
        assert_eq!(percent_decode("%E6%B9%96", false), "湖".as_bytes());
        assert_eq!(form_decode_lossy("%FF"), "\u{FFFD}");
    }
}
