//! Session cookies. The old-Mac client keeps a cookie file next to the
//! saved LogoffURL: a stateful session, not a stateless single POST
//! (cleanroom/08 §1.3). This jar keeps cookies in memory for one round,
//! sends each back only to the exact host that set it (the `Domain`
//! attribute is not honoured, which can only send less), and never prints
//! values: they may be session credentials (clean-room rule 2).

use std::fmt;

use gswifi_core::HttpResponse;

/// Most cookies kept; a portal sets a handful.
const MAX_COOKIES: usize = 32;

#[derive(Clone, Default)]
pub(crate) struct CookieJar {
    /// `(host, name, value)` in arrival order.
    cookies: Vec<(String, String, String)>,
}

impl fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CookieJar({} cookies)", self.cookies.len())
    }
}

impl CookieJar {
    /// Records every `Set-Cookie` of a response from `host`. `Max-Age=0`
    /// (or negative) deletes; other attributes are ignored for a session
    /// that lasts minutes to hours.
    pub fn store(&mut self, host: &str, response: &HttpResponse) {
        for (name, value) in &response.headers {
            if !name.eq_ignore_ascii_case("Set-Cookie") {
                continue;
            }
            let mut parts = value.split(';');
            let Some((k, v)) = parts.next().and_then(|p| p.split_once('=')) else { continue };
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() || k.contains([' ', '\t', ',']) || v.contains(['\r', '\n']) {
                continue;
            }
            let delete = parts.any(|a| {
                a.split_once('=').is_some_and(|(n, val)| {
                    n.trim().eq_ignore_ascii_case("Max-Age") && val.trim().parse::<i64>().is_ok_and(|s| s <= 0)
                })
            });
            self.cookies.retain(|(h, n, _)| !(h == host && n == k));
            if !delete && self.cookies.len() < MAX_COOKIES {
                self.cookies.push((host.to_string(), k.to_string(), v.to_string()));
            }
        }
    }

    /// `Cookie` header value for a request to `host`.
    pub fn header(&self, host: &str) -> Option<String> {
        let pairs: Vec<String> =
            self.cookies.iter().filter(|(h, _, _)| h == host).map(|(_, n, v)| format!("{}={}", n, v)).collect();
        (!pairs.is_empty()).then(|| pairs.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_cookies(values: &[&str]) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: values.iter().map(|v| ("set-cookie".to_string(), v.to_string())).collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn stores_replaces_deletes_per_host() {
        let mut jar = CookieJar::default();
        jar.store("a", &set_cookies(&["JSESSIONID=abc; Path=/; HttpOnly", "lang=zh"]));
        jar.store("b", &set_cookies(&["other=1"]));
        assert_eq!(jar.header("a").as_deref(), Some("JSESSIONID=abc; lang=zh"));
        assert_eq!(jar.header("b").as_deref(), Some("other=1"));
        jar.store("a", &set_cookies(&["JSESSIONID=def", "lang=x; Max-Age=0", "bad", "=x"]));
        assert_eq!(jar.header("a").as_deref(), Some("JSESSIONID=def"));
        assert_eq!(jar.header("c"), None);
        assert_eq!(format!("{:?}", jar), "CookieJar(2 cookies)");
    }
}
