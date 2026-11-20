//! Portal discovery: classify the probe answer, read the redirect
//! parameters and build the WISPr XML entry URL (cleanroom/07 §1,
//! cleanroom/08 header, docs/05 §5.2).
//!
//! ```text
//! probe   GET http://www.baidu.com            → 302 Location: <portal>?...
//! Hubei   http://<host>/?userip=<ip>&wlanacname=<ac>&nasip=<nas>&usermac=<mac>&aidcauthtype=0
//! Yunnan  http://<host>/?wlanacname=<ac>&wlanuserip=<ip>
//! ```
//!
//! Differences from the firmware, all deliberate (docs/05 §5.2): any 3xx
//! with a `Location` is a redirect, not only `HTTP/1.x 302` followed by the
//! literal `Location: http://`; the header name is case-insensitive;
//! relative locations are resolved against the request URL; ports are kept;
//! query names are matched whole (the firmware's substring search would find
//! `userip=` inside `wlanuserip=`) and case-insensitively. Parameter values
//! are re-emitted exactly as the redirect encoded them, so no
//! decode/re-encode round trip can alter them.

use std::fmt;

use gswifi_core::HttpResponse;

use crate::hubei::{AIDC_AUTH_TYPE, DISCOVERY_PARAMS};
use crate::url::{form_decode_lossy, Url, UrlError};

/// Default connectivity probe (cleanroom/07 §1, docs/05 §5.2).
pub const DEFAULT_PROBE_URL: &str = "http://www.baidu.com/";

/// What the probe answer means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// 2xx: the request reached its destination, nothing intercepted it.
    NotIntercepted,
    /// 3xx with a `Location`, resolved against the request URL.
    Redirect(Url),
    /// Anything else (4xx/5xx, 3xx without or with an unusable `Location`).
    Failed(String),
}

/// Classifies the answer to a probe sent to `request_url`.
pub fn classify_probe(request_url: &Url, response: &HttpResponse) -> ProbeOutcome {
    match response.status {
        200..=299 => ProbeOutcome::NotIntercepted,
        301 | 302 | 303 | 307 | 308 => match response.header("Location").map(str::trim) {
            Some(location) if !location.is_empty() => match request_url.join(location) {
                Ok(url) => ProbeOutcome::Redirect(url),
                Err(e) => ProbeOutcome::Failed(format!("HTTP {} 跳转地址无效: {}", response.status, e)),
            },
            _ => ProbeOutcome::Failed(format!("HTTP {} 没有 Location", response.status)),
        },
        status => ProbeOutcome::Failed(format!("HTTP {}", status)),
    }
}

/// A redirect looks like a portal redirect when it carries `wlanacname`,
/// the parameter both families read.
pub fn is_portal_redirect(url: &Url) -> bool {
    url.raw_query_value("wlanacname").is_some()
}

/// One redirect parameter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    /// As found in the redirect (percent-encoding kept, already normalized
    /// to RFC 3986 characters by [`Url::parse`]).
    pub raw: String,
    /// Form-decoded text, for display and checks.
    pub value: String,
}

impl Param {
    fn from_raw(raw: &str) -> Param {
        Param { raw: raw.to_string(), value: form_decode_lossy(raw) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    /// A parameter the entry URL needs is absent or empty. The client never
    /// substitutes a guess (gaps.md convention 3).
    MissingParam(&'static str),
    Url(UrlError),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::MissingParam(p) => write!(f, "Portal 跳转地址缺少参数 {}", p),
            DiscoveryError::Url(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DiscoveryError {}

fn required(url: &Url, name: &'static str) -> Result<Param, DiscoveryError> {
    match url.raw_query_value(name) {
        Some(raw) if !form_decode_lossy(raw).trim().is_empty() => Ok(Param::from_raw(raw)),
        _ => Err(DiscoveryError::MissingParam(name)),
    }
}

fn optional(url: &Url, name: &str) -> Option<Param> {
    url.raw_query_value(name).map(Param::from_raw)
}

/// Authority for an entry URL built from a redirect: its host, plus its
/// port when the redirect itself was plain HTTP (an `https` port is not an
/// HTTP port).
pub fn entry_authority(redirect: &Url) -> String {
    if redirect.is_http() {
        redirect.authority()
    } else {
        redirect.host().to_string()
    }
}

/// Hubei redirect parameters (cleanroom/08 header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubeiDiscovery {
    /// The resolved redirect target.
    pub redirect: Url,
    pub userip: Param,
    pub wlanacname: Param,
    pub nasip: Param,
    pub usermac: Param,
    /// `aidcauthtype` of the redirect, if any; the entry URL always sends
    /// [`AIDC_AUTH_TYPE`] as the spec gives it.
    pub aidcauthtype: Option<Param>,
}

impl HubeiDiscovery {
    /// Reads the four mandatory parameters of [`DISCOVERY_PARAMS`].
    pub fn from_redirect(redirect: &Url) -> Result<HubeiDiscovery, DiscoveryError> {
        let [ip, ac, nas, mac] = DISCOVERY_PARAMS;
        Ok(HubeiDiscovery {
            userip: required(redirect, ip)?,
            wlanacname: required(redirect, ac)?,
            nasip: required(redirect, nas)?,
            usermac: required(redirect, mac)?,
            aidcauthtype: optional(redirect, "aidcauthtype"),
            redirect: redirect.clone(),
        })
    }

    /// `http://<authority>/?userip=..&wlanacname=..&nasip=..&usermac=..&aidcauthtype=0`.
    pub fn entry_url(&self, authority: &str) -> Result<Url, UrlError> {
        Url::parse(&format!(
            "http://{}/?userip={}&wlanacname={}&nasip={}&usermac={}&aidcauthtype={}",
            authority, self.userip.raw, self.wlanacname.raw, self.nasip.raw, self.usermac.raw, AIDC_AUTH_TYPE
        ))
    }
}

/// Yunnan redirect parameters (cleanroom/07 §1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YunnanDiscovery {
    pub redirect: Url,
    pub wlanacname: Param,
    pub wlanuserip: Param,
}

impl YunnanDiscovery {
    pub fn from_redirect(redirect: &Url) -> Result<YunnanDiscovery, DiscoveryError> {
        Ok(YunnanDiscovery {
            wlanacname: required(redirect, "wlanacname")?,
            wlanuserip: required(redirect, "wlanuserip")?,
            redirect: redirect.clone(),
        })
    }

    /// `http://<authority>/?wlanacname=..&wlanuserip=..`.
    pub fn entry_url(&self, authority: &str) -> Result<Url, UrlError> {
        Url::parse(&format!(
            "http://{}/?wlanacname={}&wlanuserip={}",
            authority, self.wlanacname.raw, self.wlanuserip.raw
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, headers: &[(&str, &str)]) -> HttpResponse {
        HttpResponse {
            status,
            headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            body: Vec::new(),
        }
    }

    fn probe() -> Url {
        Url::parse(DEFAULT_PROBE_URL).unwrap()
    }

    #[test]
    fn probe_classification() {
        assert_eq!(classify_probe(&probe(), &response(200, &[])), ProbeOutcome::NotIntercepted);
        assert_eq!(classify_probe(&probe(), &response(204, &[])), ProbeOutcome::NotIntercepted);
        let r = classify_probe(&probe(), &response(302, &[("LOCATION", " /portal?wlanacname=ac ")]));
        assert_eq!(r, ProbeOutcome::Redirect(Url::parse("http://www.baidu.com/portal?wlanacname=ac").unwrap()));
        let r = classify_probe(&probe(), &response(307, &[("location", "HTTP://10.0.0.1:8080/x")]));
        assert_eq!(r, ProbeOutcome::Redirect(Url::parse("http://10.0.0.1:8080/x").unwrap()));
        assert!(matches!(classify_probe(&probe(), &response(302, &[])), ProbeOutcome::Failed(_)));
        assert!(matches!(
            classify_probe(&probe(), &response(302, &[("Location", "http://[x/")])),
            ProbeOutcome::Failed(_)
        ));
        assert!(matches!(classify_probe(&probe(), &response(304, &[("Location", "/x")])), ProbeOutcome::Failed(_)));
        assert!(matches!(classify_probe(&probe(), &response(500, &[])), ProbeOutcome::Failed(_)));
    }

    #[test]
    fn hubei_parameters_and_entry_url() {
        let redirect = Url::parse(
            "http://58.53.199.1:8080/portal/index.jsp?UserIP=10.1.2.3&wlanacname=HB%2DWH%2DME60&nasip=58.53.1.1\
             &usermac=02:00:00:00:00:01&aidcauthtype=1&wlanuserip=9.9.9.9",
        )
        .unwrap();
        assert!(is_portal_redirect(&redirect));
        let d = HubeiDiscovery::from_redirect(&redirect).unwrap();
        assert_eq!(d.userip.value, "10.1.2.3");
        assert_eq!(d.wlanacname.raw, "HB%2DWH%2DME60");
        assert_eq!(d.wlanacname.value, "HB-WH-ME60");
        assert_eq!(d.usermac.value, "02:00:00:00:00:01");
        assert_eq!(d.aidcauthtype.as_ref().unwrap().value, "1");
        let entry = d.entry_url(&entry_authority(&redirect)).unwrap();
        assert_eq!(
            entry.to_string(),
            "http://58.53.199.1:8080/?userip=10.1.2.3&wlanacname=HB%2DWH%2DME60&nasip=58.53.1.1\
             &usermac=02:00:00:00:00:01&aidcauthtype=0"
        );
        // An https redirect keeps the host but not its port.
        let https = Url::parse("https://portal.example:8443/?x").unwrap();
        assert_eq!(entry_authority(&https), "portal.example");
    }

    #[test]
    fn missing_or_empty_parameters_are_errors() {
        let url = Url::parse("http://h/?userip=1.2.3.4&wlanacname=ac&usermac=m").unwrap();
        assert_eq!(HubeiDiscovery::from_redirect(&url), Err(DiscoveryError::MissingParam("nasip")));
        let url = Url::parse("http://h/?userip=1.2.3.4&wlanacname=ac&nasip=+&usermac=m").unwrap();
        assert_eq!(HubeiDiscovery::from_redirect(&url), Err(DiscoveryError::MissingParam("nasip")));
        // `wlanuserip` is not `userip`.
        let url = Url::parse("http://h/?wlanuserip=1.2.3.4&wlanacname=ac&nasip=n&usermac=m").unwrap();
        assert_eq!(HubeiDiscovery::from_redirect(&url), Err(DiscoveryError::MissingParam("userip")));
        assert!(!is_portal_redirect(&Url::parse("http://h/?ac=1").unwrap()));
    }

    #[test]
    fn yunnan_parameters_and_entry_url() {
        let redirect = Url::parse("http://222.1.1.1/a?wlanuserip=10.0.0.9&wlanacname=YN%20AC").unwrap();
        let d = YunnanDiscovery::from_redirect(&redirect).unwrap();
        assert_eq!(d.wlanacname.value, "YN AC");
        assert_eq!(
            d.entry_url(&entry_authority(&redirect)).unwrap().to_string(),
            "http://222.1.1.1/?wlanacname=YN%20AC&wlanuserip=10.0.0.9"
        );
        let url = Url::parse("http://h/?wlanacname=ac").unwrap();
        assert_eq!(YunnanDiscovery::from_redirect(&url), Err(DiscoveryError::MissingParam("wlanuserip")));
    }
}
