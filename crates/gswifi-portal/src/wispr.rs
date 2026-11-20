//! WISPr gateway messages of the Aidc/NetKeeper portals (cleanroom/07 §1,
//! cleanroom/08 header, docs/05 §5.2).
//!
//! What the firmware evidence fixes (grade F): the root element must be
//! `WISPAccessGatewayParam` (the docs spell it both `WISPAccessGatewayParam`
//! and `WISPaccessGatewayParam`, so names are compared case-insensitively);
//! the entry answer is read for `Redirect` → `LoginURL` / `ConfigURL`; the
//! login answer for `AuthenticationReply` → `ResponseCode` / `ReplyMessage`
//! / `LogoffURL`. Fields are checked explicitly, the body is never searched
//! for "success".
//!
//! What it does not fix: which `ResponseCode` values the Aidc servers send.
//! [`classify_login`] uses the public WISPr 1.0 best-current-practice codes
//! (【补充】, not firmware evidence) and, per the binding gap convention
//! (gaps.md "缺口驱动的默认行为约定" 1), callers must treat everything but
//! success as retryable unless a credential error is explicitly confirmed.

use std::fmt;

use encoding_rs::{Encoding, GBK, UTF_8};

use crate::xml::{self, Element, XmlError};

/// Root element of every gateway message.
pub const ROOT: &str = "WISPAccessGatewayParam";

/// `Redirect` of the entry answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Redirect {
    /// Where to POST the login form; may be relative.
    pub login_url: Option<String>,
    /// Client configuration (`AidcConfig`/`NkConfig`); its container is not
    /// decoded (cleanroom/07 §5), so it is only reported.
    pub config_url: Option<String>,
    pub message_type: Option<u32>,
    pub response_code: Option<u32>,
}

/// `AuthenticationReply` of the login answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthenticationReply {
    pub message_type: Option<u32>,
    pub response_code: Option<u32>,
    pub reply_message: Option<String>,
    pub logoff_url: Option<String>,
}

/// `LogoffReply` (WISPr; not mentioned by the firmware evidence).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogoffReply {
    pub response_code: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Redirect(Redirect),
    AuthenticationReply(AuthenticationReply),
    LogoffReply(LogoffReply),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WisprError {
    /// No `WISPAccessGatewayParam` in the body (an HTML page, an error...).
    NoRoot,
    Xml(XmlError),
    /// The root holds none of the messages this client understands.
    UnknownMessage(Vec<String>),
}

impl fmt::Display for WisprError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WisprError::NoRoot => write!(f, "响应中没有 {} XML", ROOT),
            WisprError::Xml(e) => write!(f, "WISPr XML 无法解析: {}", e),
            WisprError::UnknownMessage(names) => write!(f, "未知的 WISPr 消息: {}", names.join(", ")),
        }
    }
}

impl std::error::Error for WisprError {}

/// Decodes a response body to text: the encoding named in an XML
/// declaration (`encoding="gb2312"` etc., via the WHATWG label table), else
/// UTF-8, else GBK (Chinese portals). Undecodable bytes become U+FFFD.
pub fn decode_body(body: &[u8]) -> String {
    let head = &body[..body.len().min(200)];
    let head = String::from_utf8_lossy(head);
    let declared = head.find("<?xml").and_then(|i| {
        let decl = &head[i..];
        let decl = &decl[..decl.find("?>").unwrap_or(decl.len())];
        let at = decl.find("encoding")?;
        let value = decl[at + 8..].trim_start().strip_prefix('=')?.trim_start();
        let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'')?;
        let value = &value[1..];
        Encoding::for_label(&value.as_bytes()[..value.find(quote)?])
    });
    let encoding = match declared {
        Some(e) => e,
        None if std::str::from_utf8(body).is_ok() => UTF_8,
        None => GBK,
    };
    encoding.decode_with_bom_removal(body).0.into_owned()
}

fn code(e: &Element, name: &str) -> Option<u32> {
    e.child_text(name).and_then(|t| t.parse().ok())
}

fn text(e: &Element, name: &str) -> Option<String> {
    e.child_text(name).map(str::to_string)
}

/// Parses the gateway message in a response body.
pub fn parse(body: &[u8]) -> Result<Message, WisprError> {
    let doc = decode_body(body);
    let root = match xml::find_element(&doc, ROOT) {
        Ok(root) => root,
        Err(XmlError::NotFound(_)) => return Err(WisprError::NoRoot),
        Err(e) => return Err(WisprError::Xml(e)),
    };
    if let Some(r) = root.child("Redirect") {
        return Ok(Message::Redirect(Redirect {
            login_url: text(r, "LoginURL"),
            config_url: text(r, "ConfigURL"),
            message_type: code(r, "MessageType"),
            response_code: code(r, "ResponseCode"),
        }));
    }
    if let Some(r) = root.child("AuthenticationReply") {
        return Ok(Message::AuthenticationReply(AuthenticationReply {
            message_type: code(r, "MessageType"),
            response_code: code(r, "ResponseCode"),
            reply_message: text(r, "ReplyMessage"),
            logoff_url: text(r, "LogoffURL"),
        }));
    }
    if let Some(r) = root.child("LogoffReply") {
        return Ok(Message::LogoffReply(LogoffReply { response_code: code(r, "ResponseCode") }));
    }
    Err(WisprError::UnknownMessage(root.children.iter().map(|c| c.name.clone()).collect()))
}

/// Meaning of an `AuthenticationReply` `ResponseCode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    /// 50, "Login succeeded (Access ACCEPT)".
    Success,
    /// 100, "Login failed (Access REJECT)". Unconfirmed for Aidc servers:
    /// may also mean "already online elsewhere"; retryable by default.
    Rejected,
    /// 201, "Authentication pending": WISPr would poll `LoginResultsURL`,
    /// which the Hubei evidence does not mention.
    Pending,
    /// 102 (AAA server error/timeout), 105 (network administrator error),
    /// 255 (access gateway internal error).
    ServerError,
    /// Missing or any other code.
    Unknown,
}

/// Classifies a login `ResponseCode` by WISPr 1.0 BCP Appendix D
/// (【补充】 standard framework; see module docs).
pub fn classify_login(response_code: Option<u32>) -> LoginOutcome {
    match response_code {
        Some(50) => LoginOutcome::Success,
        Some(100) => LoginOutcome::Rejected,
        Some(201) => LoginOutcome::Pending,
        Some(102 | 105 | 255) => LoginOutcome::ServerError,
        _ => LoginOutcome::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_message() {
        let body = br#"<?xml version="1.0" encoding="UTF-8"?>
<WISPAccessGatewayParam><Redirect><AccessProcedure>1.0</AccessProcedure>
<LoginURL>http://58.53.199.1:8080/portal/login.do?a=1&amp;b=2</LoginURL>
<ConfigURL>http://58.53.199.1:8005/aidcclient/settings/AidcConfig_HB.dat</ConfigURL>
<MessageType>100</MessageType><ResponseCode>0</ResponseCode></Redirect></WISPAccessGatewayParam>"#;
        let Message::Redirect(r) = parse(body).unwrap() else { panic!() };
        assert_eq!(r.login_url.as_deref(), Some("http://58.53.199.1:8080/portal/login.do?a=1&b=2"));
        assert!(r.config_url.unwrap().ends_with("AidcConfig_HB.dat"));
        assert_eq!((r.message_type, r.response_code), (Some(100), Some(0)));
    }

    #[test]
    fn authentication_reply_in_gbk() {
        let mut body = br#"<?xml version="1.0" encoding="gb2312"?><WISPaccessGatewayParam><AuthenticationReply>
<MessageType>120</MessageType><ResponseCode>100</ResponseCode><ReplyMessage>"#
            .to_vec();
        body.extend_from_slice(&GBK.encode("密码错误").0);
        body.extend_from_slice(b"</ReplyMessage></AuthenticationReply></WISPaccessGatewayParam>");
        let Message::AuthenticationReply(r) = parse(&body).unwrap() else { panic!() };
        assert_eq!(r.reply_message.as_deref(), Some("密码错误"));
        assert_eq!(classify_login(r.response_code), LoginOutcome::Rejected);
        assert_eq!(r.logoff_url, None);
    }

    #[test]
    fn undeclared_non_utf8_is_gbk() {
        let mut body =
            b"<WISPAccessGatewayParam><AuthenticationReply><ResponseCode>50</ResponseCode><ReplyMessage>".to_vec();
        body.extend_from_slice(&GBK.encode("认证成功").0);
        body.extend_from_slice(
            b"</ReplyMessage><LogoffURL>/logoff?x=1</LogoffURL></AuthenticationReply></WISPAccessGatewayParam>",
        );
        let Message::AuthenticationReply(r) = parse(&body).unwrap() else { panic!() };
        assert_eq!(r.reply_message.as_deref(), Some("认证成功"));
        assert_eq!(r.logoff_url.as_deref(), Some("/logoff?x=1"));
        assert_eq!(classify_login(r.response_code), LoginOutcome::Success);
    }

    #[test]
    fn non_wispr_bodies() {
        assert_eq!(parse(b"<html><body>success</body></html>"), Err(WisprError::NoRoot));
        assert_eq!(parse(b""), Err(WisprError::NoRoot));
        assert!(matches!(parse(b"<WISPAccessGatewayParam><Redirect>"), Err(WisprError::Xml(XmlError::Eof))));
        assert_eq!(
            parse(b"<WISPAccessGatewayParam><Proxy/></WISPAccessGatewayParam>"),
            Err(WisprError::UnknownMessage(vec!["Proxy".into()]))
        );
        assert_eq!(
            parse(b"<WISPAccessGatewayParam><LogoffReply><ResponseCode>150</ResponseCode></LogoffReply></WISPAccessGatewayParam>"),
            Ok(Message::LogoffReply(LogoffReply { response_code: Some(150) }))
        );
    }

    #[test]
    fn response_codes() {
        assert_eq!(classify_login(Some(50)), LoginOutcome::Success);
        assert_eq!(classify_login(Some(100)), LoginOutcome::Rejected);
        assert_eq!(classify_login(Some(201)), LoginOutcome::Pending);
        for c in [102, 105, 255] {
            assert_eq!(classify_login(Some(c)), LoginOutcome::ServerError);
        }
        assert_eq!(classify_login(Some(0)), LoginOutcome::Unknown);
        assert_eq!(classify_login(None), LoginOutcome::Unknown);
    }
}
