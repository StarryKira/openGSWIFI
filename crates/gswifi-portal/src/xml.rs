//! Minimal, safe XML reader for WISPr gateway messages.
//!
//! The portal answers with a `WISPAccessGatewayParam` document, either as
//! the whole body or embedded in an HTML page (usually inside a comment).
//! The firmware checks the root and fields explicitly with libxml2
//! (cleanroom/07 §1, docs/05 §5.2); this reader does the same on the located
//! element only. It understands elements, text, CDATA, comments, processing
//! instructions and the five predefined plus numeric character references.
//! It refuses any DTD and any other entity, so no external entity can ever
//! be resolved (cleanroom/07 §1 "禁止 XML 外部实体与 DTD 访问").

use std::fmt;

/// Deepest nesting accepted; WISPr messages are three levels deep.
const MAX_DEPTH: usize = 16;

/// One element: its name, the concatenation of its direct text (entities
/// decoded) and its child elements. Attributes are skipped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    pub text: String,
    pub children: Vec<Element>,
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

impl Element {
    /// Local name without a namespace prefix.
    pub fn local_name(&self) -> &str {
        local_name(&self.name)
    }

    /// First child with this local name (ASCII case-insensitive).
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.local_name().eq_ignore_ascii_case(name))
    }

    /// Trimmed text of the first such child; `None` when absent or empty.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.trim()).filter(|t| !t.is_empty())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XmlError {
    /// No element of that name in the document.
    NotFound(String),
    /// Input ended inside an element.
    Eof,
    /// Malformed markup at a byte offset.
    Syntax(usize),
    /// Closing tag does not match.
    Mismatch {
        open: String,
        close: String,
    },
    /// Entity other than the predefined/numeric ones.
    Entity(String),
    /// `<!DOCTYPE` or another declaration inside the message.
    Dtd,
    TooDeep,
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XmlError::NotFound(n) => write!(f, "没有 <{}> 元素", n),
            XmlError::Eof => f.write_str("XML 不完整"),
            XmlError::Syntax(at) => write!(f, "XML 语法错误（第 {} 字节）", at),
            XmlError::Mismatch { open, close } => write!(f, "XML 标签不匹配: <{}> 与 </{}>", open, close),
            XmlError::Entity(e) => write!(f, "不支持的 XML 实体 &{};", e),
            XmlError::Dtd => f.write_str("拒绝含 DTD 的 XML"),
            XmlError::TooDeep => f.write_str("XML 嵌套过深"),
        }
    }
}

impl std::error::Error for XmlError {}

/// Byte offset of the first `<name` start tag (local name compared ASCII
/// case-insensitively, prefix allowed).
fn find_start_tag(doc: &str, name: &str) -> Option<usize> {
    let bytes = doc.as_bytes();
    let mut from = 0;
    while let Some(i) = doc[from..].find('<').map(|i| i + from) {
        let rest = &doc[i + 1..];
        let end = rest.find(|c: char| c.is_whitespace() || c == '/' || c == '>').unwrap_or(rest.len());
        if end > 0 && end < rest.len() && local_name(&rest[..end]).eq_ignore_ascii_case(name) {
            return Some(i);
        }
        from = i + 1;
        if from >= bytes.len() {
            break;
        }
    }
    None
}

/// Locates the element `root` anywhere in `doc` and parses it.
pub fn find_element(doc: &str, root: &str) -> Result<Element, XmlError> {
    let start = find_start_tag(doc, root).ok_or_else(|| XmlError::NotFound(root.to_string()))?;
    let mut parser = Parser { doc, pos: start, depth: 0 };
    parser.element()
}

struct Parser<'a> {
    doc: &'a str,
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.doc[self.pos..]
    }

    fn skip_past(&mut self, terminator: &str) -> Result<&str, XmlError> {
        let rest = &self.doc[self.pos..];
        let i = rest.find(terminator).ok_or(XmlError::Eof)?;
        self.pos += i + terminator.len();
        Ok(&rest[..i])
    }

    fn name(&mut self) -> Result<String, XmlError> {
        let rest = self.rest();
        let end = rest.find(|c: char| c.is_whitespace() || c == '/' || c == '>').unwrap_or(rest.len());
        if end == 0 {
            return Err(XmlError::Syntax(self.pos));
        }
        let name = rest[..end].to_string();
        self.pos += end;
        Ok(name)
    }

    fn element(&mut self) -> Result<Element, XmlError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(XmlError::TooDeep);
        }
        if !self.rest().starts_with('<') {
            return Err(XmlError::Syntax(self.pos));
        }
        self.pos += 1;
        let mut element = Element { name: self.name()?, ..Default::default() };
        // Attributes: skipped, honouring quotes so a '>' inside one is fine.
        loop {
            let rest = self.rest();
            if rest.is_empty() {
                return Err(XmlError::Eof);
            }
            if rest.starts_with("/>") {
                self.pos += 2;
                self.depth -= 1;
                return Ok(element);
            }
            let c = rest.as_bytes()[0];
            match c {
                b'>' => {
                    self.pos += 1;
                    break;
                }
                b'"' | b'\'' => {
                    self.pos += 1;
                    self.skip_past(if c == b'"' { "\"" } else { "'" })?;
                }
                b'<' => return Err(XmlError::Syntax(self.pos)),
                _ => self.pos += rest.chars().next().map_or(1, char::len_utf8),
            }
        }
        // Content.
        loop {
            let rest = self.rest();
            if rest.is_empty() {
                return Err(XmlError::Eof);
            }
            if rest.starts_with("</") {
                self.pos += 2;
                let close = self.name()?;
                let tail = self.rest();
                let gt = tail.find('>').ok_or(XmlError::Eof)?;
                if !tail[..gt].trim().is_empty() {
                    return Err(XmlError::Syntax(self.pos));
                }
                self.pos += gt + 1;
                if !close.eq_ignore_ascii_case(&element.name) {
                    return Err(XmlError::Mismatch { open: element.name, close });
                }
                self.depth -= 1;
                return Ok(element);
            } else if rest.starts_with("<!--") {
                self.pos += 4;
                self.skip_past("-->")?;
            } else if rest.starts_with("<![CDATA[") {
                self.pos += 9;
                let data = self.skip_past("]]>")?.to_string();
                element.text.push_str(&data);
            } else if rest.starts_with("<?") {
                self.pos += 2;
                self.skip_past("?>")?;
            } else if rest.starts_with("<!") {
                return Err(XmlError::Dtd);
            } else if rest.starts_with('<') {
                let child = self.element()?;
                element.children.push(child);
            } else {
                let end = rest.find('<').unwrap_or(rest.len());
                let raw = &rest[..end];
                element.text.push_str(&decode_entities(raw)?);
                self.pos += end;
            }
        }
    }
}

/// Decodes `&lt; &gt; &amp; &quot; &apos; &#N; &#xH;`; anything else fails.
pub fn decode_entities(raw: &str) -> Result<String, XmlError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        let semi =
            tail.find(';').filter(|&n| n <= 10).ok_or_else(|| XmlError::Entity(tail.chars().take(10).collect()))?;
        let name = &tail[..semi];
        let ch = match name {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(hex) = name.strip_prefix("#x").or_else(|| name.strip_prefix("#X")) {
                    u32::from_str_radix(hex, 16).ok()
                } else if let Some(dec) = name.strip_prefix('#') {
                    dec.parse::<u32>().ok()
                } else {
                    None
                };
                code.filter(|&c| c != 0).and_then(char::from_u32).ok_or_else(|| XmlError::Entity(name.to_string()))?
            }
        };
        out.push(ch);
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_elements_text_and_entities() {
        let doc = r#"<?xml version="1.0"?>
<WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" a='x>y'>
  <Redirect>
    <LoginURL>http://h/login?a=1&amp;b=2</LoginURL>
    <!-- comment <LoginURL>evil</LoginURL> -->
    <Empty/>
    <MessageType>100</MessageType>
    <Note><![CDATA[<raw & text>]]> &#x6e56;&#21271;</Note>
  </Redirect>
</WISPAccessGatewayParam>"#;
        let root = find_element(doc, "wispaccessgatewayparam").unwrap();
        let redirect = root.child("redirect").unwrap();
        assert_eq!(redirect.child_text("LoginURL"), Some("http://h/login?a=1&b=2"));
        assert_eq!(redirect.children.iter().filter(|c| c.name == "LoginURL").count(), 1);
        assert_eq!(redirect.child_text("Empty"), None);
        assert!(redirect.child("Empty").is_some());
        assert_eq!(redirect.child_text("MessageType"), Some("100"));
        assert_eq!(redirect.child_text("Note"), Some("<raw & text> 湖北"));
    }

    #[test]
    fn finds_the_element_embedded_in_html() {
        let doc = "<html><head><title>x</title></head><body>\n<!--<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                   <WISPAccessGatewayParam><AuthenticationReply><ResponseCode>50</ResponseCode>\
                   </AuthenticationReply></WISPAccessGatewayParam>-->\n</body></html>";
        let root = find_element(doc, "WISPAccessGatewayParam").unwrap();
        assert_eq!(root.child("AuthenticationReply").unwrap().child_text("ResponseCode"), Some("50"));
        // A prefixed name or a different case still matches; a longer name does not.
        assert!(find_element("<w:Root><a>1</a></w:Root>", "root").is_ok());
        assert_eq!(find_element("<RootX/>", "Root"), Err(XmlError::NotFound("Root".into())));
    }

    #[test]
    fn refuses_dtd_and_unknown_entities() {
        assert_eq!(
            find_element("<r><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><a>&e;</a></r>", "r"),
            Err(XmlError::Dtd)
        );
        assert_eq!(find_element("<r>&e;</r>", "r"), Err(XmlError::Entity("e".into())));
        assert_eq!(find_element("<r>&#0;</r>", "r"), Err(XmlError::Entity("#0".into())));
        assert!(matches!(find_element("<r>& x</r>", "r"), Err(XmlError::Entity(_))));
        // Content before the root, including a DOCTYPE, is never processed.
        assert!(find_element("<!DOCTYPE html><r>ok</r>", "r").is_ok());
    }

    #[test]
    fn malformed_input() {
        assert_eq!(
            find_element("<r><a>1</b></r>", "r"),
            Err(XmlError::Mismatch { open: "a".into(), close: "b".into() })
        );
        assert_eq!(find_element("<r><a>1</a>", "r"), Err(XmlError::Eof));
        assert_eq!(find_element("<r", "r"), Err(XmlError::NotFound("r".into())));
        assert_eq!(find_element("<r a=\"x", "r"), Err(XmlError::Eof));
        assert_eq!(find_element("<r><!-- x </r>", "r"), Err(XmlError::Eof));
        let deep = format!("{}{}", "<r>".repeat(40), "</r>".repeat(40));
        assert_eq!(find_element(&deep, "r"), Err(XmlError::TooDeep));
        assert!(find_element("<r>\u{6e56}</r>", "r").is_ok());
    }
}
