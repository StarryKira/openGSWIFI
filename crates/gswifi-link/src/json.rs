//! A JSON writer for the machine-readable outputs (`--json`, the status
//! files read by front ends such as the LuCI app).
//!
//! Those outputs are small and flat, and the workspace deliberately has no
//! JSON dependency (the binary is built for size), so this only knows how
//! to escape strings and join members. It never parses.

use std::fmt::Display;

/// `s` as a JSON string literal, quotes included.
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Other control characters, and the two line separators that
            // are valid JSON but break JavaScript string literals.
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `[a,b,c]` from already encoded values.
pub fn array<I: IntoIterator<Item = String>>(items: I) -> String {
    let mut out = String::from("[");
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&item);
    }
    out.push(']');
    out
}

/// Builds one JSON object, member by member.
#[derive(Clone, Debug, Default)]
pub struct Object {
    buf: String,
}

impl Object {
    pub fn new() -> Self {
        Object::default()
    }

    /// Adds a member whose value is already JSON (a nested object, an
    /// array, `null`).
    pub fn raw(mut self, key: &str, json: &str) -> Self {
        self.buf.push(if self.buf.is_empty() { '{' } else { ',' });
        self.buf.push_str(&string(key));
        self.buf.push(':');
        self.buf.push_str(json);
        self
    }

    pub fn str(self, key: &str, value: &str) -> Self {
        let value = string(value);
        self.raw(key, &value)
    }

    /// A string, or `null`.
    pub fn opt_str(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(v) => self.str(key, v),
            None => self.raw(key, "null"),
        }
    }

    /// An integer (anything whose `Display` is a JSON number).
    pub fn num<N: Display>(self, key: &str, value: N) -> Self {
        let value = value.to_string();
        self.raw(key, &value)
    }

    /// An integer, or `null`.
    pub fn opt_num<N: Display>(self, key: &str, value: Option<N>) -> Self {
        match value {
            Some(v) => self.num(key, v),
            None => self.raw(key, "null"),
        }
    }

    pub fn bool(self, key: &str, value: bool) -> Self {
        self.raw(key, if value { "true" } else { "false" })
    }

    pub fn finish(mut self) -> String {
        if self.buf.is_empty() {
            self.buf.push('{');
        }
        self.buf.push('}');
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        assert_eq!(string("plain 中文"), "\"plain 中文\"");
        assert_eq!(string("a\"b\\c"), r#""a\"b\\c""#);
        assert_eq!(string("line1\nline2\r\tend"), r#""line1\nline2\r\tend""#);
        assert_eq!(string("\u{1}\u{1f}"), r#""\u0001\u001f""#);
        assert_eq!(string("\u{2028}"), "\"\\u2028\"");
        // Markup is data, not something to strip: the reader must treat it as text.
        assert_eq!(string("<img src=x onerror=alert(1)>"), "\"<img src=x onerror=alert(1)>\"");
    }

    #[test]
    fn objects_and_arrays() {
        assert_eq!(Object::new().finish(), "{}");
        let o = Object::new()
            .str("name", "ttl4")
            .num("packets", 12u64)
            .bool("ok", true)
            .opt_str("why", None)
            .opt_num("code", Some(3))
            .opt_num::<i32>("none", None)
            .raw("list", &array(["1".to_string(), string("x")]))
            .finish();
        assert_eq!(o, r#"{"name":"ttl4","packets":12,"ok":true,"why":null,"code":3,"none":null,"list":[1,"x"]}"#);
        assert_eq!(array(Vec::new()), "[]");
    }
}
