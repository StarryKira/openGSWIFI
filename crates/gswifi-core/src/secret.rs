use std::fmt;

use serde::{Deserialize, Deserializer};

/// A password or derived credential. `Debug` never prints it and the
/// memory is overwritten on drop (doc 01.4: passwords leak through logs,
/// `ps` and config dumps).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Secret(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Secret(value.to_owned())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8.
        for b in unsafe { self.0.as_bytes_mut() } {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Secret)
    }
}

/// Account of one session.
#[derive(Clone, Debug, Default)]
pub struct Credentials {
    pub username: String,
    pub password: Secret,
}

impl Credentials {
    pub fn new(username: impl Into<String>, password: impl Into<Secret>) -> Self {
        Credentials { username: username.into(), password: password.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let c = Credentials::new("user", "hunter2");
        let shown = format!("{:?}", c);
        assert!(shown.contains("user"));
        assert!(!shown.contains("hunter2"));
        assert_eq!(c.password.expose(), "hunter2");
    }
}
