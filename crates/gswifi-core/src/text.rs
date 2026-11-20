//! Text helpers for server messages.

use encoding_rs::GBK;

/// Decodes a GBK server message up to the first NUL, trailing whitespace
/// removed. Chinese campus servers send GBK almost without exception.
pub fn gbk(text: &[u8]) -> String {
    let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
    GBK.decode(&text[..end]).0.trim_end().to_string()
}

/// Lower case hex of the first `max` bytes, for trace logs.
pub fn hex_head(data: &[u8], max: usize) -> String {
    data.iter().take(max).map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gbk_stops_at_nul() {
        // "认证成功" in GBK, NUL, garbage.
        let bytes = [0xc8, 0xcf, 0xd6, 0xa4, 0xb3, 0xc9, 0xb9, 0xa6, b' ', 0, 0xff];
        assert_eq!(gbk(&bytes), "认证成功");
        assert_eq!(hex_head(&[1, 2, 0xab], 2), "0102");
    }
}
