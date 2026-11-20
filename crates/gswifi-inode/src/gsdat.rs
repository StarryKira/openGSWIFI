//! `inode-gs.dat`: the client check material of the GS H3C branch
//! (research doc 29.6).
//!
//! The file is a sequence of 516-byte records `identifier: BE32 |
//! payload: 512`. A wrapped variant starts with ASCII `GSDAT`; the rest is
//! standard RC4 with the ASCII key `GSNB` and then parses the same way.
//! The original reader (`0x41bd18`) returns the first record whose
//! identifier matches; offset and length are `u8`. The file carries no
//! slice length table. The H3C challenge families 4 and 5 read from it
//! (doc 29.5); no use in the AuthType 1 EAP frames is documented.

use crate::InodeError;

/// Size of one record.
pub const RECORD_SIZE: usize = 516;
/// Size of a record payload.
pub const PAYLOAD_SIZE: usize = 512;
const WRAP_MAGIC: &[u8] = b"GSDAT";
const WRAP_KEY: &[u8] = b"GSNB";

/// Standard RC4 (KSA + PRGA); `key` must not be empty.
pub fn rc4(key: &[u8], data: &[u8]) -> Result<Vec<u8>, InodeError> {
    if key.is_empty() {
        return Err(InodeError::Invalid("RC4 密钥为空"));
    }
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    Ok(data
        .iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect())
}

/// Parsed `inode-gs.dat`.
#[derive(Clone, PartialEq, Eq)]
pub struct GsData {
    /// Unwrapped content, a whole number of records.
    data: Vec<u8>,
}

impl std::fmt::Debug for GsData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GsData({} records)", self.len())
    }
}

impl GsData {
    /// Parses raw or `GSDAT` wrapped file content. The unwrapped size must
    /// be a multiple of 516 (an empty file has no records).
    pub fn parse(file: &[u8]) -> Result<Self, InodeError> {
        let data = match file.strip_prefix(WRAP_MAGIC) {
            Some(rest) => rc4(WRAP_KEY, rest)?,
            None => file.to_vec(),
        };
        if data.len() % RECORD_SIZE != 0 {
            return Err(InodeError::Invalid("inode-gs.dat 长度不是 516 字节记录的整数倍"));
        }
        Ok(GsData { data })
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.data.len() / RECORD_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Identifiers in file order.
    pub fn identifiers(&self) -> impl Iterator<Item = u32> + '_ {
        self.data.chunks_exact(RECORD_SIZE).map(|r| u32::from_be_bytes([r[0], r[1], r[2], r[3]]))
    }

    /// Payload of the first record with `identifier`.
    pub fn record(&self, identifier: u32) -> Option<&[u8]> {
        self.data.chunks_exact(RECORD_SIZE).find(|r| r[..4] == identifier.to_be_bytes()).map(|r| &r[4..])
    }

    /// `payload[offset..offset + length]` of the first record with
    /// `identifier` (`0x41bd18`). With `u8` offset and length the slice
    /// always fits the 512-byte payload; the check is kept explicit.
    pub fn read(&self, identifier: u32, offset: u8, length: u8) -> Result<&[u8], InodeError> {
        let (offset, length) = (offset as usize, length as usize);
        if offset + length > PAYLOAD_SIZE {
            return Err(InodeError::Invalid("inode-gs.dat 读取范围超出 512 字节记录"));
        }
        let payload = self.record(identifier).ok_or(InodeError::MissingRecord(identifier))?;
        Ok(&payload[offset..offset + length])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_known_answer() {
        // RFC 6229 style test: key "Key", plaintext "Plaintext".
        assert_eq!(rc4(b"Key", b"Plaintext").unwrap(), [0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3]);
        assert!(rc4(b"", b"x").is_err());
    }

    #[test]
    fn records_and_bounds() {
        let mut file = vec![0u8; RECORD_SIZE * 2];
        file[..4].copy_from_slice(&7u32.to_be_bytes());
        file[4] = 0xaa;
        file[RECORD_SIZE..RECORD_SIZE + 4].copy_from_slice(&7u32.to_be_bytes());
        let d = GsData::parse(&file).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d.read(7, 0, 1).unwrap(), &[0xaa]);
        // u8 offset + u8 length never leaves the 512-byte payload.
        assert_eq!(d.read(7, 255, 255).unwrap().len(), 255);
        assert_eq!(d.read(8, 0, 1).unwrap_err(), InodeError::MissingRecord(8));
        assert!(GsData::parse(b"bad").is_err());
        assert!(GsData::parse(b"").unwrap().is_empty());
        let wrapped = [WRAP_MAGIC, &rc4(WRAP_KEY, &file).unwrap()].concat();
        assert_eq!(GsData::parse(&wrapped).unwrap(), d);
    }
}
