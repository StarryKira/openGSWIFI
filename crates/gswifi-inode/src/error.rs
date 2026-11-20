use std::fmt;

/// Errors of the iNode primitives and material loaders. `Display` texts
/// are Chinese because they end up in user facing logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InodeError {
    /// Input violates a documented precondition (length, alignment, ...).
    Invalid(&'static str),
    /// The text is not canonical Base64.
    Base64,
    /// `DecodeINodeP` padding byte is inconsistent (doc 25.4).
    Padding,
    /// `inode-gs.dat` has no record with this identifier (doc 29.6).
    MissingRecord(u32),
    /// Reading a configured file failed.
    Io { path: String, reason: String },
}

impl fmt::Display for InodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InodeError::Invalid(what) => write!(f, "iNode 数据无效：{}", what),
            InodeError::Base64 => f.write_str("iNode 版本文件不是有效的 Base64 文本"),
            InodeError::Padding => f.write_str("iNode 版本文件解码后的填充字节不一致"),
            InodeError::MissingRecord(id) => write!(f, "inode-gs.dat 中没有编号为 {:#010x} 的记录", id),
            InodeError::Io { path, reason } => write!(f, "读取文件 {} 失败：{}", path, reason),
        }
    }
}

impl std::error::Error for InodeError {}
