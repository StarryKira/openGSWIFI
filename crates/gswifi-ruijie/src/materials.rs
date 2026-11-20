//! Ruijie client materials (research docs 20.3, 25.1): the A/B byte strings
//! and the V2 code the client checks (attributes 0x17 and 0x4d) run over,
//! built from the files of the official Windows client.
//!
//! Like MentoHUST's `DataFile`, the configured path is either a directory or
//! a data file; `8021x.exe`, `W32N55.dll` and `SuConfig.dat` are looked up in
//! that directory. Every format reader checks its bounds: where the original
//! read past a buffer, these return an error instead.

use super::check::mix::{des_dec, DES_KEY_3F72};
use encoding_rs::GBK;
use std::fs;
use std::path::Path;

/// Client files by the role the original loader gives them.
#[derive(Clone, Debug, Default)]
pub struct ClientFiles {
    /// `8021x.exe`
    pub exe: Option<Vec<u8>>,
    /// `W32N55.dll`
    pub dll: Option<Vec<u8>>,
    /// `SuConfig.dat`
    pub suconfig: Option<Vec<u8>>,
    /// The data file itself (ReadCode2 container), when a file was configured.
    pub data: Option<Vec<u8>>,
}

/// Runtime materials after the loader (0x407fcc) and post-processing (0x407d44).
#[derive(Clone, Debug, PartialEq)]
pub struct Materials {
    /// Loader result 2..=5. Only 2 means "V2 only"; 3/4/5 add the mix check.
    /// These are labels of the loader branches, not mix selectors.
    pub check_type: u8,
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    /// What V2 runs over: the first `len(code)` bytes of the processed A,
    /// so an appended Title never reaches it.
    pub v2_code: Vec<u8>,
    /// Which file the code came from, for the log.
    pub source: &'static str,
}

/// B for 449..480 (VA 0x4230b8 without its NUL).
const B_PREFIX_449: &[u8] = b"~!@#$%^&*(";
/// B prefix for 481..498 (VA 0x4230c4 without its NUL).
const B_PREFIX_481: &[u8] = b"~!@#$%^&*(-++=1323223";
/// XOR key of 481..494 (VA 0x422f04); only the first 17 bytes are used.
const XOR_PREFIX: &[u8; 18] = b"xei2112023al;f012a";
/// Offset of the block the fixed-key transform rewrites (495 and later).
const BLOCK_OFFSET: usize = 1024;
/// Most bytes the original decodes from SuConfig.dat.
const SUCONFIG_MAX_OUTPUT: usize = 2048;

fn le16(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// Raw data of the first section whose characteristics have the code or the
/// execute bit (`& 0x20000020`). Like the original, the section table is read
/// at the fixed PE32 position `PE + 248` inside the first 4096 bytes; file
/// offsets are used, not RVAs.
pub fn pe_code(file: &[u8]) -> Result<&[u8], &'static str> {
    const HEAD: usize = 4096;
    if file.len() < HEAD || &file[..2] != b"MZ" {
        return Err("不是 PE 文件或不足 4096 字节");
    }
    let pe = le32(file, 0x3c) as usize;
    if pe + 24 > HEAD || &file[pe..pe + 4] != b"PE\0\0" {
        return Err("PE 头无效");
    }
    for i in 0..le16(file, pe + 6) {
        let s = pe + 248 + i * 40;
        if s + 40 > HEAD {
            return Err("节表超出前 4096 字节");
        }
        let (size, offset, flags) = (le32(file, s + 16) as usize, le32(file, s + 20) as usize, le32(file, s + 36));
        if flags & 0x2000_0020 != 0 {
            return match offset.checked_add(size) {
                Some(end) if size > 0 && end <= file.len() => Ok(&file[offset..end]),
                _ => Err("代码节为空或被截断"),
            };
        }
    }
    Err("没有代码节")
}

/// `dwFileVersionMS` of the version resource (0x40b0a8, doc 19.2), read the
/// way the original does: the last section named `.rsrc` from the table at
/// `PE + 248` inside the first 4096 bytes; in the root directory the
/// `NumberOfIdEntries` entries from the very first one (named entries are
/// not skipped) are searched for RT_VERSION (16); then the first name and
/// the first language; the LE32 at offset 48 of the data (inside a usual
/// `VS_VERSION_INFO`, its `VS_FIXEDFILEINFO.dwFileVersionMS`).
pub fn pe_file_version(file: &[u8]) -> Result<u32, &'static str> {
    const HEAD: usize = 4096;
    const RT_VERSION: u32 = 16;
    if file.len() < HEAD || &file[..2] != b"MZ" {
        return Err("不是 PE 文件或不足 4096 字节");
    }
    let pe = le32(file, 0x3c) as usize;
    if pe + 24 > HEAD || &file[pe..pe + 4] != b"PE\0\0" {
        return Err("PE 头无效");
    }
    let mut rsrc = None;
    for i in (0..le16(file, pe + 6)).rev() {
        let s = pe + 248 + i * 40;
        if s + 40 > HEAD {
            return Err("节表超出前 4096 字节");
        }
        if file[s..s + 8] == *b".rsrc\0\0\0" {
            rsrc = Some(s);
            break;
        }
    }
    let s = rsrc.ok_or("没有 .rsrc 节")?;
    let (rva, size, offset) = (le32(file, s + 12), le32(file, s + 16) as usize, le32(file, s + 20) as usize);
    let data = match offset.checked_add(size) {
        Some(end) if end <= file.len() => &file[offset..end],
        _ => return Err("资源节被截断"),
    };
    // Entry `i` of the directory at `dir`: (name or ID, offset).
    let entry = |dir: usize, i: usize| match dir.checked_add(16 + i * 8) {
        Some(at) if at + 8 <= data.len() => Ok((le32(data, at), le32(data, at + 4) & 0x7fff_ffff)),
        _ => Err("资源目录越界"),
    };
    if data.len() < 16 {
        return Err("资源目录越界");
    }
    let mut names = None;
    for i in 0..le16(data, 14) {
        let (id, dir) = entry(0, i)?;
        if id == RT_VERSION {
            names = Some(dir as usize);
            break;
        }
    }
    let names = names.ok_or("没有版本资源")?;
    let languages = entry(names, 0)?.1 as usize;
    let leaf = entry(languages, 0)?.1 as usize;
    if leaf + 4 > data.len() {
        return Err("资源数据项越界");
    }
    let at = le32(data, leaf).checked_sub(rva).ok_or("版本资源不在 .rsrc 节里")? as usize;
    if at + 52 > data.len() {
        return Err("版本资源被截断");
    }
    Ok(le32(data, at + 48))
}

/// ReadCode2 container: 16 byte header, `n = LE32(h[0..4]) ^ LE32(h[4..8])`,
/// then n bytes of code. Not the format of the DataPackA/B.mpf templates.
pub fn read_code2(file: &[u8]) -> Result<&[u8], &'static str> {
    if file.len() < 16 {
        return Err("数据文件不足 16 字节");
    }
    let n = (le32(file, 0) ^ le32(file, 4)) as usize;
    if n == 0 || n >= 0x8000_0000 || n > file.len() - 16 {
        return Err("数据文件长度字段无效");
    }
    Ok(&file[16..16 + n])
}

/// SuConfig.dat: every byte XOR 0xff, then a small LZ scheme over a 32 KiB
/// table of spaces. Each control byte gives 8 flags, low bit first; with
/// `index = (m << 7) ^ n` a set flag copies `table[index]`, a clear one takes
/// the next input byte and stores it there. Output stops at 2048 bytes.
pub fn decode_suconfig(data: &[u8]) -> Vec<u8> {
    let mut src = data.iter().map(|b| b ^ 0xff);
    let mut table = vec![b' '; 32768];
    let (mut m, mut n) = (0usize, 0usize);
    let mut out = Vec::new();
    while let Some(flags) = src.next() {
        for bit in 0..8 {
            let index = (m << 7) ^ n;
            let v = if flags & (1 << bit) != 0 {
                table[index]
            } else {
                let Some(v) = src.next() else { return out };
                table[index] = v;
                v
            };
            out.push(v);
            if out.len() >= SUCONFIG_MAX_OUTPUT {
                return out;
            }
            (m, n) = (n, v as usize);
        }
    }
    out
}

/// UTF-8 bytes of the `Title=` value of SuConfig.dat (GBK in the file, a
/// single 0x80 is the euro sign), trailing CRs removed. `Ok(None)` without
/// a Title.
pub fn suconfig_title(data: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
    let plain = decode_suconfig(data);
    let plain = plain.split(|&b| b == 0).next().unwrap_or(&[]);
    let Some(start) = plain.windows(6).position(|w| w == b"Title=") else { return Ok(None) };
    let rest = &plain[start + 6..];
    let end = rest.iter().position(|&b| b == b'\n').ok_or("SuConfig.dat 的 Title 行没有换行")?;
    let mut value = &rest[..end];
    while let [head @ .., b'\r'] = value {
        value = head;
    }
    let (text, bad) = GBK.decode_without_bom_handling(value);
    if bad {
        return Err("SuConfig.dat 的 Title 不是有效的 GBK");
    }
    Ok(Some(text.into_owned().into_bytes()))
}

/// The loader 0x407fcc for an algorithm version `major*100+minor`. `Ok(None)`
/// when neither 8021x.exe nor the data file yields code (checktype -1).
/// `ruijie-rp.dat` is not needed: the original goes on to the other files
/// after reading it, and they decide the result.
pub fn assemble_raw(files: &ClientFiles, version: u32) -> Result<Option<Materials>, &'static str> {
    fn pe(file: &Option<Vec<u8>>) -> Option<&[u8]> {
        file.as_deref().and_then(|f| pe_code(f).ok())
    }
    let (code, source) = match (pe(&files.exe), files.data.as_deref().map(read_code2)) {
        (Some(code), _) => (code, "8021x.exe"),
        (None, Some(Ok(code))) => (code, "数据文件"),
        _ => return Ok(None),
    };
    let done = |check_type, b: &[u8]| {
        Ok(Some(Materials { check_type, a: code.to_vec(), b: b.to_vec(), v2_code: code.to_vec(), source }))
    };
    let (check_type, mut b, with_title) = match version {
        200..=299 => return done(2, &[]),
        0..=448 => match pe(&files.dll) {
            None => return done(2, &[]),
            Some(dll) => (3, dll.to_vec(), !(300..=363).contains(&version)),
        },
        449..=480 => (4, B_PREFIX_449.to_vec(), true),
        481..=484 => (5, B_PREFIX_481.to_vec(), true),
        485..=498 => return done(5, B_PREFIX_481),
        _ => return done(5, &[]),
    };
    let mut a = code.to_vec();
    if let (true, Some(su)) = (with_title, files.suconfig.as_deref()) {
        if let Some(title) = suconfig_title(su)? {
            a.extend_from_slice(&title);
            b.extend_from_slice(&title);
        }
    }
    Ok(Some(Materials { check_type, a, b, v2_code: code.to_vec(), source }))
}

/// Post-processing 0x407d44, only for checktype 5; B is left alone.
/// - 481..494: A[0..17] ^= `xei2112023al;f012`
/// - 495 and later: the fixed-key block transform on A[1024..1032]
/// - 499..524: then standard DES-ECB decryption of all of A with `?r^3d)5,`,
///   skipped when A is not whole blocks
///
/// A of at most 1024 bytes has no block at 1024 (the original wrote past
/// it), so the transform is left out; a partial block is an error.
pub fn post_process(m: Materials, version: u32) -> Result<Materials, &'static str> {
    if m.check_type != 5 {
        return Ok(m);
    }
    let mut a = m.a;
    match version {
        481..=494 => {
            if a.len() < 17 {
                return Err("客户端代码不足 17 字节");
            }
            a.iter_mut().zip(&XOR_PREFIX[..17]).for_each(|(x, k)| *x ^= k);
        }
        495.. => {
            if a.len() >= BLOCK_OFFSET + 8 {
                let block: [u8; 8] = a[BLOCK_OFFSET..BLOCK_OFFSET + 8].try_into().unwrap();
                a[BLOCK_OFFSET..BLOCK_OFFSET + 8].copy_from_slice(&block_transform(block));
            } else if a.len() > BLOCK_OFFSET {
                return Err("客户端代码在 1024 处只有半个块");
            }
            if (499..=524).contains(&version) && a.len() % 8 == 0 {
                a = des_dec(&a, &DES_KEY_3F72);
            }
        }
        _ => {}
    }
    let v2_code = a[..m.v2_code.len()].to_vec();
    Ok(Materials { a, v2_code, ..m })
}

/// Loader plus post-processing.
pub fn assemble(files: &ClientFiles, version: u32) -> Result<Materials, &'static str> {
    let raw = assemble_raw(files, version)?.ok_or("没有可用的客户端代码（8021x.exe 或数据文件）")?;
    post_process(raw, version)
}

impl ClientFiles {
    /// Reads the files for a configured directory or data file. File names
    /// are matched without regard to case.
    pub fn load(path: &Path) -> Result<Self, String> {
        let (dir, data) = if path.is_dir() {
            (path, None)
        } else {
            let data = fs::read(path).map_err(|e| format!("读取 {} 失败: {}", path.display(), e))?;
            let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            (dir, Some(data))
        };
        let entries: Vec<_> = fs::read_dir(dir)
            .map_err(|e| format!("读取目录 {} 失败: {}", dir.display(), e))?
            .filter_map(Result::ok)
            .collect();
        let read = |name: &str| -> Result<Option<Vec<u8>>, String> {
            let Some(e) = entries.iter().find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(name)) else {
                return Ok(None);
            };
            fs::read(e.path()).map(Some).map_err(|err| format!("读取 {} 失败: {}", e.path().display(), err))
        };
        Ok(Self { exe: read("8021x.exe")?, dll: read("W32N55.dll")?, suconfig: read("SuConfig.dat")?, data })
    }

    /// Client version `[major, minor]` from 8021x.exe: the low bytes of the
    /// two halves of `dwFileVersionMS`, so 0x0004000a is 4.10. Build and
    /// product version and the version strings are not used (doc 19.2).
    pub fn client_version(&self) -> Result<[u8; 2], &'static str> {
        let w = pe_file_version(self.exe.as_deref().ok_or("没有 8021x.exe")?)?;
        Ok([(w >> 16) as u8, w as u8])
    }
}

// ---- fixed-key block transform (0x418468 key schedule -> 0x41a43c) ----

/// 96 LE32 subkeys as left by 0x418468 for the 24 byte key at VA 0x4230a0
/// (a run-time product, not a table in the ELF), three rounds of 16 pairs.
static SUBKEYS: &[u8; 384] = include_bytes!("check/data/client-des3-keys.bin");
/// 8 SP tables of 64 LE32 (VA 0x42c200). Not interchangeable with the
/// standard DES tables: system 3DES gives other results.
static SP: &[u8; 2048] = include_bytes!("check/data/client-des3-sp.bin");

fn subkey(i: usize) -> u32 {
    le32(SUBKEYS, i * 4)
}

fn sp(table: usize, i: u32) -> u32 {
    le32(SP, (table * 64 + (i & 63) as usize) * 4)
}

fn feistel(r: u32, k1: u32, k2: u32) -> u32 {
    let a = r ^ k1;
    let b = r.rotate_left(28) ^ k2;
    sp(6, a >> 24)
        ^ sp(4, a >> 16)
        ^ sp(2, a >> 8)
        ^ sp(0, a)
        ^ sp(7, b >> 24)
        ^ sp(5, b >> 16)
        ^ sp(3, b >> 8)
        ^ sp(1, b)
}

/// One 16-round pass with the subkeys `pass*32..pass*32+32`; the input is
/// two big-endian words.
fn block_pass(block: [u8; 8], pass: usize) -> [u8; 8] {
    let a0 = u32::from_be_bytes(block[..4].try_into().unwrap());
    let mut a3 = u32::from_be_bytes(block[4..].try_into().unwrap());
    let mut v1 = (a3 << 4 & 0xf0f0_f0f0) ^ a0;
    let mut a2 = v1 >> 4 & 0x0f0f_0f0f;
    a3 ^= a2;
    v1 ^= a3 << 16;
    v1 ^= a3 << 4 & 0xf0f0_f0f0;
    a3 ^= v1 >> 16;
    let mut a1 = (a3 << 16) ^ v1;
    a2 = (a1 << 2 & 0xcccc_cccc) ^ a3;
    a1 ^= a2 >> 2 & 0x3333_3333;
    v1 = (a1 << 2 & 0xcccc_cccc) ^ (a1 << 8 & 0xff00_ff00) ^ a2;
    let mut a0 = (v1 >> 8 & 0x00ff_00ff) ^ a1;
    a2 = (a0 << 8 & 0xff00_ff00) ^ v1;
    v1 = a2.rotate_left(1) ^ (a0 & 0xaaaa_aaaa);
    a0 ^= v1 & 0xaaaa_aaaa;
    v1 ^= a0 & 0xaaaa_aaaa;
    let mut ra = a0.rotate_left(1);
    for i in (0..16).step_by(2) {
        let k = pass * 32 + i * 2;
        ra ^= feistel(v1, subkey(k), subkey(k + 1));
        v1 ^= feistel(ra, subkey(k + 2), subkey(k + 3));
    }
    v1 = v1.rotate_left(31);
    v1 ^= ra & 0xaaaa_aaaa;
    a0 = ra ^ (v1 & 0xaaaa_aaaa);
    v1 ^= a0 & 0xaaaa_aaaa;
    a2 = (v1 << 8 & 0xff00_ff00) ^ a0.rotate_left(31);
    v1 ^= a2 >> 8 & 0x00ff_00ff;
    a1 = (v1 << 8 & 0xff00_ff00) ^ (v1 << 2 & 0xcccc_cccc) ^ a2;
    v1 ^= a1 >> 2 & 0x3333_3333;
    a2 = (v1 << 2 & 0xcccc_cccc) ^ a1 ^ (v1 >> 16);
    a3 = (a2 << 16) ^ v1;
    a2 ^= a3 >> 16;
    a0 = (a3 >> 4 & 0x0f0f_0f0f) ^ a2;
    v1 = (a0 << 4 & 0xf0f0_f0f0) ^ a3;
    a2 = (v1 >> 4 & 0x0f0f_0f0f) ^ a0;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&v1.to_be_bytes());
    out[4..].copy_from_slice(&a2.to_be_bytes());
    out
}

/// The fixed-key transform of one 8 byte block: three passes.
pub fn block_transform(block: [u8; 8]) -> [u8; 8] {
    (0..3).fold(block, block_pass)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::check::mix;
    use crate::packets::{self, Checks, ExtFormat, ExtParams, NetInfo};
    use crate::v2;
    use std::path::PathBuf;

    /// Synthetic client files of the research pack (evidence/compat/fixtures).
    fn fixture(profile: &str) -> ClientFiles {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/check/testdata/materials").join(profile);
        let data = dir.join("default.mpf");
        ClientFiles::load(if data.exists() { &data } else { &dir }).unwrap()
    }

    fn md5hex(b: &[u8]) -> String {
        hex::encode(md5::compute(b).0)
    }

    fn vectors(text: &'static str) -> impl Iterator<Item = Vec<&'static str>> {
        text.lines().filter(|l| !l.starts_with('#')).map(|l| l.split(' ').collect())
    }

    /// 93 calls of the original loader: profiles with/without DLL, SuConfig,
    /// PE (data file only), RP container, and a GBK Title, 18 versions each.
    #[test]
    fn loader_vectors() {
        let mut n = 0;
        for f in vectors(include_str!("check/testdata/material-loader.txt")) {
            let version: u32 = f[1].parse().unwrap();
            let m = assemble_raw(&fixture(f[0]), version).unwrap().unwrap();
            let got = [
                m.check_type.to_string(),
                m.a.len().to_string(),
                m.b.len().to_string(),
                m.v2_code.len().to_string(),
                md5hex(&m.a),
                md5hex(&m.b),
                md5hex(&m.v2_code),
            ];
            assert_eq!(got.as_slice(), &f[2..], "{} {}", f[0], version);
            n += 1;
        }
        assert_eq!(n, 93);
    }

    /// 18 original runs from the files to the MD5 response: post-processed
    /// materials, attribute 0x17 / 0x4d and the whole 1000 byte frame.
    #[test]
    fn integration_vectors() {
        let seed: [u8; 16] = std::array::from_fn(|i| i as u8);
        let net = NetInfo {
            ip: [192, 0, 2, 10],
            mask: [255, 255, 255, 0],
            gateway: [192, 0, 2, 1],
            dns: [198, 51, 100, 53],
            ipv6: [0; 16],
        };
        let p = ExtParams {
            format: ExtFormat::Classic,
            mac: [2, 0, 0, 0, 0, 1],
            net: &net,
            dhcp_mode: 0,
            version: Some([4, 10]),
        };
        let digest = packets::md5_digest(7, b"synthetic", b"", &seed);
        let mut n = 0;
        for f in vectors(include_str!("check/testdata/material-integration.txt")) {
            let version: u32 = f[1].parse().unwrap();
            let m = assemble(&fixture(f[0]), version).unwrap();
            let case = format!("{} {}", f[0], version);
            assert_eq!(
                [m.a.len().to_string(), md5hex(&m.a), md5hex(&m.b), md5hex(&m.v2_code)].as_slice(),
                &f[2..6],
                "{}",
                case
            );

            let field17 = v2::v2_check(&seed, &m.v2_code);
            let field4d = (m.check_type != 2).then(|| mix::family_result(version, &m.a, &m.b, &seed));
            assert_eq!(std::str::from_utf8(&field17).unwrap(), f[6], "{}", case);
            assert_eq!(field4d.as_ref().map(|v| std::str::from_utf8(v).unwrap()).unwrap_or("-"), f[7], "{}", case);

            let checks = Checks { field17: Some(&field17), field4d: field4d.as_ref(), field2f: None };
            let frame = packets::build_password_packet(&[2, 0, 0, 0, 0, 2], &p, checks, b"synthetic", &digest, 7);
            assert_eq!([frame.len().to_string(), md5hex(&frame)].as_slice(), &f[8..], "{}", case);
            n += 1;
        }
        assert_eq!(n, 18);
    }

    /// Original 0x41a43c on one block after 0x418468 (material-keys.log).
    #[test]
    fn block_transform_vector() {
        assert_eq!(hex::encode(block_transform([3, 20, 37, 54, 71, 88, 105, 122])), "7b24347108b99749");
    }

    #[test]
    fn suconfig_decoding() {
        let pe = fixture("pe").suconfig.unwrap();
        assert_eq!(decode_suconfig(&pe), b"[General]\r\nTitle=CampusFixture\r\nOther=abc\r\n");
        assert_eq!(suconfig_title(&pe).unwrap().unwrap(), b"CampusFixture");
        // GBK with a single 0x80 byte (euro sign).
        let cn = fixture("pe-cn").suconfig.unwrap();
        assert_eq!(String::from_utf8(suconfig_title(&cn).unwrap().unwrap()).unwrap(), "校园认证€");
        // Title line without LF.
        let plain = b"Title=x";
        let mut packed = vec![0x00];
        packed.extend_from_slice(plain);
        let packed: Vec<u8> = packed.iter().map(|b| b ^ 0xff).collect();
        assert_eq!(decode_suconfig(&packed), plain);
        assert!(suconfig_title(&packed).is_err());
    }

    #[test]
    fn short_materials_are_rejected() {
        let m = |len: usize| Materials { check_type: 5, a: vec![1; len], b: vec![], v2_code: vec![1; len], source: "" };
        assert!(post_process(m(16), 481).is_err());
        assert!(post_process(m(17), 494).is_ok());
        assert!(post_process(m(1028), 495).is_err());
        assert_eq!(post_process(m(1024), 525).unwrap().a, vec![1; 1024]);
        assert_ne!(post_process(m(1032), 525).unwrap().a[1024..], [1; 8]);
        // 499..524: not whole blocks, no DES (the block at 1024 still changes).
        let odd = post_process(m(1033), 499).unwrap().a;
        assert_eq!((odd[..1024].to_vec(), odd[1032]), (vec![1; 1024], 1));
        // Other check types are left alone.
        let v3 = Materials { check_type: 3, ..m(4) };
        assert_eq!(post_process(v3.clone(), 499).unwrap(), v3);
    }

    /// The synthetic PE32 of tools/p0/pe_version_harness.c: two sections,
    /// a `.rsrc` at file offset 0x1000 / RVA 0x3000 with root -> name ->
    /// language -> data entry -> VS_VERSION_INFO.
    pub(crate) fn version_fixture(ver: u32, with_rsrc: bool, with_version: bool, size: usize) -> Vec<u8> {
        let mut bin = vec![0u8; 0x1200];
        let put16 = |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 2].copy_from_slice(&(v as u16).to_le_bytes());
        let put32 = |b: &mut Vec<u8>, at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        bin[..2].copy_from_slice(b"MZ");
        put32(&mut bin, 0x3c, 0x80);
        bin[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut bin, 0x84, 0x14c);
        put16(&mut bin, 0x86, 2);
        put16(&mut bin, 0x94, 0xe0);
        put16(&mut bin, 0x98, 0x10b);
        bin[0x178..0x17d].copy_from_slice(if with_rsrc { b".rsrc" } else { b".data" });
        put32(&mut bin, 0x180, 0x200);
        put32(&mut bin, 0x184, 0x3000);
        put32(&mut bin, 0x188, 0x200);
        put32(&mut bin, 0x18c, 0x1000);
        bin[0x1a0..0x1a5].copy_from_slice(b".text");
        let r = 0x1000;
        put16(&mut bin, r + 14, 1);
        put32(&mut bin, r + 16, if with_version { 16 } else { 15 });
        put32(&mut bin, r + 20, 0x8000_0020);
        put16(&mut bin, r + 0x20 + 14, 1);
        put32(&mut bin, r + 0x20 + 16, 1);
        put32(&mut bin, r + 0x20 + 20, 0x8000_0040);
        put16(&mut bin, r + 0x40 + 14, 1);
        put32(&mut bin, r + 0x40 + 16, 1033);
        put32(&mut bin, r + 0x40 + 20, 0x60);
        put32(&mut bin, r + 0x60, 0x3080);
        put32(&mut bin, r + 0x64, 92);
        let v = r + 0x80;
        put16(&mut bin, v, 92);
        put16(&mut bin, v + 2, 52);
        for (i, c) in "VS_VERSION_INFO".bytes().enumerate() {
            put16(&mut bin, v + 6 + 2 * i, c as u32);
        }
        put32(&mut bin, v + 40, 0xfeef_04bd);
        put32(&mut bin, v + 44, 0x10000);
        put32(&mut bin, v + 48, ver);
        put32(&mut bin, v + 52, 0x0063_0058);
        put32(&mut bin, v + 56, 0x0008_0007);
        bin.truncate(size);
        bin
    }

    /// Results of the original 0x40b0a8 (evidence/p0/pe-version.log): only
    /// dwFileVersionMS counts, a zero resource value is a valid result.
    #[test]
    fn pe_version_vectors() {
        assert_eq!(pe_file_version(&version_fixture(0x0004_000a, true, true, 0x1200)), Ok(0x0004_000a));
        assert!(pe_file_version(&version_fixture(0x0004_000a, false, true, 0x1200)).is_err());
        assert!(pe_file_version(&version_fixture(0x0004_000a, true, false, 0x1200)).is_err());
        assert!(pe_file_version(&version_fixture(0x0004_000a, true, true, 0x800)).is_err());
        assert_eq!(pe_file_version(&version_fixture(0, true, true, 0x1200)), Ok(0));
        let files = |exe| ClientFiles { exe, ..Default::default() };
        assert_eq!(files(Some(version_fixture(0x0004_000a, true, true, 0x1200))).client_version(), Ok([4, 10]));
        assert_eq!(files(Some(version_fixture(0x0006_002a, true, true, 0x1200))).client_version(), Ok([6, 42]));
        assert!(files(None).client_version().is_err());
        // Truncated resource section and a data entry pointing before it.
        let full = version_fixture(0x0004_000a, true, true, 0x1200);
        assert!(pe_file_version(&full[..0x11ff]).is_err());
        let mut before = full.clone();
        before[0x1060..0x1064].copy_from_slice(&0x2000u32.to_le_bytes());
        assert!(pe_file_version(&before).is_err());
    }

    #[test]
    fn readers_check_bounds() {
        let mut dat = vec![0u8; 16];
        dat[..4].copy_from_slice(&0x1234_0005u32.to_le_bytes());
        dat[4..8].copy_from_slice(&0x1234_0000u32.to_le_bytes());
        dat.extend_from_slice(b"abcdefg");
        assert_eq!(read_code2(&dat), Ok(&b"abcde"[..]));
        dat.truncate(20);
        assert!(read_code2(&dat).is_err());

        let exe = fixture("pe").exe.unwrap();
        let code = pe_code(&exe).unwrap();
        let end = exe.len() - (exe.as_ptr_range().end as usize - code.as_ptr_range().end as usize);
        assert!(pe_code(&exe[..end - 1]).is_err());
        assert!(pe_code(&exe[..4095]).is_err());

        assert_eq!(assemble_raw(&ClientFiles::default(), 410), Ok(None));
        assert!(assemble(&ClientFiles::default(), 410).is_err());
    }
}
