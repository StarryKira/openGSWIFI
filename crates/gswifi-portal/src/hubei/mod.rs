//! 湖北 Aidc WISPr Portal: profiles, protocol constants and the old-Mac
//! credential derivation (cleanroom/08, docs/05 §5.2 and §5.6–5.8).
//!
//! Three separate firmware binaries, three separate password pipelines; only
//! the old Mac one is closed (cleanroom/08 §5). Constants of the other two
//! profiles are recorded for reference but no derivation is offered.

mod fixhbkey;
mod password;

use serde::Deserialize;

pub use fixhbkey::{fix_hb_key, Key128, KeyError, KEY_SALT};
pub use password::{derive_password, rc4, OldMacPassword};

use crate::url::form_encode_pairs;

/// The three Hubei clients, named explicitly.
///
/// `hubei-service.sh` selects them with UCI `usecapture` (docs/01 §1.3):
/// 0 = old Mac, 1 = new Mac, 2 = Android. The LuCI page labels 0 as
/// "hubei mac new" and 1 as "hubei mac old", the opposite of what the
/// script runs; the script is what executes, so [`HubeiProfile::from_usecapture`]
/// follows it. Never identify a profile by the number alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HubeiProfile {
    /// `hubei_mac_web_old`, `ClientVersion: Mdsc`. Closed (cleanroom/08 §1).
    OldMac,
    /// `hubei_mac_web_new`, `ClientVersion: Mswx`. Not closed (§2).
    NewMac,
    /// `hubei_android_web`, user prefix `!^Adcm0`. Not closed (§3).
    Android,
}

impl HubeiProfile {
    /// `old-mac`, `new-mac`, `android`.
    pub fn name(self) -> &'static str {
        match self {
            HubeiProfile::OldMac => "old-mac",
            HubeiProfile::NewMac => "new-mac",
            HubeiProfile::Android => "android",
        }
    }

    pub fn from_name(name: &str) -> Option<HubeiProfile> {
        [HubeiProfile::OldMac, HubeiProfile::NewMac, HubeiProfile::Android].into_iter().find(|p| p.name() == name)
    }

    /// Firmware binary that implements the profile.
    pub fn firmware_binary(self) -> &'static str {
        match self {
            HubeiProfile::OldMac => "/usr/sbin/hubei_mac_web_old",
            HubeiProfile::NewMac => "/usr/sbin/hubei_mac_web_new",
            HubeiProfile::Android => "/usr/sbin/hubei_android_web",
        }
    }

    /// Profile that `/usr/bin/hubei-service.sh` runs for UCI `usecapture`
    /// (docs/01 §1.3; see the type docs for the LuCI label mismatch).
    pub fn from_usecapture(code: u32) -> Option<HubeiProfile> {
        match code {
            0 => Some(HubeiProfile::OldMac),
            1 => Some(HubeiProfile::NewMac),
            2 => Some(HubeiProfile::Android),
            _ => None,
        }
    }
}

/// Query parameters the Hubei clients take from the portal redirect, in
/// the order of the XML entry URL (cleanroom/08 header, docs/05 §5.2).
pub const DISCOVERY_PARAMS: [&str; 4] = ["userip", "wlanacname", "nasip", "usermac"];

/// Fixed `aidcauthtype` value of the entry URL.
pub const AIDC_AUTH_TYPE: &str = "0";

/// Heartbeat magic shared with the Yunnan family (cleanroom/08 §1.3).
pub const HEARTBEAT_MAGIC: &str = "0x214B544E";

/// Old Mac (`hubei_mac_web_old`) constants, cleanroom/08 §1 and §1.3.
pub mod old_mac {
    /// `ClientVersion` request header.
    pub const CLIENT_VERSION: &str = "Mdsc";
    /// Prefix of the login `UserName`.
    pub const USER_PREFIX: &str = "!^Mdsc0";
    /// `OriginatingServer` form field.
    pub const ORIGINATING_SERVER: &str = "http://www.sina.com.cn/";
    /// Heartbeat `nkcversion` (the heartbeat itself is not closed).
    pub const NKC_VERSION: &str = "1.0.2326";
    /// Heartbeat `winversion` (the heartbeat itself is not closed).
    pub const WIN_VERSION: &str = "OSX 10.14.5";
}

/// New Mac (`hubei_mac_web_new`) constants, cleanroom/08 §2. Recorded only:
/// the derivation is not closed.
pub mod new_mac {
    pub const CLIENT_VERSION: &str = "Mswx";
    pub const USER_PREFIX: &str = "!^Mswx0";
    pub const NKC_VERSION: &str = "1.0.2667";
    pub const WIN_VERSION: &str = "OSX10.16.0";
}

/// Android (`hubei_android_web`) constants, cleanroom/08 §3. Recorded only.
pub mod android {
    /// Prefix of `UserName`; the firmware writes it already URL-encoded as
    /// `%21%5E` and it must not be encoded a second time.
    pub const USER_PREFIX: &str = "!^Adcm0";
    /// `AidcAuthAttr` numbers present in the login form; meanings unknown.
    pub const AUTH_ATTRS: [u8; 10] = [1, 3, 4, 5, 6, 7, 8, 15, 22, 23];
}

/// Old-Mac login body (cleanroom/08 §1), form-encoded (WHATWG
/// `application/x-www-form-urlencoded`):
///
/// ```text
/// button=Login&UserName=!^Mdsc0<user>&Password=<derived16>&FNAME=0&OriginatingServer=http://www.sina.com.cn/
/// ```
///
/// `!^` goes out as `%21%5E`, the same bytes the Android binary puts on the
/// wire for its own prefix (cleanroom/08 §3), so the Aidc servers decode
/// percent-encoding in `UserName`. The result contains the derived password:
/// never log it.
pub fn old_mac_login_form(username: &str, derived_password: &str) -> String {
    let user = format!("{}{}", old_mac::USER_PREFIX, username);
    form_encode_pairs(&[
        ("button", "Login"),
        ("UserName", &user),
        ("Password", derived_password),
        ("FNAME", "0"),
        ("OriginatingServer", old_mac::ORIGINATING_SERVER),
    ])
}

/// Full old-Mac derivation: FixHBKey for `mmdd`, then the password chain.
pub fn derive_old_mac(username: &str, password: &[u8], mmdd: &str) -> Result<OldMacPassword, KeyError> {
    Ok(derive_password(password, &fix_hb_key(username, mmdd)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testjson::Json;

    fn s(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap()
    }

    fn testdata(name: &str) -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/");
        std::fs::read_to_string(format!("{}{}", path, name)).unwrap()
    }

    /// 9 FixHBKey vectors (`hubei_oldmac_vectors.json`): m1..m4, ga, gb and
    /// key128 for each.
    #[test]
    fn fixhbkey_golden_vectors() {
        let vectors = Json::parse(&testdata("hubei_oldmac_vectors.json")).unwrap();
        assert_eq!(vectors.arr().len(), 9);
        let mut branches = std::collections::HashSet::new();
        for v in vectors.arr() {
            let (user, mmdd) = (v.get("user").str(), v.get("mmdd").str());
            let t = fixhbkey::trace(user, mmdd).unwrap();
            for (i, name) in ["m1", "m2", "m3", "m4"].iter().enumerate() {
                assert_eq!(s(&t.m[i]), v.get(name).str(), "{} {}", user, name);
            }
            assert_eq!(s(&t.ga), v.get("ga").str(), "{} ga", user);
            assert_eq!(s(&t.gb), v.get("gb").str(), "{} gb", user);
            assert_eq!(s(&t.key), v.get("key128").str(), "{} key128", user);
            assert_eq!(fix_hb_key(user, mmdd).unwrap().expose(), v.get("key128").str());
            branches.insert(t.selectors);
        }
        // cleanroom/08 §1.1: the vectors cover S1/S2/S3 and both zips.
        let seen = |i: usize, v: u8| branches.iter().any(|b| b[i] == v);
        for i in 0..5 {
            assert!(seen(i, 0) && seen(i, 1), "selector {} not covered both ways", i);
        }
    }

    struct LogKey {
        mdata: [(String, String); 4],
        tmp: [(String, String); 4],
        ga: String,
        gb: String,
        sga: String,
        sgb: String,
        key_hex: String,
    }

    fn after<'a>(text: &'a str, tag: &str) -> &'a str {
        let start = text.find(tag).unwrap_or_else(|| panic!("{} missing", tag)) + tag.len();
        text[start..].lines().next().unwrap().trim()
    }

    fn parse_key_log(text: &str) -> LogKey {
        let md = |n: usize| {
            // "mdata1: 0905studentc, [faab...]"
            let line = after(text, &format!("mdata{}: ", n));
            let (input, digest) = line.split_once(", [").unwrap();
            (input.to_string(), digest.trim_end_matches(']').to_string())
        };
        let tmp = |name: &str| (name.to_string(), after(text, &format!("{}_tmp=", name)).to_string());
        LogKey {
            mdata: [md(1), md(2), md(3), md(4)],
            tmp: [tmp("ga1"), tmp("ga2"), tmp("gb1"), tmp("gb2")],
            ga: after(text, "\nga=").to_string(),
            gb: after(text, "\ngb=").to_string(),
            sga: after(text, "sga=").to_string(),
            sgb: after(text, "sgb=").to_string(),
            key_hex: after(text, "key128 len=128 ").to_string(),
        }
    }

    /// The raw harness logs carry more intermediates than the JSON: the
    /// MD5 inputs, the interleaved 32-character buffers ga1/ga2/gb1/gb2 and
    /// the case-mixed sga/sgb. `out_sim.txt` is a tenth key (a realistic
    /// account with a domain, date 1120).
    #[test]
    fn fixhbkey_matches_every_harness_log() {
        let logs = [
            "out_hb1.txt",
            "out_hb2.txt",
            "out_hb3.txt",
            "out_x_aaa.txt",
            "out_x_bb.txt",
            "out_x_longernamedom.txt",
            "out_x_test123x.txt",
            "out_x_u1.txt",
            "out_x_zzq.txt",
            "out_sim.txt",
        ];
        for name in logs {
            let log = parse_key_log(&testdata(&format!("logs/{}", name)));
            // mdata1 = MMDD‖X‖c: recover the inputs from the log itself.
            let m1 = &log.mdata[0].0;
            let (mmdd, x) = (&m1[..4], &m1[4..m1.len() - 1]);
            assert_eq!(log.mdata[1].0, format!("{}c{}", mmdd, x));
            assert_eq!(log.mdata[2].0, format!("{}c{}", x, mmdd));
            assert_eq!(log.mdata[3].0, format!("c{}{}", x, mmdd));
            // A domain after '@' must not change the key.
            let t = fixhbkey::trace(&format!("{}@hubupt", x), mmdd).unwrap();
            for i in 0..4 {
                assert_eq!(s(&t.m[i]), log.mdata[i].1, "{} mdata{}", name, i + 1);
            }
            let bufs = [&t.ga1, &t.ga2, &t.gb1, &t.gb2];
            for (i, (tag, value)) in log.tmp.iter().enumerate() {
                assert_eq!(s(bufs[i]), value, "{} {}", name, tag);
            }
            assert_eq!(s(&t.ga), log.ga, "{} ga", name);
            assert_eq!(s(&t.gb), log.gb, "{} gb", name);
            assert_eq!(s(&t.sga), log.sga, "{} sga", name);
            assert_eq!(s(&t.sgb), log.sgb, "{} sgb", name);
            assert_eq!(hex::encode(t.key), log.key_hex, "{} key128", name);
        }
    }

    /// `hubei_password_vectors.json`: every chain intermediate.
    #[test]
    fn password_chain_golden_vector() {
        let vectors = Json::parse(&testdata("hubei_password_vectors.json")).unwrap();
        assert!(!vectors.arr().is_empty());
        for v in vectors.arr() {
            let key = Key128::from_ascii(v.get("key128").str()).unwrap();
            let t = password::trace(v.get("password").str().as_bytes(), &key);
            assert_eq!(hex::encode(&t.p1_rc4), v.get("p1_rc4").str());
            assert_eq!(s(&t.p1_md5), v.get("p1_md5").str());
            assert_eq!(s(&t.p2), v.get("p2").str());
            assert_eq!(hex::encode(&t.p3_rc4), v.get("p3_rc4").str());
            assert_eq!(s(&t.p3_md5), v.get("p3_md5").str());
            assert_eq!(s(&t.result), v.get("final").str());
            assert_eq!(derive_password(v.get("password").str().as_bytes(), &key).expose(), v.get("final").str());
        }
    }

    fn bracket<'a>(text: &'a str, tag: &str) -> &'a str {
        let line = after(text, tag);
        line.trim_start_matches('[').split(']').next().unwrap()
    }

    /// The three password-chain harness logs. `out_pw1.txt` ran the chain
    /// with the `student@x`/0905 key and "password123" (the RC4 output
    /// decrypts to that password under that key and no other logged key);
    /// only its first pass is meaningful, the repeated "Password2" lines
    /// after the simulated stack check are harness artefacts.
    /// `out_pw2.txt` is the JSON vector; `out_sim_pw.txt` is the account
    /// `2026310488@hubupt` / `Xy9#k2Lt` (the mentohust simulation's
    /// credentials) on 1120, ending with the firmware's 33-byte output.
    #[test]
    fn password_chain_matches_harness_logs() {
        let student = fix_hb_key("student@x", "0905").unwrap();
        let synthetic = Key128::from_ascii(&"0123456789abcdef".repeat(8)).unwrap();
        let sim = fix_hb_key("2026310488@hubupt", "1120").unwrap();
        let cases: [(&str, &Key128, &str, Option<&str>); 3] = [
            ("out_pw1.txt", &student, "password123", None),
            ("out_pw2.txt", &synthetic, "password123", Some("5ebd03cfbd166b4b")),
            ("out_sim_pw.txt", &sim, "Xy9#k2Lt", Some("0e6124a3cb4dec5a")),
        ];
        for (name, key, pw, out33) in cases {
            let log = testdata(&format!("logs/{}", name));
            let t = password::trace(pw.as_bytes(), key);
            assert_eq!(hex::encode(&t.p1_rc4), bracket(&log, "Password1 - RC4: "), "{}", name);
            assert_eq!(s(&t.p1_md5), bracket(&log, "Password1 - MD5: "), "{}", name);
            assert_eq!(s(&t.p2), bracket(&log, "Password2: "), "{}", name);
            assert_eq!(hex::encode(&t.p3_rc4), bracket(&log, "Password3 - RC4: "), "{}", name);
            assert_eq!(s(&t.p3_md5), bracket(&log, "Password3 - MD5: "), "{}", name);
            if let Some(expected) = out33 {
                // OUT33 = the 16 characters plus NUL padding, as hex.
                let dumped = hex::decode(after(&log, "OUT33-AT-CHKFAIL ")).unwrap();
                assert_eq!(&dumped[..16], expected.as_bytes());
                assert!(dumped[16..].iter().all(|&b| b == 0));
                assert_eq!(s(&t.result), expected);
            }
        }
        // out_pw1's final value (P3[8..24] of its first pass).
        assert_eq!(derive_password(b"password123", &student).expose(), "66cd02c602d032fb");
    }

    /// End to end, as the driver uses it: account with domain, raw password
    /// bytes, MMDD.
    #[test]
    fn full_derivation_of_the_simulated_account() {
        let pw = derive_old_mac("2026310488@hubupt", b"Xy9#k2Lt", "1120").unwrap();
        assert_eq!(pw.expose(), "0e6124a3cb4dec5a");
        assert!(!pw.rc4_output_had_nul());
        assert_eq!(format!("{:?}", pw), "OldMacPassword(***)");
        let key = fix_hb_key("2026310488", "1120").unwrap();
        assert_eq!(format!("{:?}", key), "Key128(***)");
        assert!(key.expose().starts_with("9A5c4FEc7668d565"));
    }

    #[test]
    fn rc4_known_answers() {
        // Classic test vectors (Wikipedia / RFC 6229 style).
        assert_eq!(hex::encode(rc4(b"Key", b"Plaintext")), "bbf316e8d940af0ad3");
        assert_eq!(hex::encode(rc4(b"Wiki", b"pedia")), "1021bf0420");
        assert_eq!(hex::encode(rc4(b"Secret", b"Attack at dawn")), "45a01f645fc35b383552544b9bf5");
        assert!(rc4(b"k", b"").is_empty());
    }

    #[test]
    fn nul_in_rc4_output_is_flagged() {
        let key = fix_hb_key("2026310488@hubupt", "1120").unwrap();
        // A password byte equal to the keystream byte encrypts to 0x00.
        let ks = rc4(key.as_bytes(), &[0u8; 4]);
        let pw = [ks[0], b'a', b'b', b'c'];
        assert!(derive_password(&pw, &key).rc4_output_had_nul());
    }

    #[test]
    fn key_input_validation() {
        assert_eq!(fix_hb_key("u", "503").unwrap_err(), KeyError::BadDate);
        assert_eq!(fix_hb_key("u", "05a3").unwrap_err(), KeyError::BadDate);
        assert_eq!(fix_hb_key("u\0", "0503").unwrap_err(), KeyError::Nul);
        assert_eq!(Key128::from_ascii("abc").unwrap_err(), KeyError::BadKey);
        assert_eq!(Key128::from_ascii(&"é".repeat(64)).unwrap_err(), KeyError::BadKey);
        // Empty local part and multiple '@' only use the text before the first.
        assert_eq!(fix_hb_key("a@b@c", "0101").unwrap(), fix_hb_key("a", "0101").unwrap());
        assert!(fix_hb_key("@x", "0101").is_ok());
    }

    #[test]
    fn login_form_encoding() {
        assert_eq!(
            old_mac_login_form("2026310488@hubupt", "0e6124a3cb4dec5a"),
            "button=Login&UserName=%21%5EMdsc02026310488%40hubupt&Password=0e6124a3cb4dec5a&FNAME=0\
             &OriginatingServer=http%3A%2F%2Fwww.sina.com.cn%2F"
        );
        // Separators in the account cannot inject fields.
        assert!(old_mac_login_form("a&Password=x", "p").contains("UserName=%21%5EMdsc0a%26Password%3Dx&"));
    }

    #[test]
    fn profiles_follow_the_service_script() {
        assert_eq!(HubeiProfile::from_usecapture(0), Some(HubeiProfile::OldMac));
        assert_eq!(HubeiProfile::from_usecapture(1), Some(HubeiProfile::NewMac));
        assert_eq!(HubeiProfile::from_usecapture(2), Some(HubeiProfile::Android));
        assert_eq!(HubeiProfile::from_usecapture(3), None);
        for p in [HubeiProfile::OldMac, HubeiProfile::NewMac, HubeiProfile::Android] {
            assert_eq!(HubeiProfile::from_name(p.name()), Some(p));
        }
        assert_eq!(HubeiProfile::OldMac.name(), "old-mac");
        assert!(HubeiProfile::NewMac.firmware_binary().ends_with("hubei_mac_web_new"));
    }
}
