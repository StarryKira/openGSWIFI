use std::env;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    major: usize,
    minor: usize,
    micro: usize,
}

impl Version {
    const LOWEST_SUPPORTED: Self = Self {
        major: 1,
        minor: 0,
        micro: 0,
    };

    fn new(major: usize, minor: usize, micro: usize) -> Version {
        Version {
            major,
            minor,
            micro,
        }
    }

    fn list() -> Vec<Version> {
        vec![
            Version::new(1, 2, 1),
            Version::new(1, 5, 0),
            Version::new(1, 5, 3),
            Version::new(1, 7, 2),
            Version::new(1, 9, 0),
            Version::new(1, 9, 1),
        ]
    }

    fn max() -> Version {
        #[cfg(not(windows))]
        {
            Version::new(1, 9, 1)
        }
        #[cfg(windows)]
        {
            Version::new(1, 0, 0)
        }
    }

    fn docs_rs() -> Version {
        Version::new(2, 0, 0)
    }

    fn parse(s: &str) -> Result<Version, Box<dyn std::error::Error>> {
        let err = format!("invalid pcap lib version: {}", s);

        let re = regex::Regex::new(r"([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(s).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();
        let micro_str = captures.get(3).ok_or_else(|| err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            micro_str.parse::<usize>()?,
        ))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Version {
            major,
            minor,
            micro,
        } = self;
        write!(f, "{}.{}.{}", major, minor, micro)
    }
}

fn get_libpcap_version(libdirpath: Option<PathBuf>) -> Result<Version, Box<dyn std::error::Error>> {
    if std::env::var("DOCS_RS").is_ok() {
        return Ok(Version::docs_rs());
    }

    if let Ok(libver) = env::var("LIBPCAP_VER") {
        return Version::parse(&libver);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    let mut libfile = PathBuf::from("libpcap.so");
    #[cfg(target_os = "macos")]
    let mut libfile = PathBuf::from("libpcap.dylib");
    #[cfg(windows)]
    let mut libfile = PathBuf::from("wpcap.dll");

    if let Some(libdir) = libdirpath {
        libfile = libdir.join(libfile);
    }

    let lib = if let Ok(lib) = unsafe {
        // Loading a shared library is unsafe in the general case since initialization and
        // termination routines could have arbitrary behavior. This is sound as long as the shared
        // library is "well-behaved." See https://github.com/nagisa/rust_libloading/issues/86 and
        // https://github.com/nagisa/rust_libloading/blob/0.8.3/src/changelog.rs#L96-L151 for
        // details.
        libloading::Library::new(libfile)
    } {
        lib
    } else {
        return Ok(Version::max());
    };

    type PcapLibVersion = unsafe extern "C" fn() -> *mut c_char;
    let pcap_lib_version = unsafe { lib.get::<PcapLibVersion>(b"pcap_lib_version")? };

    let c_buf: *const c_char = unsafe { pcap_lib_version() };
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let v_str: &str = c_str.to_str()?;

    let err = format!("cannot infer pcap lib version from: {}", v_str);

    #[cfg(not(windows))]
    {
        let re =
            regex::Regex::new(r"libpcap version ([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(v_str).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();
        let micro_str = captures.get(3).ok_or_else(|| err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            micro_str.parse::<usize>()?,
        ))
    }

    #[cfg(windows)]
    {
        let re = regex::Regex::new(r"based on libpcap version ([[:digit:]]+)\.([[:digit:]]+)")?;
        let captures = re.captures(v_str).ok_or_else(|| err.clone())?;

        let major_str = captures.get(1).ok_or_else(|| err.clone())?.as_str();
        let minor_str = captures.get(2).ok_or_else(|| err.clone())?.as_str();

        Ok(Version::new(
            major_str.parse::<usize>()?,
            minor_str.parse::<usize>()?,
            0,
        ))
    }
}

fn emit_cfg_flags(version: Version) {
    assert!(
        version >= Version::LOWEST_SUPPORTED,
        "required pcap lib version: >=1.0.0"
    );

    for v in Version::list().iter() {
        println!(
            "cargo:rustc-check-cfg=cfg(libpcap_{}_{}_{})",
            v.major, v.minor, v.micro
        );
        if v <= &version {
            println!(
                "cargo:rustc-cfg=libpcap_{}_{}_{}",
                v.major, v.minor, v.micro
            );
        }
    }
}

/// `struct pcap_pkthdr` starts with a `struct timeval`. On 32-bit targets its
/// size depends on the C library libpcap was compiled against: musl >= 1.2
/// (OpenWrt >= 21.02) always uses a 64-bit time_t, while the libc crate still
/// describes the old 32-bit layout. Getting this wrong makes every packet
/// header unreadable, so find out what the target C library does.
///
/// LIBPCAP_TIME64=1/0 overrides the detection.
fn emit_time64_cfg() {
    println!("cargo:rustc-check-cfg=cfg(libpcap_time64)");
    println!("cargo:rerun-if-env-changed=LIBPCAP_TIME64");

    let time64 = match env::var("LIBPCAP_TIME64").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        _ => {
            let width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap_or_default();
            let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

            // 64-bit targets: time_t is 64 bits everywhere, nothing to adjust.
            // glibc: 32-bit time_t unless built with _TIME_BITS=64, which the
            // libc crate cannot express either; leave it alone.
            if width != "32" || target_env != "musl" {
                false
            } else {
                match target_c_has_time64() {
                    Some(v) => v,
                    None => {
                        println!(
                            "cargo:warning=cannot run the target C compiler to check the size of \
                             time_t; assuming musl >= 1.2 (64-bit). Set LIBPCAP_TIME64=0 for older musl."
                        );
                        true
                    }
                }
            }
        }
    };

    if time64 {
        println!("cargo:rustc-cfg=libpcap_time64");
    }
}

/// Preprocesses <sys/time.h> with the target C compiler. musl >= 1.2 defines
/// _REDIR_TIME64 on every 32-bit architecture.
fn target_c_has_time64() -> Option<bool> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let target = env::var("TARGET").ok()?;
    let keys = [
        format!("CC_{}", target),
        format!("CC_{}", target.replace('-', "_")),
        "TARGET_CC".to_string(),
    ];
    for key in &keys {
        println!("cargo:rerun-if-env-changed={}", key);
    }

    let cc = keys
        .iter()
        .filter_map(|k| env::var(k).ok())
        .find(|v| !v.trim().is_empty())?;

    // CC may carry a wrapper or flags, e.g. "ccache mipsel-openwrt-linux-gcc".
    let mut words = cc.split_whitespace();
    let mut child = Command::new(words.next()?)
        .args(words)
        .args(["-E", "-dM", "-x", "c", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    child
        .stdin
        .take()?
        .write_all(b"#include <sys/time.h>\n")
        .ok()?;

    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&out.stdout).contains("_REDIR_TIME64"))
}

fn main() {
    println!("cargo:rerun-if-env-changed=LIBPCAP_LIBDIR");
    println!("cargo:rerun-if-env-changed=LIBPCAP_VER");

    emit_time64_cfg();

    // If user explicitly set LIBPCAP_LIBDIR, honour their wishes. This keeps
    // existing build scripts running. If it's not set, try pkg-config. If
    // that's not set, try last ditch effort to build even though library wasn't
    // explicitly given.
    let version = if let Ok(libdir) = env::var("LIBPCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={}", libdir);
        get_libpcap_version(Some(PathBuf::from(&libdir))).unwrap()
    } else if let Ok(library) = from_pkg_config() {
        Version::parse(&library.version).unwrap()
    } else {
        get_libpcap_version(None).unwrap()
    };

    emit_cfg_flags(version);
}

fn from_pkg_config() -> Result<pkg_config::Library, pkg_config::Error> {
    let mut config = pkg_config::Config::new();
    // If the user has went out of their way to specify LIBPCAP_VER (even though
    // LIBCAP_LIBDIR wasn't set), respect it. Otherwise fall back to any version
    // as long as it's supported.
    if let Ok(v) = env::var("LIBPCAP_VER") {
        config.exactly_version(&v);
    } else {
        config.atleast_version(&Version::LOWEST_SUPPORTED.to_string());
    };
    config.probe("libpcap")
}
