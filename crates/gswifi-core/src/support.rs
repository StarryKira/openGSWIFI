use std::fmt;

/// How far a driver has been verified (doc 09.9). Never claim more than
/// the evidence supports: offline golden vectors are not a campus login.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SupportLevel {
    /// Protocol described in the research docs; code follows the spec but
    /// has no golden vectors for the whole exchange.
    Documented,
    /// Codecs and the state machine match golden vectors from the original
    /// firmware functions or reference implementations.
    OfflineTested,
    /// Full exchange against a simulated or lab server.
    LabTested,
    /// Used successfully on real campus networks.
    FieldTested,
}

impl SupportLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            SupportLevel::Documented => "documented",
            SupportLevel::OfflineTested => "offline-tested",
            SupportLevel::LabTested => "lab-tested",
            SupportLevel::FieldTested => "field-tested",
        }
    }

    /// Below lab-tested the runtime asks for `experimental = true`.
    pub fn is_experimental(self) -> bool {
        self < SupportLevel::LabTested
    }
}

impl fmt::Display for SupportLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Transport a driver uses on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Raw 802.1X frames (EtherType 0x888e).
    Eapol,
    /// UDP to an authentication server.
    Udp,
    /// Derives PPPoE credentials; the link itself is pppd's job.
    Pppoe,
    /// HTTP Portal.
    Http,
}

/// Static description of a driver, shown by `gswifi drivers`.
#[derive(Clone, Copy, Debug)]
pub struct DriverInfo {
    /// Value of `driver = "..."` in the configuration.
    pub name: &'static str,
    /// Display name.
    pub title: &'static str,
    pub transport: Transport,
    pub support: SupportLevel,
    /// Research docs the implementation follows.
    pub docs: &'static [u8],
}
