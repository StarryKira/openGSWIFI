//! Wall-clock helpers for the date-dependent Hubei derivation.
//!
//! FixHBKey mixes `strftime("%m%d", localtime(t))` of the authentication
//! time into every MD5 input (cleanroom/08 §1.1), and the firmware imports
//! `Date:`/`curl_getdate`/`settimeofday`, i.e. it can correct its clock from
//! the server (cleanroom/07 §2, docs/05 §5.3). Following clean-room rule 3
//! this crate never touches the system clock and never uses wall time for
//! timers: the driver reads an injectable wall clock, adds a server offset
//! taken from an HTTP `Date` header (or configured), and applies a fixed UTC
//! offset, because `std` has no time-zone database. China has no DST, so a
//! fixed +08:00 matches the firmware's `localtime` on a CST-8 router.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, negative before 1970.
pub fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day)` of a day count since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `strftime("%m%d")` of `unix_secs` shifted by `utc_offset_minutes`
/// (cleanroom/08 §1.1 `mmdd`).
pub fn local_mmdd(unix_secs: i64, utc_offset_minutes: i32) -> String {
    let local = unix_secs.saturating_add(i64::from(utc_offset_minutes) * 60);
    let (_, month, day) = civil_from_days(local.div_euclid(86_400));
    format!("{:02}{:02}", month, day)
}

fn month_number(name: &str) -> Option<u32> {
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    MONTHS.iter().position(|m| m.eq_ignore_ascii_case(name)).map(|i| i as u32 + 1)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        _ => 28,
    }
}

fn hms(text: &str) -> Option<i64> {
    let mut parts = text.split(':');
    let mut field = |max: i64| -> Option<i64> {
        let p = parts.next()?;
        if p.len() != 2 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let v: i64 = p.parse().ok()?;
        (v <= max).then_some(v)
    };
    // 60 allows a leap second, which is then folded into the next minute.
    let (h, m, s) = (field(23)?, field(59)?, field(60)?);
    parts.next().is_none().then_some(h * 3600 + m * 60 + s)
}

fn assemble(year: i64, month: &str, day: &str, time: &str) -> Option<i64> {
    let month = month_number(month)?;
    if day.is_empty() || day.len() > 2 || !day.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let day: u32 = day.parse().ok()?;
    if day == 0 || day > days_in_month(year, month) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hms(time)?)
}

fn four_digit_year(text: &str) -> Option<i64> {
    (text.len() == 4 && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok()).flatten()
}

/// Parses an HTTP `Date` value (RFC 9110 §5.6.7): IMF-fixdate
/// `Sun, 06 Nov 1994 08:49:37 GMT`, the obsolete RFC 850 form
/// `Sunday, 06-Nov-94 08:49:37 GMT` (two-digit years: 70-99 → 19xx,
/// otherwise 20xx) and asctime `Sun Nov  6 08:49:37 1994`. Returns Unix
/// seconds. The weekday is not checked.
pub fn parse_http_date(value: &str) -> Option<i64> {
    let value = value.trim();
    if let Some((_, rest)) = value.split_once(',') {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        match parts.as_slice() {
            [day, month, year, time, zone] if zone.eq_ignore_ascii_case("GMT") || zone.eq_ignore_ascii_case("UTC") => {
                assemble(four_digit_year(year)?, month, day, time)
            }
            [date, time, zone] if zone.eq_ignore_ascii_case("GMT") => {
                let mut d = date.split('-');
                let (day, month, yy) = (d.next()?, d.next()?, d.next()?);
                if d.next().is_some() || yy.len() != 2 || !yy.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let yy: i64 = yy.parse().ok()?;
                assemble(if yy >= 70 { 1900 + yy } else { 2000 + yy }, month, day, time)
            }
            _ => None,
        }
    } else {
        match value.split_whitespace().collect::<Vec<_>>().as_slice() {
            [_, month, day, time, year] => assemble(four_digit_year(year)?, month, day, time),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn civil_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        for days in (-800_000..800_000).step_by(997) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    /// The harness of `out_sim.txt` / `out_sim_pw.txt` pinned `time()` to
    /// 0x6aff9488 = 2026-11-20 00:30:00 UTC and the firmware derived MMDD
    /// "1120" (QEMU, TZ unset = UTC). +08:00 gives the same day.
    #[test]
    fn mmdd_of_the_harness_time() {
        let t = 0x6aff_9488;
        assert_eq!(unix_secs(UNIX_EPOCH + Duration::from_secs(t as u64)), t);
        assert_eq!(local_mmdd(t, 0), "1120");
        assert_eq!(local_mmdd(t, 480), "1120");
    }

    #[test]
    fn mmdd_follows_the_utc_offset_across_midnight() {
        // 2026-11-19 20:00:00 UTC = 2026-11-20 04:00 in China.
        let t = days_from_civil(2026, 11, 19) * 86_400 + 20 * 3600;
        assert_eq!(local_mmdd(t, 0), "1119");
        assert_eq!(local_mmdd(t, 480), "1120");
        // New year's eve 23:59:59 local, and one second later.
        let t = days_from_civil(2027, 1, 1) * 86_400 - 8 * 3600 - 1;
        assert_eq!(local_mmdd(t, 480), "1231");
        assert_eq!(local_mmdd(t + 1, 480), "0101");
        assert_eq!(local_mmdd(t + 1, -300), "1231");
        // Before 1970 still works (no wrap).
        assert_eq!(local_mmdd(-1, 0), "1231");
        assert_eq!(unix_secs(UNIX_EPOCH - Duration::from_secs(5)), -5);
    }

    #[test]
    fn http_dates() {
        let expected = days_from_civil(1994, 11, 6) * 86_400 + 8 * 3600 + 49 * 60 + 37;
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"), Some(expected));
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), Some(expected));
        assert_eq!(parse_http_date("Sun Nov  6 08:49:37 1994"), Some(expected));
        assert_eq!(parse_http_date("  fri, 20 nov 2026 00:30:00 gmt "), Some(0x6aff_9488));
        assert_eq!(parse_http_date("Thu, 01-Jan-70 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("Sat, 01-Jan-33 00:00:00 GMT"), Some(days_from_civil(2033, 1, 1) * 86_400));
        for bad in [
            "",
            "Sun, 06 Nov 1994 08:49:37 PST",
            "Sun, 31 Nov 1994 08:49:37 GMT",
            "Sun, 29 Feb 2023 08:49:37 GMT",
            "Sun, 06 Foo 1994 08:49:37 GMT",
            "Sun, 06 Nov 94 08:49:37 GMT",
            "Sun, 06 Nov 1994 24:00:00 GMT",
            "Sun, 06 Nov 1994 8:49:37 GMT",
            "1994-11-06T08:49:37Z",
        ] {
            assert_eq!(parse_http_date(bad), None, "{:?}", bad);
        }
        assert!(parse_http_date("Tue, 29 Feb 2028 12:00:00 GMT").is_some());
    }
}
