// Bug: from_uefi accepts impossible calendar dates because day is only validated
//      against 1..=31, regardless of month and leap year.
// Expected: from_uefi(2025-02-31) returns None.
// Observed: 2025-02-31 is accepted and silently normalizes to 2025-03-03.
// Build/run: rustc 144-nonexistent-dates-accepted.rs -o /tmp/poc144 && /tmp/poc144
// Target note: code transcribed from library/std/src/sys/pal/uefi/system_time.rs.

const SECS_IN_MINUTE: u64 = 60;
const SECS_IN_HOUR: u64 = SECS_IN_MINUTE * 60;
const SECS_IN_DAY: u64 = SECS_IN_HOUR * 24;
const SYSTEMTIME_TIMEZONE: i64 = -1440 * SECS_IN_MINUTE as i64;
const UNSPECIFIED_TIMEZONE: i16 = 0x07FF;

#[derive(Clone, Copy)]
struct Time { year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8, nanosecond: u32, timezone: i16 }

fn from_uefi(t: &Time) -> Option<u64> {
    if !(t.month <= 12 && t.month != 0 && t.year >= 1900 && t.year <= 9999
        && t.day <= 31 && t.day != 0 && t.second < 60 && t.minute <= 60
        && t.hour < 24 && t.nanosecond < 1_000_000_000
        && ((t.timezone <= 1440 && t.timezone >= -1440) || t.timezone == UNSPECIFIED_TIMEZONE)) {
        return None;
    }
    const YEAR_BASE: u32 = 4800;
    let (m_adj, overflow): (u32, bool) = (t.month as u32).overflowing_sub(3);
    let (carry, adjust): (u32, u32) = if overflow { (1, 12) } else { (0, 0) };
    let y_adj: u32 = (t.year as u32) + YEAR_BASE - carry;
    let month_days: u32 = (m_adj.wrapping_add(adjust) * 62719 + 769) / 2048;
    let leap_days: u32 = y_adj / 4 - y_adj / 100 + y_adj / 400;
    let days: u32 = y_adj * 365 + leap_days + month_days + (t.day as u32 - 1) - 2447065;
    let localtime_epoch: u64 = (days as u64) * SECS_IN_DAY
        + (t.second as u64) + (t.minute as u64) * SECS_IN_MINUTE
        + (t.hour as u64) * SECS_IN_HOUR;
    let normalized_timezone = (t.timezone as i64) * SECS_IN_MINUTE as i64 - SYSTEMTIME_TIMEZONE;
    Some(localtime_epoch.checked_add_signed(normalized_timezone).unwrap())
}

fn main() {
    let nonexistent = Time { year: 2025, month: 2, day: 31, hour: 0, minute: 0, second: 0, nanosecond: 0, timezone: 0 };
    let normalized = Time { month: 3, day: 3, ..nonexistent };
    let bad = from_uefi(&nonexistent).expect("bug not triggered: 2025-02-31 must currently be accepted");
    let same = from_uefi(&normalized).expect("baseline failed");
    println!("2025-02-31 accepted, epoch = {}", bad);
    println!("2025-03-03 baseline    = {}", same);
    assert_eq!(bad, same);
    println!("BUG: nonexistent 2025-02-31 silently equals 2025-03-03");
}
