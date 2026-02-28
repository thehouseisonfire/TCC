#[cfg(miri)]
const MIRI_UNIX_TIMESTAMP_NOW: i64 = 1_700_000_000;

#[cfg(miri)]
pub(crate) fn unix_timestamp_now() -> i64 {
    MIRI_UNIX_TIMESTAMP_NOW
}

#[cfg(not(miri))]
pub(crate) fn unix_timestamp_now() -> i64 {
    chrono::Utc::now().timestamp()
}
