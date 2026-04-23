//! Shared data types used across DB, scanner, and web layers.
//!
//! `Device` is what comes out of the database and is serialized to JSON for
//! the web UI. `ScanRun` records each sweep.

use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub id: i64,
    /// Canonical lower-case, colon-separated MAC, e.g. "aa:bb:cc:dd:ee:ff".
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_online: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRun {
    pub id: i64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub devices_found: i64,
}

/// What the ARP scanner produces for each responding host.
#[derive(Debug, Clone)]
pub struct ArpHit {
    pub ip: std::net::Ipv4Addr,
    pub mac: pnet::util::MacAddr,
}
