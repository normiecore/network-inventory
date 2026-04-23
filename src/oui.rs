//! OUI (Organizationally Unique Identifier) -> vendor lookup.
//!
//! On first run we download the IEEE OUI CSV (public, free) and cache it
//! next to the database. Subsequent runs just read the cached copy.
//!
//! Parsing is deliberately forgiving — the CSV has occasional quirks and we
//! don't want a single weird row to fail the startup.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::OnceCell;

const IEEE_OUI_URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";

/// Small fallback table used if the IEEE fetch fails (e.g. no internet).
/// Keys are the 6-hex-char OUI prefix, upper-case, no separators.
const FALLBACK: &[(&str, &str)] = &[
    ("F8E71E", "Ruckus Wireless"),
    ("3C5AB4", "Google"),
    ("B827EB", "Raspberry Pi Foundation"),
    ("DCA632", "Raspberry Pi Trading"),
    ("E45F01", "Raspberry Pi Trading"),
    ("001A11", "Google"),
    ("F4F5D8", "Google"),
    ("A4B197", "Apple"),
    ("8C8590", "Apple"),
    ("F0D1A9", "Apple"),
    ("000C29", "VMware"),
    ("005056", "VMware"),
    ("080027", "Oracle VirtualBox"),
    ("525400", "QEMU/KVM"),
    ("001C42", "Parallels"),
    ("0003FF", "Microsoft"),
    ("00155D", "Microsoft Hyper-V"),
    ("F0DEF1", "Wistron InfoComm"),
    ("D85ED3", "TP-Link"),
    ("FCECDA", "Ubiquiti"),
    ("245A4C", "Ubiquiti"),
    ("B4FBE4", "Ubiquiti"),
    ("78A351", "Ubiquiti"),
    ("E063DA", "Ubiquiti"),
    ("A0F3C1", "Tp-Link"),
    ("EC086B", "TP-Link"),
    ("F81A67", "TP-Link"),
    ("001DD8", "Microsoft"),
    ("ACDE48", "Apple"),
];

/// Shared, lazily-initialised OUI database.
#[derive(Debug, Default)]
pub struct OuiDb {
    /// OUI (6 upper-case hex chars) -> vendor name.
    table: HashMap<String, String>,
}

impl OuiDb {
    /// Load the OUI table. Prefers a cached CSV at `cache_path`; otherwise
    /// tries to fetch from IEEE; falls back to a small bundled table.
    pub async fn load(cache_path: &Path) -> Self {
        let mut table = HashMap::new();

        // Seed with the fallback so we always have *something*.
        for (prefix, name) in FALLBACK {
            table.insert((*prefix).to_string(), (*name).to_string());
        }

        // Try the on-disk cache first.
        if cache_path.exists() {
            match std::fs::read_to_string(cache_path) {
                Ok(text) => {
                    let before = table.len();
                    parse_ieee_csv(&text, &mut table);
                    tracing::info!(
                        "OUI cache loaded: {} -> {} entries",
                        before,
                        table.len()
                    );
                    return Self { table };
                }
                Err(e) => {
                    tracing::warn!("couldn't read OUI cache at {}: {e}", cache_path.display());
                }
            }
        }

        // Otherwise try to fetch fresh.
        match fetch_ieee_csv().await {
            Ok(text) => {
                parse_ieee_csv(&text, &mut table);
                if let Err(e) = std::fs::write(cache_path, &text) {
                    tracing::warn!(
                        "couldn't cache OUI CSV to {}: {e}",
                        cache_path.display()
                    );
                }
                tracing::info!("OUI database fetched from IEEE: {} entries", table.len());
            }
            Err(e) => {
                tracing::warn!(
                    "OUI fetch failed ({e}); using {} fallback entries",
                    table.len()
                );
            }
        }

        Self { table }
    }

    /// Resolve a MAC to a vendor name, or `None` if unknown.
    /// Accepts MAC strings in "aa:bb:cc:dd:ee:ff" (or any format — we strip
    /// non-hex characters before taking the first 6 chars).
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        let prefix = mac_prefix(mac)?;
        self.table.get(&prefix).map(|s| s.as_str())
    }
}

/// Where the cached OUI CSV lives: same directory as the db, named `oui.csv`.
pub fn cache_path_for(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("oui.csv")
}

fn mac_prefix(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() == 6 {
        Some(hex)
    } else {
        None
    }
}

async fn fetch_ieee_csv() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building reqwest client")?;
    let resp = client
        .get(IEEE_OUI_URL)
        .send()
        .await
        .context("fetching OUI CSV")?
        .error_for_status()
        .context("OUI CSV HTTP status")?;
    let text = resp.text().await.context("reading OUI CSV body")?;
    Ok(text)
}

/// Minimal IEEE oui.csv parser. Columns:
///   Registry,Assignment,Organization Name,Organization Address
/// We only care about columns 1 (assignment, e.g. "28C68E") and 2 (org).
fn parse_ieee_csv(text: &str, out: &mut HashMap<String, String>) {
    for (i, line) in text.lines().enumerate() {
        if i == 0 && line.starts_with("Registry") {
            continue; // header
        }
        let fields = split_csv_fields(line);
        if fields.len() < 3 {
            continue;
        }
        let assignment = fields[1].trim().to_ascii_uppercase();
        let org = fields[2].trim().to_string();
        if assignment.len() == 6 && !org.is_empty() {
            out.insert(assignment, org);
        }
    }
}

/// Tiny CSV splitter that handles double-quoted fields containing commas.
/// Good enough for the IEEE file; not a general CSV parser.
fn split_csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                buf.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut buf));
            }
            other => buf.push(other),
        }
    }
    out.push(buf);
    out
}

/// Process-wide OUI database, initialised once at startup.
pub static OUI: OnceCell<OuiDb> = OnceCell::const_new();
