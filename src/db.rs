//! SQLite layer.
//!
//! We use plain runtime-checked `sqlx::query` (not `query!`) so the project
//! builds without a live database at compile time.

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::models::{Device, ScanRun};

/// Opens (or creates) the SQLite database and runs the schema migration.
pub async fn init(db_path: &Path) -> Result<SqlitePool> {
    // Make sure the parent directory exists so SQLite can create the file.
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating db parent dir {}", parent.display()))?;
        }
    }

    let url = format!("sqlite://{}", db_path.display());
    let opts = SqliteConnectOptions::from_str(&url)
        .context("parsing sqlite url")?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(opts)
        .await
        .context("connecting to sqlite")?;

    migrate(&pool).await?;
    Ok(pool)
}

/// Create tables if they don't already exist. Kept inline (rather than
/// `sqlx migrate`) to keep the MVP self-contained.
async fn migrate(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mac         TEXT    NOT NULL UNIQUE,
            ip          TEXT    NOT NULL,
            hostname    TEXT,
            vendor      TEXT,
            first_seen  TEXT    NOT NULL,
            last_seen   TEXT    NOT NULL,
            is_online   INTEGER NOT NULL DEFAULT 1
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_runs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at    TEXT    NOT NULL,
            completed_at  TEXT,
            devices_found INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);")
        .execute(pool)
        .await?;

    Ok(())
}

/// Insert a new scan-run row and return its id.
pub async fn start_scan(pool: &SqlitePool) -> Result<i64> {
    let now = Utc::now();
    let row = sqlx::query("INSERT INTO scan_runs (started_at) VALUES (?) RETURNING id")
        .bind(now.to_rfc3339())
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("id"))
}

/// Mark a scan-run as completed.
pub async fn finish_scan(pool: &SqlitePool, scan_id: i64, devices_found: i64) -> Result<()> {
    let now = Utc::now();
    sqlx::query(
        "UPDATE scan_runs SET completed_at = ?, devices_found = ? WHERE id = ?",
    )
    .bind(now.to_rfc3339())
    .bind(devices_found)
    .bind(scan_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Upsert a discovered device. If the MAC is new, inserts with `first_seen =
/// last_seen = now`. If it already exists, bumps `last_seen` and updates the
/// IP / hostname / vendor in case they've changed.
pub async fn upsert_device(
    pool: &SqlitePool,
    mac: &str,
    ip: &str,
    hostname: Option<&str>,
    vendor: Option<&str>,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        r#"
        INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, is_online)
        VALUES (?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(mac) DO UPDATE SET
            ip        = excluded.ip,
            hostname  = COALESCE(excluded.hostname, devices.hostname),
            vendor    = COALESCE(excluded.vendor, devices.vendor),
            last_seen = excluded.last_seen,
            is_online = 1
        "#,
    )
    .bind(mac)
    .bind(ip)
    .bind(hostname)
    .bind(vendor)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Any device whose `last_seen` is older than the online cutoff is marked
/// offline. Called at the end of each scan.
pub async fn mark_stale_offline(pool: &SqlitePool, online_window_minutes: i64) -> Result<()> {
    let cutoff = (Utc::now() - Duration::minutes(online_window_minutes)).to_rfc3339();
    sqlx::query("UPDATE devices SET is_online = 0 WHERE last_seen < ?")
        .bind(cutoff)
        .execute(pool)
        .await?;
    Ok(())
}

/// Fetch every device, newest `last_seen` first.
pub async fn list_devices(pool: &SqlitePool) -> Result<Vec<Device>> {
    let rows = sqlx::query(
        "SELECT id, mac, ip, hostname, vendor, first_seen, last_seen, is_online
         FROM devices ORDER BY last_seen DESC",
    )
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let first_seen: String = r.get("first_seen");
        let last_seen: String = r.get("last_seen");
        out.push(Device {
            id: r.get("id"),
            mac: r.get("mac"),
            ip: r.get("ip"),
            hostname: r.get("hostname"),
            vendor: r.get("vendor"),
            first_seen: parse_ts(&first_seen),
            last_seen: parse_ts(&last_seen),
            is_online: r.get::<i64, _>("is_online") != 0,
        });
    }
    Ok(out)
}

/// Most recent scan_runs row, if any.
pub async fn latest_scan(pool: &SqlitePool) -> Result<Option<ScanRun>> {
    let row = sqlx::query(
        "SELECT id, started_at, completed_at, devices_found
         FROM scan_runs ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| {
        let started_at: String = r.get("started_at");
        let completed_at: Option<String> = r.get("completed_at");
        ScanRun {
            id: r.get("id"),
            started_at: parse_ts(&started_at),
            completed_at: completed_at.as_deref().map(parse_ts),
            devices_found: r.get("devices_found"),
        }
    }))
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}
