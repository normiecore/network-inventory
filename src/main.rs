//! mce-inventory — ARP-sweep LAN scanner with a tiny web UI.
//!
//! Flow at startup:
//!   1. Parse CLI + optional config.toml.
//!   2. Open SQLite, run schema migration.
//!   3. Load / fetch the OUI vendor table.
//!   4. Spawn the scheduler task — fires a scan immediately, then every
//!      `interval` minutes, or whenever POST /api/scan is hit.
//!   5. Serve the web UI on the configured port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing_subscriber::EnvFilter;

mod config;
mod db;
mod models;
mod oui;
mod scanner;
mod web;

use crate::config::{Cli, Config};
use crate::web::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // Logging: honour RUST_LOG if set, otherwise default to info level.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = Config::load(cli).context("loading config")?;
    tracing::info!(
        "starting mce-inventory: subnet={} bind={}:{} interval={}min db={}",
        cfg.subnet,
        cfg.host,
        cfg.port,
        cfg.interval_minutes,
        cfg.db_path.display()
    );

    let pool = db::init(&cfg.db_path).await.context("initialising db")?;

    // OUI table — cache file sits beside the db.
    scanner::init_oui(&cfg.db_path).await;

    // Shared trigger used by both the scheduler and the `/api/scan` endpoint.
    let scan_trigger = Arc::new(Notify::new());

    // Scheduler task.
    {
        let pool = pool.clone();
        let trigger = scan_trigger.clone();
        let subnet = cfg.subnet;
        let interval = Duration::from_secs(cfg.interval_minutes * 60);

        tokio::spawn(async move {
            // Fire one scan immediately on startup so the UI isn't empty.
            trigger.notify_one();

            loop {
                // Wait for either the interval to elapse or an on-demand
                // trigger from the web handler.
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = trigger.notified() => {}
                }

                match scanner::run_scan_once(&pool, subnet).await {
                    Ok(n) => tracing::info!("scan complete, {n} hosts"),
                    Err(e) => tracing::error!("scan failed: {e:#}"),
                }
            }
        });
    }

    // Web server.
    let state = AppState {
        pool: pool.clone(),
        scan_trigger: scan_trigger.clone(),
    };
    let app = web::router(state);
    let addr = SocketAddr::new(cfg.host, cfg.port);
    tracing::info!("listening on http://{addr}");
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    axum::serve(listener, app).await.context("axum serve")?;

    Ok(())
}
