//! Configuration loading.
//!
//! Values are resolved in this order (later wins):
//!   1. Built-in defaults
//!   2. `config.toml` next to the executable (or a path passed via `--config`)
//!   3. Command-line flags
//!
//! This keeps the MVP simple: drop a `config.toml` beside the binary for
//! permanent settings, or pass flags for one-off overrides.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use ipnet::Ipv4Net;
use serde::Deserialize;

/// CLI flags. Every flag is optional so that `config.toml` can supply the
/// value; clap fills in `None` when the flag is omitted.
#[derive(Parser, Debug)]
#[command(
    name = "mce-inventory",
    version,
    about = "MCE Network Inventory — ARP-sweep LAN scanner with a web UI"
)]
pub struct Cli {
    /// Path to an optional config.toml file.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// CIDR subnet to scan, e.g. 192.168.1.0/24.
    #[arg(long)]
    pub subnet: Option<Ipv4Net>,

    /// Web UI bind address. Defaults to 127.0.0.1 (localhost only).
    /// Set to 0.0.0.0 to expose on all interfaces (e.g. for a preview proxy).
    #[arg(long)]
    pub host: Option<std::net::IpAddr>,

    /// Web UI port.
    #[arg(long)]
    pub port: Option<u16>,

    /// Scan interval in minutes.
    #[arg(long)]
    pub interval: Option<u64>,

    /// SQLite database file path.
    #[arg(long)]
    pub db_path: Option<PathBuf>,
}

/// The TOML file schema. All fields optional.
#[derive(Deserialize, Debug, Default)]
struct FileConfig {
    subnet: Option<Ipv4Net>,
    host: Option<std::net::IpAddr>,
    port: Option<u16>,
    interval: Option<u64>,
    db_path: Option<PathBuf>,
}

/// Fully resolved runtime config.
#[derive(Debug, Clone)]
pub struct Config {
    pub subnet: Ipv4Net,
    pub host: std::net::IpAddr,
    pub port: u16,
    pub interval_minutes: u64,
    pub db_path: PathBuf,
}

impl Config {
    /// Load config, merging defaults, an optional TOML file, and CLI flags.
    pub fn load(cli: Cli) -> Result<Self> {
        let file_cfg = match &cli.config {
            Some(path) => load_file(path)?,
            None => {
                // If no --config was given, try a file named `config.toml`
                // next to the current working directory. Silently ignore if
                // it doesn't exist.
                let default_path = Path::new("config.toml");
                if default_path.exists() {
                    load_file(default_path)?
                } else {
                    FileConfig::default()
                }
            }
        };

        // Defaults match the spec.
        let subnet = cli
            .subnet
            .or(file_cfg.subnet)
            .unwrap_or_else(|| "192.168.1.0/24".parse().expect("valid default subnet"));
        let host = cli
            .host
            .or(file_cfg.host)
            .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        let port = cli.port.or(file_cfg.port).unwrap_or(3000);
        let interval_minutes = cli.interval.or(file_cfg.interval).unwrap_or(10);
        let db_path = cli
            .db_path
            .or(file_cfg.db_path)
            .unwrap_or_else(|| PathBuf::from("./inventory.db"));

        Ok(Self {
            subnet,
            host,
            port,
            interval_minutes,
            db_path,
        })
    }
}

fn load_file(path: &Path) -> Result<FileConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let cfg: FileConfig = toml::from_str(&text)
        .with_context(|| format!("parsing config file {}", path.display()))?;
    Ok(cfg)
}
