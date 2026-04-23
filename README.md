# MCE Network Inventory

A small Rust daemon (`mce-inventory`) that ARP-sweeps the local network on a
schedule, resolves hostnames and MAC vendors, and serves a web UI showing
discovered devices.

Internal IT tool, MVP quality. No auth — it binds to localhost.

## Features

- **ARP sweep** of a configurable CIDR (default `192.168.1.0/24`) every 10
  minutes (configurable), plus an on-demand "Scan now" button.
- **Reverse DNS** lookup for each responding host.
- **Vendor lookup** from the IEEE OUI database (downloaded and cached on
  first run — a small fallback table ships with the binary in case you have
  no internet).
- **SQLite** storage (two tables: `devices`, `scan_runs`).
- **Web UI** on `http://localhost:3000` with search, status/vendor filters,
  a stats row, and a scan-now button.

## Prerequisites

- **Rust toolchain** — install via <https://rustup.rs>.
- **Windows only**: the [Npcap](https://npcap.com/#download) driver. Install
  it with the *"WinPcap API-compatible mode"* option so that `pnet` can open
  a raw packet channel. The legacy WinPcap driver also works but Npcap is
  recommended on modern Windows.
- **Administrator / root privileges** when running, because ARP requires
  sending raw link-layer frames.
  - Windows: run the terminal "as Administrator".
  - Linux: `sudo ./mce-inventory` or
    `sudo setcap cap_net_raw,cap_net_admin=eip ./mce-inventory`.

## Build

```sh
cargo build --release
```

The resulting binary is `target/release/mce-inventory` (or
`mce-inventory.exe` on Windows).

## Run

```sh
# Use defaults (192.168.1.0/24, port 3000, 10-minute scan interval).
./target/release/mce-inventory

# Or override per-flag.
./target/release/mce-inventory \
  --subnet 10.0.0.0/24 \
  --port 8080 \
  --interval 5 \
  --db-path ./inventory.db
```

On Windows:

```powershell
# In an Administrator terminal:
.\target\release\mce-inventory.exe --subnet 192.168.1.0/24
```

### Config file

Instead of flags you can drop a `config.toml` in the working directory (see
`config.toml.example`):

```toml
subnet   = "192.168.1.0/24"
port     = 3000
interval = 10
db_path  = "./inventory.db"
```

CLI flags take precedence over the file.

## Open the UI

<http://localhost:3000>

The UI shows a table of every device ever seen, with:

- a **status badge** — `online` (last seen < 15 min), `new` (first seen
  < 24 h), or `offline`,
- hostname, IP, MAC, vendor, first seen, last seen,
- filters for status and vendor,
- search box covering hostname / IP / MAC,
- a **Scan now** button that triggers an immediate sweep.

The JSON API is also available if you want to script against it:

- `GET  /api/devices` — list of devices with derived status.
- `GET  /api/stats`   — summary counts + last scan metadata.
- `POST /api/scan`    — trigger an immediate scan (returns `202 Accepted`).

## How it works (quick tour of the code)

- `src/config.rs` — CLI flags + `config.toml` merge.
- `src/db.rs` — SQLite pool, schema migration, upsert / query helpers.
- `src/oui.rs` — IEEE OUI CSV download + cache + lookup.
- `src/scanner.rs` — ARP sweep (pnet) on a blocking thread, reverse-DNS,
  upsert.
- `src/web.rs` — Axum router + handlers; the single-page UI is inlined
  via `include_str!`.
- `src/main.rs` — wiring: DB, OUI, scheduler task, HTTP server.

## Troubleshooting

- **"no local interface found inside 192.168.x.x/24"** — your machine's
  IPv4 address isn't inside the subnet you're scanning. Pass `--subnet`
  matching the LAN you're on.
- **Windows: "The system cannot find the file specified" / no hits** — Npcap
  isn't installed, or you didn't enable WinPcap API-compatible mode, or
  you're not running as Administrator.
- **Linux: "Operation not permitted"** — need `CAP_NET_RAW` (run as root or
  use `setcap`, see Prerequisites).
- **Empty vendor column** — the OUI CSV failed to download on first run.
  Delete `oui.csv` next to the DB and restart, or copy the file from IEEE
  manually to that path.
