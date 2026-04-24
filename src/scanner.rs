//! ARP sweep + reverse DNS.
//!
//! On Windows this requires Npcap (or the legacy WinPcap) to be installed,
//! and the process has to be running with administrator privileges to send
//! raw link-layer frames. On Linux you'll need `CAP_NET_RAW` (either root or
//! `setcap cap_net_raw=eip ./mce-inventory`).
//!
//! The sweep itself runs on a dedicated blocking thread because pnet's
//! channels are synchronous. The outer `run_scan_once` function is async so
//! it fits cleanly into the tokio scheduler.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use ipnet::Ipv4Net;
use pnet::datalink::{self, Channel, Config as DatalinkConfig, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use sqlx::SqlitePool;

use crate::models::ArpHit;
use crate::oui::{OuiDb, OUI};
use crate::{db, oui};

/// How long we listen for ARP replies after sending all requests.
const ARP_LISTEN: Duration = Duration::from_secs(3);

/// Per-packet read timeout inside the listen loop — small enough that we
/// can check the deadline frequently.
const READ_TIMEOUT: Duration = Duration::from_millis(250);

/// Devices whose `last_seen` is within this window are considered online.
pub const ONLINE_WINDOW_MINUTES: i64 = 15;

/// Run a single scan: start a scan_run row, ARP sweep, reverse-DNS, upsert
/// each device, mark stale hosts offline, complete the scan_run.
pub async fn run_scan_once(pool: &SqlitePool, subnet: Ipv4Net) -> Result<usize> {
    let scan_id = db::start_scan(pool).await?;
    tracing::info!("scan {scan_id} starting for {subnet}");

    // The ARP work is synchronous — do it on a blocking thread.
    let hits = tokio::task::spawn_blocking(move || arp_sweep(subnet))
        .await
        .context("arp_sweep join")??;

    tracing::info!("scan {scan_id}: {} ARP replies", hits.len());

    // Resolve OUI vendor (cheap, in-memory) and reverse-DNS (blocking, but
    // tiny workload — a single sweep returns at most a /24 of entries).
    let oui_db = OUI.get().expect("OUI database initialised at startup");

    for hit in &hits {
        let mac_str = format_mac(hit.mac);
        let ip_str = hit.ip.to_string();
        let vendor = oui_db.lookup(&mac_str).map(|s| s.to_string());
        let hostname = reverse_dns(hit.ip).await;

        if let Err(e) = db::upsert_device(
            pool,
            &mac_str,
            &ip_str,
            hostname.as_deref(),
            vendor.as_deref(),
        )
        .await
        {
            tracing::warn!("upsert failed for {mac_str}/{ip_str}: {e}");
        }
    }

    db::mark_stale_offline(pool, ONLINE_WINDOW_MINUTES).await?;
    db::finish_scan(pool, scan_id, hits.len() as i64).await?;

    tracing::info!("scan {scan_id} complete");
    Ok(hits.len())
}

/// Perform the blocking ARP sweep. Picks the first non-loopback interface
/// whose IPv4 address falls within `subnet`.
fn arp_sweep(subnet: Ipv4Net) -> Result<Vec<ArpHit>> {
    let iface = pick_interface(subnet)
        .ok_or_else(|| anyhow!("no local interface found inside {subnet}"))?;
    let src_mac = iface
        .mac
        .ok_or_else(|| anyhow!("interface {} has no MAC address", iface.name))?;
    let src_ip = iface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) if subnet.contains(&v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| anyhow!("interface {} has no IPv4 in {subnet}", iface.name))?;

    tracing::info!(
        "arp sweep: iface={} src_ip={} src_mac={}",
        iface.name,
        src_ip,
        src_mac
    );

    let cfg = DatalinkConfig {
        read_timeout: Some(READ_TIMEOUT),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(&iface, cfg) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("unsupported datalink channel type")),
        Err(e) => return Err(anyhow!("opening datalink channel: {e}")),
    };

    // 1. Fire an ARP request at every address in the subnet (skipping
    //    network / broadcast / our own IP).
    let targets: Vec<Ipv4Addr> = subnet
        .hosts()
        .filter(|ip| *ip != src_ip)
        .collect();

    for target in &targets {
        let mut eth_buf = [0u8; 42]; // 14 (eth hdr) + 28 (ARP)
        let mut eth_pkt =
            MutableEthernetPacket::new(&mut eth_buf).expect("buffer sized for ethernet");
        eth_pkt.set_destination(MacAddr::broadcast());
        eth_pkt.set_source(src_mac);
        eth_pkt.set_ethertype(EtherTypes::Arp);

        {
            let mut arp_pkt = MutableArpPacket::new(eth_pkt.payload_mut())
                .expect("buffer sized for ARP payload");
            arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_pkt.set_protocol_type(EtherTypes::Ipv4);
            arp_pkt.set_hw_addr_len(6);
            arp_pkt.set_proto_addr_len(4);
            arp_pkt.set_operation(ArpOperations::Request);
            arp_pkt.set_sender_hw_addr(src_mac);
            arp_pkt.set_sender_proto_addr(src_ip);
            arp_pkt.set_target_hw_addr(MacAddr::zero());
            arp_pkt.set_target_proto_addr(*target);
        }

        if let Some(Err(e)) = tx.send_to(eth_pkt.packet(), None) {
            tracing::debug!("send_to({target}) failed: {e}");
        }
    }

    // 2. Listen for replies for a fixed window. We deduplicate by MAC since
    //    some hosts (e.g. those with multiple IPs) may reply more than once.
    let mut hits = Vec::new();
    let deadline = Instant::now() + ARP_LISTEN;
    while Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if let Some(hit) = parse_arp_reply(frame) {
                    if !hits.iter().any(|h: &ArpHit| h.mac == hit.mac) {
                        hits.push(hit);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => {
                tracing::debug!("datalink rx error: {e}");
                continue;
            }
        }
    }

    Ok(hits)
}

/// If `frame` is an ARP *reply*, extract the sender's IP + MAC.
fn parse_arp_reply(frame: &[u8]) -> Option<ArpHit> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some(ArpHit {
        ip: arp.get_sender_proto_addr(),
        mac: arp.get_sender_hw_addr(),
    })
}

/// Choose an interface whose IPv4 address lies within `subnet`.
/// Skips loopback and down interfaces.
fn pick_interface(subnet: Ipv4Net) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .filter(|i| !i.is_loopback() && i.is_up() && !i.ips.is_empty() && i.mac.is_some())
        .find(|i| {
            i.ips.iter().any(|ip| match ip.ip() {
                std::net::IpAddr::V4(v4) => subnet.contains(&v4),
                _ => false,
            })
        })
}

fn format_mac(mac: MacAddr) -> String {
    // MacAddr's Display is "aa:bb:cc:dd:ee:ff"; we just lower-case.
    format!("{}", mac).to_ascii_lowercase()
}

/// Reverse-DNS is blocking — wrap in `spawn_blocking`.
async fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        dns_lookup::lookup_addr(&std::net::IpAddr::V4(ip)).ok()
    })
    .await
    .ok()
    .flatten()
    .filter(|name| !name.is_empty() && *name != ip.to_string())
}

/// Initialise the global OUI database. Call once at startup.
pub async fn init_oui(db_path: &std::path::Path) -> &'static OuiDb {
    OUI.get_or_init(|| async {
        let cache = oui::cache_path_for(db_path);
        OuiDb::load(&cache).await
    })
    .await
}
