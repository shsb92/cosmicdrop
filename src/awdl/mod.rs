// SPDX-License-Identifier: GPL-3.0-or-later
// A faithful Rust port of OWL (Open Wireless Link), an AWDL implementation.
//
// This module ports the OWL C sources under src/ (protocol) and daemon/
// (Linux platform layer) into Rust. It exposes a high-level `start`/`stop`
// API that runs the AWDL daemon loop (mirroring daemon/core.c) on a
// background thread.
//
// Much of the ported wire-format surface is not yet exercised by the daemon
// loop; keep the port complete and warning-free until those paths are wired.
#![allow(dead_code)]

pub mod channel;
pub mod crc32;
pub mod election;
pub mod frame;
pub mod io;
pub mod netlink;
pub mod peers;
pub mod rx;
pub mod siphash;
pub mod state;
pub mod sync;
pub mod tx;
pub mod wire;

pub use state::AwdlState;

use anyhow::{bail, Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

// ---------------------------------------------------------------------------
// Schedule constants (from OWL schedule.h)
// ---------------------------------------------------------------------------

pub const AWDL_UNICAST_GUARD_TU: i32 = 3;
pub const AWDL_MULTICAST_GUARD_TU: i32 = 16;

// ---------------------------------------------------------------------------
// Public handle
// ---------------------------------------------------------------------------

/// Handle to a running AWDL instance. Drop or call `stop` to shut it down.
pub struct Awdl {
    stop_flag: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    ifindex: i32,
    ifname: String,
    /// Expose the underlying run state for status reporting.
    pub stats: Arc<Mutex<AwdlStatsSnapshot>>,
    mac: [u8; 6],
}

#[derive(Debug, Clone, Default)]
pub struct AwdlStatsSnapshot {
    pub tx_action: u64,
    pub tx_data: u64,
    pub rx_action: u64,
    pub rx_data: u64,
    pub rx_unknown: u64,
}

/// Build an AWDL channel from a channel number. Only 6, 44, 149 are supported
/// (matching OWL).
pub fn channel_from_num(chan: u8) -> Result<channel::AwdlChan> {
    use channel::{CHAN_OPCLASS_149, CHAN_OPCLASS_44, CHAN_OPCLASS_6};
    match chan {
        6 => Ok(CHAN_OPCLASS_6),
        44 => Ok(CHAN_OPCLASS_44),
        149 => Ok(CHAN_OPCLASS_149),
        other => bail!(
            "Unsupported AWDL channel {} (use 6, 44, or 149)",
            other
        ),
    }
}

/// Start an AWDL instance on the given Wi-Fi interface and channel (6, 44, 149).
///
/// This initializes the AWDL state, opens raw packet I/O on the interface,
/// attempts to set up the virtual `awdl0` TAP device and netlink channel
/// switching, and runs the daemon loop on a background thread.
pub fn start(iface: &str, channel: u8) -> Result<Awdl> {
    let chan = channel_from_num(channel)?;

    // Open raw packet I/O first (needed for the loop regardless of netlink).
    let io = io::IoState::open(iface)
        .context("failed to open packet I/O on Wi-Fi interface")?;
    let mac = io.mac();
    let ifindex = io.ifindex();

    // Attempt netlink interface setup; non-fatal if permissions are missing,
    // but record the result clearly.
    let hostname = netlink::get_hostname().unwrap_or_else(|_| "awdl".to_string());
    let tap_result = netlink::open_tun(netlink::AWDL_DEFAULT_DEVICE, mac);
    match &tap_result {
        Ok(_fd) => {
            log::info!("Created virtual interface {}", netlink::AWDL_DEFAULT_DEVICE);
        }
        Err(e) => {
            // Not fatal; the AWDL data path can still run when raw injection
            // is available. Surface a clear warning.
            log::warn!("Could not set up virtual {} interface: {}", netlink::AWDL_DEFAULT_DEVICE, e);
        }
    }
    // Keep the TAP fd alive for the daemon's lifetime if created.
    let _tap_fd = tap_result.ok();

    // Switch to monitor mode / channel via netlink (needs privileges).
    // If these fail we still proceed; the loop will try to send and may fail.
    if let Err(e) = netlink::set_channel(ifindex, channel as i32) {
        log::warn!("Could not set channel {} on {}: {}", channel, iface, e);
    }

    // Initialize AWDL state on the daemon's own data (a Mutex<AwdlState>).
    let now = state::clock_time_us();
    let awdl = AwdlState::new(&hostname, mac, chan, now);

    // Store the I/O socket in the shared daemon context.
    let daemon = Arc::new(Mutex::new(DaemonContext {
        io,
        awdl,
        ieee80211: state::Ieee80211State::new(),
        tap_fd: _tap_fd,
    }));

    // Shared stats snapshot exposed to the caller.
    let stats = Arc::new(Mutex::new(AwdlStatsSnapshot::default()));
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Start the daemon thread.
    let thread_stop = stop_flag.clone();
    let thread_daemon = daemon.clone();
    let thread_stats = stats.clone();
    let thread = thread::Builder::new()
        .name("awdl-daemon".to_string())
        .spawn(move || {
            run_daemon_loop(thread_daemon, thread_stop, thread_stats);
        })
        .context("failed to spawn AWDL daemon thread")?;

    Ok(Awdl {
        stop_flag,
        thread: Some(thread),
        ifindex,
        ifname: iface.to_string(),
        stats,
        mac,
    })
}

impl Awdl {
    /// Stop the AWDL instance, joining the background thread.
    pub fn stop(mut self) -> Result<()> {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        Ok(())
    }

    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Current status snapshot of the running instance.
    pub fn status(&self) -> AwdlStatsSnapshot {
        if let Ok(g) = self.stats.lock() {
            g.clone()
        } else {
            AwdlStatsSnapshot::default()
        }
    }
}

impl Drop for Awdl {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Daemon context shared between threads
// ---------------------------------------------------------------------------

struct DaemonContext {
    io: io::IoState,
    awdl: AwdlState,
    ieee80211: state::Ieee80211State,
    tap_fd: Option<std::os::fd::RawFd>,
}

// ---------------------------------------------------------------------------
// Scheduler (mirrors daemon/core.c)
// ---------------------------------------------------------------------------

use std::time::{Duration, Instant};

/// Timeline of periodic tasks, mirroring the timers in awdl_schedule().
struct Scheduler {
    next_psf: Instant,
    next_mif: Instant,
    next_chan: Instant,
    next_peer: Instant,
    next_election: Instant,
    next_tx: Instant,
}

impl Scheduler {
    fn new(now: Instant) -> Self {
        let psf_interval = Duration::from_micros(
            state::ieee80211_tu_to_usec(110), // PSF_INTERVAL_MASTER_TU
        );
        Self {
            next_psf: now + psf_interval,
            next_mif: now,
            next_chan: now + Duration::from_millis(10),
            next_peer: now + Duration::from_micros(1_000_000),
            next_election: now + Duration::from_millis(500),
            next_tx: now + Duration::from_millis(5),
        }
    }

    /// Return how long to sleep until the next task fires.
    fn sleep_until(&self, now: Instant) -> Duration {
        let mut next = self.next_psf;
        next = next.min(self.next_mif);
        next = next.min(self.next_chan);
        next = next.min(self.next_peer);
        next = next.min(self.next_election);
        next = next.min(self.next_tx);
        next.saturating_duration_since(now).max(Duration::from_millis(1))
    }
}

fn run_daemon_loop(
    daemon: Arc<Mutex<DaemonContext>>,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<AwdlStatsSnapshot>>,
) {
    let mut sched = Scheduler::new(Instant::now());

    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        let sleep_for = sched.sleep_until(now);
        // Bounded, non-hanging sleep.
        thread::sleep(sleep_for.min(Duration::from_secs(1)));
        if stop.load(Ordering::SeqCst) {
            break;
        }

        let now = Instant::now();

        let mut ctx = match daemon.lock() {
            Ok(c) => c,
            Err(_) => continue,
        };

        // ---- Channel switching (mirrors awdl_switch_channel) ----
        if now >= sched.next_chan {
            sched.next_chan = now + Duration::from_millis(10);
            let (current_eaw, slot, chan) = {
                let now_us = state::clock_time_us();
                let eaw = sync::awdl_sync_current_eaw(now_us, &ctx.awdl.sync);
                let eaw64 = eaw as usize;
                let slot = eaw64 % channel::AWDL_CHANSEQ_LENGTH;
                let chan = ctx.awdl.channel.sequence[slot];
                (eaw, slot, chan)
            };
            let chan_new_num = channel::awdl_chan_num(
                chan,
                ctx.awdl.channel.enc,
            );
            let chan_old_num = channel::awdl_chan_num(
                ctx.awdl.channel.current,
                ctx.awdl.channel.enc,
            );
            if chan_new_num != 0 && chan_new_num != chan_old_num {
                log::debug!(
                    "switch channel to {} (slot {}, eaw {})",
                    chan_new_num,
                    slot,
                    current_eaw
                );
                let ifindex = ctx.io.ifindex();
                if let Err(e) = netlink::set_channel(ifindex, chan_new_num as i32) {
                    log::debug!("set_channel failed: {}", e);
                }
                ctx.awdl.channel.current = chan;
            }
        }

        // ---- Peer table cleanup + election (mirrors awdl_clean_peers) ----
        if now >= sched.next_peer {
            sched.next_peer = now + Duration::from_micros(
                ctx.awdl.peers.clean_interval,
            );
            let now_us = state::clock_time_us();
            let cutoff = now_us.saturating_sub(ctx.awdl.peers.timeout);
            ctx.awdl.peers.peers_remove_before(cutoff);
            // Run election
            let peer_snapshot: Vec<(crate::awdl::election::AwdlElectionState, bool)> = ctx
                .awdl
                .peers
                .peers
                .values()
                .map(|p| (p.election.clone(), p.is_valid))
                .collect();
            crate::awdl::election::awdl_election_run(&mut ctx.awdl.election, &peer_snapshot);
        }

        // ---- Election timer (independent, periodic) ----
        if now >= sched.next_election {
            sched.next_election = now + Duration::from_millis(500);
            let peer_snapshot: Vec<(crate::awdl::election::AwdlElectionState, bool)> = ctx
                .awdl
                .peers
                .peers
                .values()
                .map(|p| (p.election.clone(), p.is_valid))
                .collect();
            crate::awdl::election::awdl_election_run(&mut ctx.awdl.election, &peer_snapshot);
        }

        // ---- Send PSF and MIF action frames (mirrors awdl_send_psf / awdl_send_mif) ----
        if now >= sched.next_psf {
            let psf_interval = state::ieee80211_tu_to_usec(
                ctx.awdl.psf_interval as u64
            );
            sched.next_psf = now + Duration::from_micros(psf_interval);
            send_action(&mut ctx, AwdlActionTypeUnit::PSF);
            if let Ok(mut s) = stats.lock() {
                s.tx_action += 1;
            }
        }

        if now >= sched.next_mif {
            // Next MIF scheduled in the middle of the sequence
            let now_us = state::clock_time_us();
            let next_aw = sync::awdl_sync_next_aw_us(now_us, &ctx.awdl.sync);
            let eaw_len = (ctx.awdl.sync.presence_mode as u64)
                * (ctx.awdl.sync.aw_period as u64);
            let in_us = next_aw + state::ieee80211_tu_to_usec(eaw_len / 2);
            sched.next_mif = now + Duration::from_micros(in_us.max(1));

            let current_chan = channel::awdl_chan_num(
                ctx.awdl.channel.current,
                ctx.awdl.channel.enc,
            );
            if current_chan > 0 {
                send_action(&mut ctx, AwdlActionTypeUnit::MIF);
                if let Ok(mut s) = stats.lock() {
                    s.tx_action += 1;
                }
            }
        }

        // ---- Read frames from WLAN (mirrors wlan_device_ready) ----
        read_wlan_frames(&mut ctx, &stats);

        // Drop the lock before the sleep at the top of the loop.
        drop(ctx);
    }
}

/// Internal unit to avoid importing tx::AwdlActionType directly here.
#[derive(Clone, Copy)]
enum AwdlActionTypeUnit {
    PSF,
    MIF,
}

fn send_action(ctx: &mut DaemonContext, action_type: AwdlActionTypeUnit) {
    let ty = match action_type {
        AwdlActionTypeUnit::PSF => tx::AwdlActionType::PSF,
        AwdlActionTypeUnit::MIF => tx::AwdlActionType::MIF,
    };
    let mut frame = vec![0u8; 65535];
    let len = tx::awdl_init_full_action_frame(
        &mut frame,
        &mut ctx.awdl,
        &mut ctx.ieee80211,
        ty,
    );
    if len == 0 {
        return;
    }
    let _ = ctx.io.wlan_send(&frame[..len]);
}

fn read_wlan_frames(
    ctx: &mut DaemonContext,
    stats: &Arc<Mutex<AwdlStatsSnapshot>>,
) {
    // Drain all available frames (bounded).
    for _ in 0..64 {
        let got = match ctx.io.wlan_recv() {
            Ok(g) => g,
            Err(_) => break,
        };
        let frame = match got {
            Some(f) => f,
            None => break,
        };
        let (result, eth) = rx::awdl_rx_frame(&frame, &mut ctx.awdl);
        if let Some(eth_frame) = eth {
            // Send converted Ethernet frame out the TAP device.
            if let Some(fd) = ctx.tap_fd {
                unsafe {
                    libc::write(
                        fd,
                        eth_frame.as_ptr() as *const libc::c_void,
                        eth_frame.len(),
                    );
                }
            }
            if let Ok(mut s) = stats.lock() {
                s.rx_data += 1;
            }
        }
        match result {
            rx::RxResult::Ok => {}
            rx::RxResult::Ignore => {}
            _ if (result as i32) < 0 => {
                if let Ok(mut s) = stats.lock() {
                    s.rx_unknown += 1;
                }
            }
            _ => {}
        }
    }
}
