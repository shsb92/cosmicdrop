// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL state.h/state.c – AWDL node state

use std::time::{SystemTime, UNIX_EPOCH};

use crate::awdl::channel::{AwdlChan, AwdlChannelState};
use crate::awdl::election::AwdlElectionState;
use crate::awdl::peers::AwdlPeerState;
use crate::awdl::sync::AwdlSyncState;

pub const RSSI_THRESHOLD_DEFAULT: i8 = -65;
pub const RSSI_GRACE_DEFAULT: i8 = -5;
pub const PSF_INTERVAL_MASTER_TU: u16 = 110;
pub const PSF_INTERVAL_SLAVE_TU: u16 = 440;

pub const ETHER_BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// AWDL version: awdl_version(3, 4) = (3 << 4) | 4 = 0x34
pub const AWDL_VERSION_3_4: u8 = 0x34;

/// AWDL device class for macOS
pub const AWDL_DEVCLASS_MACOS: u8 = 1;

/// Statistics counters
#[derive(Debug, Clone, Default)]
pub struct AwdlStats {
    pub tx_action: u64,
    pub tx_data: u64,
    pub tx_data_unicast: u64,
    pub tx_data_multicast: u64,
    pub rx_action: u64,
    pub rx_data: u64,
    pub rx_unknown: u64,
}

/// Complete AWDL node state
#[derive(Debug)]
pub struct AwdlState {
    pub self_address: [u8; 6],
    pub name: String,
    pub version: u8,
    pub dev_class: u8,
    pub sequence_number: u16,
    pub psf_interval: u16,
    pub dst: [u8; 6],
    pub filter_rssi: bool,
    pub rssi_threshold: i8,
    pub rssi_grace: i8,
    pub election: AwdlElectionState,
    pub sync: AwdlSyncState,
    pub channel: AwdlChannelState,
    pub peers: AwdlPeerState,
    pub stats: AwdlStats,
}

impl AwdlState {
    /// Create a new AWDL state with defaults
    pub fn new(hostname: &str, self_addr: [u8; 6], chan: AwdlChan, now: u64) -> Self {
        let mut election = AwdlElectionState::new(self_addr);
        crate::awdl::election::awdl_election_state_init(&mut election, &self_addr);

        let channel = AwdlChannelState::new(chan);

        Self {
            self_address: self_addr,
            name: hostname.to_string(),
            version: AWDL_VERSION_3_4,
            dev_class: AWDL_DEVCLASS_MACOS,
            sequence_number: 0,
            psf_interval: PSF_INTERVAL_MASTER_TU,
            dst: ETHER_BROADCAST,
            filter_rssi: true,
            rssi_threshold: RSSI_THRESHOLD_DEFAULT,
            rssi_grace: RSSI_GRACE_DEFAULT,
            election,
            sync: AwdlSyncState::new(now),
            channel,
            peers: AwdlPeerState::new(),
            stats: AwdlStats::default(),
        }
    }

    /// Get next sequence number (wrapping, matches C behavior)
    pub fn next_sequence_number(&mut self) -> u16 {
        let seq = self.sequence_number;
        self.sequence_number = self.sequence_number.wrapping_add(1);
        seq
    }
}

/// IEEE 802.11 state
#[derive(Debug)]
pub struct Ieee80211State {
    pub sequence_number: u16,
    pub fcs: bool,
}

impl Ieee80211State {
    pub fn new() -> Self {
        Self {
            sequence_number: 0,
            fcs: false,
        }
    }

    /// Get next sequence number (12-bit, wrapping)
    pub fn next_sequence_number(&mut self) -> u16 {
        let seq = self.sequence_number;
        self.sequence_number = (self.sequence_number + 1) & 0x0fff;
        seq
    }
}

/// Get monotonic clock time in microseconds
pub fn clock_time_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// IEEE 802.11 TU (time unit) to microseconds: 1 TU = 1024 usec
pub fn ieee80211_tu_to_usec(tu: u64) -> u64 {
    1024 * tu
}

/// IEEE 802.11 microseconds to TU
pub fn ieee80211_usec_to_tu(usec: u64) -> u64 {
    usec / 1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_encoding() {
        assert_eq!(AWDL_VERSION_3_4, 0x34);
    }

    #[test]
    fn test_sequence_number_wrap() {
        let mut ieee = Ieee80211State::new();
        ieee.sequence_number = 0x0fff;
        let seq = ieee.next_sequence_number();
        assert_eq!(seq, 0x0fff);
        assert_eq!(ieee.sequence_number, 0); // wrapped to 12 bits
    }

    #[test]
    fn test_tu_conversion() {
        assert_eq!(ieee80211_tu_to_usec(1), 1024);
        assert_eq!(ieee80211_usec_to_tu(1024), 1);
    }
}
