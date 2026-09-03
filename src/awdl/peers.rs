// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL peers.h/peers.c – peer table using std HashMap

use std::collections::HashMap;

use crate::awdl::channel::{AwdlChan, AWDL_CHANSEQ_LENGTH, CHAN_NULL};
use crate::awdl::election::AwdlElectionState;

pub const HOST_NAME_LENGTH_MAX: usize = 64;

pub const PEERS_DEFAULT_TIMEOUT: u64 = 2_000_000; // microseconds
pub const PEERS_DEFAULT_CLEAN_INTERVAL: u64 = 1_000_000; // microseconds

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeersStatus {
    Update,
    Ok,
    Missing,
    Internal,
}

/// A single AWDL peer
#[derive(Debug, Clone)]
pub struct AwdlPeer {
    pub addr: [u8; 6],
    pub last_update: u64,
    pub election: AwdlElectionState,
    pub sequence: [AwdlChan; AWDL_CHANSEQ_LENGTH],
    pub sync_offset: u64,
    pub name: String,
    pub country_code: String,
    pub infra_addr: [u8; 6],
    pub version: u8,
    pub devclass: u8,
    pub supports_v2: bool,
    pub sent_mif: bool,
    pub is_valid: bool,
}

impl AwdlPeer {
    pub fn new(addr: [u8; 6]) -> Self {
        let mut seq = [CHAN_NULL; AWDL_CHANSEQ_LENGTH];
        crate::awdl::channel::awdl_chanseq_init_static(&mut seq, &CHAN_NULL);
        let mut election = AwdlElectionState::new(addr);
        crate::awdl::election::awdl_election_state_init(&mut election, &addr);

        Self {
            addr,
            last_update: 0,
            election,
            sequence: seq,
            sync_offset: 0,
            name: String::new(),
            country_code: "NA".to_string(),
            infra_addr: [0; 6],
            version: 0,
            devclass: 0,
            supports_v2: false,
            sent_mif: false,
            is_valid: false,
        }
    }

    /// Check if this peer has the minimum required fields to be valid
    fn check_valid(&self) -> bool {
        self.sent_mif && self.devclass != 0 && self.version != 0
    }
}

/// Peer table state
#[derive(Debug)]
pub struct AwdlPeerState {
    pub peers: HashMap<[u8; 6], AwdlPeer>,
    pub timeout: u64,
    pub clean_interval: u64,
}

impl AwdlPeerState {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            timeout: PEERS_DEFAULT_TIMEOUT,
            clean_interval: PEERS_DEFAULT_CLEAN_INTERVAL,
        }
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Add or update a peer. Returns (status, whether peer just became valid).
    pub fn peer_add(
        &mut self,
        addr: &[u8; 6],
        now: u64,
    ) -> (PeersStatus, bool) {
        let existed = self.peers.contains_key(addr);
        let peer = self.peers.entry(*addr).or_insert_with(|| AwdlPeer::new(*addr));
        peer.last_update = now;

        let was_valid = peer.is_valid;
        let now_valid = peer.check_valid();
        let just_became_valid = !was_valid && now_valid;
        peer.is_valid = now_valid;

        if existed {
            (PeersStatus::Update, just_became_valid)
        } else {
            (PeersStatus::Ok, just_became_valid)
        }
    }

    /// Get a peer reference
    pub fn peer_get(&self, addr: &[u8; 6]) -> Option<&AwdlPeer> {
        self.peers.get(addr)
    }

    /// Get a mutable peer reference
    pub fn peer_get_mut(&mut self, addr: &[u8; 6]) -> Option<&mut AwdlPeer> {
        self.peers.get_mut(addr)
    }

    /// Remove a peer. Returns true if removed.
    pub fn peer_remove(&mut self, addr: &[u8; 6]) -> Option<AwdlPeer> {
        self.peers.remove(addr)
    }

    /// Remove peers whose last_update is older than `before`.
    /// Returns the list of removed peers.
    pub fn peers_remove_before(&mut self, before: u64) -> Vec<AwdlPeer> {
        let mut removed = Vec::new();
        self.peers.retain(|_, peer| {
            if peer.last_update < before {
                removed.push(peer.clone());
                false
            } else {
                true
            }
        });
        removed
    }

    /// Iterate over all peers (for election)
    pub fn peers_iter(&self) -> impl Iterator<Item = (&AwdlElectionState, bool)> {
        self.peers.values().map(|p| (&p.election, p.is_valid))
    }
}

/// Format a peer for display
pub fn awdl_peer_print(peer: &AwdlPeer) -> String {
    let name = if peer.name.is_empty() {
        "<UNNAMED>"
    } else {
        &peer.name
    };
    format!(
        "{}: {}",
        name,
        crate::awdl::election::awdl_election_tree_print(&peer.election)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_add_and_get() {
        let mut state = AwdlPeerState::new();
        let addr = [1, 2, 3, 4, 5, 6];
        let (status, _valid) = state.peer_add(&addr, 100);
        assert_eq!(status, PeersStatus::Ok);
        assert!(state.peer_get(&addr).is_some());

        let (status, _valid) = state.peer_add(&addr, 200);
        assert_eq!(status, PeersStatus::Update);
        assert_eq!(state.peer_get(&addr).unwrap().last_update, 200);
    }

    #[test]
    fn test_peer_remove_before() {
        let mut state = AwdlPeerState::new();
        state.peer_add(&[1, 2, 3, 4, 5, 6], 100);
        state.peer_add(&[7, 8, 9, 10, 11, 12], 300);
        let removed = state.peers_remove_before(200);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].addr, [1, 2, 3, 4, 5, 6]);
        assert_eq!(state.len(), 1);
    }
}
