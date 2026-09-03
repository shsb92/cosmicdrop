// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL election.h/election.c – AWDL master election

pub const AWDL_ELECTION_TREE_MAX_HEIGHT: u32 = 10;
pub const AWDL_ELECTION_METRIC_INIT: u32 = 60;
pub const AWDL_ELECTION_COUNTER_INIT: u32 = 0;

/// Election state for a single node
#[derive(Debug, Clone)]
pub struct AwdlElectionState {
    pub master_addr: [u8; 6],
    pub sync_addr: [u8; 6],
    pub self_addr: [u8; 6],
    pub height: u32,
    pub master_metric: u32,
    pub self_metric: u32,
    pub master_counter: u32,
    pub self_counter: u32,
}

impl AwdlElectionState {
    pub fn new(self_addr: [u8; 6]) -> Self {
        let mut state = Self {
            master_addr: self_addr,
            sync_addr: self_addr,
            self_addr,
            height: 0,
            master_metric: AWDL_ELECTION_METRIC_INIT,
            self_metric: AWDL_ELECTION_METRIC_INIT,
            master_counter: AWDL_ELECTION_COUNTER_INIT,
            self_counter: AWDL_ELECTION_COUNTER_INIT,
        };
        state.reset_self();
        state
    }
}

impl AwdlElectionState {
    fn reset_metric(&mut self) {
        self.self_counter = AWDL_ELECTION_COUNTER_INIT;
        self.self_metric = AWDL_ELECTION_METRIC_INIT;
    }

    fn reset_self(&mut self) {
        self.height = 0;
        self.master_addr = self.self_addr;
        self.sync_addr = self.self_addr;
        self.master_metric = self.self_metric;
        self.master_counter = self.self_counter;
    }
}

/// Initialize election state
pub fn awdl_election_state_init(state: &mut AwdlElectionState, self_addr: &[u8; 6]) {
    state.master_addr = *self_addr;
    state.sync_addr = *self_addr;
    state.self_addr = *self_addr;
    state.reset_metric();
    state.reset_self();
}

/// Check if a given address is our sync master
pub fn awdl_election_is_sync_master(state: &AwdlElectionState, addr: &[u8; 6]) -> bool {
    state.sync_addr == *addr
}

/// Compare two MAC addresses (returns Ordering-like: <0, 0, >0)
pub fn compare_ether_addr(a: &[u8; 6], b: &[u8; 6]) -> i32 {
    for i in 0..6 {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
    }
    0
}

fn compare_u32(a: u32, b: u32) -> i32 {
    if a < b {
        -1
    } else if a > b {
        1
    } else {
        0
    }
}

/// Compare two election states by master metric (counter first, then metric)
fn awdl_election_compare_master(a: &AwdlElectionState, b: &AwdlElectionState) -> i32 {
    let result = compare_u32(a.master_counter, b.master_counter);
    if result != 0 {
        return result;
    }
    compare_u32(a.master_metric, b.master_metric)
}

/// Run the election algorithm over the given peer list.
/// `peers` is a slice of (election_state, is_valid) tuples.
pub fn awdl_election_run(
    state: &mut AwdlElectionState,
    peers: &[(AwdlElectionState, bool)], // (peer_election, is_valid)
) {
    let old_master = state.master_addr;
    let old_sync = state.sync_addr;

    state.reset_self();

    let mut best: Option<usize> = None; // index of best peer (None = self)

    for (i, (peer_state, is_valid)) in peers.iter().enumerate() {
        if !is_valid {
            continue;
        }
        if peer_state.height + 1 > AWDL_ELECTION_TREE_MAX_HEIGHT {
            continue; // tree would be too large
        }
        // Reject: do not allow cycles in sync tree
        if awdl_election_is_sync_master(peer_state, &state.self_addr) {
            continue;
        }

        let best_state = match best {
            Some(idx) => &peers[idx].0,
            None => state, // self is current best
        };

        let cmp = awdl_election_compare_master(peer_state, best_state);
        if cmp < 0 {
            continue; // reject: lower master metric
        } else if cmp == 0 {
            // same metric: compare distance to master
            if peer_state.height > best_state.height {
                continue; // reject: longer path
            } else if peer_state.height == best_state.height {
                // tie break: prefer higher self_addr
                if compare_ether_addr(&peer_state.self_addr, &best_state.self_addr) <= 0 {
                    continue; // reject: peer has smaller address
                }
            }
        }
        // accept this peer as best
        best = Some(i);
    }

    if let Some(idx) = best {
        let peer = &peers[idx].0;
        state.master_addr = peer.master_addr;
        state.sync_addr = peer.self_addr;
        state.master_metric = peer.master_metric;
        state.master_counter = peer.master_counter;
        state.height = peer.height + 1;
    }
    // else: self remains master (reset_self already done)

    // Log if master changed
    if compare_ether_addr(&old_master, &state.master_addr) != 0
        || compare_ether_addr(&old_sync, &state.sync_addr) != 0
    {
        log::debug!(
            "new election tree: {}",
            awdl_election_tree_print(state)
        );
    }
}

/// Print the election tree as a string
pub fn awdl_election_tree_print(state: &AwdlElectionState) -> String {
    let mut result = format!(
        "{}",
        ether_ntoa(&state.self_addr)
    );
    if state.height > 0 {
        result.push_str(&format!(" -> {}", ether_ntoa(&state.sync_addr)));
    }
    if state.height > 1 {
        result.push(' ');
        for _ in 1..state.height {
            result.push('-');
        }
        result.push_str(&format!("> {}", ether_ntoa(&state.master_addr)));
    }
    result.push_str(&format!(
        " (met {}, ctr {})",
        state.master_metric, state.master_counter
    ));
    result
}

/// Format an Ethernet address as a colon-separated hex string
pub fn ether_ntoa(addr: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_ether_addr() {
        let a = [0, 0, 0, 0, 0, 1];
        let b = [0, 0, 0, 0, 0, 2];
        assert_eq!(compare_ether_addr(&a, &b), -1);
        assert_eq!(compare_ether_addr(&b, &a), 1);
        assert_eq!(compare_ether_addr(&a, &a), 0);
    }

    #[test]
    fn test_election_self_is_master() {
        let self_addr = [1, 2, 3, 4, 5, 6];
        let state = AwdlElectionState::new(self_addr);
        assert_eq!(state.master_addr, self_addr);
        assert_eq!(state.sync_addr, self_addr);
        assert!(awdl_election_is_sync_master(&state, &self_addr));
    }

    #[test]
    fn test_election_chooses_higher_counter() {
        let self_addr = [1, 2, 3, 4, 5, 6];
        let mut state = AwdlElectionState::new(self_addr);

        let peer_addr = [0, 0, 0, 0, 0, 2];
        let mut peer_election = AwdlElectionState::new(peer_addr);
        peer_election.self_counter = 10;
        peer_election.self_metric = 60;
        peer_election.master_addr = peer_addr;
        peer_election.master_counter = 10;
        peer_election.master_metric = 60;

        awdl_election_run(&mut state, &[(peer_election, true)]);
        assert_eq!(state.sync_addr, peer_addr);
        assert_eq!(state.height, 1);
    }
}
