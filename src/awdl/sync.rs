// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL sync.h/sync.c – availability-window sync timing

use crate::awdl::state::ieee80211_tu_to_usec;
use crate::awdl::state::ieee80211_usec_to_tu;

/// AWDL sync state
#[derive(Debug, Clone)]
pub struct AwdlSyncState {
    pub aw_counter: u16,
    pub last_update: u64, // in microseconds
    pub aw_period: u16,   // in TUs
    pub presence_mode: u8,

    // statistics
    pub meas_err: u64,
    pub meas_total: u64,
}

impl AwdlSyncState {
    pub fn new(now: u64) -> Self {
        Self {
            aw_counter: 0,
            last_update: now,
            aw_period: 16,
            presence_mode: 4,
            meas_err: 0,
            meas_total: 0,
        }
    }
}

/// Initialize sync state
pub fn awdl_sync_state_init(state: &mut AwdlSyncState, now: u64) {
    state.last_update = now;
    state.aw_counter = 0;
    state.aw_period = 16;
    state.presence_mode = 4;
    state.meas_err = 0;
    state.meas_total = 0;
}

/// Get time to next AW in TUs
pub fn awdl_sync_next_aw_tu(now_usec: u64, state: &AwdlSyncState) -> u16 {
    let eaw_period = (state.presence_mode as u64) * (state.aw_period as u64);
    let time_since = ieee80211_usec_to_tu(now_usec.wrapping_sub(state.last_update));
    let next_aw_tu = eaw_period - (time_since % eaw_period);
    next_aw_tu as u16
}

/// Get time to next AW in microseconds
pub fn awdl_sync_next_aw_us(now_usec: u64, state: &AwdlSyncState) -> u64 {
    let eaw_period = ieee80211_tu_to_usec((state.presence_mode as u64) * (state.aw_period as u64));
    let time_since = now_usec.wrapping_sub(state.last_update);
    let next_aw_us = eaw_period - (time_since % eaw_period);
    next_aw_us
}

/// Get current AW counter
pub fn awdl_sync_current_aw(now_usec: u64, state: &AwdlSyncState) -> u16 {
    let eaw_period = (state.presence_mode as u64) * (state.aw_period as u64);
    let time_since = ieee80211_usec_to_tu(now_usec.wrapping_sub(state.last_update));
    let current_aw = (state.aw_counter as u64)
        + (time_since % eaw_period) / (state.aw_period as u64)
        + (state.presence_mode as u64) * (time_since / eaw_period);
    current_aw as u16
}

/// Get current EAW counter
pub fn awdl_sync_current_eaw(now_usec: u64, state: &AwdlSyncState) -> u16 {
    awdl_sync_current_aw(now_usec, state) / (state.presence_mode as u16)
}

/// Compute synchronization error in TUs
pub fn awdl_sync_error_tu(
    now_usec: u64,
    time_to_next_aw: u16,
    aw_counter: u16,
    state: &AwdlSyncState,
) -> i64 {
    let remote_eaw = (aw_counter / state.presence_mode as u16) as i64;
    let local_eaw = awdl_sync_current_eaw(now_usec, state) as i64;
    let eaw_period = (state.presence_mode as i64) * (state.aw_period as i64);
    let eaw_diff = (remote_eaw - local_eaw) * eaw_period;
    let aw_diff = (time_to_next_aw as i64) - (awdl_sync_next_aw_tu(now_usec, state) as i64);
    eaw_diff - aw_diff
}

/// Update last seen timestamp from sync parameters
pub fn awdl_sync_update_last(
    now_usec: u64,
    time_to_next_aw: u16,
    aw_counter: u16,
    state: &mut AwdlSyncState,
) {
    let eaw_period = (state.presence_mode as u64) * (state.aw_period as u64);
    state.last_update = now_usec
        .wrapping_sub(ieee80211_tu_to_usec(
            eaw_period - (time_to_next_aw as u64),
        ));
    state.aw_counter = aw_counter & 0xfffc; // mask last two bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_next_aw_tu() {
        let state = AwdlSyncState {
            aw_counter: 0,
            last_update: 0,
            aw_period: 16,
            presence_mode: 4,
            meas_err: 0,
            meas_total: 0,
        };
        // At time 0, next AW should be eaw_period = 4 * 16 = 64 TUs
        assert_eq!(awdl_sync_next_aw_tu(0, &state), 64);
    }

    #[test]
    fn test_sync_current_aw() {
        let state = AwdlSyncState {
            aw_counter: 0,
            last_update: 0,
            aw_period: 16,
            presence_mode: 4,
            meas_err: 0,
            meas_total: 0,
        };
        // At time 0, current AW should be 0
        assert_eq!(awdl_sync_current_aw(0, &state), 0);
        // After 16 TUs = 16 * 1024 usec, we should be at AW 1
        let now = ieee80211_tu_to_usec(16);
        assert_eq!(awdl_sync_current_aw(now, &state), 1);
    }
}
