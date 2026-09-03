// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL channel.h/channel.c – channel state, sequences, and siphash-based expected calculation

use crate::awdl::siphash;

pub const AWDL_CHANSEQ_LENGTH: usize = 16;

/// Channel encoding modes (matching C enum awdl_chan_encoding)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AwdlChanEncoding {
    Simple = 0,
    Legacy = 1,
    Opclass = 3,
}

/// AWDL channel (2-byte wire format)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AwdlChan {
    pub val: [u8; 2],
}

impl AwdlChan {
    pub fn new(chan_num: u8, opclass: u8) -> Self {
        Self {
            val: [chan_num, opclass],
        }
    }

    pub fn chan_num_simple(&self) -> u8 {
        self.val[0]
    }

    pub fn chan_num_legacy(&self) -> u8 {
        self.val[1]
    }

    pub fn chan_num_opclass(&self) -> u8 {
        self.val[0]
    }

    pub fn chan_num_for_enc(&self, enc: AwdlChanEncoding) -> u8 {
        match enc {
            AwdlChanEncoding::Simple => self.chan_num_simple(),
            AwdlChanEncoding::Legacy => self.chan_num_legacy(),
            AwdlChanEncoding::Opclass => self.chan_num_opclass(),
        }
    }
}

pub const CHAN_NULL: AwdlChan = AwdlChan { val: [0, 0x00] };
pub const CHAN_OPCLASS_6: AwdlChan = AwdlChan { val: [6, 0x51] };
pub const CHAN_OPCLASS_44: AwdlChan = AwdlChan { val: [44, 0x80] };
pub const CHAN_OPCLASS_149: AwdlChan = AwdlChan {
    val: [149, 0x80],
};

/// Channel encoding size in bytes
pub fn awdl_chan_encoding_size(enc: AwdlChanEncoding) -> usize {
    match enc {
        AwdlChanEncoding::Simple => 1,
        AwdlChanEncoding::Legacy | AwdlChanEncoding::Opclass => 2,
    }
}

/// Channel state
#[derive(Debug, Clone)]
pub struct AwdlChannelState {
    pub enc: AwdlChanEncoding,
    pub sequence: [AwdlChan; AWDL_CHANSEQ_LENGTH],
    pub master: AwdlChan,
    pub current: AwdlChan,
}

impl AwdlChannelState {
    pub fn new(master: AwdlChan) -> Self {
        let mut seq = [CHAN_NULL; AWDL_CHANSEQ_LENGTH];
        awdl_chanseq_init_static(&mut seq, &master);
        Self {
            enc: AwdlChanEncoding::Opclass,
            sequence: seq,
            master,
            current: CHAN_NULL,
        }
    }
}

/// Initialize channel sequence: first 8 slots = CHAN_OPCLASS_149, rest = CHAN_OPCLASS_6
pub fn awdl_chanseq_init(seq: &mut [AwdlChan; AWDL_CHANSEQ_LENGTH]) {
    for i in 0..AWDL_CHANSEQ_LENGTH {
        if i < 8 {
            seq[i] = CHAN_OPCLASS_149;
        } else {
            seq[i] = CHAN_OPCLASS_6;
        }
    }
}

/// Initialize idle channel sequence
pub fn awdl_chanseq_init_idle(seq: &mut [AwdlChan; AWDL_CHANSEQ_LENGTH]) {
    for i in 0..AWDL_CHANSEQ_LENGTH {
        match i {
            8 => seq[i] = CHAN_OPCLASS_6,
            0 | 9 | 10 => seq[i] = CHAN_OPCLASS_149,
            _ => seq[i] = CHAN_NULL,
        }
    }
}

/// Initialize channel sequence to a single channel repeated
pub fn awdl_chanseq_init_static(seq: &mut [AwdlChan; AWDL_CHANSEQ_LENGTH], chan: &AwdlChan) {
    for slot in seq.iter_mut() {
        *slot = *chan;
    }
}

/// Get channel number from a channel value for a given encoding
pub fn awdl_chan_num(chan: AwdlChan, enc: AwdlChanEncoding) -> u8 {
    chan.chan_num_for_enc(enc)
}

// ---------------------------------------------------------------------------
// ieee80211 channel <-> frequency conversion
// ---------------------------------------------------------------------------

/// Convert channel number to center frequency in MHz
pub fn ieee80211_channel_to_frequency(chan: i32) -> i32 {
    if chan <= 0 {
        return 0;
    }
    if chan == 14 {
        return 2484;
    } else if chan < 14 {
        return 2407 + chan * 5;
    }
    if chan < 32 {
        return 0;
    }
    if chan >= 182 && chan <= 196 {
        return 4000 + chan * 5;
    }
    5000 + chan * 5
}

/// Convert center frequency in MHz to channel number
pub fn ieee80211_frequency_to_channel(freq: i32) -> i32 {
    if freq == 2484 {
        return 14;
    } else if freq < 2484 {
        return (freq - 2407) / 5;
    } else if freq >= 4910 && freq <= 4980 {
        return (freq - 4000) / 5;
    } else if freq <= 45000 {
        return (freq - 5000) / 5;
    } else if freq >= 58320 && freq <= 64800 {
        return (freq - 56160) / 2160;
    }
    0
}

// ---------------------------------------------------------------------------
// SipHash-based channel sequence expected value (from OWL's channel_expected)
// ---------------------------------------------------------------------------

/// SipHash key used by OWL for channel sequence derivation (from the OWL code)
/// The key is "0123456789012345" as bytes (a well-known test key in OWL).
const SIPHASH_KEY: [u8; 16] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
];

/// Compute the expected channel sequence slot from AWDL parameters.
///
/// `chanseq_id` is the 2-byte channel sequence identifier.
/// `aw_counter` is the current AW counter.
/// `presence_mode` is the presence mode (typically 4).
///
/// Returns the expected channel slot index within AWDL_CHANSEQ_LENGTH.
pub fn awdl_channel_expected(
    chanseq_id: u16,
    aw_counter: u16,
    presence_mode: u8,
) -> usize {
    let input = chanseq_id.to_le_bytes();
    let hash = siphash::siphash24(&input, &SIPHASH_KEY);
    let truncated = siphash::siphash_truncate(hash);
    let eaw = (aw_counter / presence_mode as u16) as usize;
    (eaw.wrapping_add(truncated as usize)) % AWDL_CHANSEQ_LENGTH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chanseq_init_static() {
        let mut seq = [CHAN_NULL; AWDL_CHANSEQ_LENGTH];
        awdl_chanseq_init_static(&mut seq, &CHAN_OPCLASS_6);
        for s in &seq {
            assert_eq!(s.chan_num_opclass(), 6);
        }
    }

    #[test]
    fn test_channel_to_freq() {
        assert_eq!(ieee80211_channel_to_frequency(6), 2437);
        assert_eq!(ieee80211_channel_to_frequency(36), 5180);
        assert_eq!(ieee80211_channel_to_frequency(149), 5745);
    }

    #[test]
    fn test_freq_to_channel() {
        assert_eq!(ieee80211_frequency_to_channel(2437), 6);
        assert_eq!(ieee80211_frequency_to_channel(5180), 36);
        assert_eq!(ieee80211_frequency_to_channel(5745), 149);
    }
}
