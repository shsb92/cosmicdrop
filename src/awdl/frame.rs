// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL frame.h/frame.c and ieee80211.h – AWDL wire format, TLV definitions

// ---------------------------------------------------------------------------
// IEEE 802.11 constants
// ---------------------------------------------------------------------------

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const OUI_LEN: usize = 3;
pub const FCS_LEN: usize = 4;

// Frame control field masks
pub const IEEE80211_FCTL_FTYPE: u16 = 0x000c;
pub const IEEE80211_FCTL_STYPE: u16 = 0x00f0;

pub const IEEE80211_FTYPE_MGMT: u16 = 0x0000;
pub const IEEE80211_FTYPE_DATA: u16 = 0x0008;

pub const IEEE80211_STYPE_ACTION: u16 = 0x00D0;
pub const IEEE80211_STYPE_DATA: u16 = 0x0000;
pub const IEEE80211_STYPE_QOS_DATA: u16 = 0x0080;

pub const IEEE80211_QOS_CTL_LEN: usize = 2;
pub const IEEE80211_QOS_CTL_A_MSDU_PRESENT: u16 = 0x0080;
pub const IEEE80211_QOS_CTL_ACK_POLICY_NOACK: u16 = 0x0020;

pub const IEEE80211_MAX_DATA_LEN: usize = 2304;
pub const IEEE80211_MAX_FRAME_LEN: usize = 2352;

pub const ETHER_ADDR_LEN: usize = 6;
pub const ETHER_MAX_LEN: usize = 1518;

// ---------------------------------------------------------------------------
// AWDL constants
// ---------------------------------------------------------------------------

pub const AWDL_LLC_PROTOCOL_ID: u16 = 0x0800;

/// AWDL OUI: 00:17:f2
pub const AWDL_OUI: [u8; 3] = [0x00, 0x17, 0xf2];

/// AWDL BSSID: 00:25:00:ff:94:73
pub const AWDL_BSSID: [u8; 6] = [0x00, 0x25, 0x00, 0xff, 0x94, 0x73];

/// IEEE802.11 vendor-specific action category
pub const IEEE80211_VENDOR_SPECIFIC: u8 = 127;

/// AWDL_VERSION_COMPAT = awdl_version(1, 0) = 0x10
pub const AWDL_VERSION_COMPAT: u8 = 0x10;

pub const AWDL_TYPE: u8 = 8;

/// AWDL DNS short for ".local"
pub const AWDL_DNS_SHORT_LOCAL: u16 = 0xc00c;

pub const AWDL_DATA_HEAD: u16 = 0x0403;
pub const AWDL_DATA_PAD: u16 = 0x0000;

pub const AWDL_SOCIAL_CHANNEL_6_BIT: u16 = 0x0001;
pub const AWDL_SOCIAL_CHANNEL_44_BIT: u16 = 0x0002;
pub const AWDL_SOCIAL_CHANNEL_149_BIT: u16 = 0x0004;

// ---------------------------------------------------------------------------
// AWDL action frame subtypes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AwdlActionType {
    PSF = 0,
    MIF = 3,
}

pub fn awdl_frame_as_str(t: u8) -> &'static str {
    match t {
        0 => "PSF",
        3 => "MIF",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// AWDL TLV type values
// ---------------------------------------------------------------------------

pub const AWDL_SSTH_REQUEST_TLV: u8 = 0;
pub const AWDL_SERVICE_REQUEST_TLV: u8 = 1;
pub const AWDL_SERVICE_RESPONSE_TLV: u8 = 2;
pub const AWDL_SYNCHRONIZATON_PARAMETERS_TLV: u8 = 4;
pub const AWDL_ELECTION_PARAMETERS_TLV: u8 = 5;
pub const AWDL_SERVICE_PARAMETERS_TLV: u8 = 6;
pub const AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV: u8 = 7;
pub const AWDL_ENHANCED_DATA_RATE_OPERATION_TLV: u8 = 8;
pub const AWDL_INFRA_TLV: u8 = 9;
pub const AWDL_INVITE_TLV: u8 = 10;
pub const AWDL_DBG_STRING_TLV: u8 = 11;
pub const AWDL_DATA_PATH_STATE_TLV: u8 = 12;
pub const AWDL_ENCAPSULATED_IP_TLV: u8 = 13;
pub const AWDL_DATAPATH_DEBUG_PACKET_LIVE_TLV: u8 = 14;
pub const AWDL_DATAPATH_DEBUG_AF_LIVE_TLV: u8 = 15;
pub const AWDL_ARPA_TLV: u8 = 16;
pub const AWDL_IEEE80211_CNTNR_TLV: u8 = 17;
pub const AWDL_CHAN_SEQ_TLV: u8 = 18;
pub const AWDL_SYNCTREE_TLV: u8 = 20;
pub const AWDL_VERSION_TLV: u8 = 21;
pub const AWDL_BLOOM_FILTER_TLV: u8 = 22;
pub const AWDL_NAN_SYNC_TLV: u8 = 23;
pub const AWDL_ELECTION_PARAMETERS_V2_TLV: u8 = 24;

pub fn awdl_tlv_as_str(t: u8) -> &'static str {
    match t {
        0 => "SSTH Request",
        1 => "Service Request",
        2 => "Service Response",
        4 => "Synchronization Parameters",
        5 => "Election Parameters",
        6 => "Service Parameters",
        7 => "HT Capabilities",
        8 => "HT Operation",
        9 => "Infra",
        10 => "Invite",
        11 => "Debug String",
        12 => "Data Path State",
        13 => "Encapsulated IP",
        14 => "Datapath Debug Packet Live",
        15 => "Datapath Debug AF Live",
        16 => "Arpa",
        17 => "VHT Capabilities",
        18 => "Channel Sequence",
        20 => "Synchronization Tree",
        21 => "Version",
        22 => "Bloom Filter",
        23 => "NAN Sync",
        24 => "Election Parameters v2",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Packed wire structs (C __attribute__((packed)) equivalents)
// ---------------------------------------------------------------------------

/// IEEE 802.11 frame header (24 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Ieee80211Hdr {
    pub frame_control: u16,
    pub duration_id: u16,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_ctrl: u16,
}

/// LLC/SNAP header (8 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct LlcHdr {
    pub dsap: u8,
    pub ssap: u8,
    pub control: u8,
    pub oui: [u8; 3],
    pub pid: u16,
}

/// AWDL action frame header (16 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlAction {
    pub category: u8,
    pub oui: [u8; 3],
    pub type_: u8,
    pub version: u8,
    pub subtype: u8,
    pub reserved: u8,
    pub phy_tx: u32,
    pub target_tx: u32,
}

/// TLV header (type u8 + length u16 LE = 3 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Tl {
    pub type_: u8,
    pub length: u16,
}

/// AWDL data frame header (8 bytes)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlData {
    pub head: u16,
    pub seq: u16,
    pub pad: u16,
    pub ethertype: u16,
}

/// Channel sequence descriptor header (6 bytes, followed by per-channel data)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlChanseq {
    pub count: u8,
    pub encoding: u8,
    pub duplicate_count: u8,
    pub step_count: u8,
    pub fill_channel: u16,
}

/// Sync parameters TLV value (variable-length due to appended chanseq)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlSyncParamsTlv {
    pub type_: u8,
    pub length: u16,
    pub next_aw_channel: u8,
    pub tx_down_counter: u16,
    pub master_channel: u8,
    pub guard_time: u8,
    pub aw_period: u16,
    pub af_period: u16,
    pub flags: u16,
    pub aw_ext_length: u16,
    pub aw_com_length: u16,
    pub remaining_aw_length: u16,
    pub min_ext: u8,
    pub max_ext_multicast: u8,
    pub max_ext_unicast: u8,
    pub max_ext_af: u8,
    pub master_addr: [u8; 6],
    pub presence_mode: u8,
    pub reserved: u8,
    pub next_aw_seq: u16,
    pub ap_alignment: u16,
}

/// Channel sequence TLV header (chanseq appended after)
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlChanseqTlv {
    pub type_: u8,
    pub length: u16,
}

/// Election parameters TLV
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlElectionParamsTlv {
    pub type_: u8,
    pub length: u16,
    pub flags: u8,
    pub id: u16,
    pub distancetop: u8,
    pub unknown: u8,
    pub top_master_addr: [u8; 6],
    pub top_master_metric: u32,
    pub self_metric: u32,
    pub pad: [u8; 2],
}

/// Election parameters v2 TLV
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlElectionParamsV2Tlv {
    pub type_: u8,
    pub length: u16,
    pub master_addr: [u8; 6],
    pub sync_addr: [u8; 6],
    pub master_counter: u32,
    pub distance_to_master: u32,
    pub master_metric: u32,
    pub self_metric: u32,
    pub unknown: u32,
    pub reserved: u32,
    pub self_counter: u32,
}

/// Service parameters TLV
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlServiceParamsTlv {
    pub type_: u8,
    pub length: u16,
    pub unknown: [u8; 3],
    pub sui: u16,
    pub bitmask: u32,
}

/// HT capabilities TLV
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlHtCapabilitiesTlv {
    pub type_: u8,
    pub length: u16,
    pub unknown: u16,
    pub ht_capabilities: u16,
    pub ampdu_params: u8,
    pub rx_mcs: u8,
    pub unknown2: u16,
}

/// Data path state TLV
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlDataPathStateTlv {
    pub type_: u8,
    pub length: u16,
    pub flags: u16,
    pub country_code: [u8; 3],
    pub social_channels: u16,
    pub awdl_addr: [u8; 6],
    pub ext_flags: u16,
}

/// ARPA TLV
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlArpaTlv {
    pub type_: u8,
    pub length: u16,
    pub flags: u8,
    pub name_length: u8,
}

/// Version TLV
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AwdlVersionTlv {
    pub type_: u8,
    pub length: u16,
    pub version: u8,
    pub devclass: u8,
}

// ---------------------------------------------------------------------------
// Data path state flags
// ---------------------------------------------------------------------------

pub const AWDL_DATA_PATH_FLAG_COUNTRY_CODE: u16 = 0x0100;
pub const AWDL_DATA_PATH_FLAG_SOCIAL_CHANNEL_MAP: u16 = 0x0200;
pub const AWDL_DATA_PATH_FLAG_INFRA_INFO: u16 = 0x0001;
pub const AWDL_DATA_PATH_FLAG_INFRA_ADDRESS: u16 = 0x0002;
pub const AWDL_DATA_PATH_FLAG_AWDL_ADDRESS: u16 = 0x0004;
pub const AWDL_DATA_PATH_FLAG_UMI: u16 = 0x0010;

// ---------------------------------------------------------------------------
// Safe transmutation helpers for packed structs
// ---------------------------------------------------------------------------

/// Read a packed struct from a byte slice. Safe because we copy bytes.
pub unsafe fn read_packed<T: Copy>(data: &[u8], offset: usize) -> Option<T> {
    let size = std::mem::size_of::<T>();
    if offset + size > data.len() {
        return None;
    }
    Some(std::ptr::read_unaligned(data[offset..].as_ptr() as *const T))
}

/// Write a packed struct into a byte slice. Safe because we copy bytes.
pub unsafe fn write_packed<T: Copy>(buf: &mut [u8], offset: usize, val: &T) -> bool {
    let size = std::mem::size_of::<T>();
    if offset + size > buf.len() {
        return false;
    }
    std::ptr::copy_nonoverlapping(
        val as *const T as *const u8,
        buf[offset..].as_mut_ptr(),
        size,
    );
    true
}

/// Size of a packed struct
pub fn packed_size_of<T: Copy>() -> usize {
    std::mem::size_of::<T>()
}

// ---------------------------------------------------------------------------
// TLV builder helpers
// ---------------------------------------------------------------------------

use crate::awdl::wire;

/// Write a TLV header (type + LE16 length) and return total bytes written
/// including header. `len` is the value length.
pub fn write_tlv_header(buf: &mut [u8], offset: usize, tlv_type: u8, len: u16) -> usize {
    buf[offset] = tlv_type;
    wire::write_le16(buf, offset + 1, len).expect("TLV header fits");
    3 + len as usize
}

// ---------------------------------------------------------------------------
// Self-test for sizes matching C packed structs
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_sizes() {
        assert_eq!(std::mem::size_of::<Ieee80211Hdr>(), 24);
        assert_eq!(std::mem::size_of::<LlcHdr>(), 8);
        assert_eq!(std::mem::size_of::<AwdlAction>(), 16);
        assert_eq!(std::mem::size_of::<Tl>(), 3);
        assert_eq!(std::mem::size_of::<AwdlData>(), 8);
        assert_eq!(std::mem::size_of::<AwdlChanseq>(), 6);
        assert_eq!(std::mem::size_of::<AwdlElectionParamsV2Tlv>(), 39);
        assert_eq!(std::mem::size_of::<AwdlVersionTlv>(), 5);
    }
}
