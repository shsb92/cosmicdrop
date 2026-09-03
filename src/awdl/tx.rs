// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL tx.h/tx.c – crafting action/data frames

use crate::awdl::channel::AWDL_CHANSEQ_LENGTH;
use crate::awdl::frame::*;
pub use crate::awdl::frame::AwdlActionType;
use crate::awdl::state::{
    clock_time_us, AwdlState, Ieee80211State,
};
use crate::awdl::sync::{awdl_sync_current_aw, awdl_sync_next_aw_tu};

pub const TX_OK: i32 = 0;
pub const TX_FAIL: i32 = -1;

/// Size of the AWDL action frame header
pub const AWDL_ACTION_SIZE: usize = std::mem::size_of::<AwdlAction>();

const AWDL_SYNC_PARAMS_TLV_FIXED: usize = std::mem::size_of::<AwdlSyncParamsTlv>();

/// Initialize the AWDL action frame header
pub fn awdl_init_action(buf: &mut [u8], action_type: AwdlActionType) -> usize {
    let steady_time = (clock_time_us() & 0xffffffff) as u32;
    let af = AwdlAction {
        category: IEEE80211_VENDOR_SPECIFIC,
        oui: AWDL_OUI,
        type_: AWDL_TYPE,
        version: AWDL_VERSION_COMPAT,
        subtype: action_type as u8,
        reserved: 0,
        phy_tx: steady_time,
        target_tx: steady_time,
    };
    // phy_tx and target_tx are stored little-endian on the wire (as in C where
    // they are assigned with htole32 into the packed struct).
    unsafe {
        if !write_packed(buf, 0, &af) {
            return 0;
        }
    }
    AWDL_ACTION_SIZE
}

/// Get the encoding length for channel encoding (bytes per channel value)
pub fn awdl_chan_encoding_length_enc(enc: crate::awdl::channel::AwdlChanEncoding) -> usize {
    match enc {
        crate::awdl::channel::AwdlChanEncoding::Simple => 1,
        crate::awdl::channel::AwdlChanEncoding::Legacy
        | crate::awdl::channel::AwdlChanEncoding::Opclass => 2,
    }
}

/// Initialize the channel sequence payload (used inside sync params & chanseq TLVs)
pub fn awdl_init_chanseq(buf: &mut [u8], state: &AwdlState) -> usize {
    let enc_len = awdl_chan_encoding_length_enc(state.channel.enc);
    let chanseq = AwdlChanseq {
        count: (AWDL_CHANSEQ_LENGTH - 1) as u8,
        encoding: state.channel.enc as u8,
        duplicate_count: 0,
        step_count: 3,
        fill_channel: 0xffff,
    };
    unsafe {
        if !write_packed(buf, 0, &chanseq) {
            return 0;
        }
    }
    let mut offset = std::mem::size_of::<AwdlChanseq>();
    for i in 0..AWDL_CHANSEQ_LENGTH {
        let val = &state.channel.sequence[i].val;
        if offset + enc_len > buf.len() {
            break;
        }
        buf[offset..offset + enc_len].copy_from_slice(&val[..enc_len]);
        offset += enc_len;
    }
    offset
}

/// Initialize the sync parameters TLV
pub fn awdl_init_sync_params_tlv(buf: &mut [u8], state: &AwdlState) -> usize {
    let now = clock_time_us();
    let aw_period = state.sync.aw_period;
    let presence_mode = state.sync.presence_mode;
    let next_aw = awdl_sync_next_aw_tu(now, &state.sync);
    let next_aw_seq = awdl_sync_current_aw(now, &state.sync);

    let mut tlv = AwdlSyncParamsTlv {
        type_: AWDL_SYNCHRONIZATON_PARAMETERS_TLV,
        length: 0,
        next_aw_channel: crate::awdl::channel::awdl_chan_num(
            state.channel.current,
            state.channel.enc,
        ),
        tx_down_counter: next_aw,
        master_channel: crate::awdl::channel::awdl_chan_num(
            state.channel.master,
            state.channel.enc,
        ),
        guard_time: 0,
        aw_period,
        af_period: state.psf_interval,
        flags: 0x1800,
        aw_ext_length: aw_period,
        aw_com_length: aw_period,
        remaining_aw_length: 0,
        min_ext: presence_mode - 1,
        max_ext_multicast: presence_mode - 1,
        max_ext_unicast: presence_mode - 1,
        max_ext_af: presence_mode - 1,
        master_addr: state.election.master_addr,
        presence_mode,
        reserved: 0,
        next_aw_seq,
        ap_alignment: next_aw_seq,
    };

    // remaining_aw_length computation
    let aw_com = tlv.aw_com_length as i64;
    let tx_down = tlv.tx_down_counter as i64;
    let guard = (aw_period as i64) * (presence_mode as i64) - tx_down;
    tlv.remaining_aw_length = if aw_com < guard {
        0
    } else {
        (aw_com - guard) as u16
    };

    let fixed = AWDL_SYNC_PARAMS_TLV_FIXED;
    let mut len = fixed;

    // write fixed fields first
    unsafe {
        if !write_packed(buf, 0, &tlv) {
            return 0;
        }
    }

    // append chanseq
    len += awdl_init_chanseq(&mut buf[fixed..], state);

    // padding (2 zero bytes to make TLV length a multiple of 4)
    if buf.len() >= len + 2 {
        buf[len] = 0;
        buf[len + 1] = 0;
        len += 2;
    }

    // write TLV length
    let _ = crate::awdl::wire::write_le16(&mut buf[1..], 0, (len - 3) as u16);

    len
}

/// Initialize the channel sequence TLV
pub fn awdl_init_chanseq_tlv(buf: &mut [u8], state: &AwdlState) -> usize {
    buf[0] = AWDL_CHAN_SEQ_TLV;
    let mut len = std::mem::size_of::<AwdlChanseqTlv>();
    len += awdl_init_chanseq(&mut buf[len..], state);
    // padding (3 zero bytes)
    if buf.len() >= len + 3 {
        buf[len] = 0;
        buf[len + 1] = 0;
        buf[len + 2] = 0;
        len += 3;
    }
    let _ = crate::awdl::wire::write_le16(&mut buf[1..], 0, (len - 3) as u16);
    len
}

/// Initialize the election parameters TLV
pub fn awdl_init_election_params_tlv(buf: &mut [u8], state: &AwdlState) -> usize {
    let mut tlv = AwdlElectionParamsTlv {
        type_: AWDL_ELECTION_PARAMETERS_TLV,
        length: 0,
        flags: 0,
        id: 0,
        distancetop: state.election.height as u8,
        unknown: 0,
        top_master_addr: state.election.master_addr,
        top_master_metric: state.election.master_metric,
        self_metric: state.election.self_metric,
        pad: [0, 0],
    };
    let size = std::mem::size_of::<AwdlElectionParamsTlv>();
    tlv.length = (size - 3) as u16;
    unsafe {
        if !write_packed(buf, 0, &tlv) {
            return 0;
        }
    }
    size
}

/// Initialize the election parameters v2 TLV
pub fn awdl_init_election_params_v2_tlv(buf: &mut [u8], state: &AwdlState) -> usize {
    let mut tlv = AwdlElectionParamsV2Tlv {
        type_: AWDL_ELECTION_PARAMETERS_V2_TLV,
        length: 0,
        master_addr: state.election.master_addr,
        sync_addr: state.election.sync_addr,
        master_counter: state.election.master_counter,
        distance_to_master: state.election.height,
        master_metric: state.election.master_metric,
        self_metric: state.election.self_metric,
        unknown: 0,
        reserved: 0,
        self_counter: state.election.self_counter,
    };
    let size = std::mem::size_of::<AwdlElectionParamsV2Tlv>();
    tlv.length = (size - 3) as u16;
    unsafe {
        if !write_packed(buf, 0, &tlv) {
            return 0;
        }
    }
    size
}

/// Initialize the service parameters TLV
pub fn awdl_init_service_params_tlv(buf: &mut [u8], _state: &AwdlState) -> usize {
    let mut tlv = AwdlServiceParamsTlv {
        type_: AWDL_SERVICE_PARAMETERS_TLV,
        length: 0,
        unknown: [0, 0, 0],
        sui: 0,
        bitmask: 0,
    };
    let size = std::mem::size_of::<AwdlServiceParamsTlv>();
    tlv.length = (size - 3) as u16;
    unsafe {
        if !write_packed(buf, 0, &tlv) {
            return 0;
        }
    }
    size
}

/// Initialize the HT capabilities TLV
pub fn awdl_init_ht_capabilities_tlv(buf: &mut [u8], _state: &AwdlState) -> usize {
    let mut tlv = AwdlHtCapabilitiesTlv {
        type_: AWDL_ENHANCED_DATA_RATE_CAPABILITIES_TLV,
        length: 0,
        unknown: 0,
        ht_capabilities: 0x11ce,
        ampdu_params: 0x1b,
        rx_mcs: 0xff,
        unknown2: 0,
    };
    let size = std::mem::size_of::<AwdlHtCapabilitiesTlv>();
    tlv.length = (size - 3) as u16;
    unsafe {
        if !write_packed(buf, 0, &tlv) {
            return 0;
        }
    }
    size
}

/// Initialize the data path state TLV
pub fn awdl_init_data_path_state_tlv(buf: &mut [u8], state: &AwdlState) -> usize {
    let master_chan = crate::awdl::channel::awdl_chan_num(
        state.channel.master,
        crate::awdl::channel::AwdlChanEncoding::Opclass,
    );
    let social_channels = if master_chan == 6 {
        AWDL_SOCIAL_CHANNEL_6_BIT
    } else if master_chan == 44 {
        AWDL_SOCIAL_CHANNEL_44_BIT
    } else {
        AWDL_SOCIAL_CHANNEL_149_BIT
    };

    let mut tlv = AwdlDataPathStateTlv {
        type_: AWDL_DATA_PATH_STATE_TLV,
        length: 0,
        flags: 0x8f24,
        country_code: [b'X', b'0', 0],
        social_channels,
        awdl_addr: state.self_address,
        ext_flags: 0x0000,
    };
    let size = std::mem::size_of::<AwdlDataPathStateTlv>();
    tlv.length = (size - 3) as u16;
    unsafe {
        if !write_packed(buf, 0, &tlv) {
            return 0;
        }
    }
    size
}

/// Initialize the ARPA TLV
pub fn awdl_init_arpa_tlv(buf: &mut [u8], state: &AwdlState) -> usize {
    let name = state.name.as_bytes();
    let name_len = name.len();
    let mut tlv = AwdlArpaTlv {
        type_: AWDL_ARPA_TLV,
        length: 0,
        flags: 3,
        name_length: name_len as u8,
    };
    let size = std::mem::size_of::<AwdlArpaTlv>();
    let total_len = size - 3 + name_len + 2; // +2 for DNS suffix
    tlv.length = total_len as u16;
    unsafe {
        if !write_packed(buf, 0, &tlv) {
            return 0;
        }
    }
    // write name + DNS suffix (.local short)
    let name_off = size;
    let mut off = name_off;
    if name_off + name_len + 2 <= buf.len() {
        buf[off..off + name_len].copy_from_slice(name);
        off += name_len;
        buf[off..off + 2].copy_from_slice(&AWDL_DNS_SHORT_LOCAL.to_be_bytes());
    }
    3 + total_len as usize
}

/// Initialize the version TLV
pub fn awdl_init_version_tlv(buf: &mut [u8], state: &AwdlState) -> usize {
    let mut tlv = AwdlVersionTlv {
        type_: AWDL_VERSION_TLV,
        length: 0,
        version: state.version,
        devclass: state.dev_class,
    };
    let size = std::mem::size_of::<AwdlVersionTlv>();
    tlv.length = (size - 3) as u16;
    unsafe {
        if !write_packed(buf, 0, &tlv) {
            return 0;
        }
    }
    size
}

/// Initialize the radiotap header (TX)
pub fn ieee80211_init_radiotap_header(buf: &mut [u8]) -> usize {
    // Radiotap header + rate field
    // it_version (1) + it_pad (1) + it_len (2) + it_present (4) + rate (1)
    let mut present: u32 = 0;
    present |= 1 << 2; // IEEE80211_RADIOTAP_RATE = 2
    buf[0] = 0; // it_version
    buf[1] = 0; // it_pad
    let it_len: u16 = 8 + 1; // header + rate byte
    buf[2] = (it_len & 0xff) as u8;
    buf[3] = ((it_len >> 8) & 0xff) as u8;
    buf[4] = (present & 0xff) as u8;
    buf[5] = ((present >> 8) & 0xff) as u8;
    buf[6] = ((present >> 16) & 0xff) as u8;
    buf[7] = ((present >> 24) & 0xff) as u8;
    // rate field: 2 * rate (12 -> 24)
    buf[8] = 24;
    it_len as usize
}

/// Initialize an IEEE 802.11 header (3-address)
pub fn ieee80211_init_awdl_hdr(
    buf: &mut [u8],
    src: &[u8; 6],
    dst: &[u8; 6],
    ieee_state: &mut Ieee80211State,
    ftype_stype: u16,
) -> usize {
    let hdr = Ieee80211Hdr {
        frame_control: ftype_stype,
        duration_id: 0,
        addr1: *dst,
        addr2: *src,
        addr3: AWDL_BSSID,
        seq_ctrl: ieee_state.next_sequence_number() << 4,
    };
    unsafe {
        if !write_packed(buf, 0, &hdr) {
            return 0;
        }
    }
    std::mem::size_of::<Ieee80211Hdr>()
}

/// Initialize an AWDL action 802.11 header
pub fn ieee80211_init_awdl_action_hdr(
    buf: &mut [u8],
    src: &[u8; 6],
    dst: &[u8; 6],
    ieee_state: &mut Ieee80211State,
) -> usize {
    ieee80211_init_awdl_hdr(
        buf,
        src,
        dst,
        ieee_state,
        IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_ACTION,
    )
}

/// Initialize an AWDL data 802.11 header
pub fn ieee80211_init_awdl_data_hdr(
    buf: &mut [u8],
    src: &[u8; 6],
    dst: &[u8; 6],
    ieee_state: &mut Ieee80211State,
) -> usize {
    ieee80211_init_awdl_hdr(
        buf,
        src,
        dst,
        ieee_state,
        IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA,
    )
}

/// Initialize the LLC/SNAP header
pub fn llc_init_awdl_hdr(buf: &mut [u8]) -> usize {
    let hdr = LlcHdr {
        dsap: 0xaa,
        ssap: 0xaa,
        control: 0x03,
        oui: AWDL_OUI,
        pid: AWDL_LLC_PROTOCOL_ID, // big-endian on wire
    };
    unsafe {
        if !write_packed(buf, 0, &hdr) {
            return 0;
        }
    }
    std::mem::size_of::<LlcHdr>()
}

/// Initialize the AWDL data frame header
pub fn awdl_init_data(buf: &mut [u8], state: &mut AwdlState) -> usize {
    let hdr = AwdlData {
        head: AWDL_DATA_HEAD,
        seq: state.next_sequence_number(),
        pad: AWDL_DATA_PAD,
        ethertype: ETH_P_IPV6, // big-endian on wire
    };
    unsafe {
        if !write_packed(buf, 0, &hdr) {
            return 0;
        }
    }
    std::mem::size_of::<AwdlData>()
}

/// Add FCS (CRC32) to the end of the frame
pub fn ieee80211_add_fcs(start: &[u8], end: &mut [u8]) -> usize {
    let crc = crate::awdl::crc32::crc32(start);
    end.copy_from_slice(&crc.to_le_bytes());
    4
}

/// Build a complete AWDL action frame
pub fn awdl_init_full_action_frame(
    buf: &mut [u8],
    state: &mut AwdlState,
    ieee_state: &mut Ieee80211State,
    action_type: AwdlActionType,
) -> usize {
    let mut ptr = 0usize;

    ptr += ieee80211_init_radiotap_header(&mut buf[ptr..]);
    ptr += ieee80211_init_awdl_action_hdr(
        &mut buf[ptr..],
        &state.self_address,
        &state.dst,
        ieee_state,
    );
    ptr += awdl_init_action(&mut buf[ptr..], action_type);
    ptr += awdl_init_sync_params_tlv(&mut buf[ptr..], state);
    ptr += awdl_init_election_params_tlv(&mut buf[ptr..], state);
    ptr += awdl_init_chanseq_tlv(&mut buf[ptr..], state);
    ptr += awdl_init_election_params_v2_tlv(&mut buf[ptr..], state);
    ptr += awdl_init_service_params_tlv(&mut buf[ptr..], state);
    if action_type == AwdlActionType::MIF {
        ptr += awdl_init_ht_capabilities_tlv(&mut buf[ptr..], state);
    }
    if action_type == AwdlActionType::MIF {
        ptr += awdl_init_arpa_tlv(&mut buf[ptr..], state);
    }
    ptr += awdl_init_data_path_state_tlv(&mut buf[ptr..], state);
    ptr += awdl_init_version_tlv(&mut buf[ptr..], state);
    if ieee_state.fcs {
        let (data, tail) = buf.split_at_mut(ptr);
        let crc = crate::awdl::crc32::crc32(data);
        tail[..4].copy_from_slice(&crc.to_le_bytes());
        ptr += 4;
    }

    ptr
}

/// Build a complete AWDL data frame
pub fn awdl_init_full_data_frame(
    buf: &mut [u8],
    src: &[u8; 6],
    dst: &[u8; 6],
    payload: &[u8],
    state: &mut AwdlState,
    ieee_state: &mut Ieee80211State,
) -> usize {
    let mut ptr = 0usize;

    ptr += ieee80211_init_radiotap_header(&mut buf[ptr..]);
    ptr += ieee80211_init_awdl_data_hdr(&mut buf[ptr..], src, dst, ieee_state);
    ptr += llc_init_awdl_hdr(&mut buf[ptr..]);
    ptr += awdl_init_data(&mut buf[ptr..], state);
    if ptr + payload.len() <= buf.len() {
        buf[ptr..ptr + payload.len()].copy_from_slice(payload);
        ptr += payload.len();
    }
    if ieee_state.fcs {
        let (data, tail) = buf.split_at_mut(ptr);
        let crc = crate::awdl::crc32::crc32(data);
        tail[..4].copy_from_slice(&crc.to_le_bytes());
        ptr += 4;
    }

    ptr
}
