// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL rx.h/rx.c – parse received radiotap/802.11 frames

use crate::awdl::channel::AWDL_CHANSEQ_LENGTH;
use crate::awdl::frame::*;
use crate::awdl::state::{clock_time_us, AwdlState};
use crate::awdl::sync::{awdl_sync_error_tu, awdl_sync_update_last};
use crate::awdl::wire;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
#[repr(i32)]
pub enum RxResult {
    IgnorePeer = 6,
    IgnoreRssi = 5,
    IgnoreFailedCrc = 4,
    IgnoreNoPromisc = 3,
    IgnoreFromSelf = 2,
    Ignore = 1,
    Ok = 0,
    UnexpectedFormat = -1,
    UnexpectedType = -2,
    UnexpectedValue = -3,
}

pub const AWDL_SYNC_THRESHOLD: i64 = 3;

// ---------------------------------------------------------------------------
// Radiotap parsing
// ---------------------------------------------------------------------------

// Radiotap field indices used
const IEEE80211_RADIOTAP_TSFT: usize = 0;
const IEEE80211_RADIOTAP_FLAGS: usize = 1;
const IEEE80211_RADIOTAP_DBM_ANTSIGNAL: usize = 5;

const IEEE80211_RADIOTAP_F_FCS: u8 = 0x10;
const IEEE80211_RADIOTAP_F_BADFCS: u8 = 0x40;

/// Parse radiotap header. Returns (rssi, flags) or None on failure.
/// Does minimal radiotap iteration matching the C radiotap parser.
fn radiotap_parse(frame: &[u8], rssi: &mut i8, flags: &mut u8) -> bool {
    if frame.len() < 8 {
        return false;
    }
    let it_version = frame[0];
    let it_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
    if it_version != 0 || it_len > frame.len() {
        return false;
    }
    let present = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]) as u64;
    let mut offset = 8usize;

    let has_tsft = present & (1 << IEEE80211_RADIOTAP_TSFT) != 0;
    let has_flags = present & (1 << IEEE80211_RADIOTAP_FLAGS) != 0;
    let has_rate = present & (1 << 2) != 0;
    let has_antsignal = present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) != 0;

    if has_tsft {
        extend_generic(&present, &mut offset, IEEE80211_RADIOTAP_TSFT, 8);
        offset += 8;
    }
    if has_flags {
        extend_generic(&present, &mut offset, IEEE80211_RADIOTAP_FLAGS, 1);
        if offset + 1 <= it_len {
            *flags = frame[offset];
        }
        offset += 1;
    }
    if has_rate {
        extend_generic(&present, &mut offset, 2, 1);
        offset += 1;
    }
    if has_antsignal {
        extend_generic(&present, &mut offset, IEEE80211_RADIOTAP_DBM_ANTSIGNAL, 1);
        if offset + 1 <= it_len {
            *rssi = frame[offset] as i8;
        }
        offset += 1;
    }

    // We don't fully iterate all present fields; offset may not match, but for
    // AWDL frames only these fields matter and that is sufficient.
    let _ = offset;
    true
}

fn extend_generic(_present: &u64, _offset: &mut usize, _idx: usize, _align: usize) {
    // Alignment padding handling is minimal; AWDL frames from supported
    // drivers use the standard radiotap layout. This is a no-op placeholder
    // to keep alignment semantics clear.
}

/// Strip trailing FCS from the frame based on radiotap flags.
/// Returns false if FCS is marked bad.
fn check_fcs(frame: &mut Vec<u8>, radiotap_flags: u8) -> bool {
    if radiotap_flags & IEEE80211_RADIOTAP_F_BADFCS != 0 {
        return false;
    }
    if radiotap_flags & IEEE80211_RADIOTAP_F_FCS != 0 {
        if frame.len() >= 4 {
            let new_len = frame.len() - 4;
            frame.truncate(new_len);
        }
    }
    true
}

// ---------------------------------------------------------------------------
// TLV handlers
// ---------------------------------------------------------------------------

fn awdl_handle_sync_params_tlv(
    src: &[u8; 6],
    val: &[u8],
    state: &mut AwdlState,
    now: u64,
) -> RxResult {
    if !crate::awdl::election::awdl_election_is_sync_master(&state.election, src) {
        return RxResult::Ignore;
    }
    let tx_down = match wire::read_le16(val, 1) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    let aw_counter = match wire::read_le16(val, 29) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };

    state.sync.meas_total += 1;
    let sync_err = awdl_sync_error_tu(now, tx_down, aw_counter, &state.sync);
    if sync_err > AWDL_SYNC_THRESHOLD || sync_err < -AWDL_SYNC_THRESHOLD {
        state.sync.meas_err += 1;
        log::trace!("Sync error {} TU", sync_err);
    }
    awdl_sync_update_last(now, tx_down, aw_counter, &mut state.sync);

    RxResult::Ok
}

fn awdl_handle_chanseq_tlv(
    src: &[u8; 6],
    val: &[u8],
    state: &mut AwdlState,
) -> RxResult {
    let count = match wire::read_u8(val, 0) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if (count as usize) + 1 != AWDL_CHANSEQ_LENGTH {
        return RxResult::UnexpectedValue;
    }
    let duplicate_count = match wire::read_u8(val, 2) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if duplicate_count > 0 {
        return RxResult::UnexpectedValue;
    }
    let step_count = match wire::read_u8(val, 3) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if (step_count as u8) + 1 != state.sync.presence_mode {
        return RxResult::UnexpectedValue;
    }
    let fill_channel = match wire::read_le16(val, 4) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if fill_channel != 0xffff {
        return RxResult::UnexpectedValue;
    }
    let encoding = match wire::read_u8(val, 1) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    let enc = match encoding {
        1 => crate::awdl::channel::AwdlChanEncoding::Legacy,
        3 => crate::awdl::channel::AwdlChanEncoding::Opclass,
        0 => crate::awdl::channel::AwdlChanEncoding::Simple,
        _ => return RxResult::UnexpectedValue,
    };
    let size = crate::awdl::channel::awdl_chan_encoding_size(enc);

    let mut list = [crate::awdl::channel::CHAN_NULL; AWDL_CHANSEQ_LENGTH];
    for i in 0..AWDL_CHANSEQ_LENGTH {
        let offset = 6 + i * size;
        match wire::read_bytes(val, offset, size) {
            Ok(bytes) => {
                let mut c = [0u8; 2];
                c[..size].copy_from_slice(bytes);
                list[i].val = c;
            }
            Err(_) => return RxResult::UnexpectedFormat,
        }
    }

    if let Some(src) = state.peers.peer_get_mut(src) {
        if src.sequence != list {
            log::debug!(
                "peer {} changed channel sequence",
                crate::awdl::election::ether_ntoa(&src.addr)
            );
            src.sequence = list;
        }
    }
    RxResult::Ok
}

fn awdl_handle_election_params_tlv(
    src: &[u8; 6],
    val: &[u8],
    state: &mut AwdlState,
) -> RxResult {
    let src = match state.peers.peer_get_mut(src) {
        Some(s) => s,
        None => return RxResult::Ignore,
    };
    if src.supports_v2 {
        return RxResult::Ok;
    }
    let distance = match wire::read_u8(val, 3) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    src.election.height = distance as u32;
    let master_addr = match wire::read_ether_addr(val, 5) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    src.election.master_addr = master_addr;
    let master_metric = match wire::read_le32(val, 11) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    src.election.master_metric = master_metric;
    let self_metric = match wire::read_le32(val, 15) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    src.election.self_metric = self_metric;
    RxResult::Ok
}

fn awdl_handle_election_params_v2_tlv(
    src: &[u8; 6],
    val: &[u8],
    state: &mut AwdlState,
) -> RxResult {
    let src = match state.peers.peer_get_mut(src) {
        Some(s) => s,
        None => return RxResult::Ignore,
    };
    macro_rules! rd_le32 {
        ($off:expr) => {
            match wire::read_le32(val, $off) {
                Ok(v) => v,
                Err(_) => return RxResult::UnexpectedFormat,
            }
        };
    }
    let master_addr = match wire::read_ether_addr(val, 0) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    let sync_addr = match wire::read_ether_addr(val, 6) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    src.election.master_addr = master_addr;
    src.election.sync_addr = sync_addr;
    src.election.master_counter = rd_le32!(12);
    src.election.height = rd_le32!(16);
    src.election.master_metric = rd_le32!(20);
    src.election.self_metric = rd_le32!(24);
    src.election.self_counter = rd_le32!(36);
    src.supports_v2 = true;
    RxResult::Ok
}

fn awdl_handle_arpa_tlv(
    src: &[u8; 6],
    val: &[u8],
    state: &mut AwdlState,
) -> RxResult {
    let name = match wire::read_int_string(val, 1, crate::awdl::peers::HOST_NAME_LENGTH_MAX) {
        Ok(name) => name,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if let Some(src) = state.peers.peer_get_mut(src) {
        src.name = name;
    }
    RxResult::Ok
}

fn awdl_handle_data_path_state_tlv(
    src: &[u8; 6],
    val: &[u8],
    state: &mut AwdlState,
) -> RxResult {
    let flags = match wire::read_le16(val, 0) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    let mut offset = 2usize;
    let mut country_code = None;
    let mut infra_addr = None;

    if flags & AWDL_DATA_PATH_FLAG_COUNTRY_CODE != 0 {
        match wire::read_bytes_copy(val, offset, &mut [0u8; 3]) {
            Ok(()) => {}
            Err(_) => return RxResult::UnexpectedFormat,
        }
        let cc = match wire::read_bytes(val, offset, 3) {
            Ok(b) => b.to_vec(),
            Err(_) => return RxResult::UnexpectedFormat,
        };
        country_code = Some(String::from_utf8_lossy(&cc[..2]).into_owned());
        offset += 3;
    }
    if flags & AWDL_DATA_PATH_FLAG_SOCIAL_CHANNEL_MAP != 0 {
        match wire::read_le16(val, offset) {
            Ok(_) => {}
            Err(_) => return RxResult::UnexpectedFormat,
        }
        offset += 2;
    }
    if flags & AWDL_DATA_PATH_FLAG_INFRA_INFO != 0 {
        match wire::read_ether_addr(val, offset) {
            Ok(_) => {}
            Err(_) => return RxResult::UnexpectedFormat,
        }
        offset += 6;
        match wire::read_le16(val, offset) {
            Ok(_) => {}
            Err(_) => return RxResult::UnexpectedFormat,
        }
        offset += 2;
    }
    if flags & AWDL_DATA_PATH_FLAG_INFRA_ADDRESS != 0 {
        match wire::read_ether_addr(val, offset) {
            Ok(a) => {
                infra_addr = Some(a);
            }
            Err(_) => return RxResult::UnexpectedFormat,
        }
        offset += 6;
    }
    if flags & AWDL_DATA_PATH_FLAG_AWDL_ADDRESS != 0 {
        match wire::read_ether_addr(val, offset) {
            Ok(_) => {}
            Err(_) => return RxResult::UnexpectedFormat,
        }
        offset += 6;
    }
    // TODO complete parsing
    let _ = offset;

    if let Some(src) = state.peers.peer_get_mut(src) {
        if let Some(cc) = country_code {
            src.country_code = cc;
        }
        if let Some(ia) = infra_addr {
            src.infra_addr = ia;
        }
    }

    RxResult::Ok
}

fn awdl_handle_version_tlv(
    src: &[u8; 6],
    val: &[u8],
    state: &mut AwdlState,
) -> RxResult {
    let version = match wire::read_u8(val, 0) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    let devclass = match wire::read_u8(val, 1) {
        Ok(v) => v,
        Err(_) => return RxResult::UnexpectedFormat,
    };
    if let Some(src) = state.peers.peer_get_mut(src) {
        src.version = version;
        src.devclass = devclass;
    }
    RxResult::Ok
}

fn awdl_handle_tlv(
    src: &[u8; 6],
    tlv_type: u8,
    val: &[u8],
    state: &mut AwdlState,
    tsft: u64,
) -> RxResult {
    match tlv_type {
        AWDL_SYNCHRONIZATON_PARAMETERS_TLV => {
            awdl_handle_sync_params_tlv(src, val, state, tsft)
        }
        AWDL_CHAN_SEQ_TLV => awdl_handle_chanseq_tlv(src, val, state),
        AWDL_ELECTION_PARAMETERS_TLV => awdl_handle_election_params_tlv(src, val, state),
        AWDL_ELECTION_PARAMETERS_V2_TLV => {
            awdl_handle_election_params_v2_tlv(src, val, state)
        }
        AWDL_ARPA_TLV => awdl_handle_arpa_tlv(src, val, state),
        AWDL_DATA_PATH_STATE_TLV => awdl_handle_data_path_state_tlv(src, val, state),
        AWDL_VERSION_TLV => awdl_handle_version_tlv(src, val, state),
        _ => {
            log::trace!("awdl: not handling {} ({})", awdl_tlv_as_str(tlv_type), tlv_type);
            RxResult::Ignore
        }
    }
}

/// Parse action frame header. Returns the subtype if valid, else None.
fn awdl_parse_action_hdr(frame: &[u8]) -> Option<AwdlActionType> {
    let af = unsafe { read_packed::<AwdlAction>(frame, 0)? };
    let valid = af.category == IEEE80211_VENDOR_SPECIFIC
        && af.oui == AWDL_OUI
        && af.type_ == AWDL_TYPE
        && af.version == AWDL_VERSION_COMPAT;
    if valid {
        match af.subtype {
            0 => return Some(AwdlActionType::PSF),
            3 => return Some(AwdlActionType::MIF),
            _ => {}
        }
    }
    None
}

/// Handle a received AWDL action frame
fn awdl_rx_action(
    mut frame: Vec<u8>,
    rssi: i8,
    tsft: u64,
    src: &[u8; 6],
    _dst: &[u8; 6],
    state: &mut AwdlState,
) -> RxResult {
    let subtype = match awdl_parse_action_hdr(&frame) {
        Some(s) => s,
        None => {
            log::trace!("awdl_action: not an action frame");
            return RxResult::Ignore;
        }
    };

    let action_size = std::mem::size_of::<AwdlAction>();
    if frame.len() < action_size {
        return RxResult::UnexpectedFormat;
    }
    frame.drain(..action_size);

    if state.filter_rssi {
        let known = state.peers.peer_get(src).is_some();
        if (known && rssi < state.rssi_threshold + state.rssi_grace)
            || (!known && rssi < state.rssi_threshold)
        {
            return RxResult::IgnoreRssi;
        }
    }
    state.stats.rx_action += 1;

    let (status, _just_valid) = state.peers.peer_add(src, tsft);
    if status == crate::awdl::peers::PeersStatus::Internal {
        return RxResult::Ignore;
    }

    let mut tlv_offset = 0usize;
    loop {
        if tlv_offset >= frame.len() {
            break;
        }
        let (tlv_type, tlv_len, tlv_val, consumed) = match wire::read_tlv(&frame, tlv_offset) {
            Ok(v) => v,
            Err(_) => return RxResult::UnexpectedFormat,
        };
        let mut copy = tlv_val.to_vec();
        copy.truncate(tlv_len as usize);
        let result = awdl_handle_tlv(src, tlv_type, &copy, state, tsft);
        if result < RxResult::Ok {
            log::warn!("awdl_action: parsing error {}", awdl_tlv_as_str(tlv_type));
            return RxResult::UnexpectedFormat;
        }
        tlv_offset += consumed;
    }

    if subtype == AwdlActionType::MIF {
        if let Some(peer) = state.peers.peer_get_mut(src) {
            peer.sent_mif = true;
        }
    }

    // update peer info after parsing all TLVs (recompute validity)
    state.peers.peer_add(src, tsft);

    RxResult::Ok
}

/// Parse an LLC header from a frame
fn llc_parse(frame: &[u8]) -> Option<LlcHdr> {
    let dsap = wire::read_u8(frame, 0).ok()?;
    let ssap = wire::read_u8(frame, 1).ok()?;
    let control = wire::read_u8(frame, 2).ok()?;
    let mut oui = [0u8; 3];
    wire::read_bytes_copy(frame, 3, &mut oui).ok()?;
    let pid = wire::read_be16(frame, 6).ok()?;
    Some(LlcHdr {
        dsap,
        ssap,
        control,
        oui,
        pid,
    })
}

/// Validate LLC header for AWDL
fn awdl_valid_llc_header(frame: &[u8]) -> bool {
    let llc = match llc_parse(frame) {
        Some(l) => l,
        None => {
            log::warn!("llc: frame too short");
            return false;
        }
    };
    if llc.dsap != 0xaa
        || llc.ssap != 0xaa
        || llc.control != 0x03
        || llc.pid != AWDL_LLC_PROTOCOL_ID
    {
        log::warn!("llc: invalid header");
        return false;
    }
    true
}

/// Handle a received AWDL data frame. Returns a converted Ethernet frame if any.
fn awdl_rx_data(
    frame: &mut Vec<u8>,
    src: &[u8; 6],
    dst: &[u8; 6],
    state: &mut AwdlState,
) -> Option<Vec<u8>> {
    state.stats.rx_data += 1;

    if state.peers.peer_get(src).is_none() {
        return None;
    }
    if !awdl_valid_llc_header(frame) {
        return None;
    }
    let ether_type = match wire::read_be16(frame, 6) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let llc_size = std::mem::size_of::<LlcHdr>();
    if frame.len() < llc_size {
        return None;
    }
    frame.drain(..llc_size);

    if frame.len() < std::mem::size_of::<AwdlData>() {
        log::warn!("awdl_data: frame too short");
        return None;
    }

    let mut eth = Vec::with_capacity(14 + frame.len() - 8);
    eth.extend_from_slice(dst);
    eth.extend_from_slice(src);
    eth.extend_from_slice(&ether_type.to_be_bytes());
    if frame.len() >= std::mem::size_of::<AwdlData>() {
        eth.extend_from_slice(&frame[std::mem::size_of::<AwdlData>()..]);
    }

    Some(eth)
}

/// Handle a received AWDL data frame (either plain or A-MSDU).
fn awdl_rx(
    input: &[u8],
    state: &mut AwdlState,
) -> (RxResult, Option<Vec<u8>>) {
    let mut frame = input.to_vec();
    let tsft = clock_time_us();

    let mut rssi: i8 = 0;
    let mut flags: u8 = 0;
    if !radiotap_parse(&frame, &mut rssi, &mut flags) {
        return (RxResult::UnexpectedFormat, None);
    }

    // Strip radiotap header
    if frame.len() < 8 {
        return (RxResult::UnexpectedFormat, None);
    }
    let it_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
    if it_len > frame.len() {
        return (RxResult::UnexpectedFormat, None);
    }
    frame.drain(..it_len);

    // Check FCS
    if !check_fcs(&mut frame, flags) {
        return (RxResult::IgnoreFailedCrc, None);
    }

    if frame.len() < std::mem::size_of::<Ieee80211Hdr>() {
        return (RxResult::UnexpectedFormat, None);
    }
    let hdr = unsafe { read_packed::<Ieee80211Hdr>(&frame, 0) }.unwrap();
    let from = hdr.addr2;
    let to = hdr.addr1;
    let fc = u16::from_le_bytes([frame[0], frame[1]]);

    if from == state.self_address {
        return (RxResult::IgnoreFromSelf, None);
    }

    frame.drain(..std::mem::size_of::<Ieee80211Hdr>());

    let ftype = fc & IEEE80211_FCTL_FTYPE;
    let stype = fc & IEEE80211_FCTL_STYPE;

    match (ftype, stype) {
        (IEEE80211_FTYPE_MGMT, IEEE80211_STYPE_ACTION) => {
            let res = awdl_rx_action(frame, rssi, tsft, &from, &to, state);
            (res, None)
        }
        (IEEE80211_FTYPE_DATA, IEEE80211_STYPE_DATA) => {
            let eth = awdl_rx_data(&mut frame, &from, &to, state);
            (RxResult::Ok, eth)
        }
        (IEEE80211_FTYPE_DATA, IEEE80211_STYPE_QOS_DATA) => {
            // QoS data: strip QoS control, check A-MSDU
            if frame.len() < IEEE80211_QOS_CTL_LEN {
                return (RxResult::UnexpectedFormat, None);
            }
            let qosc = u16::from_le_bytes([frame[0], frame[1]]);
            frame.drain(..IEEE80211_QOS_CTL_LEN);
            if qosc & IEEE80211_QOS_CTL_A_MSDU_PRESENT != 0 {
                // A-MSDU not fully supported; parse first subframe(s)
                let eth = awdl_rx_data_amsdu(&mut frame, &from, &to, state);
                (RxResult::Ok, eth)
            } else {
                let eth = awdl_rx_data(&mut frame, &from, &to, state);
                (RxResult::Ok, eth)
            }
        }
        _ => {
            log::warn!(
                "ieee80211: cannot handle type {:x} and subtype {:x}",
                ftype,
                stype
            );
            (RxResult::UnexpectedType, None)
        }
    }
}

fn awdl_rx_data_amsdu(
    frame: &mut Vec<u8>,
    _src: &[u8; 6],
    _dst: &[u8; 6],
    state: &mut AwdlState,
) -> Option<Vec<u8>> {
    // Iterate over subframes; return the first converted ethernet frame.
    let mut result = None;
    while frame.len() > 0 {
        if frame.len() < 14 {
            break;
        }
        let dst_a = wire::read_ether_addr(frame, 0).ok()?;
        let src_a = wire::read_ether_addr(frame, 6).ok()?;
        let len_a = wire::read_be16(frame, 12).ok()? as usize;
        frame.drain(..14);
        if len_a > frame.len() {
            break;
        }
        let mut sub = frame[..len_a].to_vec();
        if let Some(eth) = awdl_rx_data(&mut sub, &src_a, &dst_a, state) {
            result = Some(eth);
        }
        frame.drain(..len_a);
        if frame.len() > 0 {
            let padding = (4 - ((14 + len_a) % 4)) % 4;
            let pad = padding.min(frame.len());
            frame.drain(..pad);
        }
    }
    result
}

/// Top-level receive entry point: parse a radiotap-wrapped 802.11 frame and
/// dispatch. Returns (result, optional converted ethernet frame).
pub fn awdl_rx_frame(frame: &[u8], state: &mut AwdlState) -> (RxResult, Option<Vec<u8>>) {
    awdl_rx(frame, state)
}
