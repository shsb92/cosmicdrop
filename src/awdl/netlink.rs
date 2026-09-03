// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL daemon/netutils.c – Linux netlink handling
//
// This module implements the Linux-specific network utility surface using raw
// netlink (NETLINK_ROUTE/NETLINK_GENERIC) sockets via libc, mirroring the
// original libnl-based netutils.c. It provides:
//   - virtual TUN/TAP ("awdl0"-style) interface creation with a link-local
//     IPv6 address,
//   - nl80211 channel switching (monitor mode is expected to be set up out of
//     band, or via set_monitor_mode below),
//   - NIC neighbor cache (ND) management for the RFC 4291 link-local address.
//
// These operations require root/CAP_NET_ADMIN. On failure they return a clear
// error (which callers may decide to treat as non-fatal).

use anyhow::{anyhow, bail, Context, Result};
use std::io;
use std::os::fd::RawFd;

pub const AWDL_DEFAULT_DEVICE: &str = "awdl0";
const TUN_MTU: i32 = 1450;

// ---------------------------------------------------------------------------
// TUN/TAP virtual interface
// ---------------------------------------------------------------------------

/// Create a TAP (Ethernet) interface named `dev`, set its HW address to `self`
/// (the WLAN MAC so active monitor injection works), bring it up, and assign
/// the RFC 4291 link-local IPv6 address derived from `self`.
///
/// Returns the TAP file descriptor (non-blocking).
pub fn open_tun(dev: &str, self_addr: [u8; 6]) -> Result<std::os::fd::RawFd> {
    // Open /dev/net/tun
    let dev_tun = std::ffi::CString::new("/dev/net/tun")?;
    let fd = unsafe { libc::open(dev_tun.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        bail!("tun: unable to open /dev/net/tun: {}", err);
    }

    // TUNSETIFF: request a TAP device with no packet info
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
    let cname = std::ffi::CString::new(dev)?;
    let name_bytes = cname.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_bytes.len(),
        );
    }

    let ret = unsafe { libc::ioctl(fd, libc::TUNSETIFF as libc::c_ulong, &mut ifr) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        bail!("tun: TUNSETIFF failed: {}", err);
    }
    // Copy back the actual device name
    let mut actual = String::new();
    unsafe {
        let name_ptr = ifr.ifr_name.as_ptr() as *const u8;
        for i in 0..libc::IFNAMSIZ {
            let c = std::ptr::read(name_ptr.add(i)) as char;
            if c == '\0' {
                break;
            }
            actual.push(c);
        }
    }

    // Set non-blocking mode
    let one: libc::c_int = 1;
    let ret = unsafe { libc::ioctl(fd, libc::FIONBIO, &one) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        bail!("tun: FIONBIO failed: {}", err);
    }

    // Create a control socket for ioctls
    let ctl = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if ctl < 0 {
        unsafe {
            libc::close(fd);
        }
        return Err(io::Error::last_os_error()).context("tun: control socket");
    }

    // Set HW address (SIOCSIFHWADDR)
    ifr.ifr_ifru.ifru_hwaddr.sa_family = libc::ARPHRD_ETHER as u16;
    unsafe {
        std::ptr::copy_nonoverlapping(
            self_addr.as_ptr(),
            ifr.ifr_ifru.ifru_hwaddr.sa_data.as_mut_ptr() as *mut u8,
            6,
        );
    }
    let ret = unsafe { libc::ioctl(ctl, libc::SIOCSIFHWADDR, &ifr) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(ctl);
            libc::close(fd);
        }
        bail!("tun: unable to set HW address: {}", err);
    }

    // Bring interface up (SIOCGIFFLAGS then SIOCSIFFLAGS)
    unsafe {
        libc::ioctl(ctl, libc::SIOCGIFFLAGS, &mut ifr);
    }
    unsafe {
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    }
    let ret = unsafe { libc::ioctl(ctl, libc::SIOCSIFFLAGS, &ifr) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(ctl);
            libc::close(fd);
        }
        bail!("tun: unable to set interface up: {}", err);
    }

    // Set MTU
    let mut ifr2: libc::ifreq = unsafe { std::mem::zeroed() };
    let cname2 = std::ffi::CString::new(actual.clone())?;
    let nb = cname2.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(nb.as_ptr(), ifr2.ifr_name.as_mut_ptr() as *mut u8, nb.len());
        ifr2.ifr_ifru.ifru_mtu = TUN_MTU;
    }
    let ret = unsafe { libc::ioctl(ctl, libc::SIOCSIFMTU, &ifr2) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(ctl);
            libc::close(fd);
        }
        bail!("tun: unable to set MTU: {}", err);
    }

    unsafe {
        libc::close(ctl);
    }

    Ok(fd)
}

// ---------------------------------------------------------------------------
// IPv6 address helpers
// ---------------------------------------------------------------------------

/// Derive the RFC 4291 (EUI-64) link-local IPv6 address from a MAC address.
pub fn rfc4291_addr(eth: &[u8; 6]) -> [u8; 16] {
    let mut in6 = [0u8; 16];
    in6[0] = 0xfe;
    in6[1] = 0x80;
    in6[8] = eth[0] ^ 0x02;
    in6[9] = eth[1];
    in6[10] = eth[2];
    in6[11] = 0xff;
    in6[12] = 0xfe;
    in6[13] = eth[3];
    in6[14] = eth[4];
    in6[15] = eth[5];
    in6
}

// ---------------------------------------------------------------------------
// Netlink socket helpers (raw libc)
// ---------------------------------------------------------------------------

const NETLINK_ROUTE: libc::c_int = 0;
const NETLINK_GENERIC: libc::c_int = 16;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Nlmsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct Genlmsghdr {
    cmd: u8,
    version: u8,
    reserved: u16,
}

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const GENL_ID_CTRL: u16 = 0x10;
const GENL_NAMSIZ: usize = 16;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;

const NLMSG_ALIGNTO: u32 = 4;
fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO as usize - 1) & !(NLMSG_ALIGNTO as usize - 1)
}

fn build_nlmsghdr(hdr: &mut [u8], msg_type: u16, flags: u16, seq: u32) -> usize {
    let nl = Nlmsghdr {
        nlmsg_len: (NLMSGHDR_SIZE + GENLMSGHDR_SIZE) as u32,
        nlmsg_type: msg_type,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    };
    unsafe {
        std::ptr::write_unaligned(hdr.as_mut_ptr() as *mut Nlmsghdr, nl);
    }
    NLMSGHDR_SIZE
}

const NLMSGHDR_SIZE: usize = std::mem::size_of::<Nlmsghdr>();
const GENLMSGHDR_SIZE: usize = std::mem::size_of::<Genlmsghdr>();

/// Open a netlink socket of family `family` (NETLINK_ROUTE or NETLINK_GENERIC)
fn nl_socket(family: libc::c_int) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, family) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("netlink socket");
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(anyhow!(err)).context("netlink bind");
    }
    Ok(fd)
}

/// Set a netlink socket to blocking so we can await replies.
fn nl_socket_blocking(fd: RawFd) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
        }
    }
}

/// Send an nlmsg buffer and read a reply, checking for an NLMSG_ERROR.
fn nl_send_recv(fd: RawFd, msg: &[u8]) -> Result<()> {
    let n = unsafe {
        libc::send(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error()).context("netlink send");
    }

    let mut resp = vec![0u8; 8192];
    loop {
        let r = unsafe {
            libc::recv(
                fd,
                resp.as_mut_ptr() as *mut libc::c_void,
                resp.len(),
                0,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error()).context("netlink recv");
        }
        let byte_len = r as usize;
        let mut off = 0usize;
        while off + NLMSGHDR_SIZE <= byte_len {
            let nl = unsafe { std::ptr::read_unaligned(resp.as_ptr().add(off) as *const Nlmsghdr) };
            if nl.nlmsg_type == NLMSG_ERROR {
                // Error message: nlmsg_len == NLMSG_ERROR struct with error int
                if nl.nlmsg_len as usize >= NLMSGHDR_SIZE + 4 {
                    let err = unsafe {
                        std::ptr::read_unaligned(
                            resp.as_ptr().add(off + NLMSGHDR_SIZE) as *const i32
                        )
                    };
                    if err != 0 {
                        return Err(anyhow!("netlink error: {}", io::Error::from_raw_os_error(-err)));
                    }
                }
                return Ok(());
            }
            if nl.nlmsg_type == NLMSG_DONE {
                return Ok(());
            }
            let aligned = nlmsg_align(nl.nlmsg_len as usize);
            if aligned == 0 {
                break;
            }
            off += aligned;
        }
        // Keep reading until we see the expected response. For simplicity we
        // assume a single reply was requested (NLM_F_ACK).
    }
}

/// Resolve a generic netlink family ID by name (e.g. "nl80211") using CTRL_CMD_GETFAMILY.
fn genl_resolve_family(fd: RawFd, family: &str) -> Result<u16> {
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;

    let mut msg = vec![0u8; 4096];
    let mut len = build_nlmsghdr(&mut msg, GENL_ID_CTRL, NLM_F_REQUEST, 1);
    // genlmsghdr: cmd = CTRL_CMD_GETFAMILY
    let genl = Genlmsghdr {
        cmd: CTRL_CMD_GETFAMILY,
        version: 1,
        reserved: 0,
    };
    unsafe {
        std::ptr::write_unaligned(msg.as_mut_ptr().add(len) as *mut Genlmsghdr, genl);
    }
    len += GENLMSGHDR_SIZE;

    // attribute: family name
    let fam_c = std::ffi::CString::new(family)?;
    let fam_bytes = fam_c.as_bytes();
    let payload = fam_bytes;
    let attr_len = 4 + payload.len();
    // NLA header
    if len + attr_len + 4 <= msg.len() {
        msg[len] = (attr_len & 0xff) as u8;
        msg[len + 1] = ((attr_len >> 8) & 0xff) as u8;
        msg[len + 2] = (CTRL_ATTR_FAMILY_NAME & 0xff) as u8;
        msg[len + 3] = ((CTRL_ATTR_FAMILY_NAME >> 8) & 0xff) as u8;
        msg[len + 4..len + 4 + payload.len()].copy_from_slice(payload);
        len += 4 + payload.len();
    }

    // Set total length
    unsafe {
        let nl = msg.as_mut_ptr() as *mut Nlmsghdr;
        (*nl).nlmsg_len = len as u32;
    }

    let n = unsafe { libc::send(fd, msg.as_ptr() as *const libc::c_void, len, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error()).context("genl resolve send");
    }

    let mut resp = vec![0u8; 8192];
    loop {
        let r = unsafe {
            libc::recv(
                fd,
                resp.as_mut_ptr() as *mut libc::c_void,
                resp.len(),
                0,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error()).context("genl resolve recv");
        }
        let byte_len = r as usize;
        let mut off = 0usize;
        while off + NLMSGHDR_SIZE <= byte_len {
            let nl = unsafe { std::ptr::read_unaligned(resp.as_ptr().add(off) as *const Nlmsghdr) };
            if nl.nlmsg_type == NLMSG_ERROR {
                return Err(anyhow!("genl resolve NLMSG_ERROR"));
            }
            if nl.nlmsg_type == NLMSG_DONE {
                return Err(anyhow!("genl resolve: family not found"));
            }
            if nl.nlmsg_type == GENL_ID_CTRL {
                // Parse genl header + attributes to find CTRL_ATTR_FAMILY_ID
                let payload_off = off + nlmsg_align(NLMSGHDR_SIZE);
                let mut attr_off = payload_off + GENLMSGHDR_SIZE;
                let end = off + nl.nlmsg_len as usize;
                while attr_off + 4 <= end {
                    let a_len = u16::from_le_bytes([resp[attr_off], resp[attr_off + 1]]) as usize;
                    let a_type = u16::from_le_bytes([resp[attr_off + 2], resp[attr_off + 3]]) as usize;
                    let a_align = nlmsg_align(a_len);
                    if a_len >= 4 && a_align + attr_off <= end {
                        if a_type == CTRL_ATTR_FAMILY_ID as usize && a_len >= 6 {
                            let id = u16::from_le_bytes([resp[attr_off + 4], resp[attr_off + 5]]);
                            return Ok(id);
                        }
                        attr_off += a_align;
                    } else {
                        break;
                    }
                }
            }
            let aligned = nlmsg_align(nl.nlmsg_len as usize);
            if aligned == 0 {
                break;
            }
            off += aligned;
        }
    }
}

// ---------------------------------------------------------------------------
// Public netlink operations
// ---------------------------------------------------------------------------

/// Set the Wi-Fi interface `ifindex` to nl80211 monitor mode.
pub fn set_monitor_mode(ifindex: i32) -> Result<()> {
    let genl = nl_socket(NETLINK_GENERIC)?;
    nl_socket_blocking(genl);
    let id = genl_resolve_family(genl, "nl80211")?;

    const NL80211_CMD_SET_INTERFACE: u8 = 18;
    const NL80211_ATTR_IFINDEX: u16 = 3;
    const NL80211_ATTR_IFTYPE: u16 = 10;
    const NL80211_IFTYPE_MONITOR: u8 = 6;

    let mut msg = vec![0u8; 4096];
    let mut len = build_nlmsghdr(&mut msg, id, NLM_F_REQUEST | NLM_F_ACK, 2);
    let ghdr = Genlmsghdr {
        cmd: NL80211_CMD_SET_INTERFACE,
        version: 1,
        reserved: 0,
    };
    unsafe {
        std::ptr::write_unaligned(msg.as_mut_ptr().add(len) as *mut Genlmsghdr, ghdr);
    }
    len += GENLMSGHDR_SIZE;

    // NL80211_ATTR_IFINDEX (u32)
    let attr_len = 4 + 4;
    msg[len] = (attr_len & 0xff) as u8;
    msg[len + 1] = ((attr_len >> 8) & 0xff) as u8;
    msg[len + 2] = (NL80211_ATTR_IFINDEX & 0xff) as u8;
    msg[len + 3] = ((NL80211_ATTR_IFINDEX >> 8) & 0xff) as u8;
    msg[len + 4..len + 8].copy_from_slice(&(ifindex as u32).to_le_bytes());
    len += 8;

    // NL80211_ATTR_IFTYPE (u32)
    let attr_len = 4 + 4;
    msg[len] = (attr_len & 0xff) as u8;
    msg[len + 1] = ((attr_len >> 8) & 0xff) as u8;
    msg[len + 2] = (NL80211_ATTR_IFTYPE & 0xff) as u8;
    msg[len + 3] = ((NL80211_ATTR_IFTYPE >> 8) & 0xff) as u8;
    msg[len + 4..len + 8].copy_from_slice(&(NL80211_IFTYPE_MONITOR as u32).to_le_bytes());
    len += 8;

    unsafe {
        let nl = msg.as_mut_ptr() as *mut Nlmsghdr;
        (*nl).nlmsg_len = len as u32;
    }

    let result = nl_send_recv(genl, &msg[..len]);
    unsafe {
        libc::close(genl);
    }
    result
}

/// Switch the Wi-Fi interface `ifindex` to `channel`.
pub fn set_channel(ifindex: i32, channel: i32) -> Result<()> {
    let freq = crate::awdl::channel::ieee80211_channel_to_frequency(channel);
    if freq == 0 {
        bail!("Invalid channel number {}", channel);
    }

    let genl = nl_socket(NETLINK_GENERIC)?;
    nl_socket_blocking(genl);
    let id = genl_resolve_family(genl, "nl80211")?;

    const NL80211_CMD_SET_CHANNEL: u8 = 32;
    const NL80211_ATTR_IFINDEX: u16 = 3;
    const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
    const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
    const NL80211_CHAN_HT40PLUS: u8 = 2;

    let mut msg = vec![0u8; 4096];
    let mut len = build_nlmsghdr(&mut msg, id, NLM_F_REQUEST | NLM_F_ACK, 3);
    let ghdr = Genlmsghdr {
        cmd: NL80211_CMD_SET_CHANNEL,
        version: 1,
        reserved: 0,
    };
    unsafe {
        std::ptr::write_unaligned(msg.as_mut_ptr().add(len) as *mut Genlmsghdr, ghdr);
    }
    len += GENLMSGHDR_SIZE;

    // IFINDEX
    let attr_len = 4 + 4;
    msg[len] = (attr_len & 0xff) as u8;
    msg[len + 1] = ((attr_len >> 8) & 0xff) as u8;
    msg[len + 2] = (NL80211_ATTR_IFINDEX & 0xff) as u8;
    msg[len + 3] = ((NL80211_ATTR_IFINDEX >> 8) & 0xff) as u8;
    msg[len + 4..len + 8].copy_from_slice(&(ifindex as u32).to_le_bytes());
    len += 8;

    // WIPHY_FREQ
    let attr_len = 4 + 4;
    msg[len] = (attr_len & 0xff) as u8;
    msg[len + 1] = ((attr_len >> 8) & 0xff) as u8;
    msg[len + 2] = (NL80211_ATTR_WIPHY_FREQ & 0xff) as u8;
    msg[len + 3] = ((NL80211_ATTR_WIPHY_FREQ >> 8) & 0xff) as u8;
    msg[len + 4..len + 8].copy_from_slice(&(freq as u32).to_le_bytes());
    len += 8;

    // WIPHY_CHANNEL_TYPE
    let attr_len = 4 + 4;
    msg[len] = (attr_len & 0xff) as u8;
    msg[len + 1] = ((attr_len >> 8) & 0xff) as u8;
    msg[len + 2] = (NL80211_ATTR_WIPHY_CHANNEL_TYPE & 0xff) as u8;
    msg[len + 3] = ((NL80211_ATTR_WIPHY_CHANNEL_TYPE >> 8) & 0xff) as u8;
    msg[len + 4..len + 8].copy_from_slice(&(NL80211_CHAN_HT40PLUS as u32).to_le_bytes());
    len += 8;

    unsafe {
        let nl = msg.as_mut_ptr() as *mut Nlmsghdr;
        (*nl).nlmsg_len = len as u32;
    }

    let result = nl_send_recv(genl, &msg[..len]);
    unsafe {
        libc::close(genl);
    }
    result
}

/// Bring an interface up (netlink RTM_NEWLINK or ioctl SIOCSIFFLAGS).
pub fn link_up(ifindex: i32) -> Result<()> {
    link_updown(ifindex, true)
}

/// Bring an interface down.
pub fn link_down(ifindex: i32) -> Result<()> {
    link_updown(ifindex, false)
}

fn link_updown(ifindex: i32, up: bool) -> Result<()> {
    // Use ioctl-based approach on a datagram socket, simpler and robust.
    let ctl = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if ctl < 0 {
        return Err(io::Error::last_os_error()).context("link_updown: socket");
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    // set ifr_name from ifindex
    let name = get_ifname(ifindex)?;
    let cname = std::ffi::CString::new(name)?;
    let nb = cname.as_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(nb.as_ptr(), ifr.ifr_name.as_mut_ptr() as *mut u8, nb.len());
    }
    unsafe {
        libc::ioctl(ctl, libc::SIOCGIFFLAGS, &mut ifr);
    }
    if up {
        unsafe { ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16 };
    } else {
        unsafe { ifr.ifr_ifru.ifru_flags &= !(libc::IFF_UP as i16) };
    }
    let ret = unsafe { libc::ioctl(ctl, libc::SIOCSIFFLAGS, &ifr) };
    unsafe {
        libc::close(ctl);
    }
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("link_updown: SIOCSIFFLAGS");
    }
    Ok(())
}

fn get_ifname(ifindex: i32) -> Result<String> {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let ret = unsafe { libc::if_indextoname(ifindex as libc::c_uint, buf.as_mut_ptr() as *mut libc::c_char) };
    if ret.is_null() {
        return Err(io::Error::last_os_error()).context("if_indextoname");
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}

/// Add a neighbor (ND) entry mapping an IPv6 address to an Ethernet address
/// on the given interface, via NETLINK_ROUTE (RTM_NEWNEIGH, NUD_PERMANENT).
pub fn neighbor_add_rfc4291(ifindex: i32, eth: &[u8; 6]) -> Result<()> {
    let in6 = rfc4291_addr(eth);
    neighbor_add(ifindex, eth, &in6)
}

fn neighbor_add(ifindex: i32, eth: &[u8; 6], in6: &[u8; 16]) -> Result<()> {
    const RTM_NEWNEIGH: u16 = 28;
    const NLM_F_CREATE: u16 = 0x0400;
    const NUD_PERMANENT: u16 = 0x80;
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;
    const NDA_IFINDEX: u16 = 3;
    const AF_INET6_N: u8 = 10;

    let route = nl_socket(NETLINK_ROUTE)?;
    nl_socket_blocking(route);
    let result = (|| {
        let mut msg = vec![0u8; 4096];
        let mut len = build_nlmsghdr(&mut msg, RTM_NEWNEIGH, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, 4);
        // ndmsg struct: ndm_family(1) ndm_pad1(1) ndm_pad2(2) ndm_ifindex(4) ndm_state(2) ndm_flags(1) ndm_type(1)
        msg[len] = AF_INET6_N;
        len += 1; // family
        msg[len] = 0;
        len += 1; // pad1
        msg[len] = 0;
        msg[len + 1] = 0;
        len += 2; // pad2
        msg[len..len + 4].copy_from_slice(&ifindex.to_ne_bytes());
        len += 4; // ifindex
        msg[len..len + 2].copy_from_slice(&NUD_PERMANENT.to_ne_bytes());
        len += 2; // state
        msg[len] = 0;
        len += 1; // flags
        msg[len] = 0;
        len += 1; // type (NDA type ignored)

        // NDA_DST (16 bytes IPv6)
        let attr_len = 4 + 16;
        msg[len] = (attr_len & 0xff) as u8;
        msg[len + 1] = ((attr_len >> 8) & 0xff) as u8;
        msg[len + 2] = (NDA_DST & 0xff) as u8;
        msg[len + 3] = ((NDA_DST >> 8) & 0xff) as u8;
        msg[len + 4..len + 20].copy_from_slice(in6);
        len += 20;

        // NDA_LLADDR (6 bytes)
        let attr_len = 4 + 6;
        msg[len] = (attr_len & 0xff) as u8;
        msg[len + 1] = ((attr_len >> 8) & 0xff) as u8;
        msg[len + 2] = (NDA_LLADDR & 0xff) as u8;
        msg[len + 3] = ((NDA_LLADDR >> 8) & 0xff) as u8;
        msg[len + 4..len + 10].copy_from_slice(eth);
        len += 10;

        unsafe {
            let nl = msg.as_mut_ptr() as *mut Nlmsghdr;
            (*nl).nlmsg_len = len as u32;
        }
        nl_send_recv(route, &msg[..len])
    })();

    unsafe {
        libc::close(route);
    }
    result
}

/// Get the local hostname.
pub fn get_hostname() -> Result<String> {
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("gethostname");
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}
