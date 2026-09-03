// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL daemon/io.c – Linux raw packet I/O (AF_PACKET) with radiotap handling

use anyhow::{anyhow, bail, Context, Result};
use std::io;
use std::os::fd::{AsRawFd, RawFd};

// ---------------------------------------------------------------------------
// Raw socket I/O state
// ---------------------------------------------------------------------------

pub struct IoState {
    /// Raw AF_PACKET socket bound to the interface
    sock: RawFd,
    /// Interface index
    ifindex: i32,
    /// Interface name
    ifname: String,
    /// Interface MAC address
    if_ether_addr: [u8; 6],
}

impl IoState {
    /// Open a raw AF_PACKET socket on the given interface for frame injection
    /// and reception (802.11 radiotap frames).
    pub fn open(ifname: &str) -> Result<Self> {
        let ifindex = get_ifindex(ifname)?;
        let if_ether_addr = get_ether_addr(ifname)?;

        // Open raw packet socket for both sending and receiving radiotap frames.
        // AF_PACKET, SOCK_RAW gives us full 802.11 frames (including radiotap).
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context(format!("Failed to open AF_PACKET socket on {}", ifname));
        }

        // Non-blocking
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            unsafe {
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }

        let state = Self {
            sock: fd,
            ifindex,
            ifname: ifname.to_string(),
            if_ether_addr,
        };

        Ok(state)
    }

    pub fn raw_fd(&self) -> RawFd {
        self.sock
    }

    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }

    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    pub fn mac(&self) -> [u8; 6] {
        self.if_ether_addr
    }

    /// Inject a raw 802.11 frame (radiotap header included) onto the interface.
    pub fn wlan_send(&self, buf: &[u8]) -> Result<()> {
        let sockaddr_family = libc::AF_PACKET as u16;
        // Build a sockaddr_ll to send directly on the bound interface.
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = sockaddr_family;
        sll.sll_protocol = 0;
        sll.sll_ifindex = self.ifindex;
        sll.sll_halen = 6;

        let n = unsafe {
            libc::sendto(
                self.sock,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                bail!("wlan_send: would block");
            }
            return Err(anyhow!(err).context("wlan_send failed"));
        }
        if (n as usize) < buf.len() {
            bail!("wlan_send: short write");
        }
        Ok(())
    }

    /// Read one raw frame from the interface into `buf`.
    /// Returns the number of bytes read, or Ok(0) if no data available (EWOULDBLOCK).
    /// The returned frame is a fresh Vec of reasonable size.
    pub fn wlan_recv(&self) -> Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; 65536];
        let n = unsafe {
            libc::recvfrom(
                self.sock,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(anyhow!(err).context("wlan_recv failed"));
        }
        buf.truncate(n as usize);
        Ok(Some(buf))
    }
}

impl Drop for IoState {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.sock);
        }
    }
}

// ---------------------------------------------------------------------------
// ioctl helpers
// ---------------------------------------------------------------------------

/// Get interface index from interface name
fn get_ifindex(ifname: &str) -> Result<i32> {
    let cname = std::ffi::CString::new(ifname)?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        bail!("No such interface exists: {}", ifname);
    }
    Ok(idx as i32)
}

/// Get interface hardware (Ethernet) address via SIOCGIFHWADDR
fn get_ether_addr(ifname: &str) -> Result<[u8; 6]> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("get_ether_addr: socket");
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let cname = std::ffi::CString::new(ifname)?;
    let name_bytes = cname.as_bytes();
    let name_ptr = ifr.ifr_name.as_mut_ptr();
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            name_ptr as *mut u8,
            name_bytes.len(),
        );
    }
    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifr) };
    unsafe {
        libc::close(fd);
    }
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("get_ether_addr: ioctl SIOCGIFHWADDR");
    }
    let mut addr = [0u8; 6];
    unsafe {
        std::ptr::copy_nonoverlapping(
            ifr.ifr_ifru.ifru_hwaddr.sa_data.as_ptr() as *const u8,
            addr.as_mut_ptr(),
            6,
        );
    }
    Ok(addr)
}

#[allow(dead_code)]
pub fn fd_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error()).context("fcntl F_GETFL");
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("fcntl F_SETFL");
    }
    Ok(())
}

impl AsRawFd for IoState {
    fn as_raw_fd(&self) -> RawFd {
        self.sock
    }
}
