// SPDX-License-Identifier: GPL-3.0-or-later
// Port of OWL wire.h/wire.c – endian-safe read/write helpers

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireError;

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wire: out of bounds")
    }
}

impl std::error::Error for WireError {}

pub type WireResult<T> = Result<T, WireError>;

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

pub fn read_u8(data: &[u8], offset: usize) -> WireResult<u8> {
    if offset + 1 > data.len() {
        return Err(WireError);
    }
    Ok(data[offset])
}

pub fn read_le16(data: &[u8], offset: usize) -> WireResult<u16> {
    if offset + 2 > data.len() {
        return Err(WireError);
    }
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

pub fn read_be16(data: &[u8], offset: usize) -> WireResult<u16> {
    if offset + 2 > data.len() {
        return Err(WireError);
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

pub fn read_le32(data: &[u8], offset: usize) -> WireResult<u32> {
    if offset + 4 > data.len() {
        return Err(WireError);
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

pub fn read_be32(data: &[u8], offset: usize) -> WireResult<u32> {
    if offset + 4 > data.len() {
        return Err(WireError);
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

pub fn read_bytes<'a>(data: &'a [u8], offset: usize, len: usize) -> WireResult<&'a [u8]> {
    if offset + len > data.len() {
        return Err(WireError);
    }
    Ok(&data[offset..offset + len])
}

pub fn read_bytes_copy(data: &[u8], offset: usize, dst: &mut [u8]) -> WireResult<()> {
    let len = dst.len();
    if offset + len > data.len() {
        return Err(WireError);
    }
    dst.copy_from_slice(&data[offset..offset + len]);
    Ok(())
}

pub fn read_ether_addr(data: &[u8], offset: usize) -> WireResult<[u8; 6]> {
    if offset + 6 > data.len() {
        return Err(WireError);
    }
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&data[offset..offset + 6]);
    Ok(addr)
}

/// Read a length-prefixed string (1-byte length prefix + chars).
/// Returns the string (without null terminator).
pub fn read_int_string(data: &[u8], offset: usize, max_len: usize) -> WireResult<String> {
    let slen = read_u8(data, offset)? as usize;
    let actual = slen.min(max_len);
    let bytes = read_bytes(data, offset + 1, actual)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

// ---------------------------------------------------------------------------
// TLV reading
// ---------------------------------------------------------------------------

/// Read a TLV header + value slice at `offset`.
/// Returns (type, length, value_slice, total_consumed).
pub fn read_tlv<'a>(
    data: &'a [u8],
    offset: usize,
) -> WireResult<(u8, u16, &'a [u8], usize)> {
    let t = read_u8(data, offset)?;
    let l = read_le16(data, offset + 1)?;
    let v = read_bytes(data, offset + 3, l as usize)?;
    let total = 3 + l as usize;
    Ok((t, l, v, total))
}

// ---------------------------------------------------------------------------
// Write helpers
// ---------------------------------------------------------------------------

pub fn write_u8(buf: &mut [u8], offset: usize, value: u8) -> WireResult<()> {
    if offset + 1 > buf.len() {
        return Err(WireError);
    }
    buf[offset] = value;
    Ok(())
}

pub fn write_le16(buf: &mut [u8], offset: usize, value: u16) -> WireResult<()> {
    if offset + 2 > buf.len() {
        return Err(WireError);
    }
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn write_be16(buf: &mut [u8], offset: usize, value: u16) -> WireResult<()> {
    if offset + 2 > buf.len() {
        return Err(WireError);
    }
    buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn write_le32(buf: &mut [u8], offset: usize, value: u32) -> WireResult<()> {
    if offset + 4 > buf.len() {
        return Err(WireError);
    }
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn write_be32(buf: &mut [u8], offset: usize, value: u32) -> WireResult<()> {
    if offset + 4 > buf.len() {
        return Err(WireError);
    }
    buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

pub fn write_ether_addr(buf: &mut [u8], offset: usize, addr: &[u8; 6]) -> WireResult<()> {
    if offset + 6 > buf.len() {
        return Err(WireError);
    }
    buf[offset..offset + 6].copy_from_slice(addr);
    Ok(())
}

pub fn write_bytes(buf: &mut [u8], offset: usize, src: &[u8]) -> WireResult<()> {
    if offset + src.len() > buf.len() {
        return Err(WireError);
    }
    buf[offset..offset + src.len()].copy_from_slice(src);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_roundtrip() {
        let mut buf = [0u8; 16];
        write_u8(&mut buf, 0, 0xAB).unwrap();
        write_le16(&mut buf, 1, 0x1234).unwrap();
        write_be32(&mut buf, 3, 0xDEADBEEF).unwrap();
        write_ether_addr(&mut buf, 7, &[1, 2, 3, 4, 5, 6]).unwrap();

        assert_eq!(read_u8(&buf, 0).unwrap(), 0xAB);
        assert_eq!(read_le16(&buf, 1).unwrap(), 0x1234);
        assert_eq!(read_be32(&buf, 3).unwrap(), 0xDEADBEEF);
        assert_eq!(read_ether_addr(&buf, 7).unwrap(), [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_oob_returns_error() {
        let buf = [0u8; 4];
        assert!(read_u8(&buf, 4).is_err());
        assert!(read_le16(&buf, 3).is_err());
        assert!(read_le32(&buf, 1).is_err());
        assert!(write_u8(&mut [], 0, 0).is_err());
    }
}
