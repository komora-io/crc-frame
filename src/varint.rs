//! Variable-length encoding of `u64`

use std::convert::TryFrom;
use std::io;

use fault_injection::annotate;

/// Returns the number of bytes that a varint corresponding
/// to the provided `u64` would use when encoded.
pub const fn size(int: u64) -> usize {
    if int <= 240 {
        1
    } else if int <= 2287 {
        2
    } else if int <= 67823 {
        3
    } else if int <= 0x00FF_FFFF {
        4
    } else if int <= 0xFFFF_FFFF {
        5
    } else if int <= 0x00FF_FFFF_FFFF {
        6
    } else if int <= 0xFFFF_FFFF_FFFF {
        7
    } else if int <= 0x00FF_FFFF_FFFF_FFFF {
        8
    } else {
        9
    }
}

/// Based on the first byte from the varint, this function returns the
/// total size of the varint in bytes.
pub const fn size_of_varint_from_first_byte(byte: u8) -> usize {
    match byte {
        0..=240 => 1,
        241..=248 => 2,
        249 => 3,
        250 => 4,
        251 => 5,
        252 => 6,
        253 => 7,
        254 => 8,
        255 => 9,
    }
}

/// Writes the provided `u64` into the beginning of the
/// provided buffer and returns how many bytes the
/// corresponding varint consumed. If the buffer is
/// not large enough, returns `UnexpectedEof`.
pub fn get_varint(int: u64) -> ([u8; 9], usize) {
    const LOW_BYTE_MASK: u64 = u8::MAX as u64;

    let mut buf = [0_u8; 9];

    let size = if int <= 240 {
        buf[0] = u8::try_from(int).unwrap();
        1
    } else if int <= 2287 {
        buf[0] = u8::try_from((int - 240) / 256 + 241).unwrap();
        buf[1] = u8::try_from((int - 240) & LOW_BYTE_MASK).unwrap();
        2
    } else if int <= 67823 {
        buf[0] = 249;
        buf[1] = u8::try_from((int - 2288) / 256).unwrap();
        buf[2] = u8::try_from((int - 2288) & LOW_BYTE_MASK).unwrap();
        3
    } else if int <= 0x00FF_FFFF {
        buf[0] = 250;
        let bytes = int.to_le_bytes();
        buf[1..4].copy_from_slice(&bytes[..3]);
        4
    } else if int <= 0xFFFF_FFFF {
        buf[0] = 251;
        let bytes = int.to_le_bytes();
        buf[1..5].copy_from_slice(&bytes[..4]);
        5
    } else if int <= 0x00FF_FFFF_FFFF {
        buf[0] = 252;
        let bytes = int.to_le_bytes();
        buf[1..6].copy_from_slice(&bytes[..5]);
        6
    } else if int <= 0xFFFF_FFFF_FFFF {
        buf[0] = 253;
        let bytes = int.to_le_bytes();
        buf[1..7].copy_from_slice(&bytes[..6]);
        7
    } else if int <= 0x00FF_FFFF_FFFF_FFFF {
        buf[0] = 254;
        let bytes = int.to_le_bytes();
        buf[1..8].copy_from_slice(&bytes[..7]);
        8
    } else {
        buf[0] = 255;
        let bytes = int.to_le_bytes();
        buf[1..9].copy_from_slice(&bytes[..8]);
        9
    };

    (buf, size)
}

/// Write a varint into the provided `Write` and return the
/// size of the encoded varint that was written into it.
pub fn serialize_into_write<W: io::Write>(int: u64, mut write: W) -> io::Result<usize> {
    let (buf, size) = get_varint(int);
    write.write_all(&buf[..size])?;
    Ok(size)
}

/// Attempt to read a varint-encided `u64` out of a provided `Read` implementation.
pub fn deserialize_from_read<R: io::Read>(mut read: R) -> io::Result<u64> {
    let buf = &mut [0_u8; 9];
    read.read_exact(&mut buf[..1])?;

    let res = match buf[0] {
        0..=240 => u64::from(buf[0]),
        241..=248 => {
            read.read_exact(&mut buf[1..2])?;
            240 + 256 * (u64::from(buf[0]) - 241) + u64::from(buf[1])
        }
        249 => {
            read.read_exact(&mut buf[1..3])?;
            2288 + 256 * u64::from(buf[1]) + u64::from(buf[2])
        }
        other => {
            let sz = other as usize - 247;
            read.read_exact(&mut buf[1..=sz])?;
            let mut aligned = [0; 8];
            aligned[..sz].copy_from_slice(&buf[1..=sz]);
            u64::from_le_bytes(aligned)
        }
    };

    Ok(res)
}

macro_rules! check_buf_len {
    ($buf:expr, $len:expr) => {
        if $buf.len() < $len {
            return Err(annotate!(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "provided buffer is not large enough to contain the expected varint",
            )));
        }
    };
}

/// Attempts to read a varint-encoded `u64` out of the provided buffer
/// and returns it along with a `usize` containing the number of bytes
/// that the encoded `u64` consumed. If the provided buffer is
/// not large enough, returns `UnexpectedEof`.
pub fn deserialize(buf: &[u8]) -> io::Result<(u64, usize)> {
    let res = match buf[0] {
        0..=240 => {
            check_buf_len!(buf, 1);
            (u64::from(buf[0]), 1)
        }
        241..=248 => {
            check_buf_len!(buf, 2);
            let varint = 240 + 256 * (u64::from(buf[0]) - 241) + u64::from(buf[1]);
            (varint, 2)
        }
        249 => {
            check_buf_len!(buf, 3);
            let varint = 2288 + 256 * u64::from(buf[1]) + u64::from(buf[2]);
            (varint, 3)
        }
        other => {
            let sz = other as usize - 247;
            check_buf_len!(buf, sz);
            let mut aligned = [0; 8];
            aligned[..sz].copy_from_slice(&buf[1..=sz]);
            let varint = u64::from_le_bytes(aligned);
            (varint, sz + 1)
        }
    };

    Ok(res)
}
