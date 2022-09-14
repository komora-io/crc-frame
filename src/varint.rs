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

/// Writes the provided `u64` into the beginning of the
/// provided buffer and returns how many bytes the
/// corresponding varint consumed. If the buffer is
/// not large enough, returns `UnexpectedEof`.
pub fn serialize_into(int: u64, buf: &mut [u8]) -> io::Result<usize> {
    Ok(if int <= 240 {
        check_buf_len!(buf, 1);
        buf[0] = u8::try_from(int).unwrap();
        1
    } else if int <= 2287 {
        check_buf_len!(buf, 2);
        buf[0] = u8::try_from((int - 240) / 256 + 241).unwrap();
        buf[1] = u8::try_from((int - 240) % 256).unwrap();
        2
    } else if int <= 67823 {
        check_buf_len!(buf, 3);
        buf[0] = 249;
        buf[1] = u8::try_from((int - 2288) / 256).unwrap();
        buf[2] = u8::try_from((int - 2288) % 256).unwrap();
        3
    } else if int <= 0x00FF_FFFF {
        check_buf_len!(buf, 4);
        buf[0] = 250;
        let bytes = int.to_le_bytes();
        buf[1..4].copy_from_slice(&bytes[..3]);
        4
    } else if int <= 0xFFFF_FFFF {
        check_buf_len!(buf, 5);
        buf[0] = 251;
        let bytes = int.to_le_bytes();
        buf[1..5].copy_from_slice(&bytes[..4]);
        5
    } else if int <= 0x00FF_FFFF_FFFF {
        check_buf_len!(buf, 6);
        buf[0] = 252;
        let bytes = int.to_le_bytes();
        buf[1..6].copy_from_slice(&bytes[..5]);
        6
    } else if int <= 0xFFFF_FFFF_FFFF {
        check_buf_len!(buf, 7);
        buf[0] = 253;
        let bytes = int.to_le_bytes();
        buf[1..7].copy_from_slice(&bytes[..6]);
        7
    } else if int <= 0x00FF_FFFF_FFFF_FFFF {
        check_buf_len!(buf, 8);
        buf[0] = 254;
        let bytes = int.to_le_bytes();
        buf[1..8].copy_from_slice(&bytes[..7]);
        8
    } else {
        check_buf_len!(buf, 9);
        buf[0] = 255;
        let bytes = int.to_le_bytes();
        buf[1..9].copy_from_slice(&bytes[..8]);
        9
    })
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
