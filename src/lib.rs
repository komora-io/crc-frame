//! Simple tools for reading and writing crc-checked frames of bytes.
//! * Uses crc32fast for a 4-byte crc.
//! * Uses varint for frame sizing
//! * Tested against libfuzzer

mod varint;

use std::fs;
use std::io;
use std::os::unix::fs::FileExt;

use crc32fast::Hasher;
use fault_injection::{annotate, fallible, maybe};

const MAX_HEADER_SIZE: usize = 13;

/// Write a crc'd frame into the provided `Write` instance. Returns the
/// number of bytes written in total, including the varint size and crc.
///
/// # Examples
///
/// ```
/// use crc_frame::{write_frame, parse_frame};
///
/// let data = b"12345";
///
/// let mut buf = vec![];
///
/// write_frame(data, &mut buf).unwrap();
///
/// let (begin, end) = parse_frame(&buf).unwrap();
///
/// assert_eq!(&buf[begin..end], data);
/// ```
pub fn write_frame<W: io::Write>(buf: &[u8], mut into: W) -> io::Result<usize> {
    let (header_buf, header_end_offset) = frame_header(buf);

    fallible!(into.write_all(&header_buf[..header_end_offset]));
    fallible!(into.write_all(buf));

    Ok(header_end_offset + buf.len())
}

/// Write a crc'd frame into the provided `File` at the given offset.
/// Returns the number of bytes written in total, including the varint size and crc.
pub fn write_frame_at(buf: &[u8], file: &fs::File, at: u64) -> io::Result<usize> {
    let (header_buf, header_end_offset) = frame_header(buf);
    let header = &header_buf[..header_end_offset];

    fallible!(file.write_all_at(header, at));
    fallible!(file.write_all_at(buf, at + header.len() as u64));

    Ok(header_end_offset + buf.len())
}

fn uninit_boxed_slice(len: usize) -> Box<[u8]> {
    use std::alloc::{alloc, Layout};

    let layout = Layout::array::<u8>(len).unwrap();

    unsafe {
        let ptr = alloc(layout);
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        Box::from_raw(slice)
    }
}

/// Read a frame out of the provided Read implementation and into the provided `Read`
/// implementation.
pub fn read_frame<R: io::Read>(mut from: R, max_len: usize) -> io::Result<Box<[u8]>> {
    let header = &mut [0; MAX_HEADER_SIZE];

    match maybe!(from.read_exact(header)) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }

    let (buf_len_u64, varint_len) = varint::deserialize(header)?;

    if buf_len_u64 > max_len as u64 {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "encountered a varint len that is larger than the \
            max_len, and is possibly corrupt or was written with \
            a different configuration.",
        )));
    }

    // at this point we know that the buffer len fits in a usize
    let buf_len = usize::try_from(buf_len_u64).unwrap();

    let mut buf = uninit_boxed_slice(buf_len);

    let crc_begin = varint_len;
    let crc_end = crc_begin + 4;
    let crc_expected = &header[crc_begin..crc_end];

    let potential_inline_len = MAX_HEADER_SIZE - crc_end;
    let header_buf_len = potential_inline_len.min(buf_len);
    let header_buf_begin = crc_end;
    let header_buf_end = header_buf_begin + header_buf_len;

    buf[..header_buf_len].copy_from_slice(&header[header_buf_begin..header_buf_end]);

    let remainder_buf_begin = header_buf_len;

    fallible!(from.read_exact(&mut buf[remainder_buf_begin..]));

    let crc_actual = hash(&buf, &header[..varint_len]);

    if crc_actual != crc_expected {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "input buffer crc does not match expected crc",
        )));
    }

    Ok(buf)
}

/// Read a frame out of the provided Read implementation and into the provided `File`
pub fn read_frame_at(file: &fs::File, at: u64, max_len: usize) -> io::Result<Box<[u8]>> {
    const FIRST_READ_SIZE: usize = 128;

    let header = &mut [0; FIRST_READ_SIZE];

    match maybe!(file.read_exact_at(header, at)) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }

    let (buf_len_u64, varint_len) = varint::deserialize(header)?;

    if buf_len_u64 > max_len as u64 {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "encountered a varint len that is larger than the \
            max_len, and is possibly corrupt or was written with \
            a different configuration.",
        )));
    }

    // at this point we know that the buffer len fits in a usize
    let buf_len = usize::try_from(buf_len_u64).unwrap();

    let mut buf = uninit_boxed_slice(buf_len);

    let crc_begin = varint_len;
    let crc_end = crc_begin + 4;
    let crc_expected = &header[crc_begin..crc_end];

    let potential_inline_len = FIRST_READ_SIZE - crc_end;
    let header_buf_len = potential_inline_len.min(buf_len);
    let header_buf_begin = crc_end;
    let header_buf_end = header_buf_begin + header_buf_len;

    buf[..header_buf_len].copy_from_slice(&header[header_buf_begin..header_buf_end]);

    let remainder_buf_begin = header_buf_len;

    fallible!(file.read_exact_at(&mut buf[remainder_buf_begin..], at + FIRST_READ_SIZE as u64));

    let crc_actual = hash(&buf, &header[..varint_len]);

    if crc_actual != crc_expected {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "input buffer crc does not match expected crc",
        )));
    }

    Ok(buf)
}

fn hash(buf: &[u8], len_bytes: &[u8]) -> [u8; 4] {
    let mut hasher = Hasher::new();
    hasher.update(&len_bytes);
    hasher.update(&buf);

    // We XOR one byte in the crc to make it non-zero
    // for empty buffers, which forces bit flips to
    // materialize in a crc mismatch more often.
    (hasher.finalize() ^ 0xFF).to_le_bytes()
}

/// Return an array which contains the crc and varint for
/// a given buffer, and a `usize` that is the length of
/// the provided array which corresponds to the valid
/// varint and crc. Returns an array instead of a Vec<u8>
/// to avoid allocations.
///
/// # Examples
/// ```
/// use crc_frame::frame_header;
///
/// let buf = b"12345";
///
/// let (header_buf, header_len) = frame_header(buf);
///
/// let mut out = vec![];
/// out.extend_from_slice(&header_buf[..header_len]);
/// out.extend_from_slice(buf);
/// ```
pub fn frame_header(buf: &[u8]) -> ([u8; MAX_HEADER_SIZE], usize) {
    let mut header_buf = [0_u8; 4 + 9];

    // write the buf len varint into the header buffer
    let bytes_for_varint = varint::serialize_into(buf.len() as u64, &mut header_buf);

    let crc_start = bytes_for_varint;
    let crc_end = bytes_for_varint + 4;

    let crc_bytes = hash(buf, &header_buf[..bytes_for_varint]);

    // write crc
    header_buf[crc_start..crc_end].copy_from_slice(&crc_bytes);

    (header_buf, crc_end)
}

/// Reads a header out of an arbitrary buffer, checks the crc,
/// and if the crc matches the corresponding bytes, returns
/// the start and end offsets in the buffer for the inner
/// bytes.
///
/// # Examples
///
/// ```
/// use crc_frame::{write_frame, parse_frame};
///
/// let data = b"12345";
///
/// let mut buf = vec![];
///
/// write_frame(data, &mut buf).unwrap();
///
/// let (begin, end) = parse_frame(&buf).unwrap();
///
/// assert_eq!(&buf[begin..end], data);
/// ```
pub fn parse_frame(buf: &[u8]) -> io::Result<(usize, usize)> {
    let (buf_len_u64, varint_len) = varint::deserialize(buf)?;

    let expected_len = buf.len() as u64 - (4 + varint_len as u64);
    if buf_len_u64 != expected_len {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "encountered a corrupt varint len or an input \
            buffer that does not contain the full frame",
        )));
    }

    // If we got this far, we know that buf_len (a u64) is convertible
    // to our platform's usize, because we know that it is less than the
    // size of the input buffer.

    let buf_len = usize::try_from(buf_len_u64).unwrap();

    let crc_begin = varint_len;
    let buf_begin = varint_len + 4;
    let buf_end = buf_begin + buf_len;

    let expected_crc: [u8; 4] = buf[crc_begin..buf_begin].try_into().unwrap();

    let actual_crc = hash(&buf[buf_begin..buf_end], &buf[..varint_len]);

    if actual_crc != expected_crc {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "input buffer crc does not match expected crc",
        )));
    }

    Ok((buf_begin, buf_end))
}
