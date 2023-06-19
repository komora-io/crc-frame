//! Simple tools for reading and writing crc-checked frames of bytes.
//! * Uses crc32fast for a 4-byte crc
//! * Uses varint for frame sizing
//! * Tested against libfuzzer
//!
//! The `varint` module is also public for direct use.

pub mod varint;

use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::FileExt;

use crc32fast::Hasher;
use fault_injection::{annotate, fallible, maybe};

const MAX_HEADER_SIZE: usize = 13;
const CRC_LEN: usize = 4;
const CRC_BEGIN: usize = 0;
const CRC_END: usize = CRC_LEN;
const VARINT_BEGIN: usize = CRC_END;

/// Write a crc'd frame into the provided `Write` instance. Returns the
/// number of bytes written in total, including the varint size and crc.
/// This is always equivalent to a [`std::io::Write::write_all`] call
/// due to the impossibility to write partial frames.
///
/// # Examples
///
/// ```
/// use crc_frame::{write_frame_into, parse_frame};
///
/// let data = b"12345";
///
/// let mut buf = vec![];
///
/// write_frame_into(&mut buf, data).unwrap();
///
/// let (begin, end) = parse_frame(&buf).unwrap();
///
/// assert_eq!(&buf[begin..end], data);
/// ```
pub fn write_frame_into<W: io::Write>(mut writer: W, buf: &[u8]) -> io::Result<usize> {
    let (header_buf, header_end_offset) = frame_header(buf);

    fallible!(writer.write_all(&header_buf[..header_end_offset]));
    fallible!(writer.write_all(buf));

    Ok(header_end_offset + buf.len())
}

/// A simple encoder that will wrap any passed data
/// into a crc'ed frame, suitable for stacking with
/// other encoders for compression or serialization
/// etc...
pub struct Encoder<W: Write> {
    inner: W,
}

impl<W: Write> Encoder<W> {
    pub const fn new(inner: W) -> Encoder<W> {
        Encoder { inner }
    }
}

impl<W: Write> Write for Encoder<W> {
    /// Write a crc'd frame into the provided `Write` instance. Returns the
    /// number of bytes written in total, including the varint size and crc.
    /// This is always equivalent to a [`std::io::Write::write_all`] call
    /// due to the impossibility to write partial frames.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_frame_into(&mut self.inner, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A simple decoder that will parse data from the
/// inner `Read` as a crc'ed frame. Suitable for
/// stacking with other decoders for decompression
/// or deserialization etc...
///
/// This will pull data from the inner `Read`
pub struct Decoder<R: Read> {
    inner: R,
    // NB: buf always contains at most one single frame
    buf: VecDeque<u8>,
    capacity: usize,
}

impl<R: Read> Decoder<R> {
    pub const fn new(inner: R) -> Decoder<R> {
        Decoder {
            inner,
            buf: VecDeque::new(),
            capacity: 128 * 1024,
        }
    }

    pub fn with_capacity(capacity: usize, inner: R) -> Decoder<R> {
        Decoder {
            inner,
            buf: VecDeque::with_capacity(capacity),
            capacity,
        }
    }
}

impl<R: Read> Read for Decoder<R> {
    /// Fills up to one frame into the provided buffer.
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        fallible!(self.fill_buf());

        let bytes_copied = usize::try_from(io::copy(&mut self.buf, &mut buf)?).unwrap();

        Ok(bytes_copied)
    }
}

impl<R: Read> BufRead for Decoder<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.buf.is_empty() {
            fallible!(read_frame_from_reader_into_writer(
                &mut self.inner,
                &mut self.buf,
                self.capacity
            ));
        }

        let (l, r) = self.buf.as_slices();
        assert!(r.is_empty());
        Ok(l)
    }

    fn consume(&mut self, amt: usize) {
        self.buf.drain(..amt);
    }
}

/// Write a crc'd frame into the provided `File` at the given offset.
/// Returns the number of bytes written in total, including the varint size and crc.
#[cfg(unix)]
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

/// Read a frame out of the provided `Read` implementation. This calls
/// [`std::io::Read::read_exact`] many times under the hood, so it's a
/// good idea to use a buffered source of data to avoid high numbers of
/// syscalls.
pub fn read_frame_from_reader_into_writer<R: io::Read, W: io::Write>(
    mut reader: R,
    mut writer: W,
    max_len: usize,
) -> io::Result<usize> {
    let mut crc_bytes = [0; 4];
    let varint_buf = &mut [0; 9];

    fallible!(reader.read_exact(&mut crc_bytes));
    fallible!(reader.read_exact(&mut varint_buf[..1]));

    let varint_size = varint::size_of_varint_from_first_byte(varint_buf[0]);

    fallible!(reader.read_exact(&mut varint_buf[1..varint_size]));

    let (buf_len_u64, _varint_len) = varint::deserialize(varint_buf)?;

    let data_len = if let Ok(data_len) = usize::try_from(buf_len_u64) {
        data_len
    } else {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "encountered a corrupt varint len or this platform \
            cannot represent the required data size as a usize"
        )));
    };

    if data_len > max_len {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "encountered a varint len that is larger than the \
            max_len, and is possibly corrupt or was written with \
            a different configuration.",
        )));
    }

    let crc_expected = u32::from_le_bytes(crc_bytes);

    let mut hasher = Hasher::new();

    let mut copy_buf: [u8; 4096] = [0; 4096];

    let mut remainder = data_len;
    while remainder > 0 {
        let bytes_to_copy = remainder.min(copy_buf.len());

        fallible!(reader.read(&mut copy_buf[..bytes_to_copy]));
        fallible!(writer.write_all(&copy_buf[..bytes_to_copy]));

        hasher.update(&copy_buf[..bytes_to_copy]);

        remainder -= bytes_to_copy;
    }

    //fallible!(reader.read_exact(&mut data_buf[..]));

    // NB: only hash varint after we finish hashing data
    hasher.update(&varint_buf[..varint_size]);

    // We XOR one byte in the crc to make it non-zero
    // for empty buffers, which forces bit flips to
    // materialize in a crc mismatch more often.
    let crc_actual = hasher.finalize() ^ 0xFF;

    if crc_actual != crc_expected {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "input buffer crc {} does not match expected crc {}",
                crc_actual, crc_expected
            ),
        )));
    }

    Ok(data_len)
}

/// Read a frame out of the provided `File`
#[cfg(unix)]
pub fn read_frame_at(file: &fs::File, at: u64, max_len: usize) -> io::Result<Box<[u8]>> {
    const FIRST_READ_SIZE: usize = 512;

    let header = &mut [0; FIRST_READ_SIZE];

    match maybe!(file.read_exact_at(header, at)) {
        Ok(_) => {}
        // it's OK if we do a short read because of CRC check
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }

    let (buf_len_u64, varint_len) = varint::deserialize(&header[VARINT_BEGIN..])?;

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

    let crc_expected = &header[CRC_BEGIN..CRC_END];

    let varint_end = VARINT_BEGIN + varint_len;
    let potential_inline_len = FIRST_READ_SIZE - varint_end;

    let header_buf_len = potential_inline_len.min(buf_len);
    let header_buf_begin = varint_end;
    let header_buf_end = header_buf_begin + header_buf_len;

    buf[..header_buf_len].copy_from_slice(&header[header_buf_begin..header_buf_end]);

    let remainder_buf_begin = header_buf_len;

    fallible!(file.read_exact_at(&mut buf[remainder_buf_begin..], at + FIRST_READ_SIZE as u64));

    let crc_actual = hash(&buf, &header[VARINT_BEGIN..varint_end]);

    if crc_actual != crc_expected {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "input buffer crc does not match expected crc",
        )));
    }

    Ok(buf)
}

fn hash(data_buf: &[u8], varint_buf: &[u8]) -> [u8; CRC_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(data_buf);
    hasher.update(varint_buf);

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
///
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
    // write the buf len varint into the header buffer
    let (varint_buf, varint_size) = varint::get_varint(buf.len() as u64);

    let crc_bytes = hash(buf, &varint_buf[..varint_size]);

    let mut header_buf = [0_u8; MAX_HEADER_SIZE];

    // write crc
    header_buf[CRC_BEGIN..CRC_END].copy_from_slice(&crc_bytes);

    // write varint
    let varint_end = VARINT_BEGIN + varint_size;
    header_buf[VARINT_BEGIN..varint_end].copy_from_slice(&varint_buf[..varint_size]);

    (header_buf, varint_end)
}

/// Reads a header out of an arbitrary buffer, checks the crc,
/// and if the crc matches the corresponding bytes, returns
/// the start and end offsets in the buffer for the inner
/// bytes. The end offset of the buffer is also the end
/// offset for this entire frame, so you may advance
/// any cursors to this point for reading the next frame
/// in a sequence of bytes etc...
///
/// # Examples
///
/// ```
/// use crc_frame::{write_frame_into, parse_frame};
///
/// let data = b"12345";
///
/// let mut buf = vec![];
///
/// write_frame_into(&mut buf, data).unwrap();
/// write_frame_into(&mut buf, data).unwrap();
///
/// let (begin_1, end_1) = parse_frame(&buf).unwrap();
///
/// assert_eq!(&buf[begin_1..end_1], data);
///
/// let (begin_2, end_2) = parse_frame(&buf[end_1..]).unwrap();
///
/// assert_eq!(&buf[begin_2..end_2], data);
/// ```
pub fn parse_frame(buf: &[u8]) -> io::Result<(usize, usize)> {
    if buf.len() < VARINT_BEGIN + 1 {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "encountered a buffer that is not even large enough to contain a CRC and minimal one-byte varint"
        )));
    }

    let expected_crc: [u8; CRC_LEN] = buf[CRC_BEGIN..CRC_END].try_into().unwrap();

    let (buf_len_u64, varint_len) = varint::deserialize(&buf[VARINT_BEGIN..])?;

    let varint_end = VARINT_BEGIN + varint_len;
    let data_begin = varint_end;

    let data_len = if let Ok(data_len) = usize::try_from(buf_len_u64) {
        data_len
    } else {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "encountered a corrupt varint len or this platform \
            cannot represent the required data size as a usize"
        )));
    };

    let data_end = data_begin + data_len;

    if data_end > buf.len() {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "encountered a corrupt varint len or an input \
                buffer of size {} that does not contain the full \
                frame of size {}",
                buf.len(),
                data_end
            )
        )));
    }

    let data_buf = &buf[data_begin..data_end];
    let varint_buf = &buf[VARINT_BEGIN..varint_end];

    let actual_crc = hash(data_buf, varint_buf);

    if actual_crc != expected_crc {
        return Err(annotate!(io::Error::new(
            io::ErrorKind::InvalidData,
            "input buffer crc does not match expected crc",
        )));
    }

    Ok((data_begin, data_end))
}
