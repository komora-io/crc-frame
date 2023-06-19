#![no_main]

use std::io::Write;

use arbitrary::Arbitrary;
use bincode::{deserialize_from, serialize_into};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use zstd::stream;

use crc_frame::{parse_frame, read_frame_at, write_frame_at, write_frame_into, Decoder, Encoder};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Arbitrary)]
struct S {
    inner: Vec<u8>,
    lol: bool,
}

fuzz_target!(|data: Vec<S>| {
    // println!("------------------------- new test -----------------------------");
    let mut buf = vec![];

    // bincode -> crc_frame -> zstd -> Vec
    let zstd_enc = stream::Encoder::new(&mut buf, 3).unwrap();
    let mut crc_frame_enc = Encoder::new(zstd_enc);

    for datum in &data {
        serialize_into(&mut crc_frame_enc, datum).expect("failed to serialize");
    }

    crc_frame_enc.flush().unwrap();
    drop(crc_frame_enc);

    let mut read_buf_1: &[u8] = &buf;

    let zstd_dec = stream::Decoder::new(&mut read_buf_1).unwrap();
    let mut crc_frame_dec = Decoder::new(zstd_dec);
    for expected_datum in &data {
        let read_datum: S = deserialize_from(&mut crc_frame_dec).unwrap();
        assert_eq!(&read_datum, expected_datum);
    }

    // assert that we get an UnexpectedEof if we try to read from the end of the stream.
    let expected_err = deserialize_from::<_, S>(&mut crc_frame_dec).unwrap_err();
    if let bincode::ErrorKind::Io(io_error) = *expected_err {
        assert_eq!(io_error.kind(), std::io::ErrorKind::UnexpectedEof);
    } else {
        unreachable!();
    }
});
