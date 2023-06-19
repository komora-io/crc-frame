#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;

use crc_frame::{parse_frame, read_frame_at, read_frame_from, write_frame_at, write_frame_into};

fuzz_target!(|data: Vec<Vec<u8>>| {
    // println!("------------------------- new test -----------------------------");
    // println!("using input: {data:?}");
    let mut buf = vec![];

    for datum in &data {
        // println!("writing datum {:?} at offset {}", datum, buf.len());
        let written = write_frame_into(&mut buf, &datum).unwrap();
        // println!("wrote buffer of len {}", written);
    }

    let mut read_buf_1: &[u8] = &buf;
    let mut read_buf_2: &[u8] = &buf;
    // println!("read buf has total len {}", read_buf.len());

    for datum in &data {
        // println!("reading");
        let (begin, end) = parse_frame(read_buf_1).unwrap();
        // println!("begin: {begin}, end: {end}");

        assert_eq!(&read_buf_1[begin..end], datum);
        // println!("got one, advancing buf to {end}");

        read_buf_1 = &read_buf_1[end..];

        let read_2 = read_frame_from(&mut read_buf_2, datum.len()).unwrap();

        assert_eq!(&*read_2, datum);
    }
});
