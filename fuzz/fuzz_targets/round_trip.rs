#![no_main]
use libfuzzer_sys::fuzz_target;

use crc_frame::{parse_frame, read_frame, read_frame_at, write_frame, write_frame_at};

fuzz_target!(|data: &[u8]| {
    //println!("using input: {data:?}");
    let mut buf = vec![];

    write_frame(data, &mut buf).unwrap();

    let (begin, end) = parse_frame(&buf).unwrap();

    assert_eq!(&buf[begin..end], data);

    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    let mut file = options.open("fuzz_file").unwrap();

    write_frame_at(data, &file, 7).unwrap();
    let rt_1 = read_frame_at(&file, 7, data.len() + 13).unwrap();

    assert_eq!(&*rt_1, data);

    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(7)).unwrap();
    let rt_2 = read_frame(&mut file, data.len() + 13).unwrap();

    assert_eq!(&*rt_2, data);
});
