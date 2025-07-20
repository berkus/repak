use {
    std::io::{Read, Write},
    threefish::{
        Threefish1024,
        cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    },
};

pub struct ThreefishWriter<W: Write> {
    writer: W,
    cipher: Box<Threefish1024>,
    buffer: Vec<u8>,
}

pub struct ThreefishReader<R: Read> {
    reader: R,
    cipher: Box<Threefish1024>,
    buffer: Vec<u8>,
}
