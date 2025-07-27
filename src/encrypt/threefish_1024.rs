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
