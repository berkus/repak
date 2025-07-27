pub struct AesXts256Writer<W: Write> {
    writer: W,
    cipher: Box<Xts128<Aes256>>,
    buffer: Vec<u8>,
    position: u64,
}

pub struct AesXts256Reader<R: Read> {
    reader: R,
    cipher: Box<Xts128<Aes256>>,
    buffer: Vec<u8>,
    position: u64,
}
