pub struct AdiantumWriter<W: Write> {
    writer: W,
    buffer: Vec<u8>,
    nonce_counter: u64,
}

pub struct AdiantumReader<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    nonce_counter: u64,
}
