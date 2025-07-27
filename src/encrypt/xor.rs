use {
    crate::Error,
    culpa::throws,
    std::io::{Read, Write},
};

//==============================================================================
// Writer
//==============================================================================

pub struct XorWriter<W: Write> {
    writer: W,
    cipher: Vec<u8>,
    buffer: Vec<u8>,
    position: u64,
}

impl<W: Write> XorWriter<W> {
    #[throws(Error)]
    pub fn new(writer: W, key: &[u8]) -> Self {
        Self {
            writer,
            cipher: key.to_owned(),
            buffer: Vec::new(),
            position: 0,
        }
    }

    pub fn finish(self) -> W {
        self.writer
    }
}

impl<W: Write> Write for XorWriter<W> {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        todo!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

//==============================================================================
// Reader
//==============================================================================

pub struct XorReader<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    position: u64,
}

impl<R: Read> Read for XorReader<R> {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

//==============================================================================
// Implementation
//==============================================================================

/// Run a cyclic xor over data buffer, starting from a key offset and returning a new key offset.
/// A `cyclic_xor` function taken from <https://lib.rs/crates/xor-cipher> and modified to maintain running key offset.
pub fn cyclic_xor<D: AsMut<[u8]>, K: AsRef<[u8]>>(mut data: D, key: K, key_offset: usize) -> usize {
    let cyclic_xor_inner = |data: &mut [u8], key: &[u8]| {
        data.iter_mut()
            .zip(key.iter().cycle().skip(key_offset))
            .for_each(|(byte, key_byte)| *byte ^= key_byte);
    };
    cyclic_xor_inner(data.as_mut(), key.as_ref());
    0
}
