use {
    crate::Error,
    culpa::{throw, throws},
    std::io::{Read, Write},
};

//==============================================================================
// Writer
//==============================================================================

pub struct AdiantumWriter<W: Write> {
    writer: W,
    buffer: Vec<u8>,
    nonce_counter: u64,
}

impl<W: Write> AdiantumWriter<W> {
    #[throws(Error)]
    pub fn new(writer: W, key: &[u8]) -> Self {
        if key.len() != 32 {
            throw!(Error::UnsupportedEncryption(
                "Adiantum requires 32-byte key".to_string()
            ));
        }

        // TODO: Implement proper Adiantum encryption with ChaCha20 and AES
        // For now, just pass through data without encryption
        Self {
            writer,
            buffer: Vec::new(),
            nonce_counter: 0,
        }
    }

    #[throws(Error)]
    pub fn finish(mut self) -> W {
        if !self.buffer.is_empty() {
            // TODO: Implement actual Adiantum encryption - for now just pass through
            self.writer.write_all(&self.buffer)?;
        }
        self.writer
    }
}

impl<W: Write> Write for AdiantumWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // TODO: Implement actual Adiantum streaming encryption
        // For now, just pass through data
        self.buffer.extend_from_slice(buf);
        if self.buffer.len() >= 16 {
            let to_write = self.buffer.drain(..16).collect::<Vec<_>>();
            self.writer.write_all(&to_write)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!()
    }
}

//==============================================================================
// Reader
//==============================================================================

pub struct AdiantumReader<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    nonce_counter: u64,
}

impl<R: Read> AdiantumReader<R> {
    #[throws(Error)]
    pub fn new(reader: R, key: &[u8]) -> Self {
        if key.len() != 32 {
            throw!(Error::UnsupportedEncryption(
                "Adiantum requires 32-byte key".to_string()
            ));
        }

        // TODO: Implement proper Adiantum decryption with ChaCha20 and AES
        // For now, just pass through data without decryption
        Self {
            reader,
            buffer: Vec::new(),
            nonce_counter: 0,
        }
    }
}

impl<R: Read> Read for AdiantumReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // TODO: Implement actual Adiantum decryption - for now just pass through
        if self.buffer.is_empty() {
            let mut data = vec![0u8; buf.len()];
            match self.reader.read(&mut data) {
                Ok(n) => {
                    self.buffer.extend_from_slice(&data[..n]);
                }
                Err(e) => return Err(e),
            }
        }

        let bytes_to_copy = buf.len().min(self.buffer.len());
        buf[..bytes_to_copy]
            .copy_from_slice(&self.buffer.drain(..bytes_to_copy).collect::<Vec<_>>());
        Ok(bytes_to_copy)
    }
}
