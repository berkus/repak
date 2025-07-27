use {
    crate::Error,
    culpa::{throw, throws},
    std::io::{Read, Write},
    threefish::{
        Threefish1024,
        cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
    },
};

//==============================================================================
// Writer
//==============================================================================

pub struct ThreefishWriter<W: Write> {
    writer: W,
    cipher: Box<Threefish1024>,
    buffer: Vec<u8>,
}

impl<W: Write> ThreefishWriter<W> {
    #[throws(Error)]
    pub fn new(writer: W, key: &[u8]) -> Self {
        if key.len() != 128 {
            throw!(Error::UnsupportedEncryption(
                "Threefish-1024 requires 128-byte key".to_string()
            ));
        }

        let cipher = Threefish1024::new(GenericArray::from_slice(key));

        Self {
            writer,
            cipher: Box::new(cipher),
            buffer: Vec::new(),
        }
    }

    // TODO: Move this to encryptor trait impl...
    #[throws(Error)]
    pub fn finish(mut self) -> W {
        if !self.buffer.is_empty() {
            // Pad to 128-byte boundary for Threefish-1024
            while !self.buffer.len().is_multiple_of(128) {
                self.buffer.push(0);
            }

            for chunk in self.buffer.chunks_mut(128) {
                if chunk.len() == 128 {
                    let mut block = GenericArray::clone_from_slice(chunk);
                    self.cipher.encrypt_block(&mut block);
                    chunk.copy_from_slice(&block);
                }
            }
            self.writer.write_all(&self.buffer)?;
        }
        self.writer
    }
}

impl<W: Write> Write for ThreefishWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);

        // Process complete 128-byte blocks
        while self.buffer.len() >= 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&self.buffer.drain(..128).collect::<Vec<_>>());

            let mut ga_block = GenericArray::clone_from_slice(&block);
            self.cipher.encrypt_block(&mut ga_block);
            block.copy_from_slice(&ga_block);
            self.writer.write_all(&block)?;
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

pub struct ThreefishReader<R: Read> {
    reader: R,
    cipher: Box<Threefish1024>,
    buffer: Vec<u8>,
}

impl<R: Read> ThreefishReader<R> {
    #[throws(Error)]
    pub fn new(reader: R, key: &[u8]) -> Self {
        if key.len() != 128 {
            throw!(Error::UnsupportedEncryption(
                "Threefish-1024 requires 128-byte key".to_string()
            ));
        }

        let cipher = Threefish1024::new(GenericArray::from_slice(key));

        Self {
            reader,
            cipher: Box::new(cipher),
            buffer: Vec::new(),
        }
    }
}

impl<R: Read> Read for ThreefishReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.is_empty() {
            // Read and decrypt a block
            let mut encrypted_block = [0u8; 128];
            match self.reader.read_exact(&mut encrypted_block) {
                Ok(()) => {
                    let mut block = GenericArray::clone_from_slice(&encrypted_block);
                    self.cipher.decrypt_block(&mut block);
                    encrypted_block.copy_from_slice(&block);
                    self.buffer.extend_from_slice(&encrypted_block);
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(0);
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
