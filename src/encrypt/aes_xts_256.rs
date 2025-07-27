use {
    crate::Error,
    aes::{
        Aes256,
        cipher::{KeyInit, generic_array::GenericArray},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
    xts_mode::{Xts128, get_tweak_default},
};

//==============================================================================
// Writer
//==============================================================================

pub struct AesXts256Writer<W: Write> {
    writer: W,
    cipher: Box<Xts128<Aes256>>,
    buffer: Vec<u8>,
    position: u64,
}

impl<W: Write> AesXts256Writer<W> {
    #[throws(Error)]
    pub fn new(writer: W, key: &[u8]) -> Self {
        if key.len() != 64 {
            throw!(Error::UnsupportedEncryption(
                "AES-XTS-256 requires 64-byte key".to_string()
            ));
        }

        let cipher1 = Aes256::new(GenericArray::from_slice(&key[..32]));
        let cipher2 = Aes256::new(GenericArray::from_slice(&key[32..]));
        let cipher = Xts128::new(cipher1, cipher2);

        Self {
            writer,
            cipher: Box::new(cipher),
            buffer: Vec::new(),
            position: 0,
        }
    }

    // TODO: Move this to encryptor trait impl...
    #[throws(Error)]
    pub fn finish(mut self) -> W {
        if !self.buffer.is_empty() {
            // Pad to 16-byte boundary for AES
            while !self.buffer.len().is_multiple_of(16) {
                self.buffer.push(0);
            }

            let sector_size = 16;
            let sector_index = self.position / sector_size;
            self.cipher.encrypt_area(
                &mut self.buffer,
                usize::try_from(sector_size)?,
                u128::from(sector_index),
                get_tweak_default,
            );
            self.writer.write_all(&self.buffer)?;
        }
        self.writer
    }
}

impl<W: Write> Write for AesXts256Writer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);

        // Process complete 16-byte blocks
        while self.buffer.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&self.buffer.drain(..16).collect::<Vec<_>>());

            let tweak = get_tweak_default(u128::from(self.position / 16));
            self.cipher.encrypt_sector(&mut block, tweak);
            self.writer.write_all(&block)?;
            self.position += 16;
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

pub struct AesXts256Reader<R: Read> {
    reader: R,
    cipher: Box<Xts128<Aes256>>,
    buffer: Vec<u8>,
    position: u64,
}

impl<R: Read> AesXts256Reader<R> {
    #[throws(Error)]
    pub fn new(reader: R, key: &[u8]) -> Self {
        if key.len() != 64 {
            throw!(Error::UnsupportedEncryption(
                "AES-XTS-256 requires 64-byte key".to_string()
            ));
        }

        let cipher1 = Aes256::new(GenericArray::from_slice(&key[..32]));
        let cipher2 = Aes256::new(GenericArray::from_slice(&key[32..]));
        let cipher = Xts128::new(cipher1, cipher2);

        Self {
            reader,
            cipher: Box::new(cipher),
            buffer: Vec::new(),
            position: 0,
        }
    }
}

impl<R: Read> Read for AesXts256Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.is_empty() {
            // Read and decrypt a block
            let mut encrypted_block = [0u8; 16];
            match self.reader.read_exact(&mut encrypted_block) {
                Ok(()) => {
                    let tweak = get_tweak_default(u128::from(self.position / 16));
                    self.cipher.decrypt_sector(&mut encrypted_block, tweak);
                    self.buffer.extend_from_slice(&encrypted_block);
                    self.position += 16;
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
