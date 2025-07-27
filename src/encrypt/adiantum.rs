use {
    crate::Error,
    culpa::{throw, throws},
    std::io::{Read, Write},
};

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
