use {
    crate::Error,
    aes::Aes256,
    culpa::{throw, throws},
    std::io::{Read, Write},
    xts_mode::Xts128,
};

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

impl<W: Write> AesXts256Writer<W> {
    #[throws(Error)]
    pub fn new(writer: W, key: &[u8]) -> Self {
        if key.len() != 64 {
            throw!(Error::UnsupportedEncryption(
                "AES-XTS-256 requires 64-byte key".to_string()
            ));
        }

        use aes::cipher::{KeyInit, generic_array::GenericArray};
        let cipher1 = Aes256::new(GenericArray::from_slice(&key[..32]));
        let cipher2 = Aes256::new(GenericArray::from_slice(&key[32..]));
        let cipher = Xts128::new(cipher1, cipher2);

        Self {
            writer,
            cipher,
            buffer: Vec::new(),
            position: 0,
        }
    }
}

impl<R: Read> AesXts256Reader<R> {
    #[throws(Error)]
    pub fn new(reader: R, key: &[u8]) -> Self {
        if key.len() != 64 {
            throw!(Error::UnsupportedEncryption(
                "AES-XTS-256 requires 64-byte key".to_string()
            ));
        }

        use aes::cipher::{KeyInit, generic_array::GenericArray};
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
