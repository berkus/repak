use {
    crate::Error,
    culpa::{throw, throws},
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

impl<W: Write> ThreefishWriter<W> {
    #[throws(Error)]
    pub fn new(writer: W, key: &[u8]) -> Self {
        if key.len() != 128 {
            throw!(Error::UnsupportedEncryption(
                "Threefish-1024 requires 128-byte key".to_string()
            ));
        }

        use threefish::cipher::generic_array::GenericArray;
        let cipher = Threefish1024::new(GenericArray::from_slice(key));

        Self {
            writer,
            cipher: Box::new(cipher),
            buffer: Vec::new(),
        }
    }
}

impl<R: Read> ThreefishReader<R> {
    #[throws(Error)]
    pub fn new(reader: R, key: &[u8]) -> Self {
        if key.len() != 128 {
            throw!(Error::UnsupportedEncryption(
                "Threefish-1024 requires 128-byte key".to_string()
            ));
        }

        use threefish::cipher::generic_array::GenericArray;
        let cipher = Threefish1024::new(GenericArray::from_slice(key));

        Self {
            reader,
            cipher: Box::new(cipher),
            buffer: Vec::new(),
        }
    }
}
