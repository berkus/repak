use {
    crate::{
        Error,
        io::{Deser, Ser},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[derive(Debug)] // temp?
pub(crate) struct EncryptionHeader {
    pub(crate) algorithm: EncryptionAlgorithm,
    #[expect(dead_code)]
    size: u64,
    // TODO: Encryption payload parameters
    payload: Vec<u8>,
}

impl EncryptionHeader {
    pub fn new(algorithm: EncryptionAlgorithm) -> Self {
        Self {
            algorithm,
            size: 0,
            payload: vec![],
        }
    }
}

impl Ser for EncryptionHeader {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, self.algorithm.into())?;
        leb128::write::unsigned(w, self.payload.len() as u64)?;
        w.write_all(&self.payload)?;
    }
}

impl Deser for EncryptionHeader {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let algorithm = EncryptionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        let size = leb128::read::unsigned(r)?;
        let payload = match algorithm {
            EncryptionAlgorithm::None | EncryptionAlgorithm::Xor => vec![],
            _ => todo!(),
        };
        Self {
            algorithm,
            size,
            payload,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EncryptionAlgorithm {
    None,
    Xor,
    AesXts256,
    Hctr2,
    Adiantum,
    Threefish1024,
}

impl From<EncryptionAlgorithm> for u64 {
    fn from(value: EncryptionAlgorithm) -> u64 {
        match value {
            EncryptionAlgorithm::None => 0,
            EncryptionAlgorithm::Xor => 1,
            _ => todo!(),
        }
    }
}

impl TryFrom<u64> for EncryptionAlgorithm {
    type Error = Error;

    #[throws(Self::Error)]
    fn try_from(value: u64) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Xor,
            _ => throw!(Error::Deser(format!(
                "Unknown encryption algorithm: {value}"
            ))),
        }
    }
}

// pub(crate) enum Encryptor<R: std::io::BufRead> {
//     None(R),
//     Xor(u8),
// }

// impl<R: std::io::BufRead> Encryptor<R> {
//     pub fn passthrough(r: R) -> Self {
//         Self::None(r)
//     }

//     pub fn xor(_r: R, key: u8) -> Self {
//         Self::Xor(key)
//     }
// }
