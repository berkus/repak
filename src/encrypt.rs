use {
    crate::{
        Error,
        io::{Deser, Ser, leb128_usize},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[derive(Debug)] // temp?
pub(crate) struct EncryptionHeader {
    algorithm: EncryptionAlgorithm,
    size: u64,
    // TODO: Encryption payload parameters
    payload: Vec<u8>,
}

impl Ser for EncryptionHeader {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        let size = leb128_usize(self.algorithm.into())? + self.payload.len();
        leb128::write::unsigned(w, size as u64)?;
        leb128::write::unsigned(w, self.algorithm.into())?;
        w.write_all(&self.payload)?;
    }
}

impl Deser for EncryptionHeader {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        let algorithm = EncryptionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        let payload = match algorithm {
            EncryptionAlgorithm::NotImplementedYet => vec![],
        };
        Self {
            size,
            algorithm,
            payload,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EncryptionAlgorithm {
    NotImplementedYet,
}

impl From<EncryptionAlgorithm> for u64 {
    fn from(value: EncryptionAlgorithm) -> u64 {
        match value {
            EncryptionAlgorithm::NotImplementedYet => 0,
        }
    }
}

impl TryFrom<u64> for EncryptionAlgorithm {
    type Error = Error;

    #[throws(Self::Error)]
    fn try_from(value: u64) -> Self {
        match value {
            0 => Self::NotImplementedYet,
            _ => throw!(Error::Deser(format!(
                "Unknown encryption algorithm: {}",
                value
            ))),
        }
    }
}
