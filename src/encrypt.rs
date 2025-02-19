use {
    crate::{
        Error,
        io::{Deser, Ser},
    },
    std::io::{Read, Write},
};

pub(crate) struct EncryptionHeader {
    size: u64,
    algorithm: EncryptionAlgorithm,
    // TODO: Encryption payload parameters
    payload: Vec<u8>,
}

impl Ser for EncryptionHeader {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        leb128::write::unsigned(w, self.size)?;
        leb128::write::unsigned(w, self.algorithm.into())?;
        w.write_all(&self.payload)?;
        Ok(())
    }
}

impl Deser for EncryptionHeader {
    fn deser(r: &mut impl Read) -> Result<Self, Error> {
        let size = leb128::read::unsigned(r)?;
        let algorithm = EncryptionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        let payload = match algorithm {
            EncryptionAlgorithm::NotImplementedYet => vec![],
        };
        Ok(Self {
            size,
            algorithm,
            payload,
        })
    }
}

#[derive(Clone, Copy)]
enum EncryptionAlgorithm {
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

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NotImplementedYet),
            _ => Err(Error::Deser(format!(
                "Unknown encryption algorithm: {}",
                value
            ))),
        }
    }
}
