use {
    crate::{
        Error,
        io::{Deser, Ser},
    },
    std::io::{Read, Write},
};

pub(crate) struct CompressionHeader {
    size: u64,
    algorithm: CompressionAlgorithm,
    // TODO: Compression payload parameters
    payload: Vec<u8>,
}

impl Ser for CompressionHeader {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        leb128::write::unsigned(w, self.size)?;
        leb128::write::unsigned(w, self.algorithm.into())?;
        w.write_all(&self.payload)?;
        Ok(())
    }
}

impl Deser for CompressionHeader {
    fn deser(r: &mut impl Read) -> Result<Self, Error> {
        let size = leb128::read::unsigned(r)?;
        let algorithm = CompressionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        let payload = match algorithm {
            CompressionAlgorithm::NoCompression => vec![],
            CompressionAlgorithm::Deflate => vec![],
            CompressionAlgorithm::Bzip => vec![],
            CompressionAlgorithm::Zstd => vec![],
            CompressionAlgorithm::Lzma => vec![],
            CompressionAlgorithm::Lz4 => vec![],
            CompressionAlgorithm::Fsst => vec![],
        };
        Ok(Self {
            size,
            algorithm,
            payload,
        })
    }
}

#[derive(Clone, Copy)]
pub enum CompressionAlgorithm {
    NoCompression,
    Deflate,
    Bzip,
    Zstd,
    Lzma,
    Lz4,
    Fsst,
}

impl From<CompressionAlgorithm> for u64 {
    fn from(value: CompressionAlgorithm) -> u64 {
        match value {
            CompressionAlgorithm::NoCompression => 0,
            CompressionAlgorithm::Deflate => 1,
            CompressionAlgorithm::Bzip => 2,
            CompressionAlgorithm::Zstd => 3,
            CompressionAlgorithm::Lzma => 4,
            CompressionAlgorithm::Lz4 => 5,
            CompressionAlgorithm::Fsst => 6,
        }
    }
}

impl TryFrom<u64> for CompressionAlgorithm {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoCompression),
            1 => Ok(Self::Deflate),
            2 => Ok(Self::Bzip),
            3 => Ok(Self::Zstd),
            4 => Ok(Self::Lzma),
            5 => Ok(Self::Lz4),
            6 => Ok(Self::Fsst),
            _ => Err(Error::Deser(format!(
                "Unknown compression algorithm: {}",
                value
            ))),
        }
    }
}
