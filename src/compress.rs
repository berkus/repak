use {
    crate::{
        Error,
        io::{Deser, Ser, leb128_usize},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[derive(Debug)] // temp?
pub(crate) struct CompressionHeader {
    size: u64,
    algorithm: CompressionAlgorithm,
    // TODO: Compression payload parameters
    payload: Vec<u8>,
}

impl Ser for CompressionHeader {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        let size = leb128_usize(self.algorithm.into())? + self.payload.len();
        leb128::write::unsigned(w, size as u64)?;
        leb128::write::unsigned(w, self.algorithm.into())?;
        w.write_all(&self.payload)?;
    }
}

impl Deser for CompressionHeader {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        let algorithm = CompressionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        let payload = match algorithm {
            CompressionAlgorithm::None => vec![],
            CompressionAlgorithm::Deflate => vec![],
            CompressionAlgorithm::Bzip => vec![],
            CompressionAlgorithm::Zstd => vec![],
            CompressionAlgorithm::Lzma => vec![],
            CompressionAlgorithm::Lz4 => vec![],
            CompressionAlgorithm::Fsst => vec![],
        };
        Self {
            size,
            algorithm,
            payload,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CompressionAlgorithm {
    None,
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
            CompressionAlgorithm::None => 0,
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

    #[throws(Self::Error)]
    fn try_from(value: u64) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Deflate,
            2 => Self::Bzip,
            3 => Self::Zstd,
            4 => Self::Lzma,
            5 => Self::Lz4,
            6 => Self::Fsst,
            _ => throw!(Error::Deser(format!(
                "Unknown compression algorithm: {}",
                value
            ))),
        }
    }
}

/// Decompress data from the given reader.
pub(crate) enum Decompressor<R: std::io::BufRead> {
    Stored(R),
    Inflate(flate2::bufread::DeflateDecoder<R>),
    // Bzip(bzip2::read::BzDecoder<R>),
    // Zstd(zstd::Decoder<R>),
    // Lzma(lzma::Decoder<R>),
    // Lz4(lz4::Decoder<R>),
    // Fsst(fsst::Decoder<R>),
}

impl<R: std::io::BufRead> std::io::Read for Decompressor<R> {
    #[throws(std::io::Error)]
    fn read(&mut self, buf: &mut [u8]) -> usize {
        match self {
            Self::Stored(r) => r.read(buf)?,
            Self::Inflate(r) => r.read(buf)?,
            // Self::Bzip(r) => r.read(buf),
            // Self::Zstd(r) => r.read(buf),
            // Self::Lzma(r) => r.read(buf),
            // Self::Lz4(r) => r.read(buf),
            // Self::Fsst(r) => r.read(buf),
        }
    }
}

pub(crate) enum Compressor<R: std::io::BufRead> {
    Stored(R),
    Deflate(flate2::bufread::DeflateEncoder<R>),
    // Bzip(bzip2::write::BzEncoder<W>),
    // Zstd(zstd::Encoder<W>),
    // Lzma(lzma::Encoder<W>),
    // Lz4(lz4::Encoder<W>),
    // Fsst(fsst::Encoder<W>),
}
