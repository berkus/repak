use {
    crate::{
        Error,
        io::{Deser, Ser, leb128_usize},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[derive(Debug)]
pub struct CompressionHeader {
    pub algorithm: CompressionAlgorithm,
    pub decompressed_size: u64,
}

impl CompressionHeader {
    pub fn new(algorithm: CompressionAlgorithm, decompressed_size: u64) -> Self {
        Self {
            algorithm,
            decompressed_size,
        }
    }
}

impl Ser for CompressionHeader {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        // Calculate total size: algorithm_id + decompressed_size
        let algorithm_id_size = leb128_usize(self.algorithm.into())?;
        let decompressed_size_size = leb128_usize(self.decompressed_size)?;
        let total_size = algorithm_id_size + decompressed_size_size;

        // Write total size, algorithm ID, then decompressed size
        leb128::write::unsigned(w, total_size as u64)?;
        leb128::write::unsigned(w, self.algorithm.into())?;
        leb128::write::unsigned(w, self.decompressed_size)?;
    }
}

impl Deser for CompressionHeader {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let _total_size = leb128::read::unsigned(r)?;
        let algorithm = CompressionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        let decompressed_size = leb128::read::unsigned(r)?;

        Self {
            algorithm,
            decompressed_size,
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
    Best,
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
            CompressionAlgorithm::Best => panic!("Should not serialize Best algorithm selector"),
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
            _ => throw!(Error::UnsupportedCompression(format!(
                "Unknown compression algorithm: {value}. If it is one of the standard compression kinds, check your library is compiled with corresponding compress-* feature enabled."
            ))),
        }
    }
}

mod compressor;
mod decompressor;

pub use {
    compressor::{compress_stream, pick_best_compression},
    decompressor::decompress_stream,
};
