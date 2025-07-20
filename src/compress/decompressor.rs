use {
    crate::{CompressionAlgorithm, Error, compress::CompressionHeader},
    culpa::{throw, throws},
    std::io::{BufRead, Read},
};

/// Decompress data from the given reader.
pub enum Decompressor<R: BufRead> {
    Stored(R),
    #[cfg(feature = "compress-deflate")]
    Inflate(flate2::bufread::DeflateDecoder<R>),
    #[cfg(feature = "compress-bzip")]
    Bzip(bzip2::read::BzDecoder<R>),
    #[cfg(feature = "compress-zstd")]
    Zstd(zstd::Decoder<'static, R>),
    #[cfg(feature = "compress-lzma")]
    Lzma(xz2::read::XzDecoder<R>),
    #[cfg(feature = "compress-lz4")]
    Lz4(lz4::Decoder<R>),
}

impl<R: BufRead> Decompressor<R> {
    #[throws(Error)]
    pub fn new(algorithm: CompressionAlgorithm, reader: R) -> Self {
        match algorithm {
            CompressionAlgorithm::None => Self::Stored(reader),
            CompressionAlgorithm::Deflate => {
                #[cfg(feature = "compress-deflate")]
                {
                    Self::Inflate(flate2::bufread::DeflateDecoder::new(reader))
                }
                #[cfg(not(feature = "compress-deflate"))]
                throw!(Error::UnsupportedCompression(
                    "Deflate compression not supported".to_string(),
                ))
            }
            CompressionAlgorithm::Bzip => {
                #[cfg(feature = "compress-bzip")]
                {
                    Self::Bzip(bzip2::read::BzDecoder::new(reader))
                }
                #[cfg(not(feature = "compress-bzip"))]
                throw!(Error::UnsupportedCompression(
                    "Bzip2 compression not supported".to_string()
                ))
            }
            CompressionAlgorithm::Zstd => {
                #[cfg(feature = "compress-zstd")]
                {
                    let decoder = zstd::Decoder::with_buffer(reader).map_err(Error::Io)?;
                    Self::Zstd(decoder)
                }
                #[cfg(not(feature = "compress-zstd"))]
                throw!(Error::UnsupportedCompression(
                    "Zstd compression not supported".to_string()
                ))
            }
            CompressionAlgorithm::Lzma => {
                #[cfg(feature = "compress-lzma")]
                {
                    Self::Lzma(xz2::read::XzDecoder::new(reader))
                }
                #[cfg(not(feature = "compress-lzma"))]
                throw!(Error::UnsupportedCompression(
                    "LZMA compression not supported".to_string()
                ))
            }
            CompressionAlgorithm::Lz4 => {
                #[cfg(feature = "compress-lz4")]
                {
                    Self::Lz4(lz4::Decoder::new(reader).map_err(Error::Io)?)
                }
                #[cfg(not(feature = "compress-lz4"))]
                throw!(Error::UnsupportedCompression(
                    "LZ4 compression not supported".to_string()
                ))
            }
            CompressionAlgorithm::Best => {
                throw!(Error::UnsupportedCompression(
                    "Best algorithm selector should not appear while decompressing".to_string(),
                ))
            }
        }
    }
}

impl<R: BufRead> Read for Decompressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Stored(r) => r.read(buf),
            #[cfg(feature = "compress-deflate")]
            Self::Inflate(r) => r.read(buf),
            #[cfg(feature = "compress-bzip")]
            Self::Bzip(r) => r.read(buf),
            #[cfg(feature = "compress-zstd")]
            Self::Zstd(r) => r.read(buf),
            #[cfg(feature = "compress-lzma")]
            Self::Lzma(r) => r.read(buf),
            #[cfg(feature = "compress-lz4")]
            Self::Lz4(r) => r.read(buf),
        }
    }
}

/// Decompress data from reader using the compression header
///
/// Creates a streaming decompressor that can read compressed data from the given reader
/// and decompress it according to the algorithm specified in the compression header.
///
/// # Errors
/// * `Error::Deser` if the compression algorithm is not supported or not enabled via features
/// * I/O errors from the underlying reader
#[throws(Error)]
pub fn decompress_stream<R: BufRead>(reader: R, header: &CompressionHeader) -> Decompressor<R> {
    Decompressor::new(header.algorithm, reader)?
}
