use {
    crate::{
        Error,
        io::{Deser, Ser, leb128_usize},
    },
    culpa,
    std::{
        io::{BufRead, Read, Write},
        path::Path,
    },
};

#[derive(Debug)]
pub(crate) struct CompressionHeader {
    pub(crate) algorithm: CompressionAlgorithm,
    pub(crate) decompressed_size: u64,
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
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        // Calculate total size: algorithm_id + decompressed_size
        let algorithm_id_size = leb128_usize(self.algorithm.into())?;
        let decompressed_size_size = leb128_usize(self.decompressed_size)?;
        let total_size = algorithm_id_size + decompressed_size_size;

        // Write total size, algorithm ID, then decompressed size
        leb128::write::unsigned(w, total_size as u64)?;
        leb128::write::unsigned(w, self.algorithm.into())?;
        leb128::write::unsigned(w, self.decompressed_size)?;
        Ok(())
    }
}

impl Deser for CompressionHeader {
    fn deser(r: &mut impl Read) -> Result<Self, Error> {
        let _total_size = leb128::read::unsigned(r)?;
        let algorithm = CompressionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        let decompressed_size = leb128::read::unsigned(r)?;

        Ok(Self {
            algorithm,
            decompressed_size,
        })
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
            CompressionAlgorithm::Best => 255, // Meta-algorithm, not stored in files
        }
    }
}

impl TryFrom<u64> for CompressionAlgorithm {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Deflate),
            2 => Ok(Self::Bzip),
            3 => Ok(Self::Zstd),
            4 => Ok(Self::Lzma),
            5 => Ok(Self::Lz4),
            255 => Ok(Self::Best),
            _ => Err(Error::Deser(format!(
                "Unknown compression algorithm: {value}"
            ))),
        }
    }
}

/// Decompress data from the given reader.
pub(crate) enum Decompressor<R: BufRead> {
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
    pub fn new(algorithm: CompressionAlgorithm, reader: R) -> Result<Self, Error> {
        Ok(match algorithm {
            CompressionAlgorithm::None => Self::Stored(reader),
            CompressionAlgorithm::Deflate => {
                #[cfg(feature = "compress-deflate")]
                {
                    Self::Inflate(flate2::bufread::DeflateDecoder::new(reader))
                }
                #[cfg(not(feature = "compress-deflate"))]
                return Err(Error::Deser(
                    "Deflate compression not supported".to_string(),
                ));
            }
            CompressionAlgorithm::Bzip => {
                #[cfg(feature = "compress-bzip")]
                {
                    Self::Bzip(bzip2::read::BzDecoder::new(reader))
                }
                #[cfg(not(feature = "compress-bzip"))]
                return Err(Error::Deser("Bzip2 compression not supported".to_string()));
            }
            CompressionAlgorithm::Zstd => {
                #[cfg(feature = "compress-zstd")]
                {
                    let decoder = zstd::Decoder::with_buffer(reader)
                        .map_err(|e| Error::Deser(e.to_string()))?;
                    Self::Zstd(decoder)
                }
                #[cfg(not(feature = "compress-zstd"))]
                return Err(Error::Deser("Zstd compression not supported".to_string()));
            }
            CompressionAlgorithm::Lzma => {
                #[cfg(feature = "compress-lzma")]
                {
                    Self::Lzma(xz2::read::XzDecoder::new(reader))
                }
                #[cfg(not(feature = "compress-lzma"))]
                return Err(Error::Deser("LZMA compression not supported".to_string()));
            }
            CompressionAlgorithm::Lz4 => {
                #[cfg(feature = "compress-lz4")]
                {
                    Self::Lz4(lz4::Decoder::new(reader).map_err(|e| Error::Deser(e.to_string()))?)
                }
                #[cfg(not(feature = "compress-lz4"))]
                return Err(Error::Deser("LZ4 compression not supported".to_string()));
            }
            CompressionAlgorithm::Best => {
                return Err(Error::Deser(
                    "Best algorithm should not appear in compressed data".to_string(),
                ));
            }
        })
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

/// Compresses data and returns compressed bytes along with compression header
pub(crate) fn compress_data(
    data: &[u8],
    algorithm: CompressionAlgorithm,
) -> Result<(CompressionHeader, Vec<u8>), Error> {
    let original_size = data.len() as u64;

    // Handle Best algorithm by trying all algorithms and picking the smallest
    if matches!(algorithm, CompressionAlgorithm::Best) {
        let algorithms = [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Deflate,
            CompressionAlgorithm::Bzip,
            CompressionAlgorithm::Zstd,
            CompressionAlgorithm::Lzma,
            CompressionAlgorithm::Lz4,
        ];

        let mut best_algorithm = CompressionAlgorithm::None;
        let mut best_size = data.len();
        let mut best_data = data.to_vec();

        for alg in algorithms {
            if let Ok((_, compressed)) = compress_data(data, alg) {
                if compressed.len() < best_size {
                    best_size = compressed.len();
                    best_algorithm = alg;
                    best_data = compressed;
                }
            }
        }

        let header = CompressionHeader::new(best_algorithm, original_size);
        return Ok((header, best_data));
    }

    let header = CompressionHeader::new(algorithm, original_size);

    let compressed = match algorithm {
        CompressionAlgorithm::None => data.to_vec(),
        CompressionAlgorithm::Deflate => {
            #[cfg(feature = "compress-deflate")]
            {
                use {
                    flate2::{Compression, write::DeflateEncoder},
                    std::io::Write,
                };

                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                encoder.finish()?
            }
            #[cfg(not(feature = "compress-deflate"))]
            return Err(Error::Ser("Deflate compression not supported".to_string()));
        }
        CompressionAlgorithm::Bzip => {
            #[cfg(feature = "compress-bzip")]
            {
                use {
                    bzip2::{Compression, write::BzEncoder},
                    std::io::Write,
                };

                let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(data)?;
                encoder.finish()?
            }
            #[cfg(not(feature = "compress-bzip"))]
            return Err(Error::Ser("Bzip2 compression not supported".to_string()));
        }
        CompressionAlgorithm::Zstd => {
            #[cfg(feature = "compress-zstd")]
            {
                zstd::encode_all(data.as_ref(), 0)?
            }
            #[cfg(not(feature = "compress-zstd"))]
            return Err(Error::Ser("Zstd compression not supported".to_string()));
        }
        CompressionAlgorithm::Lzma => {
            #[cfg(feature = "compress-lzma")]
            {
                use {std::io::Write, xz2::write::XzEncoder};

                let mut encoder = XzEncoder::new(Vec::new(), 6);
                encoder.write_all(data)?;
                encoder.finish()?
            }
            #[cfg(not(feature = "compress-lzma"))]
            return Err(Error::Ser("LZMA compression not supported".to_string()));
        }
        CompressionAlgorithm::Lz4 => {
            #[cfg(feature = "compress-lz4")]
            {
                use std::io::Write;
                let mut encoder = lz4::EncoderBuilder::new().build(Vec::new())?;
                encoder.write_all(data)?;
                let (compressed, _) = encoder.finish();
                compressed
            }
            #[cfg(not(feature = "compress-lz4"))]
            return Err(Error::Ser("LZ4 compression not supported".to_string()));
        }
        CompressionAlgorithm::Best => {
            // This should never be reached due to the early return above
            unreachable!("Best algorithm should be handled earlier")
        }
    };

    Ok((header, compressed))
}

/// Take a source file, run series of compression algorithms, and return the best compressed result.
///
/// This function compresses the entire input file with each available algorithm and chooses
/// the one that produces the smallest output. It returns a tuple with the compression header
/// and the compressed data.
///
/// - For small files or already compressed formats, returns the original file without compression
/// - Only tests algorithms that are enabled via features
///
/// # Arguments
/// * `file` - Path to the original file to compress
///
/// # Returns
/// * `(CompressionHeader, Vec<u8>)` - The best compression header and compressed data
///
/// # Errors
/// * `Error::FileNotFound` if the input file doesn't exist
/// * I/O errors from file operations
pub fn pick_best_compression(file: &Path) -> Result<(CompressionHeader, Vec<u8>), Error> {
    if !file.exists() {
        return Err(Error::FileNotFound(file.to_owned()));
    }

    // Read the entire file
    let data = std::fs::read(file)?;
    let file_size = data.len();

    // For small files, compression might not be worth it
    if file_size < 1024 {
        let header = CompressionHeader::new(CompressionAlgorithm::None, file_size as u64);
        return Ok((header, data));
    }

    // Check file extension to skip known already-compressed formats
    if let Some(ext) = file.extension().and_then(|e| e.to_str()) {
        match ext.to_lowercase().as_str() {
            // Already compressed formats
            "jpg" | "jpeg" | "png" | "mp3" | "mp4" | "zip" | "gz" | "xz" | "7z" | "rar"
            | "webp" | "webm" | "aac" | "ogg" | "flac" => {
                let header = CompressionHeader::new(CompressionAlgorithm::None, file_size as u64);
                return Ok((header, data));
            }
            _ => {}
        }
    }

    // Try each available algorithm and find the best one
    let algorithms = [
        CompressionAlgorithm::None,
        CompressionAlgorithm::Deflate,
        CompressionAlgorithm::Bzip,
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Lzma,
        CompressionAlgorithm::Lz4,
    ];

    let mut best_algorithm = CompressionAlgorithm::None;
    let mut best_size = file_size;
    let mut best_data = data.clone();

    for algorithm in algorithms {
        // Try to compress with this algorithm
        match compress_data(&data, algorithm) {
            Ok((_header, compressed)) => {
                if compressed.len() < best_size {
                    best_size = compressed.len();
                    best_algorithm = algorithm;
                    best_data = compressed;
                }
            }
            Err(_) => {
                // Algorithm not supported or failed, skip
                continue;
            }
        }
    }

    let header = CompressionHeader::new(best_algorithm, file_size as u64);
    Ok((header, best_data))
}

/// Decompress data using the given compression header
pub fn decompress_data(
    header: &CompressionHeader,
    compressed_data: &[u8],
) -> Result<Vec<u8>, Error> {
    Ok(match header.algorithm {
        CompressionAlgorithm::None => compressed_data.to_vec(),
        CompressionAlgorithm::Deflate => {
            #[cfg(feature = "compress-deflate")]
            {
                use {flate2::read::DeflateDecoder, std::io::Read};

                let mut decoder = DeflateDecoder::new(compressed_data);
                let mut decompressed = Vec::with_capacity(header.decompressed_size as usize);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            #[cfg(not(feature = "compress-deflate"))]
            return Err(Error::Deser(
                "Deflate compression not supported".to_string(),
            ));
        }
        CompressionAlgorithm::Bzip => {
            #[cfg(feature = "compress-bzip")]
            {
                use {bzip2::read::BzDecoder, std::io::Read};

                let mut decoder = BzDecoder::new(compressed_data);
                let mut decompressed = Vec::with_capacity(header.decompressed_size as usize);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            #[cfg(not(feature = "compress-bzip"))]
            return Err(Error::Deser("Bzip2 compression not supported".to_string()));
        }
        CompressionAlgorithm::Zstd => {
            #[cfg(feature = "compress-zstd")]
            {
                zstd::decode_all(compressed_data)?
            }
            #[cfg(not(feature = "compress-zstd"))]
            return Err(Error::Deser("Zstd compression not supported".to_string()));
        }
        CompressionAlgorithm::Lzma => {
            #[cfg(feature = "compress-lzma")]
            {
                use {std::io::Read, xz2::read::XzDecoder};

                let mut decoder = XzDecoder::new(compressed_data);
                let mut decompressed = Vec::with_capacity(header.decompressed_size as usize);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            #[cfg(not(feature = "compress-lzma"))]
            return Err(Error::Deser("LZMA compression not supported".to_string()));
        }
        CompressionAlgorithm::Lz4 => {
            #[cfg(feature = "compress-lz4")]
            {
                use std::io::Read;
                let mut decoder = lz4::Decoder::new(compressed_data)?;
                let mut decompressed = Vec::with_capacity(header.decompressed_size as usize);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            #[cfg(not(feature = "compress-lz4"))]
            return Err(Error::Deser("LZ4 compression not supported".to_string()));
        }
        CompressionAlgorithm::Best => {
            return Err(Error::Deser(
                "Best algorithm should not appear in compressed data".to_string(),
            ));
        }
    })
}
