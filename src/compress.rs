use {
    crate::{
        Error,
        io::{Deser, Ser, leb128_usize},
    },
    culpa::{throw, throws},
    std::{
        io::{BufRead, Read, Write},
        path::Path,
    },
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
            CompressionAlgorithm::Best => 255, // Meta-algorithm, not stored in files
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
            255 => Self::Best,
            _ => throw!(Error::Deser(format!(
                "Unknown compression algorithm: {value}"
            ))),
        }
    }
}

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
                throw!(Error::Deser(
                    "Deflate compression not supported".to_string(),
                ))
            }
            CompressionAlgorithm::Bzip => {
                #[cfg(feature = "compress-bzip")]
                {
                    Self::Bzip(bzip2::read::BzDecoder::new(reader))
                }
                #[cfg(not(feature = "compress-bzip"))]
                throw!(Error::Deser("Bzip2 compression not supported".to_string()))
            }
            CompressionAlgorithm::Zstd => {
                #[cfg(feature = "compress-zstd")]
                {
                    let decoder = zstd::Decoder::with_buffer(reader)
                        .map_err(|e| Error::Deser(e.to_string()))?;
                    Self::Zstd(decoder)
                }
                #[cfg(not(feature = "compress-zstd"))]
                throw!(Error::Deser("Zstd compression not supported".to_string()))
            }
            CompressionAlgorithm::Lzma => {
                #[cfg(feature = "compress-lzma")]
                {
                    Self::Lzma(xz2::read::XzDecoder::new(reader))
                }
                #[cfg(not(feature = "compress-lzma"))]
                throw!(Error::Deser("LZMA compression not supported".to_string()))
            }
            CompressionAlgorithm::Lz4 => {
                #[cfg(feature = "compress-lz4")]
                {
                    Self::Lz4(lz4::Decoder::new(reader).map_err(|e| Error::Deser(e.to_string()))?)
                }
                #[cfg(not(feature = "compress-lz4"))]
                throw!(Error::Deser("LZ4 compression not supported".to_string()))
            }
            CompressionAlgorithm::Best => {
                throw!(Error::Deser(
                    "Best algorithm should not appear in compressed data".to_string(),
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

/// Compress data to the given writer.
pub(crate) enum Compressor<W: Write> {
    Stored(W),
    #[cfg(feature = "compress-deflate")]
    Deflate(flate2::write::DeflateEncoder<W>),
    #[cfg(feature = "compress-bzip")]
    Bzip(bzip2::write::BzEncoder<W>),
    #[cfg(feature = "compress-zstd")]
    Zstd(zstd::Encoder<'static, W>),
    #[cfg(feature = "compress-lzma")]
    Lzma(xz2::write::XzEncoder<W>),
    #[cfg(feature = "compress-lz4")]
    Lz4(lz4::Encoder<W>),
}

impl<W: Write> Compressor<W> {
    #[throws(Error)]
    pub fn new(algorithm: CompressionAlgorithm, writer: W) -> Self {
        match algorithm {
            CompressionAlgorithm::None => Self::Stored(writer),
            CompressionAlgorithm::Deflate => {
                #[cfg(feature = "compress-deflate")]
                {
                    Self::Deflate(flate2::write::DeflateEncoder::new(
                        writer,
                        flate2::Compression::default(),
                    ))
                }
                #[cfg(not(feature = "compress-deflate"))]
                throw!(Error::Deser(
                    "Deflate compression not supported".to_string()
                ))
            }
            CompressionAlgorithm::Bzip => {
                #[cfg(feature = "compress-bzip")]
                {
                    Self::Bzip(bzip2::write::BzEncoder::new(
                        writer,
                        bzip2::Compression::default(),
                    ))
                }
                #[cfg(not(feature = "compress-bzip"))]
                throw!(Error::Deser("Bzip2 compression not supported".to_string()))
            }
            CompressionAlgorithm::Zstd => {
                #[cfg(feature = "compress-zstd")]
                {
                    let encoder =
                        zstd::Encoder::new(writer, 0).map_err(|e| Error::Deser(e.to_string()))?;
                    Self::Zstd(encoder)
                }
                #[cfg(not(feature = "compress-zstd"))]
                throw!(Error::Deser("Zstd compression not supported".to_string()))
            }
            CompressionAlgorithm::Lzma => {
                #[cfg(feature = "compress-lzma")]
                {
                    Self::Lzma(xz2::write::XzEncoder::new(writer, 6))
                }
                #[cfg(not(feature = "compress-lzma"))]
                throw!(Error::Deser("LZMA compression not supported".to_string()))
            }
            CompressionAlgorithm::Lz4 => {
                #[cfg(feature = "compress-lz4")]
                {
                    Self::Lz4(
                        lz4::EncoderBuilder::new()
                            .build(writer)
                            .map_err(|e| Error::Deser(e.to_string()))?,
                    )
                }
                #[cfg(not(feature = "compress-lz4"))]
                throw!(Error::Deser("LZ4 compression not supported".to_string()))
            }
            CompressionAlgorithm::Best => {
                throw!(Error::Deser(
                    "Best algorithm cannot be used for streaming".to_string()
                ))
            }
        }
    }

    #[throws(Error)]
    pub fn finish(self) -> W {
        match self {
            Self::Stored(w) => w,
            #[cfg(feature = "compress-deflate")]
            Self::Deflate(w) => w.finish()?,
            #[cfg(feature = "compress-bzip")]
            Self::Bzip(w) => w.finish()?,
            #[cfg(feature = "compress-zstd")]
            Self::Zstd(w) => w.finish()?,
            #[cfg(feature = "compress-lzma")]
            Self::Lzma(w) => w.finish()?,
            #[cfg(feature = "compress-lz4")]
            Self::Lz4(w) => {
                let (w, _) = w.finish();
                w
            }
        }
    }
}

impl<W: Write> Write for Compressor<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Stored(w) => w.write(buf),
            #[cfg(feature = "compress-deflate")]
            Self::Deflate(w) => w.write(buf),
            #[cfg(feature = "compress-bzip")]
            Self::Bzip(w) => w.write(buf),
            #[cfg(feature = "compress-zstd")]
            Self::Zstd(w) => w.write(buf),
            #[cfg(feature = "compress-lzma")]
            Self::Lzma(w) => w.write(buf),
            #[cfg(feature = "compress-lz4")]
            Self::Lz4(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Stored(w) => w.flush(),
            #[cfg(feature = "compress-deflate")]
            Self::Deflate(w) => w.flush(),
            #[cfg(feature = "compress-bzip")]
            Self::Bzip(w) => w.flush(),
            #[cfg(feature = "compress-zstd")]
            Self::Zstd(w) => w.flush(),
            #[cfg(feature = "compress-lzma")]
            Self::Lzma(w) => w.flush(),
            #[cfg(feature = "compress-lz4")]
            Self::Lz4(w) => w.flush(),
        }
    }
}

/// Compress data from reader to writer using streaming compression
#[throws(Error)]
pub fn compress_stream<R: Read, W: Write>(
    mut reader: R,
    writer: W,
    algorithm: CompressionAlgorithm,
) -> (CompressionHeader, W) {
    if matches!(algorithm, CompressionAlgorithm::Best) {
        throw!(Error::Deser(
            "Best algorithm cannot be used for streaming".to_string()
        ));
    }

    // Read all data to calculate original size (required for header)
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    let original_size = data.len() as u64;

    let mut compressor = Compressor::new(algorithm, writer)?;
    compressor.write_all(&data)?;
    let final_writer = compressor.finish()?;

    let header = CompressionHeader::new(algorithm, original_size);
    (header, final_writer)
}

/// Compresses data and returns compressed bytes along with compression header
#[throws(Error)]
pub(crate) fn compress_data(
    data: &[u8],
    algorithm: CompressionAlgorithm,
) -> (CompressionHeader, Vec<u8>) {
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
            if let Ok((_, compressed)) = compress_data(data, alg)
                && compressed.len() < best_size
            {
                best_size = compressed.len();
                best_algorithm = alg;
                best_data = compressed;
            }
        }

        let header = CompressionHeader::new(best_algorithm, original_size);
        return (header, best_data);
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
            throw!(Error::Deser(
                "Deflate compression not supported".to_string()
            ))
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
            throw!(Error::Deser("Bzip2 compression not supported".to_string()))
        }
        CompressionAlgorithm::Zstd => {
            #[cfg(feature = "compress-zstd")]
            {
                zstd::encode_all(data, 0)?
            }
            #[cfg(not(feature = "compress-zstd"))]
            throw!(Error::Deser("Zstd compression not supported".to_string()))
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
            throw!(Error::Deser("LZMA compression not supported".to_string()))
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
            throw!(Error::Deser("LZ4 compression not supported".to_string()))
        }
        CompressionAlgorithm::Best => {
            // This should never be reached due to the early return above
            unreachable!("Best algorithm should be handled earlier")
        }
    };

    (header, compressed)
}

/// Compress from reader to writer using the best available algorithm
#[throws(Error)]
pub fn compress_stream_best<R: Read, W: Write>(reader: R, writer: W) -> (CompressionHeader, W) {
    // For streaming best compression, we need to read all data first
    // to test different algorithms
    let mut data = Vec::new();
    let mut reader = reader;
    reader.read_to_end(&mut data)?;

    let (header, compressed_data) = compress_data(&data, CompressionAlgorithm::Best)?;

    let mut writer = writer;
    writer.write_all(&compressed_data)?;

    (header, writer)
}

/// Decompress data from reader using the compression header
#[throws(Error)]
pub fn decompress_stream<R: BufRead>(reader: R, header: &CompressionHeader) -> Decompressor<R> {
    Decompressor::new(header.algorithm, reader)?
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
#[throws(Error)]
pub fn pick_best_compression(file: &Path) -> (CompressionHeader, Vec<u8>) {
    if !file.exists() {
        throw!(Error::FileNotFound(file.to_owned()));
    }

    // Read the entire file
    let data = std::fs::read(file)?;
    let file_size = data.len();

    // For small files, compression might not be worth it
    if file_size < 1024 {
        let header = CompressionHeader::new(CompressionAlgorithm::None, file_size as u64);
        return (header, data);
    }

    // Check file extension to skip known already-compressed formats
    if let Some(ext) = file.extension().and_then(|e| e.to_str()) {
        match ext.to_lowercase().as_str() {
            // Already compressed formats
            "jpg" | "jpeg" | "png" | "mp3" | "mp4" | "zip" | "gz" | "xz" | "7z" | "rar"
            | "webp" | "webm" | "aac" | "ogg" | "flac" => {
                let header = CompressionHeader::new(CompressionAlgorithm::None, file_size as u64);
                return (header, data);
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
        if let Ok((_header, compressed)) = compress_data(&data, algorithm)
            && compressed.len() < best_size
        {
            best_size = compressed.len();
            best_algorithm = algorithm;
            best_data = compressed;
        }
    }

    let header = CompressionHeader::new(best_algorithm, file_size as u64);
    (header, best_data)
}

/// Decompress data using the given compression header
#[throws(Error)]
pub fn decompress_data(header: &CompressionHeader, compressed_data: &[u8]) -> Vec<u8> {
    match header.algorithm {
        CompressionAlgorithm::None => compressed_data.to_vec(),
        CompressionAlgorithm::Deflate => {
            #[cfg(feature = "compress-deflate")]
            {
                use {flate2::read::DeflateDecoder, std::io::Read};

                let mut decoder = DeflateDecoder::new(compressed_data);
                let mut decompressed =
                    Vec::with_capacity(usize::try_from(header.decompressed_size)?);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            #[cfg(not(feature = "compress-deflate"))]
            throw!(Error::Deser(
                "Deflate compression not supported".to_string(),
            ))
        }
        CompressionAlgorithm::Bzip => {
            #[cfg(feature = "compress-bzip")]
            {
                use {bzip2::read::BzDecoder, std::io::Read};

                let mut decoder = BzDecoder::new(compressed_data);
                let mut decompressed =
                    Vec::with_capacity(usize::try_from(header.decompressed_size)?);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            #[cfg(not(feature = "compress-bzip"))]
            throw!(Error::Deser("Bzip2 compression not supported".to_string()))
        }
        CompressionAlgorithm::Zstd => {
            #[cfg(feature = "compress-zstd")]
            {
                zstd::decode_all(compressed_data)?
            }
            #[cfg(not(feature = "compress-zstd"))]
            throw!(Error::Deser("Zstd compression not supported".to_string()))
        }
        CompressionAlgorithm::Lzma => {
            #[cfg(feature = "compress-lzma")]
            {
                use {std::io::Read, xz2::read::XzDecoder};

                let mut decoder = XzDecoder::new(compressed_data);
                let mut decompressed =
                    Vec::with_capacity(usize::try_from(header.decompressed_size)?);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            #[cfg(not(feature = "compress-lzma"))]
            throw!(Error::Deser("LZMA compression not supported".to_string()))
        }
        CompressionAlgorithm::Lz4 => {
            #[cfg(feature = "compress-lz4")]
            {
                use std::io::Read;
                let mut decoder = lz4::Decoder::new(compressed_data)?;
                let mut decompressed =
                    Vec::with_capacity(usize::try_from(header.decompressed_size)?);
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            #[cfg(not(feature = "compress-lz4"))]
            throw!(Error::Deser("LZ4 compression not supported".to_string()))
        }
        CompressionAlgorithm::Best => {
            throw!(Error::Deser(
                "Best algorithm should not appear in compressed data".to_string(),
            ))
        }
    }
}
