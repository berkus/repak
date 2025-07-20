use {
    crate::{
        CompressionAlgorithm, Error, compress::CompressionHeader, counting_writer::CountingWriter,
    },
    culpa::{throw, throws},
    std::{
        io::{BufReader, Read, Write},
        path::Path,
    },
};

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
    reader: R,
    writer: W,
    algorithm: CompressionAlgorithm,
    original_size: u64,
) -> (CompressionHeader, W) {
    if matches!(algorithm, CompressionAlgorithm::Best) {
        throw!(Error::Deser(
            "Best algorithm cannot be used for streaming".to_string()
        ));
    }

    compress_data(reader, writer, algorithm, original_size)?
}

/// Compresses data from reader to writer using streaming compression
#[throws(Error)]
pub(crate) fn compress_data<R: Read, W: Write>(
    mut reader: R,
    writer: W,
    algorithm: CompressionAlgorithm,
    original_size: u64,
) -> (CompressionHeader, W) {
    if matches!(algorithm, CompressionAlgorithm::Best) {
        throw!(Error::UnsupportedCompression(
            "Best algorithm cannot be used with compress_data. Use pick_best_compression first."
                .to_string()
        ));
    }

    let header = CompressionHeader::new(algorithm, original_size);

    // Use streaming compression via Compressor
    let mut compressor = Compressor::new(algorithm, writer)?;
    std::io::copy(&mut reader, &mut compressor)?;
    let final_writer = compressor.finish()?;

    (header, final_writer)
}

/// Analyze a source file and return the best compression algorithm choice.
///
/// This function tests compression with each available algorithm and chooses
/// the one that would produce the smallest output. It only returns the algorithm choice,
/// not the actual compressed data, allowing the streaming pipeline to handle compression.
///
/// - For small files or already compressed formats, returns None (no compression)
/// - Only tests algorithms that are enabled via features
/// - It's acceptable to compress the file twice: once for testing, once for actual use
///
/// # Arguments
/// * `file` - Path to the original file to analyze
///
/// # Returns
/// * `CompressionAlgorithm` - The best compression algorithm choice
///
/// # Errors
///
/// * `Error::FileNotFound` if the input file doesn't exist
/// * I/O errors from file operations
#[throws(Error)]
pub fn pick_best_compression(file: &Path) -> CompressionAlgorithm {
    if !file.exists() {
        throw!(Error::FileNotFound(file.to_owned()));
    }

    let file_size = std::fs::metadata(file)?.len();

    // For small files, compression might not be worth it
    if file_size < 128 {
        return CompressionAlgorithm::None;
    }

    // Check file extension to skip known already-compressed formats
    if let Some(ext) = file.extension().and_then(|e| e.to_str()) {
        match ext.to_lowercase().as_str() {
            // Already compressed formats
            "jpg" | "jpeg" | "png" | "mp3" | "mp4" | "zip" | "gz" | "xz" | "7z" | "rar"
            | "webp" | "webm" | "aac" | "ogg" | "flac" => {
                return CompressionAlgorithm::None;
            }
            _ => {}
        }
    }

    // Try each available algorithm and find the best one
    let algorithms = [
        #[cfg(feature = "compress-deflate")]
        CompressionAlgorithm::Deflate,
        #[cfg(feature = "compress-bzip")]
        CompressionAlgorithm::Bzip,
        #[cfg(feature = "compress-zstd")]
        CompressionAlgorithm::Zstd,
        #[cfg(feature = "compress-lzma")]
        CompressionAlgorithm::Lzma,
        #[cfg(feature = "compress-lz4")]
        CompressionAlgorithm::Lz4,
    ];

    let mut best_algorithm = CompressionAlgorithm::None;
    let mut best_size = file_size;

    for algorithm in algorithms {
        let buffered_reader = BufReader::new(std::fs::File::open(file)?);
        let counting_writer = CountingWriter::new();

        if let Ok((_header, final_writer)) =
            compress_data(buffered_reader, counting_writer, algorithm, file_size)
        {
            let compressed_size = final_writer.count();
            if compressed_size < best_size {
                best_size = compressed_size;
                best_algorithm = algorithm;
            }
        }
    }

    best_algorithm
}
