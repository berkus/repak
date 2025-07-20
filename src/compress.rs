use {
    crate::{
        Error,
        io::{Deser, Ser, leb128_usize},
    },
    culpa::{throw, throws},
    std::{
        io::{BufRead, BufReader, Cursor, Read, Write},
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
        throw!(Error::Deser(
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

/// Compress from reader to writer using the best available algorithm
#[throws(Error)]
pub fn compress_stream_best<R: Read, W: Write>(reader: R, writer: W) -> (CompressionHeader, W) {
    // For streaming best compression, we need to read all data first
    // to determine the best algorithm
    let mut data = Vec::new();
    let mut reader = reader;
    reader.read_to_end(&mut data)?;

    // Find the best algorithm by testing compression
    let best_algorithm = {
        let algorithms = [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Deflate,
            CompressionAlgorithm::Bzip,
            CompressionAlgorithm::Zstd,
            CompressionAlgorithm::Lzma,
            CompressionAlgorithm::Lz4,
        ];

        let mut best_algorithm = CompressionAlgorithm::None;
        let mut best_size = data.len() as u64;

        for algorithm in algorithms {
            // Test compression with counting writer to avoid storing compressed data
            let data_cursor = Cursor::new(&data);
            let counting_writer = CountingWriter::new();

            if let Ok((_header, final_writer)) =
                compress_data(data_cursor, counting_writer, algorithm, data.len() as u64)
            {
                let compressed_size = final_writer.count();
                if compressed_size < best_size {
                    best_size = compressed_size;
                    best_algorithm = algorithm;
                }
            }
        }
        best_algorithm
    };

    // Now compress with the chosen algorithm using streaming
    let cursor = Cursor::new(&data);
    compress_stream(cursor, writer, best_algorithm, data.len() as u64)?
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

    // Get file size without reading the entire file into memory
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
        CompressionAlgorithm::None,
        CompressionAlgorithm::Deflate,
        CompressionAlgorithm::Bzip,
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Lzma,
        CompressionAlgorithm::Lz4,
    ];

    let mut best_algorithm = CompressionAlgorithm::None;
    let mut best_size = file_size;

    for algorithm in algorithms {
        // Try to compress with this algorithm using streaming compression
        let file_reader = std::fs::File::open(file)?;
        let buffered_reader = BufReader::new(file_reader);
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

/// A writer that counts bytes written without storing them
struct CountingWriter {
    count: u64,
}

impl CountingWriter {
    fn new() -> Self {
        Self { count: 0 }
    }

    fn count(&self) -> u64 {
        self.count
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.count += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
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
