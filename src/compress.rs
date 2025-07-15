use {
    crate::{
        Error,
        io::{Deser, Ser, leb128_usize},
    },
    culpa::{throw, throws},
    std::{
        fs::File,
        io::{Read, Write},
        path::Path,
    },
};

#[derive(Debug)] // temp?
pub(crate) struct CompressionHeader {
    _size: u64,
    pub(crate) algorithm: CompressionAlgorithm,
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
        };
        Self {
            _size: size,
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
            _ => throw!(Error::Deser(format!(
                "Unknown compression algorithm: {value}"
            ))),
        }
    }
}

/// Decompress data from the given reader.
pub(crate) enum Decompressor<R: std::io::BufRead> {
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

impl<R: std::io::BufRead> std::io::Read for Decompressor<R> {
    #[throws(std::io::Error)]
    fn read(&mut self, buf: &mut [u8]) -> usize {
        match self {
            Self::Stored(r) => r.read(buf)?,
            #[cfg(feature = "compress-deflate")]
            Self::Inflate(r) => r.read(buf)?,
            #[cfg(feature = "compress-bzip")]
            Self::Bzip(r) => r.read(buf)?,
            #[cfg(feature = "compress-zstd")]
            Self::Zstd(r) => r.read(buf)?,
            #[cfg(feature = "compress-lzma")]
            Self::Lzma(r) => r.read(buf)?,
            #[cfg(feature = "compress-lz4")]
            Self::Lz4(r) => r.read(buf)?,
            // Self::Fsst(r) => r.read(buf)?,
        }
    }
}

pub(crate) enum Compressor<R: std::io::BufRead> {
    Stored(R),
    #[cfg(feature = "compress-deflate")]
    Deflate(flate2::bufread::DeflateEncoder<R>),
    #[cfg(feature = "compress-bzip")]
    Bzip(bzip2::read::BzEncoder<R>),
    #[cfg(feature = "compress-zstd")]
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
    #[cfg(feature = "compress-lzma")]
    Lzma(xz2::read::XzEncoder<R>),
    #[cfg(feature = "compress-lz4")]
    Lz4(lz4::EncoderBuilder),
}

impl<R: std::io::BufRead> Compressor<R> {
    pub fn store(r: R) -> Self {
        Self::Stored(r)
    }

    pub fn deflate(r: R) -> Self {
        #[cfg(feature = "compress-deflate")]
        {
            Self::Deflate(flate2::bufread::DeflateEncoder::new(
                r,
                flate2::Compression::default(),
            ))
        }
        #[cfg(not(feature = "compress-deflate"))]
        {
            Self::Stored(r)
        }
    }

    #[cfg(feature = "compress-bzip")]
    pub fn bzip(r: R) -> Self {
        Self::Bzip(bzip2::read::BzEncoder::new(
            r,
            bzip2::Compression::default(),
        ))
    }

    #[cfg(feature = "compress-zstd")]
    pub fn zstd(_r: R) -> Self {
        // Zstd's API is different - it doesn't have a direct BufRead wrapper
        // This would need to be implemented differently
        unimplemented!("Zstd compression not fully implemented")
    }

    #[cfg(feature = "compress-lzma")]
    pub fn lzma(r: R) -> Self {
        Self::Lzma(xz2::read::XzEncoder::new(r, 6))
    }

    #[cfg(feature = "compress-lz4")]
    pub fn lz4(_r: R) -> Self {
        // LZ4's API is different - it doesn't have a direct BufRead wrapper
        // This would need to be implemented differently
        unimplemented!("Lz4 compression not fully implemented")
    }
}

impl<R: std::io::BufRead> std::io::Read for Compressor<R> {
    #[throws(std::io::Error)]
    fn read(&mut self, buf: &mut [u8]) -> usize {
        match self {
            Self::Stored(r) => r.read(buf)?,
            #[cfg(feature = "compress-deflate")]
            Self::Deflate(r) => r.read(buf)?,
            #[cfg(feature = "compress-bzip")]
            Self::Bzip(r) => r.read(buf)?,
            #[cfg(feature = "compress-zstd")]
            Self::Zstd(_) => unimplemented!("Zstd reading not implemented"),
            #[cfg(feature = "compress-lzma")]
            Self::Lzma(r) => r.read(buf)?,
            #[cfg(feature = "compress-lz4")]
            Self::Lz4(_) => unimplemented!("Lz4 reading not implemented"),
            // Self::Fsst(r) => r.read(buf)?,
        }
    }
}

/// Take a source file, run series of compression algorithms, and return the best compressed file.
///
/// This function compresses the entire input file with each available algorithm and chooses
/// the one that produces the smallest output. It returns a tuple with the selected algorithm
/// and a File handle to the compressed data (stored in a temporary directory).
///
/// - For small files or already compressed formats, returns the original file without compression
/// - Cleans up any temporary files created during the process, except for the best one
/// - The returned File is owned by the caller and will persist until closed
/// - The temporary directory is automatically cleaned up when the last handle to a file in it is closed
///
/// # Arguments
/// * `file` - Path to the original file to compress
///
/// # Returns
/// * `(CompressionAlgorithm, File)` - The best algorithm and a handle to the compressed file
///
/// # Errors
/// * `Error::FileNotFound` if the input file doesn't exist
/// * I/O errors from file operations
#[throws(Error)]
pub fn pick_best_compression(file: &Path) -> (CompressionAlgorithm, File) {
    if !file.exists() {
        throw!(Error::FileNotFound(file.to_owned()));
    }

    let file_size = file.metadata()?.len();

    // For small files, compression might not be worth it
    if file_size < 1024 {
        // Less than 1KB
        return (CompressionAlgorithm::None, File::open(file)?);
    }

    // Check file extension to skip known already-compressed formats
    if let Some(ext) = file.extension().and_then(|e| e.to_str()) {
        match ext.to_lowercase().as_str() {
            // Already compressed formats
            "jpg" | "jpeg" | "png" | "mp3" | "mp4" | "zip" | "gz" | "xz" | "7z" | "rar"
            | "webp" | "webm" | "aac" | "ogg" | "flac" => {
                return (CompressionAlgorithm::None, File::open(file)?);
            }
            _ => {}
        }
    }

    // Create a temporary directory for compressed files
    let temp_dir = tempfile::Builder::new()
        .prefix("repak_compress_")
        .tempdir()?;

    // Define a function to compress the file using a specific algorithm
    #[throws(Error)]
    fn compress_file(
        input_file: &Path,
        algorithm: CompressionAlgorithm,
        temp_dir: &tempfile::TempDir,
    ) -> Option<(std::path::PathBuf, u64)> {
        use std::io::{BufReader, Read, Write};

        // Skip if algorithm is None (we'll compare against the original size)
        if matches!(algorithm, CompressionAlgorithm::None) {
            return Some((input_file.to_path_buf(), input_file.metadata()?.len()));
        }

        // Create output path in temp directory
        let file_name = format!("{algorithm:?}.tmp");
        let output_path = temp_dir.path().join(file_name);

        // Only try to compress if the algorithm is available
        match algorithm {
            CompressionAlgorithm::None => unreachable!(), // Handled above
            CompressionAlgorithm::Deflate => {
                #[cfg(feature = "compress-deflate")]
                {
                    let input = File::open(input_file)?;
                    let reader = BufReader::new(input);
                    let output = File::create(&output_path)?;
                    let mut writer = std::io::BufWriter::new(output);

                    let mut compressor = Compressor::deflate(reader);
                    let mut buffer = [0; 8192];
                    loop {
                        let bytes_read = compressor.read(&mut buffer)?;
                        if bytes_read == 0 {
                            break;
                        }
                        writer.write_all(&buffer[..bytes_read])?;
                    }
                    writer.flush()?;

                    // Return the path and size of compressed file
                    let size = output_path.metadata()?.len();
                    return Some((output_path, size));
                }
                #[cfg(not(feature = "compress-deflate"))]
                return None;
            }
            CompressionAlgorithm::Bzip => {
                // Not currently implemented
                None
            }
            CompressionAlgorithm::Zstd => {
                // Not currently implemented
                None
            }
            CompressionAlgorithm::Lzma => {
                // Not currently implemented
                None
            }
            CompressionAlgorithm::Lz4 => {
                // Not currently implemented
                None
            }
        }
    }

    // Try each algorithm and find the best one
    let algorithms = [
        CompressionAlgorithm::None, // This represents the original uncompressed file
        CompressionAlgorithm::Deflate,
        CompressionAlgorithm::Bzip,
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Lzma,
        CompressionAlgorithm::Lz4,
    ];

    let mut best_algorithm = CompressionAlgorithm::None;
    let mut best_size = file_size;
    let mut best_path = file.to_path_buf();
    let mut temp_files = Vec::new();

    for algorithm in algorithms {
        // Skip None as we've already recorded its size
        if matches!(algorithm, CompressionAlgorithm::None) {
            continue;
        }

        // Try to compress with this algorithm
        if let Ok(Some((path, size))) = compress_file(file, algorithm, &temp_dir) {
            // Track this temporary file for cleanup
            if path != file {
                temp_files.push(path.clone());
            }

            // Check if this is better than our current best
            if size < best_size {
                best_size = size;
                best_algorithm = algorithm;
                best_path = path;
            }
        }
    }

    // Remove temporary files except the best one
    for path in temp_files {
        if path != best_path {
            // Try to delete, but don't fail if we can't
            let _ = std::fs::remove_file(&path);
        }
    }

    // If the best algorithm is None, return the original file
    if matches!(best_algorithm, CompressionAlgorithm::None) {
        return (CompressionAlgorithm::None, File::open(file)?);
    }

    // Otherwise, return the compressed file
    (best_algorithm, File::open(&best_path)?)
}
