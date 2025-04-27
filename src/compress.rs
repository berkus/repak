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
    size: u64,
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

impl<R: std::io::BufRead> Compressor<R> {
    pub fn store(r: R) -> Self {
        Self::Stored(r)
    }

    pub fn deflate(r: R) -> Self {
        Self::Deflate(flate2::bufread::DeflateEncoder::new(
            r,
            flate2::Compression::default(),
        ))
    }
}

impl<R: std::io::BufRead> std::io::Read for Compressor<R> {
    #[throws(std::io::Error)]
    fn read(&mut self, buf: &mut [u8]) -> usize {
        match self {
            Self::Stored(r) => r.read(buf)?,
            Self::Deflate(r) => r.read(buf)?,
            // Self::Bzip(r) => r.read(buf),
            // Self::Zstd(r) => r.read(buf),
            // Self::Lzma(r) => r.read(buf),
            // Self::Lz4(r) => r.read(buf),
            // Self::Fsst(r) => r.read(buf),
        }
    }
}

/// Take a source file, run series of compression algorithms, and return the best compressed file.
#[throws(Error)]
pub fn pick_best_compression(file: &Path) -> (CompressionAlgorithm, File) {
    if !file.exists() {
        throw!(Error::FileNotFound(file.to_owned()));
    }
    
    let file_size = file.metadata()?.len();
    let original_file = File::open(file)?;
    
    // For small files, compression might not be worth it
    if file_size < 1024 { // Less than 1KB
        return (CompressionAlgorithm::None, original_file);
    }
    
    // In a real implementation, we would try different compressions
    // and compare the results. For now, we'll use deflate for most files.
    
    // We could also use file extension to make better guesses:
    if let Some(ext) = file.extension().and_then(|e| e.to_str()) {
        match ext.to_lowercase().as_str() {
            // Already compressed formats
            "jpg" | "jpeg" | "png" | "mp3" | "mp4" | "zip" | "gz" => {
                return (CompressionAlgorithm::None, original_file);
            }
            // Text and code files compress well with deflate
            "txt" | "md" | "rs" | "js" | "html" | "css" | "xml" | "json" => {
                return (CompressionAlgorithm::Deflate, original_file);
            }
            // Binary files might benefit from different compressions
            "fbx" | "obj" | "blend" => {
                return (CompressionAlgorithm::Zstd, original_file);
            }
            _ => {}
        }
    }
    
    // Default to deflate for now
    (CompressionAlgorithm::Deflate, original_file)
}
