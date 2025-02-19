use {
    crate::io::Deser,
    culpa::throws,
    std::{
        collections::BTreeMap,
        fs,
        io::Read,
        path::{Path, PathBuf},
    },
};

mod checksum;
mod compress;
mod encrypt;
mod io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("File I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to deserialize object: {0}")]
    Deser(String),
}

/// Public interface
///
/// Open or create a repak archive, lookup or append files, save.
/// Encrypt, compress, checksum.
pub struct REPAK {
    index: BTreeMap<String, IndexEntry>,
    index_attached: bool,
    file_path: PathBuf,
}

/// Reference to a single resource in the archive.
///
/// Allows you to validate, decrypt, decompress, extract data.
pub struct Entry {
    inner: IndexEntry,
}

/// Create a new repak archive.
///
/// The index will be created in a temporary file,
#[throws]
pub fn create(output: &Path) -> REPAK {
    REPAK {
        index: BTreeMap::new(),
        index_attached: false,
        file_path: output.to_path_buf(),
    }
}

/// Open a repak archive.
#[throws]
pub fn open(input: &Path) -> REPAK {
    let (index, attached) = if fs::exists(input)? {
        // check for an idpak file beside it
        let idpak = input.with_extension("idpak");
        if fs::exists(&idpak)? {
            // if it exists, open it
            let index = fs::read(&idpak)?; // @todo wrap in BufReader
            (index, false)
        } else {
            let input = fs::open(input); // @todo wrap in BufReader
            seek(10, fromEND);
            buf = read(10);
            reverse(buf);
            let X = read_uleb64(buf);
            seek(X, fromEND);
            let index = read!();
            (index, true)
        }
    } else {
        return Err(NoFile);
    };
    REPAK {
        index,
        index_attached: attached,
        file_path: input.to_path_buf(),
    }
}

impl REPAK {
    /// Lookup a file in the archive.
    #[throws]
    pub fn lookup(&self, id: String) -> Entry {}

    /// Append a file to the archive.
    pub fn append(&mut self, id: String, file: &Path) {}

    /// Save the archive.
    #[throws]
    pub fn save(&self) {}

    // save_index()?

    // Advanced api: extract payload, skip decryption, decompression, checksum verification.
    // @todo ❌
}

struct IndexHeader {
    version: u8,
    count: u32,
    size: u64,
}

struct IndexEntry {
    offset: u64,
    size: u64,
    flags: u16,
    name: String,
    encryption: Option<EncryptionHeader>,
    compression: Option<CompressionHeader>,
    checksum: Option<ChecksumHeader>,
}

impl Deser for IndexEntry {
    fn deser(&mut r: impl Read) -> Result<Self, Error> {
        let offset = leb128::read::unsigned(r)?;
        let size = leb128::read::unsigned(r)?;
        let flags = leb128::read::unsigned(r)?;
        let name_len = leb128::read::unsigned(r)?;
        let mut data = vec![0; name_len];
        r.read_exact(&mut data);
        let name = String::from_utf8(data)?;
        let encryption = EncryptionHeader::deser(r)?;
        let compression = CompressionHeader::deser(r)?;
        let checksum = ChecksumHeader::deser(r)?;

        Ok(Self {
            offset,
            size,
            flags,
            name,
            encryption,
            compression,
            checksum,
        })
    }
}

struct EncryptionHeader {
    size: u32,
    algorithm: EncryptionAlgorithm,
}

impl Deser for EncryptionHeader {
    fn deser(&mut r: impl Read) -> Result<Self, Error> {
        let size = leb128::read::unsigned(r)?;
        let algorithm = EncryptionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        Ok(Self { size, algorithm })
    }
}

enum EncryptionAlgorithm {
    NotImplementedYet = 0,
}

impl TryFrom<u64> for EncryptionAlgorithm {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NotImplementedYet),
            _ => Err(Error::Deser(format!(
                "Unknown encryption algorithm: {}",
                value
            ))),
        }
    }
}

struct CompressionHeader {
    size: u32,
    algorithm: CompressionAlgorithm,
}

impl Deser for CompressionHeader {
    fn deser(&mut r: impl Read) -> Result<Self, Error> {
        let size = leb128::read::unsigned(r)?;
        let algorithm = CompressionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        Ok(Self { size, algorithm })
    }
}

enum CompressionAlgorithm {
    NoCompression = 0,
    Deflate = 1,
    Bzip = 2,
    Zstd = 3,
    Lzma = 4,
    Lz4 = 5,
    Fsst = 6,
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

struct ChecksumHeader {
    size: u32,
    count: u16,
    checksums: Vec<Checksum>,
}

impl Deser for ChecksumHeader {
    fn deser(&mut r: impl Read) -> Result<Self, Error> {
        let size = leb128::read::unsigned(r)?;
        let count = leb128::read::unsigned(r)?;
        let mut checksums = Vec::with_capacity(count as usize);
        for _ in 0..count {
            checksums.push(Checksum::deser(r)?);
        }
        Ok(Self {
            size,
            count,
            checksums,
        })
    }
}

struct Checksum {
    kind: ChecksumKind,
    value: u64, // @todo
}

impl Deser for Checksum {
    fn deser(&mut r: impl Read) -> Result<Self, Error> {
        let kind = leb128::read::unsigned(r)?;
        let value = leb128::read::unsigned(r)?;
        Ok(Self { kind, value })
    }
}

enum ChecksumKind {
    SHA3 = 1,
    K12 = 2,
    BLAKE3 = 3,
    Xxhash3 = 4,
    Metrohash = 5,
    SeaHash = 6,
    CityHash = 7,
}

impl TryFrom<u64> for ChecksumKind {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SHA3),
            2 => Ok(Self::K12),
            3 => Ok(Self::BLAKE3),
            4 => Ok(Self::Xxhash3),
            5 => Ok(Self::Metrohash),
            6 => Ok(Self::SeaHash),
            7 => Ok(Self::CityHash),
            _ => Err(Error::Deser(format!("Unknown checksum kind: {}", value))),
        }
    }
}
