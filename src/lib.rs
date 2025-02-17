use {
    culpa::throws,
    std::path::{Path, PathBuf},
};

pub enum Error {}

/// Public interface
///
/// Open or create a repak archive, lookup or append files, save.
/// Encrypt, compress, checksum.
pub struct REPAK {
    index_attached: bool,
    file_path: PathBuf,
}

/// Reference to a single resource in the archive.
///
/// Allows you to validate, decrypt, decompress, extract data.
pub struct Entry {}

/// Create a new repak archive.
///
/// The index will be created in a temporary file,
#[throws]
pub fn create(output: &Path) -> REPAK {
    REPAK {
        index_attached: false,
        file_path: output.to_path_buf(),
    }
}

/// Open a repak archive.
#[throws]
pub fn open(input: &Path) -> REPAK {
    // if input exists, open it
    let index_attached = true;
    // if input exists, check for and idpak file beside it - if it exists, index_attached: false
    REPAK {
        index_attached,
        file_path: input.to_path_buf(),
    }
}

impl REPAK {
    /// Lookup a file in the archive.
    #[throws]
    pub fn lookup(id: String) -> Entry {}

    /// Append a file to the archive.
    pub fn append(id: String, file: &Path) {}

    /// Save the archive.
    #[throws]
    pub fn save() {}

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

struct EncryptionHeader {
    size: u32,
    algorithm: EncryptionAlgorithm,
}

enum EncryptionAlgorithm {
    NotImplementedYet = 0,
}

struct CompressionHeader {
    size: u32,
    algorithm: CompressionAlgorithm,
}

enum CompressionAlgorithm {
    NoCompression = 0,
    Deflate = 1,
    Gzip = 2,
    Bzip = 3,
    Zstd = 4,
    Lzma = 5,
    Lz4 = 6,
    Fsst = 7,
}

struct ChecksumHeader {
    size: u32,
    count: u16,
    checksums: Vec<Checksum>,
}

struct Checksum {
    kind: ChecksumKind,
    value: u64, // @todo
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
