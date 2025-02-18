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

pub enum Error {}

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
pub struct Entry {}

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
    }
}

enum EncryptionAlgorithm {
    NotImplementedYet = 0,
}

struct CompressionHeader {
    size: u32,
    algorithm: CompressionAlgorithm,
}

impl Deser for CompressionHeader {
    fn deser(&mut r: impl Read) -> Result<Self, Error> {
        let size = leb128::read::unsigned(r)?;
    }
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
