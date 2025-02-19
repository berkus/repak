use {
    crate::{checksum::*, compress::*, encrypt::*, io::Deser},
    byteorder::*,
    culpa::{throw, throws},
    io::Ser,
    std::{
        collections::BTreeMap,
        fs::{self, File},
        io::{BufReader, Cursor, Read, Seek, SeekFrom, Write},
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
    #[error("LEB128 error: {0}")]
    Leb128(#[from] leb128::read::Error),
    #[error("Offset is too large: {0}")]
    OffsetTooLarge(#[from] std::num::TryFromIntError),
    #[error("Name is not a valid UTF-8 string: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    #[error("File {0} not found.")]
    FileNotFound(PathBuf),
    #[error("Failed to deserialize object: {0}")]
    Deser(String),
}

/// Public interface
///
/// Open or create a repak archive, lookup or append files, save.
/// Encrypt, compress, checksum.
pub struct REPAK {
    index: IndexHeader,
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
        index: IndexHeader::default(),
        index_attached: false,
        file_path: output.to_path_buf(),
    }
}

/// Open a repak archive.
#[throws]
pub fn open(input: &Path) -> REPAK {
    if !fs::exists(input)? {
        throw!(Error::FileNotFound(input.to_path_buf()));
    }
    // check for an idpak file beside it
    let idpak = input.with_extension("idpak");
    let (index, attached) = if fs::exists(&idpak)? {
        let mut input = BufReader::new(File::open(idpak)?);
        let index = IndexHeader::deser(&mut input)?; // @todo compressed index
        (index, false)
    } else {
        let mut input = BufReader::new(File::open(input)?);
        input.seek(SeekFrom::End(-10))?;
        let mut buf = [0u8; 10];
        input.read_exact(&mut buf)?;
        buf.reverse();
        let mut cursor = Cursor::new(&buf);
        let offset = i64::try_from(leb128::read::unsigned(&mut cursor)?)?;
        input.seek(SeekFrom::End(-offset))?;
        let index = IndexHeader::deser(&mut input)?; // @todo compressed index
        (index, true)
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
    pub fn lookup(&self, _id: String) -> Entry {
        Entry {
            inner: IndexEntry::default(), //@todo remove Default impl from IndexEntry
        }
    }

    /// Append a file to the archive.
    pub fn append(&mut self, _id: String, _file: &Path) {}

    /// Save the archive.
    #[throws]
    pub fn save(&self) {}

    // save_index()?

    // Advanced api: extract payload, skip decryption, decompression, checksum verification.
    // @todo ❌
}

#[derive(Default)]
struct IndexHeader {
    count: u64,
    size: u64,
    entries: BTreeMap<String, IndexEntry>, // not part of IndexHeader really, but we can construct it here and move?
    checksum: ChecksumHeader,
}

impl Ser for IndexHeader {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        w.write_all(b"REPAK")?;
        w.write_u8(0x1)?; // Version 1
        w.write_u16::<LittleEndian>(0u16)?;
        leb128::write::unsigned(w, self.count)?;
        leb128::write::unsigned(w, self.size)?;
        Ok(())
    }
}

impl Deser for IndexHeader {
    fn deser(r: &mut impl Read) -> Result<Self, Error> {
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf)?;
        if &buf != b"REPAK" {
            return Err(Error::Deser("Not a REPAK archive".to_string()));
        }
        let version = r.read_u8()?;
        if version != 1 {
            return Err(Error::Deser(format!(
                "Unsupported REPAK version 0x{:2x}",
                version
            )));
        }
        let reserved = r.read_u16::<LittleEndian>()?;
        if reserved != 0 {
            return Err(Error::Deser("Reserved field is not zero".to_string()));
        }
        let count = leb128::read::unsigned(r)?;
        let size = leb128::read::unsigned(r)?;

        let mut entries = BTreeMap::new();
        for _ in 0..count {
            let entry = IndexEntry::deser(r)?;
            entries.insert(entry.name.clone(), entry);
        }
        // @todo checksumming

        Ok(IndexHeader {
            count,
            size,
            entries,
            checksum: ChecksumHeader::default(),
        })
    }
}

#[derive(Default)] // temp?
struct IndexEntry {
    offset: u64,
    size: u64,
    name: String,
    encryption: Option<EncryptionHeader>,
    compression: Option<CompressionHeader>,
    checksum: Option<ChecksumHeader>,
}

impl Ser for IndexEntry {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        let flags = if self.encryption.is_some() { 0x1 } else { 0 }
            | if self.compression.is_some() { 0x2 } else { 0 }
            | if self.checksum.is_some() { 0x4 } else { 0 };

        leb128::write::unsigned(w, self.offset)?;
        leb128::write::unsigned(w, self.size)?;
        leb128::write::unsigned(w, flags)?;
        leb128::write::unsigned(w, self.name.as_bytes().len() as u64)?;
        w.write_all(&self.name.as_bytes())?;
        if let Some(encryption) = &self.encryption {
            encryption.ser(w)?
        }
        if let Some(compression) = &self.compression {
            compression.ser(w)?;
        }
        if let Some(checksum) = &self.checksum {
            checksum.ser(w)?;
        }
        Ok(())
    }
}

impl Deser for IndexEntry {
    fn deser(r: &mut impl Read) -> Result<Self, Error> {
        let offset = leb128::read::unsigned(r)?;
        let size = leb128::read::unsigned(r)?;
        let flags = leb128::read::unsigned(r)?;
        let name_len = leb128::read::unsigned(r)?;
        let mut data = vec![0; name_len as usize];
        r.read_exact(&mut data)?;
        let name = String::from_utf8(data)?;
        let encryption = if flags & 0x0001 != 0 {
            Some(EncryptionHeader::deser(r)?)
        } else {
            None
        };
        let compression = if flags & 0x0002 != 0 {
            Some(CompressionHeader::deser(r)?)
        } else {
            None
        };
        let checksum = if flags & 0x0004 != 0 {
            Some(ChecksumHeader::deser(r)?)
        } else {
            None
        };

        Ok(Self {
            offset,
            size,
            name,
            encryption,
            compression,
            checksum,
        })
    }
}
