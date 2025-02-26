#![feature(default_field_values)]
#![allow(dead_code)]
#![allow(unused_imports)]

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

pub use {checksum::ChecksumKind, compress::CompressionAlgorithm, encrypt::EncryptionAlgorithm};

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
    #[error("Asset {0} already exists in the archive")]
    AlreadyExists(String),
}

/// Public interface
///
/// Open or create a repak archive, lookup or append files, save.
/// Encrypt, compress, checksum.
pub struct REPAK {
    index: IndexHeader,
    index_attached: bool,
    file_path: PathBuf,
    last_insertion_offset: u64,
}

/// Reference to a single resource in the archive.
///
/// Allows you to validate, decrypt, decompress, extract data.
pub struct Entry<'a> {
    inner: &'a IndexEntry,
    source: Source,
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
        last_insertion_offset: 0,
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
    let (index, attached, insert_pos) = if fs::exists(&idpak)? {
        let mut input = BufReader::new(File::open(idpak)?);
        let index = IndexHeader::deser(&mut input)?; // @todo compressed index
        (index, false, 0u64)
    } else {
        let mut input = BufReader::new(File::open(input)?);
        input.seek(SeekFrom::End(-10))?;
        let mut buf = [0u8; 10];
        input.read_exact(&mut buf)?;
        buf.reverse();
        let mut cursor = Cursor::new(&buf);
        let offset = i64::try_from(leb128::read::unsigned(&mut cursor)?)?;
        input.seek(SeekFrom::End(-offset))?;
        let insert_pos = input.stream_position()?;
        let index = IndexHeader::deser(&mut input)?; // @todo compressed index
        (index, true, insert_pos)
    };
    REPAK {
        index,
        index_attached: attached,
        file_path: input.to_path_buf(),
        last_insertion_offset: insert_pos,
    }
}

// Source of the asset data
enum Source {
    File(PathBuf),
    Memory(Vec<u8>),
}

#[derive(Default, Debug)]
pub struct AppendOptions {
    pub checksum: Option<ChecksumKind> = None,
    pub compression: Option<CompressionAlgorithm> = None,
    pub encryption: Option<EncryptionAlgorithm> = None,
}

impl REPAK {
    /// Lookup a file in the archive.
    ///
    /// Returns a reference to the file entry.
    #[throws]
    pub fn lookup<'a>(&'a self, id: String) -> Option<Entry<'a>> {
        self.index.entries.get(&id).map(|inner| Entry {
            inner,
            source: Source::Memory(vec![]),
        })
    }

    /// Append a file to the archive.
    ///
    /// Append options specify how to transform the file when adding.
    /// It is posible to request checksumming, compression, and encryption
    /// (in this order).
    #[throws]
    pub fn append(&mut self, id: String, file: &Path, _options: AppendOptions) {
        if self.index.entries.contains_key(&id) {
            throw!(Error::AlreadyExists(id));
        }
        let entry = IndexEntry {
            offset: self.last_insertion_offset,
            size: file.metadata()?.len(),
            name: id.clone(),
            encryption: None,  //options.encryption,
            compression: None, //options.compression,
            checksum: None,    //options.checksum,
        };
        // @todo copy file data to archive
        self.last_insertion_offset += entry.size;
        self.index.entries.insert(id, entry);
    }

    /// Save the archive.
    #[throws]
    pub fn save(&self) {
        // this func needs to save the payloads from source files, if any
        // and then save the index
        self.save_index()?;
    }

    /// Index is ordered by Name, so it makes easier to look up via binary search even
    /// if you do not apply any sorted containers and just read all entries into a Vec.
    #[throws]
    fn save_index(&self) {
        let idxfile = self.file_path.with_extension("idpak");
        let mut idxfile = File::create_new(idxfile)?;

        for x in self.index.entries.values() {
            println!("Entry: {:?}", x);
            x.ser(&mut idxfile)?;
        }
    }

    // Advanced api: extract payload, skip decryption, decompression, checksum verification.
    // @todo ❌
}

#[derive(Default)]
struct IndexHeader {
    count: u64,
    entries: BTreeMap<String, IndexEntry>, // not part of IndexHeader really, but we can construct it here and move?
    checksum: ChecksumHeader,
}

impl Ser for IndexHeader {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        w.write_all(b"REPAK")?;
        w.write_u8(0x1)?; // Version 1
        w.write_u16::<LittleEndian>(0u16)?;
        leb128::write::unsigned(w, self.count)?;
        Ok(())
    }
}

impl Deser for IndexHeader {
    fn deser(r: &mut impl Read) -> Result<Self, Error> {
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf)?;
        // if first four bytes are "0x28, 0xB5, 0x2F, 0xFD" then it's `zstd` compressed
        // if &buf == b"\x28\xb5\x2f\xfd" { // @todo
        //    let mut decoder = zstd::Decoder::new(r)?;
        //   let mut decoded = Vec::new();
        // decoder.read_to_end(&mut decoded)?;
        // r = Cursor::new(decoded);
        // return IndexHeader::deser(r); // call itself to parse decompressed data
        // }
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

        let mut entries = BTreeMap::new();
        //entries.extend_reserve(count);
        for _ in 0..count {
            let entry = IndexEntry::deser(r)?;
            entries.insert(entry.name.clone(), entry);
        }
        // @todo checksumming

        Ok(IndexHeader {
            count,
            entries,
            checksum: ChecksumHeader::default(),
        })
    }
}

#[derive(Default, Debug)] // temp?
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
