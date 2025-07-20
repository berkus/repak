#![feature(default_field_values)]
#![allow(dead_code)]

use {
    crate::{
        checksum::ChecksumHeader,
        compress::{CompressionHeader, compress_stream},
        encrypt::EncryptionHeader,
        io::Deser,
    },
    byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt},
    culpa::{throw, throws},
    io::{Ser, deser_string, leb128_usize, ser_string},
    std::{
        collections::BTreeMap,
        fs::{self, File, OpenOptions},
        io::{BufReader, Cursor, Read, Seek, SeekFrom, Write, copy},
        path::{Path, PathBuf},
    },
};

mod checksum;
mod compress;
mod encrypt;
mod io;

pub use {
    checksum::Checksum,
    compress::{CompressionAlgorithm, decompress_stream, pick_best_compression},
    encrypt::EncryptionAlgorithm,
};

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
    #[error("Unsupported compression algorithm: {0}")]
    UnsupportedCompression(String),
    #[error("Unsupported encryption algorithm: {0}")]
    UnsupportedEncryption(String),
    #[error("Checksum verification failed for {0}")]
    ChecksumMismatch(String),
    #[error("Decompression failed: {0}")]
    DecompressionError(String),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

/// Public interface for a REPAK archive.
///
/// A REPAK archive is a binary file format for packaging assets, similar to Quake PAK or DOOM WAD files.
/// It supports compression, encryption, and checksumming of assets.
///
/// # Features
/// - Append-only file structure
/// - Multiple compression algorithms (deflate, bzip2, zstd, lzma, lz4, fsst)
/// - Encryption support
/// - Multiple checksumming methods (SHA3, K12, BLAKE3, `XXHash3`, `SeaHash`, `CityHash`)
/// - Index structure for quickly locating assets
///
/// # Example
/// ```no_run
/// use repak::{create, CompressionAlgorithm, AppendOptions};
/// use std::path::Path;
///
/// // Create a new archive
/// let mut archive = create(Path::new("assets.repak")).unwrap();
///
/// // Add a file with default options
/// archive.append(
///     "texture.png".to_string(),
///     Path::new("assets/texture.png"),
///     AppendOptions::default()
/// ).unwrap();
///
/// // Add a file with compression
/// archive.append(
///     "model.fbx".to_string(),
///     Path::new("assets/model.fbx"),
///     AppendOptions::default().with_compression(CompressionAlgorithm::Deflate)
/// ).unwrap();
///
/// // Save the archive
/// archive.save().unwrap();
/// ```
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

impl Entry<'_> {
    /// Returns the name of the entry
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Returns the size of the entry in the archive
    #[must_use]
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    /// Returns the offset of the entry in the archive
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.inner.offset
    }

    /// Returns true if the entry is compressed
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.inner.compression.is_some()
    }

    /// Returns true if the entry is encrypted
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.inner.encryption.is_some()
    }

    /// Returns true if the entry has checksums
    #[must_use]
    pub fn has_checksums(&self) -> bool {
        self.inner.checksum.is_some()
    }

    /// Extracts the entry to the specified path
    ///
    /// # Errors
    ///
    /// Returns an error if the extraction fails due to I/O issues,
    /// decryption failures, decompression errors, or checksum mismatches.
    #[throws(Error)]
    pub fn extract_to(&self, _path: &Path) {
        // Implementation would open the source file,
        // decrypt and decompress the data while verifying checksums,
        // and write it to the output path
        todo!("Implement extraction");
    }

    /// Returns a reader that provides the raw content of the entry
    ///
    /// # Errors
    ///
    /// Returns an error if the reader cannot be created due to I/O issues,
    /// or if decryption/decompression setup fails.
    #[throws(Error)]
    pub fn reader(&self) -> impl Read {
        // Implementation would open the source,
        // apply decryption and decompression as needed,
        // and return a reader
        // For now, return an empty cursor as placeholder
        std::io::Cursor::new(Vec::<u8>::new())
    }
}

/// Create a new repak archive.
///
/// The index will be created in a temporary file,
///
/// # Errors
///
/// Returns an error if the archive file cannot be created due to I/O issues
/// or insufficient permissions.
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
///
/// # Errors
///
/// Returns an error if the archive file cannot be opened, read, or if the
/// archive format is invalid or corrupted.
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

/// Source of the asset data
enum Source {
    /// File on disk
    File(PathBuf),
    /// In-memory buffer
    Memory(Vec<u8>),
    /// Location in REPAK archive
    Archive(u64, usize),
}

/// Options for appending a file to a REPAK archive.
///
/// These options control how the file is processed when added to the archive:
/// - Checksums: Which hash algorithms to use for validating the file's integrity
/// - Compression: Which compression algorithm to use (if any)
/// - Encryption: Which encryption algorithm to use (if any)
///
/// # Example
/// ```no_run
/// use repak::{AppendOptions, CompressionAlgorithm, EncryptionAlgorithm, Checksum};
///
/// // Default options (no compression, no encryption, no checksums)
/// let default_options = AppendOptions::default();
///
/// // With compression only
/// let compressed = AppendOptions::default()
///     .with_compression(CompressionAlgorithm::Deflate);
///
/// // With compression and checksums
/// let secure = AppendOptions::default()
///     .with_compression(CompressionAlgorithm::Zstd)
///     .with_checksum(Checksum::new_sha3())
///     .with_checksum(Checksum::new_blake3());
/// ```
#[derive(Default, Debug)]
pub struct AppendOptions {
    pub checksums: Vec<Checksum> = vec![],
    pub compression: Option<CompressionAlgorithm> = None,
    pub encryption: Option<EncryptionAlgorithm> = None,
}

impl AppendOptions {
    #[must_use]
    pub fn with_compression(self, c: CompressionAlgorithm) -> Self {
        Self {
            compression: Some(c),
            ..self
        }
    }

    #[must_use]
    pub fn with_encryption(self, c: EncryptionAlgorithm) -> Self {
        Self {
            encryption: Some(c),
            ..self
        }
    }

    #[must_use]
    pub fn with_checksum(self, c: Checksum) -> Self {
        let mut checksums = self.checksums;
        checksums.push(c);
        Self { checksums, ..self }
    }
}

fn passthrough<R: Read>(r: R) -> R {
    r
}

impl REPAK {
    /// Lookup a file in the archive.
    ///
    /// Returns a reference to the file entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry size cannot be converted to usize on 32-bit platforms.
    #[throws]
    pub fn lookup<'a>(&'a self, id: &str) -> Option<Entry<'a>> {
        self.index
            .entries
            .get(id)
            .map(|inner| -> Result<Entry<'a>, Error> {
                Ok(Entry {
                    inner,
                    source: Source::Archive(inner.offset, usize::try_from(inner.size)?),
                })
            })
            .transpose()?
    }

    /// Append a file to the archive.
    ///
    /// Append options specify how to transform the file when adding.
    /// It is posible to request checksumming, compression, and encryption
    /// (in this order).
    ///
    /// # Errors
    ///
    /// Returns an error if the file already exists in the archive, the file
    /// cannot be read, compression/encryption fails, or I/O operations fail.
    #[throws]
    pub fn append(&mut self, id: String, file: &Path, options: AppendOptions) {
        if self.index.entries.contains_key(&id) {
            throw!(Error::AlreadyExists(id));
        }

        if !file.exists() {
            throw!(Error::FileNotFound(file.to_owned()));
        }

        // Open or create the archive file for writing
        let mut archive_file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(false)
            .open(&self.file_path)?;

        // Seek to the position where we'll write this entry's data
        archive_file.seek(SeekFrom::Start(self.last_insertion_offset))?;

        // Open source file for reading
        let source_file = File::open(file)?;
        let original_size = source_file.metadata()?.len();
        let mut source_reader = BufReader::new(source_file);

        let (compression_header, final_size) = if let Some(compression_alg) = options.compression {
            // Determine the actual algorithm to use
            let chosen_algorithm = if let CompressionAlgorithm::Best = compression_alg {
                pick_best_compression(file)?
            } else {
                compression_alg
            };

            // Apply compression using streaming

            let (header, _) = compress_stream(
                source_reader,
                &mut archive_file,
                chosen_algorithm,
                original_size,
            )?;

            // Get the current position to calculate compressed size
            let end_pos = archive_file.stream_position()?;
            let compressed_size = end_pos - self.last_insertion_offset;

            (Some(header), compressed_size)
        } else {
            // No compression, copy data directly

            let bytes_written = copy(&mut source_reader, &mut archive_file)?;

            (None, bytes_written)
        };

        // Create checksum header if checksums are specified
        let checksum_header = if options.checksums.is_empty() {
            None
        } else {
            Some(ChecksumHeader {
                checksums: options.checksums,
            })
        };

        // Create encryption header if encryption is specified
        let encryption_header = options.encryption.map(EncryptionHeader::new);

        let entry = IndexEntry {
            offset: self.last_insertion_offset,
            size: final_size,
            name: id.clone(),
            encryption: encryption_header,
            compression: compression_header,
            checksum: checksum_header,
            path: file.to_owned(), // Store original source file path
        };

        self.last_insertion_offset += entry.size;
        self.index.entries.insert(id, entry);
    }

    /// Save the archive.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive file cannot be created or written to,
    /// or if the index cannot be serialized.
    #[throws]
    pub fn save(&self) {
        // Data has already been written to the archive during append() calls.
        // We only need to append the index to the existing archive file.

        // Sort entries by offset for index consistency
        let mut sorted = self.index.entries.values().collect::<Vec<_>>();
        sorted.sort_by(|a, b| a.offset.cmp(&b.offset));

        for entry in sorted {
            println!("Sorted Entry: {entry:?}");
        }

        // Write the index to the archive file
        self.save_index()?;
    }

    /// Index is ordered by Name, so it makes easier to look up via binary search even
    /// if you do not apply any sorted containers and just read all entries into a Vec.
    #[throws]
    fn save_index(&self) {
        let idxpath = self.file_path.with_extension("idpak");
        let mut idxfile = File::create(idxpath.clone())?;

        self.index.ser(&mut idxfile)?;

        drop(idxfile);
        let offset = fs::metadata(idxpath.clone())?.len();

        let mut idxfile = File::open(idxpath.clone())?;
        let mut pakfile = OpenOptions::new()
            .write(true)
            .open(self.file_path.clone())?;
        pakfile.seek(SeekFrom::End(0))?;
        copy(&mut idxfile, &mut pakfile)?;

        let buf = make_index_locator(offset)?;

        pakfile.write_all(&buf)?;
    }

    // Advanced api: extract payload, skip decryption, decompression, checksum verification.
    // @todo ❌
}

#[throws(std::io::Error)]
fn make_index_locator(offset: u64) -> Vec<u8> {
    let n = 64 - u64::from(offset.leading_zeros());
    // dbg!("Non-zero bits {}", n);
    // let align_down = fn(x: u64) -> u64 { x & !0x7f };
    let bsize = (n & !7) / 7;
    let off = offset + bsize + 1;
    // dbg!("Offset {} + {} + {} = {off} ({off:x})", offset, bsize, 1,);
    let lenbuf = leb128_usize(off)? as u64;
    // dbg!("Lenbuf {}", lenbuf);
    let mut buf = vec![];
    leb128::write::unsigned(&mut buf, offset + lenbuf).unwrap();
    buf.reverse();
    buf
}

#[cfg(test)]
mod index_locator_tests {
    use {super::make_index_locator, std::io::Cursor};

    fn prep(offset: u64) -> (Vec<u8>, u64) {
        let mut buf = make_index_locator(offset).expect("Shouldn't fail");
        buf.reverse();
        let check = leb128::read::unsigned(&mut Cursor::new(&buf)).unwrap();
        buf.reverse();
        (buf, check)
    }

    // 126 - 1b
    // 126+1 - 1b
    // So the end offset is 127 (126 index size + 1 locator size)
    #[test]
    fn locator_close_to_1byte() {
        let (buf, check) = prep(126);
        assert_eq!(buf, vec![0x7f]);
        assert_eq!(check, 127);
    }

    // 127 - 1b
    // 127+1 - 2b
    // 127+2 - 2b
    // So the end offset is 129 (127 index size + 2 locator size)
    #[test]
    fn locator_edgecase_1byte() {
        let (buf, check) = prep(127);
        assert_eq!(buf, vec![0x01, 0x81]);
        assert_eq!(check, 129);
    }

    // @todo: This fails, but should not - 16383 should fit into 2 bytes serialization
    #[test]
    fn locator_close_to_2bytes() {
        let (buf, check) = prep(16381);
        assert_eq!(buf, vec![0x7f, 0xff]);
        assert_eq!(check, 16383);
    }

    // 2-octet VLQ (0xFF7F) is 0b_11_1111_1111_1111 = 0x3FFE = 16382
    // 16382 - 2b
    // 16382+2 - 3b
    // 16382+3 - 3b
    // So the end offset is 16385 (16382 index size + 3 locator size)
    #[test]
    fn locator_edgecase_2bytes() {
        let (buf, check) = prep(16382);
        assert_eq!(buf, vec![0x01, 0x80, 0x81]);
        assert_eq!(check, 16385);
    }

    // 3-octet VLQ (0xFF_FF_7F) is 0b_1_1111_1111_1111_1111_1111 = 0x1FFFFF = 2097151
    // 2097151 - 3b
    // 2097151+3 - 4b
    // 2097151+4 - 4b
    // So the end offset is 2097155 (2097151 index size + 4 locator size)
    #[test]
    fn locator_edgecase_3bytes() {
        let (buf, check) = prep(2097151);
        assert_eq!(buf, vec![0x01, 0x80, 0x80, 0x83]);
        assert_eq!(check, 2097155);
    }

    #[test]
    fn locator_close_to_10bytes() {
        let (buf, check) = prep(u64::MAX / 4);
        assert_eq!(
            buf,
            vec![0x40, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x88]
        );
        assert_eq!(check, u64::MAX / 4 + 9);
    }

    #[test]
    fn locator_edgecase_10bytes() {
        let (buf, check) = prep(u64::MAX / 10 * 9);
        assert_eq!(
            buf,
            vec![0x01, 0xe6, 0xb3, 0x99, 0xcc, 0xe6, 0xb3, 0x99, 0xcc, 0xeb]
        );
        assert_eq!(check, u64::MAX / 10 * 9 + 10);
    }
}

#[derive(Default)]
struct IndexHeader {
    entries: BTreeMap<String, IndexEntry>,
    checksum: ChecksumHeader,
}

impl Ser for IndexHeader {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        // @todo Checksum everything we write here! (w should be wrapped in a ChecksummingWrite)
        // @todo Add zstd compression after checksumming!
        w.write_all(b"REPAK")?;
        w.write_u8(0x1)?; // Version 1
        w.write_u16::<LittleEndian>(0u16)?;
        leb128::write::unsigned(w, self.entries.len() as u64)?;
        for entry in &mut self.entries.values() {
            println!("Entry: {entry:?}");
            entry.ser(w)?;
        }
        self.checksum.ser(w)?;
    }
}

impl Deser for IndexHeader {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        // wrap r into a ChecksummingRead with all checksummers enabled, to verify the integrity of the index
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
            throw!(Error::Deser("Not a REPAK archive".to_string()));
        }
        let version = r.read_u8()?;
        if version != 1 {
            throw!(Error::Deser(format!(
                "Unsupported REPAK version 0x{version:2x}"
            )));
        }
        let reserved = r.read_u16::<LittleEndian>()?;
        if reserved != 0 {
            throw!(Error::Deser("Reserved field is not zero".to_string()));
        }
        let count = leb128::read::unsigned(r)?;

        let mut entries = BTreeMap::new();
        //entries.extend_reserve(count);
        for _ in 0..count {
            let entry = IndexEntry::deser(r)?;
            entries.insert(entry.name.clone(), entry);
        }
        let checksum = ChecksumHeader::deser(r)?;

        // @todo validate checksums

        IndexHeader { entries, checksum }
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

    path: PathBuf,
}

impl Ser for IndexEntry {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        let flags = u64::from(self.encryption.is_some())
            | (u64::from(self.compression.is_some()) << 1)
            | (u64::from(self.checksum.is_some()) << 2);

        leb128::write::unsigned(w, self.offset)?;
        leb128::write::unsigned(w, self.size)?;
        leb128::write::unsigned(w, flags)?;
        ser_string(w, &self.name)?;
        if let Some(encryption) = &self.encryption {
            encryption.ser(w)?;
        }
        if let Some(compression) = &self.compression {
            compression.ser(w)?;
        }
        if let Some(checksum) = &self.checksum {
            checksum.ser(w)?;
        }
    }
}

impl Deser for IndexEntry {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let offset = leb128::read::unsigned(r)?;
        let size = leb128::read::unsigned(r)?;
        let flags = leb128::read::unsigned(r)?;
        let name = deser_string(r)?;
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

        Self {
            offset,
            size,
            name,
            encryption,
            compression,
            checksum,
            path: PathBuf::new(),
        }
    }
}
