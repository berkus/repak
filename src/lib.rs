#![feature(default_field_values)]
#![allow(dead_code)]
#![allow(warnings)]

use {
    crate::{
        checksum::ChecksumHeader,
        compress::CompressionHeader,
        encrypt::EncryptionHeader,
        index::{Attribute, IndexEntry, IndexHeader},
    },
    culpa::{throw, throws},
    io::{Load, Save},
    std::{
        fs::{self, File, OpenOptions},
        io::{BufReader, Cursor, Read, Seek, SeekFrom, Write, copy},
        path::{Path, PathBuf},
    },
    zstd::bulk as zstd,
};

mod checksum;
mod compress;
pub(crate) mod counting_writer;
mod encrypt;
mod index;
mod io;
mod locator;
mod read;
mod write;

pub use {
    checksum::Checksum,
    compress::{CompressionAlgorithm, decompress_stream, pick_best_compression},
    encrypt::EncryptionAlgorithm,
};

// TODO: enum ErrorKind here?
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
    #[error("Unsupported checksum algorithm: {0}")]
    UnsupportedChecksum(String),
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
/// let mut archive = create("assets.repak").unwrap();
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
    index: IndexAttachment,
    file_path: PathBuf,
    last_insertion_offset: u64,
}

enum IndexAttachment {
    Attached(IndexHeader),
    Detached(IndexHeader, PathBuf),
}

/// Reference to a single resource in the archive.
///
/// Allows you to validate, decrypt, decompress, extract data.
pub struct Entry<'a> {
    inner: &'a IndexEntry,
    #[expect(dead_code)]
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
        let index = IndexHeader::load(&mut input)?; // @todo compressed index
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
        let index = IndexHeader::load(&mut input)?; // @todo compressed index
        (index, true, insert_pos)
    };
    REPAK {
        index,
        index_attached: attached,
        file_path: input.to_path_buf(),
        last_insertion_offset: insert_pos,
    }
}

type EntryIndex = u64;

/// Source of the asset data
#[expect(dead_code)]
enum Source {
    /// File on disk
    File(PathBuf),
    /// In-memory buffer
    Memory(Vec<u8>),
    /// Location in REPAK archive
    Archive(EntryIndex, usize),
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
} //TODO: this translates to WritePipeline

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

// fn passthrough<R: Read>(r: R) -> R {
//     r
// }

impl REPAK {
    /// Lookup a file in the archive.
    ///
    /// Returns a reference to the file entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry size cannot be converted to usize on 32-bit platforms.
    #[throws]
    pub fn lookup<'a>(&'a self, id: &str, attributes: &[Attribute]) -> Option<Entry<'a>> {
        self.index
            .lookup(id, attributes)?
            .as_ref()
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
    pub fn append(
        &mut self,
        id: String,
        attributes: Vec<String>,
        file: &Path,
        options: AppendOptions,
    ) {
        if self.index.entries.contains_key(&(id, attributes)) {
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

        // Build up the checksumming, compression and encryption pipeline.
        let write_pipeline =
            write::WritePipeline::new(options.checksums, options.compression, options.encryption);

        // let checksum_header = ChecksumHeader {
        //     checksums: options.checksums,
        // };

        // let reader = checksum_header.build_ingress_pipeline(source_reader);

        let compression_header = if let Some(compression_alg) = options.compression {
            let chosen_algorithm = if let CompressionAlgorithm::Best = compression_alg {
                pick_best_compression(file)?
            } else {
                compression_alg
            };
            Some(CompressionHeader::new(chosen_algorithm, original_size))
        } else {
            None
        };

        // source_reader simply reads the source file
        // write_pipeline writes data to the repak file and calculates all headers

        // let reader = compression_header.map_or(reader, |h| h.build_ingress_pipeline(reader));

        // let encryption_header = options.encryption.map(EncryptionHeader::new);

        // let reader = encryption_header.map_or(reader, |h| h.build_ingress_pipeline(reader));

        let bytes_written = copy(&mut source_reader, &mut write_pipeline)?;

        // Now we can get all the status headers from the write_pipelne and update index entry.
        // self.index.add_entry(name, attributes, offset, size, )

        let entry = IndexEntry {
            offset: self.last_insertion_offset,
            size: bytes_written,
            name: id.clone(),
            attributes: vec![],
            encryption: write_pipeline.encryption_header(),
            compression: write_pipeline.compression_header(),
            checksum: write_pipeline.checksum_header(),
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

        // for entry in sorted {
        //     println!("Sorted Entry: {entry:?}");
        //     let infile = BufReader::new(File::open(entry.path.clone())?);

        //     // Set up checksumming if needed
        //     let checksummer = match &entry.checksum {
        //         None => ChecksummingRead::new(infile, vec![]),
        //         Some(_ch) => {
        //             // Convert Checksum enum instances to boxed Checksummer trait objects
        //             // This would need proper implementation based on how Checksum works
        //             let checksummers: Vec<Box<dyn Checksummer>> = vec![];
        //             ChecksummingRead::new(infile, checksummers)
        //         }
        //     };

        //     // Handle compression if needed
        //     let reader: Box<dyn Read> = match entry.compression {
        //         Some(CompressionHeader {
        //             algorithm: CompressionAlgorithm::Deflate,
        //             ..
        //         }) => {
        //             #[cfg(feature = "compress-deflate")]
        //             {
        //                 // Create a BufReader wrapper since Compressor expects BufRead
        //                 // TODO:
        //                 // let buf_reader = BufReader::new(checksummer);
        //                 // Box::new(Compressor::deflate(buf_reader))
        //                 Box::new(checksummer)
        //             }
        //             #[cfg(not(feature = "compress-deflate"))]
        //             {
        //                 Box::new(checksummer)
        //             }
        //         }
        //         _ => Box::new(checksummer),
        //     };

        //     // Apply encryption if needed
        //     let _reader = match &entry.encryption {
        //         Some(EncryptionHeader {
        //             algorithm: EncryptionAlgorithm::Xor,
        //             ..
        //         }) => {
        //             // Since Encryptor expects BufRead, we need to wrap in BufReader
        //             let buf_reader = BufReader::new(reader);
        //             // Not properly implemented yet
        //             Box::new(buf_reader)
        //         }
        //         _ => reader,
        //     };

        //     // Write to pakfile
        //     pakfile.seek(SeekFrom::Start(entry.offset))?;
        //     copy(&mut reader, &mut pakfile)?;

        //     // @todo: update checksummer and encryptor output metadata in the index
        //     // entry.checksums = checksums;
        // }

        // Write the index to the archive file
        self.save_index()?;
    }

    /// Save index into a separate file.
    /// Index is _ordered by Name_, so it makes easier to look up via binary search even
    /// if you do not apply any sorted containers and just read all entries into a Vec.
    #[throws]
    fn save_detached_index(&self) {
        let idxpath = self.file_path.with_extension("idpak");
        let mut idxfile = File::create(idxpath.clone())?;

        // Zstd compress the index
        let idxfile = if true {
            zstd::Compressor::new(idxfile)
        } else {
            idxfile
        };

        self.index.save(&mut idxfile)?;
        self.index = IndexAttachment::Detached(self.index.0, idxpath);
    }

    #[throws]
    fn save_attached_index(&self) {
        let start_offset = fs::metadata(self.file_path)?.len();
        let mut pakfile = OpenOptions::new()
            .write(true)
            .open(self.file_path.clone())?;
        pakfile.seek(SeekFrom::End(0))?;

        // Zstd compress the index
        let pakfile = if true {
            zstd::Compressor::new(pakfile) // the compressor should be writing to an existing write stream at proper position
        } else {
            pakfile
        };

        self.index.save(pakfile)?;

        let end_offset = fs::metadata(self.file_path)?.len();

        let offset = end_offset - start_offset;

        let buf = locator::make_index_locator(offset)?;

        pakfile.write_all(&buf)?;
        self.index = IndexAttachment::Attached(self.index.0);
    }

    // Advanced api: extract payload, skip decryption, decompression, checksum verification.
    // @todo ❌
}
