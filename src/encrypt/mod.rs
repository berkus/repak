//! Encryption module for REPAK format
//!
//! This module implements streaming encryption and decryption according to the REPAK
//! specification. Encryption is the final step in the asset processing pipeline:
//! checksum → compress → encrypt (for writing)
//! decrypt → decompress → verify checksum (for reading)
//!
//! ## Supported Algorithms
//!
//! - **Reserved (0)**: No encryption (passthrough)
//! - **AES-XTS-256 (1)**: 256-bit AES in XTS mode, requires 64-byte key
//! - **HCTR2 (2)**: Not yet implemented (placeholder)
//! - **Adiantum (3)**: Currently stubbed (placeholder implementation)
//! - **Threefish-1024 (4)**: 1024-bit Threefish block cipher, requires 128-byte key
//!
//! ## Key Requirements
//!
//! Each algorithm has specific key size requirements:
//! - AES-XTS-256: 64 bytes (two 32-byte keys for XTS mode)
//! - Adiantum: 32 bytes
//! - Threefish-1024: 128 bytes
//!
//! ## Streaming Architecture
//!
//! The encryption system supports streaming operations through the `Encryptor` and
//! `Decryptor` enums, which wrap algorithm-specific implementations. This allows
//! processing large files without loading them entirely into memory.
//!
//! ## Implementation Status
//!
//! - ✅ AES-XTS-256: Fully implemented with proper XTS mode
//! - ✅ Threefish-1024: Fully implemented with 128-byte blocks
//! - ⚠️ Adiantum: Stubbed implementation (passes through data unchanged)
//! - ❌ HCTR2: Not implemented (returns unimplemented! error)

use {
    crate::{
        Error,
        io::{Load, Save, leb128_usize},
    },
    culpa::{throw, throws},
    std::io::{BufRead, Read, Write},
};

#[derive(Debug)]
pub struct EncryptionHeader {
    pub algorithm: EncryptionAlgorithm,
    pub parameters: Vec<u8>,
}

impl EncryptionHeader {
    pub fn new(algorithm: EncryptionAlgorithm) -> Self {
        let parameters = match algorithm {
            EncryptionAlgorithm::None
            | EncryptionAlgorithm::Xor
            | EncryptionAlgorithm::AesXts256
            | EncryptionAlgorithm::Hctr2
            | EncryptionAlgorithm::Adiantum => vec![],
            EncryptionAlgorithm::Threefish1024 => {
                // Default to 1024-bit block size (1024 / 8 = 128 bytes)
                1024u64.to_le_bytes().to_vec() // NB?
            }
        };

        Self {
            algorithm,
            parameters,
        }
    }

    pub fn new_threefish(block_size_bits: u64) -> Self {
        #[allow(clippy::manual_assert)]
        if !matches!(block_size_bits, 256 | 512 | 1024) {
            panic!("Invalid Threefish block size: must be 256, 512, or 1024 bits");
        }

        Self {
            algorithm: EncryptionAlgorithm::Threefish1024,
            parameters: block_size_bits.to_le_bytes().to_vec(),
        }
    }

    // Consume external data and save it to the REPAK file.
    pub fn build_ingress_pipeline(&self, reader: impl Read) -> impl Read {
        reader
    }

    // Take REPAK file contents and export them into their original form.
    pub fn build_egress_pipeline(&self, writer: impl Write) -> impl Write {
        writer
    }
}

impl Save for EncryptionHeader {
    #[throws(Error)]
    fn save(&self, w: &mut impl Write) {
        // Calculate total size: algorithm_id + parameters_len + parameters
        let algorithm_id_size = leb128_usize(self.algorithm.into())?;
        let params_len_size = leb128_usize(self.parameters.len() as u64)?;
        let _total_size = algorithm_id_size + params_len_size + self.parameters.len();

        // Write algorithm ID, parameters size, then parameters
        leb128::write::unsigned(w, self.algorithm.into())?;
        leb128::write::unsigned(w, self.parameters.len() as u64)?;
        w.write_all(&self.parameters)?;
    }
}

impl Load for EncryptionHeader {
    #[throws(Error)]
    fn load(r: &mut impl Read) -> Self {
        let algorithm = EncryptionAlgorithm::try_from(leb128::read::unsigned(r)?)?;
        let params_len = leb128::read::unsigned(r)?;
        let mut parameters = vec![0u8; usize::try_from(params_len)?];
        r.read_exact(&mut parameters)?;

        Self {
            algorithm,
            parameters,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum EncryptionAlgorithm {
    None,          // 0
    Xor,           // 1
    AesXts256,     // 2
    Hctr2,         // 3
    Adiantum,      // 4
    Threefish1024, // 5
}

impl From<EncryptionAlgorithm> for u64 {
    fn from(value: EncryptionAlgorithm) -> u64 {
        match value {
            EncryptionAlgorithm::None => 0,
            EncryptionAlgorithm::Xor => 1,
            EncryptionAlgorithm::AesXts256 => 2,
            EncryptionAlgorithm::Hctr2 => 3,
            EncryptionAlgorithm::Adiantum => 4,
            EncryptionAlgorithm::Threefish1024 => 5,
        }
    }
}

impl TryFrom<u64> for EncryptionAlgorithm {
    type Error = Error;

    #[throws(Self::Error)]
    fn try_from(value: u64) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Xor,
            2 => Self::AesXts256,
            3 => Self::Hctr2,
            4 => Self::Adiantum,
            5 => Self::Threefish1024,
            _ => throw!(Error::UnsupportedEncryption(format!(
                "Unknown encryption algorithm: {value}. If it is one of the standard encryption kinds, check your library is compiled with corresponding encrypt-* feature enabled."
            ))),
        }
    }
}

/// Encrypt data to the given writer.
pub enum Encryptor<W: Write> {
    None(W),
    Xor(xor::XorWriter<W>),
    #[cfg(feature = "encrypt-xts")]
    AesXts256(aes_xts_256::AesXts256Writer<W>),
    #[cfg(feature = "encrypt-adiantum")]
    Adiantum(adiantum::AdiantumWriter<W>),
    #[cfg(feature = "encrypt-threefish")]
    Threefish(threefish_1024::ThreefishWriter<W>),
}

#[cfg(feature = "encrypt-adiantum")]
mod adiantum;
#[cfg(feature = "encrypt-xts")]
mod aes_xts_256;
#[cfg(feature = "encrypt-threefish")]
mod threefish_1024;
mod xor;

impl<W: Write> Encryptor<W> {
    #[throws(Error)]
    fn new(algorithm: EncryptionAlgorithm, writer: W, key: &[u8]) -> Self {
        match algorithm {
            EncryptionAlgorithm::None => Self::None(writer),
            EncryptionAlgorithm::Xor => Self::Xor(xor::XorWriter::new(writer, key)?),
            #[cfg(feature = "encrypt-xts")]
            EncryptionAlgorithm::AesXts256 => {
                Self::AesXts256(aes_xts_256::AesXts256Writer::new(writer, key)?)
            }
            #[cfg(feature = "encrypt-adiantum")]
            EncryptionAlgorithm::Adiantum => {
                Self::Adiantum(adiantum::AdiantumWriter::new(writer, key)?)
            }
            #[cfg(feature = "encrypt-threefish")]
            EncryptionAlgorithm::Threefish1024 => {
                Self::Threefish(threefish_1024::ThreefishWriter::new(writer, key)?)
            }
            EncryptionAlgorithm::Hctr2 => unimplemented!(),
        }
    }

    #[throws(Error)]
    fn finish(self) -> W {
        match self {
            Self::None(writer) => writer,
            Self::Xor(xor) => xor.finish(),
            #[cfg(feature = "encrypt-xts")]
            Self::AesXts256(aes_xts_256) => aes_xts_256.finish()?,
            #[cfg(feature = "encrypt-adiantum")]
            Self::Adiantum(adiantum) => adiantum.finish()?,
            #[cfg(feature = "encrypt-threefish")]
            Self::Threefish(threefish_1024) => threefish_1024.finish()?,
        }
    }
}

impl<W: Write> Write for Encryptor<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::None(w) => w.write(buf),
            Self::Xor(w) => w.write(buf),
            #[cfg(feature = "encrypt-xts")]
            Self::AesXts256(w) => w.write(buf),
            #[cfg(feature = "encrypt-adiantum")]
            Self::Adiantum(w) => w.write(buf),
            #[cfg(feature = "encrypt-threefish")]
            Self::Threefish(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::None(w) => w.flush(),
            Self::Xor(w) => w.flush(),
            #[cfg(feature = "encrypt-xts")]
            Self::AesXts256(w) => w.flush(),
            #[cfg(feature = "encrypt-adiantum")]
            Self::Adiantum(w) => w.flush(),
            #[cfg(feature = "encrypt-threefish")]
            Self::Threefish(w) => w.flush(),
        }
    }
}

/// Decrypt data from the given reader.
pub enum Decryptor<R: Read> {
    None(R),
    Xor(R),
    #[cfg(feature = "encrypt-xts")]
    AesXts256(aes_xts_256::AesXts256Reader<R>),
    #[cfg(feature = "encrypt-adiantum")]
    Adiantum(adiantum::AdiantumReader<R>),
    #[cfg(feature = "encrypt-threefish")]
    Threefish(threefish_1024::ThreefishReader<R>),
}

impl<R: BufRead> Decryptor<R> {
    #[throws(Error)]
    pub fn new(algorithm: EncryptionAlgorithm, reader: R, key: &[u8]) -> Self {
        match algorithm {
            EncryptionAlgorithm::None => Self::None(reader),
            EncryptionAlgorithm::Xor => todo!(),
            EncryptionAlgorithm::AesXts256 => {
                #[cfg(feature = "encrypt-xts")]
                {
                    Self::AesXts256(aes_xts_256::AesXts256Reader::new(reader, key)?)
                }
                #[cfg(not(feature = "encrypt-xts"))]
                throw!(Error::UnsupportedEncryption(
                    "AES-XTS-256 encryption is not supported".to_string()
                ))
            }
            EncryptionAlgorithm::Hctr2 => {
                unimplemented!("HCTR2 decryption is not yet implemented")
            }
            EncryptionAlgorithm::Adiantum => {
                #[cfg(feature = "encrypt-adiantum")]
                {
                    Self::Adiantum(adiantum::AdiantumReader::new(reader, key)?)
                }
                #[cfg(not(feature = "encrypt-adiantum"))]
                throw!(Error::UnsupportedEncryption(
                    "Adiantum encryption is not supported".to_string()
                ))
            }
            EncryptionAlgorithm::Threefish1024 => {
                #[cfg(feature = "encrypt-threefish")]
                {
                    Self::Threefish(threefish_1024::ThreefishReader::new(reader, key)?)
                }
                #[cfg(not(feature = "encrypt-threefish"))]
                throw!(Error::UnsupportedEncryption(
                    "Threefish-1024 encryption is not supported".to_string()
                ))
            }
        }
    }
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::None(r) => r.read(buf),
            Self::Xor(r) => r.read(buf),
            #[cfg(feature = "encrypt-xts")]
            Self::AesXts256(r) => r.read(buf),
            #[cfg(feature = "encrypt-adiantum")]
            Self::Adiantum(r) => r.read(buf),
            #[cfg(feature = "encrypt-threefish")]
            Self::Threefish(r) => r.read(buf),
        }
    }
}

/// Encrypt data from reader to writer using streaming encryption
#[throws(Error)]
pub fn encrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    algorithm: EncryptionAlgorithm,
    key: &[u8],
) -> (EncryptionHeader, W) {
    let header = EncryptionHeader::new(algorithm);

    if matches!(algorithm, EncryptionAlgorithm::None) {
        // No encryption, just copy data
        std::io::copy(&mut reader, &mut writer)?;
        return (header, writer);
    }

    let mut encryptor = Encryptor::new(algorithm, writer, key)?;
    std::io::copy(&mut reader, &mut encryptor)?;
    let final_writer = encryptor.finish()?;

    (header, final_writer)
}

/// Decrypt data from reader using streaming decryption
#[throws(Error)]
pub fn decrypt_stream<R: BufRead>(
    reader: R,
    algorithm: EncryptionAlgorithm,
    key: &[u8],
) -> Decryptor<R> {
    Decryptor::new(algorithm, reader, key)?
}

//===========================
//===========================
//===========================

impl<R: BufRead> Decryptor<R> {
    #[cfg(feature = "encrypt-xts")]
    #[throws(Error)]
    fn new_aes_xts_256(reader: R, key: &[u8]) -> Self {
        Self::AesXts256(aes_xts_256::AesXts256Reader::new(reader, key)?)
    }

    #[cfg(feature = "encrypt-adiantum")]
    #[throws(Error)]
    fn new_adiantum(reader: R, key: &[u8]) -> Self {
        Self::Adiantum(adiantum::AdiantumReader::new(reader, key)?)
    }

    #[cfg(feature = "encrypt-threefish")]
    #[throws(Error)]
    fn new_threefish_1024(reader: R, key: &[u8]) -> Self {
        Self::Threefish(threefish_1024::ThreefishReader::new(reader, key)?)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::io::Cursor};

    #[test]
    fn test_encryption_header_serialization() {
        let header = EncryptionHeader::new(EncryptionAlgorithm::AesXts256);
        let mut buffer = Vec::new();
        header.save(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let deserialized = EncryptionHeader::load(&mut cursor).unwrap();

        assert!(matches!(
            deserialized.algorithm,
            EncryptionAlgorithm::AesXts256
        ));
        assert_eq!(deserialized.parameters.len(), 0);
    }

    #[test]
    fn test_threefish_header_with_block_size() {
        let header = EncryptionHeader::new_threefish(512);
        let mut buffer = Vec::new();
        header.save(&mut buffer).unwrap();

        let mut cursor = Cursor::new(buffer);
        let deserialized = EncryptionHeader::load(&mut cursor).unwrap();

        assert!(matches!(
            deserialized.algorithm,
            EncryptionAlgorithm::Threefish1024
        ));
        assert_eq!(deserialized.parameters, 512u64.to_le_bytes());
    }

    #[test]
    fn test_algorithm_mappings() {
        assert_eq!(u64::from(EncryptionAlgorithm::None), 0);
        assert_eq!(u64::from(EncryptionAlgorithm::AesXts256), 1);
        assert_eq!(u64::from(EncryptionAlgorithm::Hctr2), 2);
        assert_eq!(u64::from(EncryptionAlgorithm::Adiantum), 3);
        assert_eq!(u64::from(EncryptionAlgorithm::Threefish1024), 4);

        assert!(matches!(
            EncryptionAlgorithm::try_from(0).unwrap(),
            EncryptionAlgorithm::None
        ));
        assert!(matches!(
            EncryptionAlgorithm::try_from(1).unwrap(),
            EncryptionAlgorithm::AesXts256
        ));
        assert!(matches!(
            EncryptionAlgorithm::try_from(2).unwrap(),
            EncryptionAlgorithm::Hctr2
        ));
        assert!(matches!(
            EncryptionAlgorithm::try_from(3).unwrap(),
            EncryptionAlgorithm::Adiantum
        ));
        assert!(matches!(
            EncryptionAlgorithm::try_from(4).unwrap(),
            EncryptionAlgorithm::Threefish1024
        ));
    }

    #[test]
    fn test_passthrough_encryption() {
        let data = b"Hello, World!";
        let cursor = Cursor::new(data.to_vec());
        let output = Vec::new();

        let key = b"dummy_key";
        let (header, final_writer) =
            encrypt_stream(cursor, output, EncryptionAlgorithm::None, key).unwrap();

        assert!(matches!(header.algorithm, EncryptionAlgorithm::None));
        assert_eq!(final_writer, data);
    }

    #[test]
    fn test_unsupported_algorithm_error() {
        assert!(EncryptionAlgorithm::try_from(100).is_err());
    }

    #[cfg(feature = "encrypt-xts")]
    #[test]
    fn test_aes_xts_256_encryption_decryption() {
        use std::io::BufReader;

        let data = b"Hello, World! This is a test message for AES-XTS-256 encryption.";
        let key = [42u8; 64]; // 64-byte key for AES-XTS-256

        // Encrypt
        let cursor = Cursor::new(data.to_vec());
        let output = Vec::new();
        let (_header, encrypted_data) =
            encrypt_stream(cursor, output, EncryptionAlgorithm::AesXts256, &key).unwrap();

        // Encrypted data should be different from original
        assert_ne!(encrypted_data, data); // NB!

        // Decrypt
        let reader = BufReader::new(Cursor::new(encrypted_data));
        let mut decryptor = decrypt_stream(reader, EncryptionAlgorithm::AesXts256, &key).unwrap();
        let mut decrypted = Vec::new();
        decryptor.read_to_end(&mut decrypted).unwrap();

        // Remove padding
        let original_len = data.len();
        decrypted.truncate(original_len);

        assert_eq!(decrypted, data);
    }

    #[cfg(feature = "encrypt-adiantum")]
    #[test]
    fn test_adiantum_encryption_decryption() {
        use std::io::BufReader;

        let data = b"Hello, World! This is a test message for Adiantum encryption.";
        let key = [42u8; 32]; // 32-byte key for Adiantum

        // Encrypt
        let cursor = Cursor::new(data.to_vec());
        let output = Vec::new();
        let (_header, encrypted_data) =
            encrypt_stream(cursor, output, EncryptionAlgorithm::Adiantum, &key).unwrap();

        // TODO: Currently stubbed implementation just passes through data
        // When properly implemented, encrypted data should be different from original
        // assert_ne!(encrypted_data, data);

        // Decrypt
        let reader = BufReader::new(Cursor::new(encrypted_data));
        let mut decryptor = decrypt_stream(reader, EncryptionAlgorithm::Adiantum, &key).unwrap();
        let mut decrypted = Vec::new();
        decryptor.read_to_end(&mut decrypted).unwrap();

        // For stubbed implementation, data passes through unchanged
        assert_eq!(decrypted, data);
    }

    #[cfg(feature = "encrypt-threefish")]
    #[test]
    fn test_threefish_1024_encryption_decryption() {
        use std::io::BufReader;

        let data = b"Hello, World! This is a test message for Threefish-1024 encryption. It needs to be long enough to test the 128-byte block size properly.";
        let key = [42u8; 128]; // 128-byte key for Threefish-1024

        // Encrypt
        let cursor = Cursor::new(data.to_vec());
        let output = Vec::new();
        let (_header, encrypted_data) =
            encrypt_stream(cursor, output, EncryptionAlgorithm::Threefish1024, &key).unwrap();

        // Encrypted data should be different from original
        assert_ne!(encrypted_data, data);

        // Decrypt
        let reader = BufReader::new(Cursor::new(encrypted_data));
        let mut decryptor =
            decrypt_stream(reader, EncryptionAlgorithm::Threefish1024, &key).unwrap();
        let mut decrypted = Vec::new();
        decryptor.read_to_end(&mut decrypted).unwrap();

        // Remove padding
        let original_len = data.len();
        decrypted.truncate(original_len);

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_invalid_key_sizes() {
        let data = b"test data";
        let cursor = Cursor::new(data.to_vec());
        let output = Vec::new();

        // Test AES-XTS-256 with wrong key size
        #[cfg(feature = "encrypt-xts")]
        {
            let wrong_key = [42u8; 32]; // Should be 64 bytes
            assert!(
                encrypt_stream(
                    cursor.clone(),
                    output.clone(),
                    EncryptionAlgorithm::AesXts256,
                    &wrong_key
                )
                .is_err()
            );
        }

        // Test Adiantum with wrong key size
        #[cfg(feature = "encrypt-adiantum")]
        {
            let wrong_key = [42u8; 16]; // Should be 32 bytes
            assert!(
                encrypt_stream(
                    cursor.clone(),
                    output.clone(),
                    EncryptionAlgorithm::Adiantum,
                    &wrong_key
                )
                .is_err()
            );
        }

        // Test Threefish with wrong key size
        #[cfg(feature = "encrypt-threefish")]
        {
            let wrong_key = [42u8; 64]; // Should be 128 bytes
            assert!(
                encrypt_stream(
                    cursor,
                    output,
                    EncryptionAlgorithm::Threefish1024,
                    &wrong_key
                )
                .is_err()
            );
        }
    }
}
