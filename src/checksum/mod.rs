use {
    crate::{
        Error,
        io::{Deser, Ser},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[cfg(feature = "checksum-blake3")]
mod blake3_256;
#[cfg(feature = "checksum-cityhash")]
mod cityhash_128;
#[cfg(feature = "checksum-k12")]
mod k12_256;
#[cfg(feature = "checksum-seahash")]
mod seahash_64;
#[cfg(feature = "checksum-sha3")]
mod sha3_256;
#[cfg(feature = "checksum-xxhash3")]
mod xxhash3_128;

#[cfg(feature = "checksum-blake3")]
pub use blake3_256::BLAKE3;
#[cfg(feature = "checksum-cityhash")]
pub use cityhash_128::CityHash;
#[cfg(feature = "checksum-k12")]
pub use k12_256::K12;
#[cfg(feature = "checksum-seahash")]
pub use seahash_64::SeaHash;
#[cfg(feature = "checksum-sha3")]
pub use sha3_256::SHA3;
#[cfg(feature = "checksum-xxhash3")]
pub use xxhash3_128::Xxhash3;

/// A header storing checksummers information in REPAK file.
///
/// It is used for both payloads and the Index.
#[derive(Default, Debug)]
pub(crate) struct ChecksumHeader {
    pub(crate) checksums: Vec<Checksum>,
}

impl ChecksumHeader {
    // Consume external data and save it to the REPAK file.
    pub fn build_ingress_pipeline(&self, reader: impl Read) -> impl Read {
        // loop self.checksums and wrap reader into an instance of each checksummer
        // TODO: must make each reader update corresponding Checksum in the Vec
        reader
    }

    // Take REPAK file contents and export them into their original form.
    pub fn build_egress_pipeline(&self, writer: impl Write) -> impl Write {
        writer
    }
}

impl Ser for ChecksumHeader {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, self.checksums.len() as u64)?;
        for c in &self.checksums {
            c.ser(w)?;
        }
    }
}

impl Deser for ChecksumHeader {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let count = leb128::read::unsigned(r)?;
        let mut checksums = Vec::with_capacity(usize::try_from(count)?);
        for _ in 0..count {
            checksums.push(Checksum::deser(r)?);
        }
        Self { checksums }
    }
}

#[derive(Clone, Debug)]
pub enum Checksum {
    #[cfg(feature = "checksum-sha3")]
    SHA3(SHA3),
    #[cfg(feature = "checksum-k12")]
    K12(K12),
    #[cfg(feature = "checksum-blake3")]
    BLAKE3(BLAKE3),
    #[cfg(feature = "checksum-xxhash3")]
    Xxhash3(Xxhash3),
    #[cfg(feature = "checksum-seahash")]
    SeaHash(SeaHash),
    #[cfg(feature = "checksum-cityhash")]
    CityHash(CityHash),
}

impl Checksum {
    pub fn passthrough(reader: impl Read) -> impl Read {
        reader
    }
}

impl Ser for Checksum {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(
            w,
            match self {
                #[cfg(feature = "checksum-sha3")]
                Checksum::SHA3(_) => 1,
                #[cfg(feature = "checksum-k12")]
                Checksum::K12(_) => 2,
                #[cfg(feature = "checksum-blake3")]
                Checksum::BLAKE3(_) => 3,
                #[cfg(feature = "checksum-xxhash3")]
                Checksum::Xxhash3(_) => 4,
                #[cfg(feature = "checksum-seahash")]
                Checksum::SeaHash(_) => 5,
                #[cfg(feature = "checksum-cityhash")]
                Checksum::CityHash(_) => 6,
            },
        )?;
        match self {
            #[cfg(feature = "checksum-sha3")]
            Checksum::SHA3(sha3) => sha3.ser(w)?,
            #[cfg(feature = "checksum-k12")]
            Checksum::K12(k12) => k12.ser(w)?,
            #[cfg(feature = "checksum-blake3")]
            Checksum::BLAKE3(blake3) => blake3.ser(w)?,
            #[cfg(feature = "checksum-xxhash3")]
            Checksum::Xxhash3(xxhash3) => xxhash3.ser(w)?,
            #[cfg(feature = "checksum-seahash")]
            Checksum::SeaHash(seahash) => seahash.ser(w)?,
            #[cfg(feature = "checksum-cityhash")]
            Checksum::CityHash(cityhash) => cityhash.ser(w)?,
        }
    }
}

impl Deser for Checksum {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let kind = leb128::read::unsigned(r)?;
        match kind {
            #[cfg(feature = "checksum-sha3")]
            1 => Checksum::SHA3(SHA3::deser(r)?),
            #[cfg(feature = "checksum-k12")]
            2 => Checksum::K12(K12::deser(r)?),
            #[cfg(feature = "checksum-blake3")]
            3 => Checksum::BLAKE3(BLAKE3::deser(r)?),
            #[cfg(feature = "checksum-xxhash3")]
            4 => Checksum::Xxhash3(Xxhash3::deser(r)?),
            #[cfg(feature = "checksum-seahash")]
            5 => Checksum::SeaHash(SeaHash::deser(r)?),
            #[cfg(feature = "checksum-cityhash")]
            6 => Checksum::CityHash(CityHash::deser(r)?),
            _ => throw!(Error::UnsupportedChecksum(format!(
                "Unknown kind: {kind}. If it is one of the standard checksum kinds, check your library is compiled with corresponding checksum-* feature enabled."
            ))),
        }
    }
}

///=============================================================================
/// Checksummer trait for uniform interface
//=============================================================================
pub(crate) trait Checksummer: 'static + Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self);
}

///=============================================================================
/// `ChecksummingRead` wrapper
///=============================================================================
pub(crate) struct ChecksummingRead<R: Read> {
    reader: R,
    checksummers: Vec<Box<dyn Checksummer>>,
}

impl<R: Read> ChecksummingRead<R> {
    pub fn new(reader: R, checksummers: Vec<Box<dyn Checksummer>>) -> Self {
        Self {
            reader,
            checksummers,
        }
    }

    pub fn finalize(&mut self) {
        for checksummer in &mut self.checksummers {
            checksummer.finalize();
        }
    }

    pub fn get_checksummers(&self) -> &Vec<Box<dyn Checksummer>> {
        &self.checksummers
    }
}

impl<R: Read> Read for ChecksummingRead<R> {
    #[throws(std::io::Error)]
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let bytes_read = self.reader.read(buf)?;
        if bytes_read > 0 {
            for checksummer in &mut self.checksummers {
                checksummer.update(&buf[0..bytes_read]);
            }
        }
        bytes_read
    }
}

///=============================================================================
/// Checksum creation helpers
///=============================================================================
impl Checksum {
    #[cfg(feature = "checksum-sha3")]
    #[must_use]
    pub fn new_sha3() -> Self {
        Checksum::SHA3(SHA3::default())
    }

    #[cfg(feature = "checksum-k12")]
    #[must_use]
    pub fn new_k12(primer: String) -> Self {
        Checksum::K12(K12::new(primer))
    }

    #[cfg(feature = "checksum-blake3")]
    #[must_use]
    pub fn new_blake3() -> Self {
        Checksum::BLAKE3(BLAKE3::default())
    }

    #[cfg(feature = "checksum-xxhash3")]
    #[must_use]
    pub fn new_xxhash3() -> Self {
        Checksum::Xxhash3(Xxhash3::default())
    }

    #[cfg(feature = "checksum-seahash")]
    #[must_use]
    pub fn new_seahash() -> Self {
        Checksum::SeaHash(SeaHash::default())
    }

    #[cfg(feature = "checksum-cityhash")]
    #[must_use]
    pub fn new_cityhash() -> Self {
        Checksum::CityHash(CityHash::default())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::io::{Cursor, Read},
    };

    /// Fixed test data pattern for consistent checksummer testing
    pub(crate) const TEST_DATA: &[u8] = b"The quick brown fox jumps over the lazy dog. This is a fixed test pattern for checksummer validation. Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

    #[test]
    fn test_checksumming_read() {
        let reader = Cursor::new(TEST_DATA);

        let checksummers: Vec<Box<dyn Checksummer>> = vec![
            #[cfg(feature = "checksum-sha3")]
            Box::new(SHA3::default()),
            #[cfg(feature = "checksum-blake3")]
            Box::new(BLAKE3::default()),
        ];

        let mut checksumming_reader = ChecksummingRead::new(reader, checksummers);

        let mut buffer = Vec::new();
        checksumming_reader.read_to_end(&mut buffer).unwrap();

        assert_eq!(buffer, TEST_DATA);

        checksumming_reader.finalize();

        let checksummers = checksumming_reader.get_checksummers();

        let expected_len = if cfg!(feature = "checksum-sha3") {
            1
        } else {
            0
        } + if cfg!(feature = "checksum-blake3") {
            1
        } else {
            0
        };

        assert_eq!(checksummers.len(), expected_len);

        // #[cfg(feature = "checksum-sha3")]
        // assert_eq!(checksummers[0].digest(), SHA3::default().digest(TEST_DATA));

        // #[cfg(feature = "checksum-blake3")]
        // assert_eq!(checksummers[0].digest, BLAKE3::default().digest(TEST_DATA));
    }
}
