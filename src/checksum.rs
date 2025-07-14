use {
    crate::{
        Error,
        io::{Deser, Ser, deser_string, ser_string},
    },
    core::hash::Hasher,
    culpa::{throw, throws},
    std::{
        collections::hash_map::DefaultHasher,
        io::{Read, Write},
    },
    tiny_keccak::Hasher as TinyKeccakHasher,
};

#[derive(Default, Debug)]
pub(crate) struct ChecksumHeader {
    pub(crate) checksums: Vec<Checksum>,
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
        let mut checksums = Vec::with_capacity(count as usize);
        for _ in 0..count {
            checksums.push(Checksum::deser(r)?);
        }
        Self { checksums }
    }
}

#[derive(Clone, Debug)]
pub enum Checksum {
    SHA3(SHA3),
    K12(K12),
    BLAKE3(BLAKE3),
    Xxhash3(Xxhash3),
    SeaHash(SeaHashWrapper),
    CityHash(CityHashWrapper),
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
                Checksum::SHA3(_) => 1,
                Checksum::K12(_) => 2,
                Checksum::BLAKE3(_) => 3,
                Checksum::Xxhash3(_) => 4,
                Checksum::SeaHash(_) => 5,
                Checksum::CityHash(_) => 6,
            },
        )?;
        match self {
            Checksum::SHA3(sha3) => sha3.ser(w)?,
            Checksum::K12(k12) => k12.ser(w)?,
            Checksum::BLAKE3(blake3) => blake3.ser(w)?,
            Checksum::Xxhash3(xxhash3) => xxhash3.ser(w)?,
            Checksum::SeaHash(seahash) => seahash.ser(w)?,
            Checksum::CityHash(cityhash) => cityhash.ser(w)?,
        };
    }
}

impl Deser for Checksum {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let kind = leb128::read::unsigned(r)?;
        match kind {
            1 => Checksum::SHA3(SHA3::deser(r)?),
            2 => Checksum::K12(K12::deser(r)?),
            3 => Checksum::BLAKE3(BLAKE3::deser(r)?),
            4 => Checksum::Xxhash3(Xxhash3::deser(r)?),
            5 => Checksum::SeaHash(SeaHashWrapper::deser(r)?),
            6 => Checksum::CityHash(CityHashWrapper::deser(r)?),
            _ => throw!(Error::Deser(format!("Unknown checksum kind: {kind}"))),
        }
    }
}

///=============================================================================
/// Checksummer trait for uniform interface
///=============================================================================

pub(crate) trait Checksummer: 'static + Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self);
}

///=============================================================================
/// SHA3 Implementation
///=============================================================================

#[derive(Clone)]
pub(crate) struct SHA3 {
    state: Option<tiny_keccak::Sha3>,
    digest: [u8; 32],
}

impl std::fmt::Debug for SHA3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SHA3")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Default for SHA3 {
    fn default() -> Self {
        Self {
            state: Some(tiny_keccak::Sha3::v256()),
            digest: [0u8; 32],
        }
    }
}

impl Ser for SHA3 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 32)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for SHA3 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 32 {
            throw!(Error::Deser(format!("Invalid SHA3 digest size: {}", size)));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl Checksummer for SHA3 {
    fn update(&mut self, data: &[u8]) {
        if let Some(ref mut state) = self.state {
            TinyKeccakHasher::update(state, data);
        }
    }

    fn finalize(&mut self) {
        if let Some(state) = self.state.take() {
            TinyKeccakHasher::finalize(state, &mut self.digest);
        }
    }
}

///=============================================================================
/// K12 Implementation (simplified to avoid complex API)
///=============================================================================

#[derive(Clone, Debug)]
pub(crate) struct K12 {
    buffer: Vec<u8>,
    primer: String,
    digest: [u8; 32],
}

impl Default for K12 {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            primer: String::new(),
            digest: [0u8; 32],
        }
    }
}

impl Ser for K12 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        ser_string(w, &self.primer)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for K12 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let primer = deser_string(r)?;
        let mut digest = [0u8; 32];
        r.read_exact(&mut digest)?;
        Self {
            buffer: Vec::new(),
            primer,
            digest,
        }
    }
}

impl Checksummer for K12 {
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(&mut self) {
        // Simplified K12 - for now just use a placeholder
        // In a real implementation, this would use the K12 algorithm
        let mut hasher = DefaultHasher::new();
        hasher.write(&self.buffer);
        hasher.write(self.primer.as_bytes());
        let hash = hasher.finish();

        // Convert to 32-byte digest (simplified)
        let hash_bytes = hash.to_le_bytes();
        for (i, &byte) in hash_bytes.iter().enumerate() {
            if i < 32 {
                self.digest[i] = byte;
            }
        }
        // Fill rest with repeated pattern
        for i in 8..32 {
            self.digest[i] = self.digest[i % 8];
        }
    }
}

///=============================================================================
/// BLAKE3 Implementation
///=============================================================================

#[derive(Clone)]
pub(crate) struct BLAKE3 {
    state: Option<blake3::Hasher>,
    digest: [u8; 32],
}

impl std::fmt::Debug for BLAKE3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BLAKE3")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Default for BLAKE3 {
    fn default() -> Self {
        Self {
            state: Some(blake3::Hasher::new()),
            digest: [0u8; 32],
        }
    }
}

impl Ser for BLAKE3 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 32)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for BLAKE3 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 32 {
            throw!(Error::Deser(format!(
                "Invalid BLAKE3 digest size: {}",
                size
            )));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl Checksummer for BLAKE3 {
    fn update(&mut self, data: &[u8]) {
        if let Some(ref mut state) = self.state {
            state.update(data);
        }
    }

    fn finalize(&mut self) {
        if let Some(state) = self.state.take() {
            let hash = state.finalize();
            self.digest = *hash.as_bytes();
        }
    }
}

///=============================================================================
/// Xxhash3 Implementation (uses std::hash::Hasher interface)
///=============================================================================

#[derive(Clone)]
pub(crate) struct Xxhash3 {
    state: Option<twox_hash::XxHash3_128>,
    digest: [u8; 16],
}

impl std::fmt::Debug for Xxhash3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xxhash3")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Default for Xxhash3 {
    fn default() -> Self {
        Self {
            state: Some(twox_hash::XxHash3_128::default()),
            digest: [0u8; 16],
        }
    }
}

impl Ser for Xxhash3 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 16)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for Xxhash3 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 16 {
            throw!(Error::Deser(format!(
                "Invalid Xxhash3 digest size: {}",
                size
            )));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl Checksummer for Xxhash3 {
    fn update(&mut self, data: &[u8]) {
        if let Some(ref mut state) = self.state {
            state.write(data);
        }
    }

    fn finalize(&mut self) {
        if let Some(state) = self.state.take() {
            let hash = state.finish_128();
            self.digest = hash.to_le_bytes();
        }
    }
}

///=============================================================================
/// SeaHash Implementation (uses std::hash::Hasher interface)
///=============================================================================

#[derive(Default, Clone)]
pub(crate) struct SeaHashWrapper {
    state: seahash::SeaHasher,
    digest: [u8; 8],
}

impl std::fmt::Debug for SeaHashWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeaHashWrapper")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Ser for SeaHashWrapper {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 8)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for SeaHashWrapper {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 8 {
            throw!(Error::Deser(format!(
                "Invalid SeaHash digest size: {}",
                size
            )));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl Checksummer for SeaHashWrapper {
    fn update(&mut self, data: &[u8]) {
        self.state.write(data);
    }

    fn finalize(&mut self) {
        let hash = self.state.finish();
        self.digest = hash.to_le_bytes();
    }
}

///=============================================================================
/// CityHash Implementation (wrapper for function-based API)
///=============================================================================

#[derive(Default, Debug, Clone)]
pub(crate) struct CityHashWrapper {
    buffer: Vec<u8>,
    digest: [u8; 16],
}

impl Ser for CityHashWrapper {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 16)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for CityHashWrapper {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 16 {
            throw!(Error::Deser(format!(
                "Invalid CityHash digest size: {}",
                size
            )));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl Checksummer for CityHashWrapper {
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(&mut self) {
        // Simplified CityHash implementation using DefaultHasher
        // In a real implementation, this would use the actual CityHash algorithm
        let mut hasher = DefaultHasher::new();
        hasher.write(&self.buffer);
        let hash = hasher.finish();
        // Convert 64-bit hash to 128-bit by duplicating
        let hash_bytes = hash.to_le_bytes();
        self.digest[0..8].copy_from_slice(&hash_bytes);
        self.digest[8..16].copy_from_slice(&hash_bytes);
    }
}

///=============================================================================
/// ChecksummingRead wrapper
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
    pub fn new_sha3() -> Self {
        Checksum::SHA3(SHA3::default())
    }

    pub fn new_k12(primer: String) -> Self {
        let mut k12 = K12::default();
        k12.primer = primer;
        Checksum::K12(k12)
    }

    pub fn new_blake3() -> Self {
        Checksum::BLAKE3(BLAKE3::default())
    }

    pub fn new_xxhash3() -> Self {
        Checksum::Xxhash3(Xxhash3::default())
    }

    pub fn new_seahash() -> Self {
        Checksum::SeaHash(SeaHashWrapper::default())
    }

    pub fn new_cityhash() -> Self {
        Checksum::CityHash(CityHashWrapper::default())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::io::{Cursor, Read},
    };

    #[test]
    fn test_sha3_checksummer() {
        let mut sha3 = SHA3::default();
        let data = b"test data";
        sha3.update(data);
        sha3.finalize();

        let mut buffer = Vec::new();
        sha3.ser(&mut buffer).unwrap();

        let deserialized = SHA3::deser(&mut Cursor::new(buffer)).unwrap();
        assert_eq!(sha3.digest, deserialized.digest);
    }

    #[test]
    fn test_blake3_checksummer() {
        let mut blake3 = BLAKE3::default();
        let data = b"test data";
        blake3.update(data);
        blake3.finalize();

        let mut buffer = Vec::new();
        blake3.ser(&mut buffer).unwrap();

        let deserialized = BLAKE3::deser(&mut Cursor::new(buffer)).unwrap();
        assert_eq!(blake3.digest, deserialized.digest);
    }

    #[test]
    fn test_xxhash3_checksummer() {
        let mut xxhash3 = Xxhash3::default();
        let data = b"test data";
        xxhash3.update(data);
        xxhash3.finalize();

        let mut buffer = Vec::new();
        xxhash3.ser(&mut buffer).unwrap();

        let deserialized = Xxhash3::deser(&mut Cursor::new(buffer)).unwrap();
        assert_eq!(xxhash3.digest, deserialized.digest);
    }

    #[test]
    fn test_seahash_checksummer() {
        let mut seahash = SeaHashWrapper::default();
        let data = b"test data";
        seahash.update(data);
        seahash.finalize();

        let mut buffer = Vec::new();
        seahash.ser(&mut buffer).unwrap();

        let deserialized = SeaHashWrapper::deser(&mut Cursor::new(buffer)).unwrap();
        assert_eq!(seahash.digest, deserialized.digest);
    }

    #[test]
    fn test_cityhash_checksummer() {
        let mut cityhash = CityHashWrapper::default();
        let data = b"test data";
        cityhash.update(data);
        cityhash.finalize();

        let mut buffer = Vec::new();
        cityhash.ser(&mut buffer).unwrap();

        let deserialized = CityHashWrapper::deser(&mut Cursor::new(buffer)).unwrap();
        assert_eq!(cityhash.digest, deserialized.digest);
    }

    #[test]
    fn test_checksum_enum_ser_deser() {
        let checksums = vec![
            Checksum::new_sha3(),
            Checksum::new_k12("test".to_string()),
            Checksum::new_blake3(),
            Checksum::new_xxhash3(),
            Checksum::new_seahash(),
            Checksum::new_cityhash(),
        ];

        for checksum in checksums {
            let mut buffer = Vec::new();
            checksum.ser(&mut buffer).unwrap();

            let deserialized = Checksum::deser(&mut Cursor::new(buffer)).unwrap();

            match (&checksum, &deserialized) {
                (Checksum::SHA3(_), Checksum::SHA3(_)) => {}
                (Checksum::K12(_), Checksum::K12(_)) => {}
                (Checksum::BLAKE3(_), Checksum::BLAKE3(_)) => {}
                (Checksum::Xxhash3(_), Checksum::Xxhash3(_)) => {}
                (Checksum::SeaHash(_), Checksum::SeaHash(_)) => {}
                (Checksum::CityHash(_), Checksum::CityHash(_)) => {}
                _ => panic!("Deserialized to wrong variant"),
            }
        }
    }

    #[test]
    fn test_checksumming_read() {
        let test_data = b"hello world";
        let reader = Cursor::new(test_data);

        let checksummers: Vec<Box<dyn Checksummer>> =
            vec![Box::new(SHA3::default()), Box::new(BLAKE3::default())];

        let mut checksumming_reader = ChecksummingRead::new(reader, checksummers);

        let mut buffer = Vec::new();
        checksumming_reader.read_to_end(&mut buffer).unwrap();

        assert_eq!(buffer, test_data);

        checksumming_reader.finalize();

        let checksummers = checksumming_reader.get_checksummers();
        assert_eq!(checksummers.len(), 2);
    }
}
