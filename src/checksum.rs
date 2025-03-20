use {
    crate::{
        Error,
        io::{Deser, Ser, deser_string},
        ser_string,
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[derive(Default, Debug)]
pub(crate) struct ChecksumHeader {
    pub(crate) count: u64, // @todo calculated field
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
        Self { count, checksums }
    }
}

#[derive(Clone, Debug)]
pub enum Checksum {
    SHA3(SHA3),
    K12(K12),
    BLAKE3(BLAKE3),
    Xxhash3(Xxhash3),
    MetroHash(MetroHash),
    SeaHash(SeaHash),
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
        leb128::write::unsigned(w, match self {
            Checksum::SHA3(_) => 1,
            Checksum::K12(_) => 2,
            Checksum::BLAKE3(_) => 3,
            Checksum::Xxhash3(_) => 4,
            Checksum::MetroHash(_) => 5,
            Checksum::SeaHash(_) => 6,
            Checksum::CityHash(_) => 7,
        })?;
        match self {
            Checksum::SHA3(sha3) => sha3.ser(w)?,
            Checksum::K12(k12) => k12.ser(w)?,
            Checksum::BLAKE3(blake3) => blake3.ser(w)?,
            Checksum::Xxhash3(xxhash3) => xxhash3.ser(w)?,
            Checksum::MetroHash(metrohash) => metrohash.ser(w)?,
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
            5 => Checksum::MetroHash(MetroHash::deser(r)?),
            6 => Checksum::SeaHash(SeaHash::deser(r)?),
            7 => Checksum::CityHash(CityHash::deser(r)?),
            _ => throw!(Error::Deser(format!("Unknown checksum kind: {kind}"))),
        }
    }
}

///=============================================================================
///=============================================================================
///=============================================================================
///=============================================================================
///=============================================================================
///=============================================================================

#[derive(Default, Debug, Clone, Copy)]
struct SHA3 {
    digest: [u8; 32],
}

impl Ser for SHA3 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        w.write_all(&self.digest)?;
    }
}

impl Deser for SHA3 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let mut s = Self { digest: [0u8; 32] };
        r.read(&mut s.digest)?;
        s
    }
}

///=============================================================================

#[derive(Default, Debug, Clone)]
struct K12 {
    primer: String,
    digest: [u8; 32],
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
        let mut s = Self {
            primer: String::new(),
            digest: [0u8; 32],
        };
        s.primer = deser_string(r)?;
        r.read(&mut s.digest)?;
        s
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct BLAKE3 {
    digest: [u8; 32],
}

impl Ser for BLAKE3 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        w.write_all(&self.digest)?;
    }
}

impl Deser for BLAKE3 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let mut s = Self { digest: [0u8; 32] };
        r.read(&mut s.digest)?;
        s
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct Xxhash3 {
    digest: [u8; 16],
}

impl Ser for Xxhash3 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        w.write_all(&self.digest)?;
    }
}

impl Deser for Xxhash3 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let mut s = Self { digest: [0u8; 16] };
        r.read(&mut s.digest)?;
        s
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct MetroHash {
    digest: [u8; 16],
}

impl Ser for MetroHash {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        w.write_all(&self.digest)?;
    }
}

impl Deser for MetroHash {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let mut s = Self { digest: [0u8; 16] };
        r.read(&mut s.digest)?;
        s
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct SeaHash {
    digest: [u8; 8],
}

impl Ser for SeaHash {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        w.write_all(&self.digest)?;
    }
}

impl Deser for SeaHash {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let mut s = Self { digest: [0u8; 8] };
        r.read(&mut s.digest)?;
        s
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct CityHash {
    digest: [u8; 16],
}

impl Ser for CityHash {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        w.write_all(&self.digest)?;
    }
}

impl Deser for CityHash {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let mut s = Self { digest: [0u8; 16] };
        r.read(&mut s.digest)?;
        s
    }
}

// #[throws(Error)]
// fn setup_checksumming<R: std::io::BufRead>(
//     r: &mut R,
//     k: ChecksumKind,
// ) -> impl std::io::Read {
//     //
//     // return a Read impl that wraps the source Read with checksumming state
//     // you could chain multiple checksumming wrapppers
// }
