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
            Checksum::SeaHash(_) => 5,
            Checksum::CityHash(_) => 6,
        })?;
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
            5 => Checksum::SeaHash(SeaHash::deser(r)?),
            6 => Checksum::CityHash(CityHash::deser(r)?),
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

trait Checksummer {
    fn update(&mut self, data: &[u8]);
    fn finalize(&mut self);
}

macro_rules! declare_checksummer {
    ($name:ident, $state:ty, $digest:ty) => {
        /// Calculate the $name checksum of a byte slice.
        #[derive(Default, Debug, Clone, Copy)]
        struct $name {
            state: $state,
            digest: $digest,
        }

        impl Ser for $name {
            #[throws(Error)]
            fn ser(&self, w: &mut impl Write) {
                w.write_all(&self.digest)?;
            }
        }

        impl Deser for $name {
            #[throws(Error)]
            fn deser(r: &mut impl Read) -> Self {
                let mut s = Self {
                    digest: <$digest>::default(),
                    state: <$state>::default(),
                };
                r.read(&mut s.digest)?;
                s
            }
        }

        impl Checksummer for $name {
            fn update(&mut self, data: &[u8]) {
                self.state.update(data);
            }

            fn finalize(&mut self) {
                self.digest = self.state.finalize();
            }
        }
    };
}

declare_checksummer!(SHA3, tiny_keccak::Sha3, [u8; 32]);
declare_checksummer!(BLAKE3, blake3::Hasher, [u8; 32]);
declare_checksummer!(K12, tiny_keccak::K12, K12State);
declare_checksummer!(Xxhash3, twoxhash::XxHash128, [u8; 16]);
// declare_checksummer!(MetroHash, fasthash::MetroHash, [u8; 16]);
declare_checksummer!(SeaHash, seahash::SeaHash, [u8; 8]);
declare_checksummer!(CityHash, cityhash_rs::CityHash128, [u8; 16]);

///=============================================================================

#[derive(Default, Debug, Clone)]
struct K12State {
    primer: String,
    digest: [u8; 32],
}

impl Ser for K12State {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        ser_string(w, &self.primer)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for K12State {
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

// #[throws(Error)]
// fn setup_checksumming<R: std::io::BufRead>(
//     r: &mut R,
//     k: ChecksumKind,
// ) -> impl std::io::Read {
//     //
//     // return a Read impl that wraps the source Read with checksumming state
//     // you could chain multiple checksumming wrapppers
// }

struct ChecksummingReader<R, C>
where
    R: Read,
    C: Checksummer,
{
    reader: R,
    checksums: Vec<C>,
}

impl ChecksummingReader {
    pub fn new(reader: R, checksummers: &[u16]) -> Self {
        Self {
            reader,
            checksums: checksummers
                .map(|id| match id {
                    0 => SeaHash::default(),
                    1 => CityHash::default(),
                    _ => panic!("unknown checksum id"),
                })
                .collect(),
        }
    }

    pub fn finalize(&mut self) -> Vec<[u8; 16]> {
        self.checksums.iter_mut().map(|c| c.finalize()).collect()
    }
}

impl Read for ChecksummingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}
