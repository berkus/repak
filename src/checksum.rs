use {
    crate::{
        Error,
        io::{Deser, Ser},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[derive(Default, Debug)]
pub(crate) struct ChecksumHeader {
    size: u64,
    count: u64,
    checksums: Vec<Checksum>,
}

impl Ser for ChecksumHeader {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, self.size)?;
        leb128::write::unsigned(w, self.count)?;
        for c in &self.checksums {
            c.ser(w)?;
        }
    }
}

impl Deser for ChecksumHeader {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        let count = leb128::read::unsigned(r)?;
        let mut checksums = Vec::with_capacity(count as usize);
        for _ in 0..count {
            checksums.push(Checksum::deser(r)?);
        }
        Self {
            size,
            count,
            checksums,
        }
    }
}

#[derive(Debug)]
struct Checksum {
    kind: ChecksumKind,
    payload: Vec<u8>, // @todo
}

impl Ser for Checksum {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, self.kind as u64)?;
        w.write_all(&self.payload)?;
    }
}

impl Deser for Checksum {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let kind = ChecksumKind::try_from(leb128::read::unsigned(r)?)?;
        let payload = match kind {
            ChecksumKind::SHA3 => vec![],
            ChecksumKind::K12 => vec![],
            ChecksumKind::BLAKE3 => vec![],
            ChecksumKind::Xxhash3 => vec![],
            ChecksumKind::MetroHash => vec![],
            ChecksumKind::SeaHash => vec![],
            ChecksumKind::CityHash => vec![],
        };
        Self { kind, payload }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ChecksumKind {
    SHA3,
    K12,
    BLAKE3,
    Xxhash3,
    MetroHash,
    SeaHash,
    CityHash,
}

impl TryFrom<u64> for ChecksumKind {
    type Error = Error;

    #[throws(Self::Error)]
    fn try_from(value: u64) -> Self {
        match value {
            1 => Self::SHA3,
            2 => Self::K12,
            3 => Self::BLAKE3,
            4 => Self::Xxhash3,
            5 => Self::MetroHash,
            6 => Self::SeaHash,
            7 => Self::CityHash,
            _ => throw!(Error::Deser(format!("Unknown checksum kind: {}", value))),
        }
    }
}

///=============================================================================
///=============================================================================
///=============================================================================
///=============================================================================
///=============================================================================
///=============================================================================
///=============================================================================

pub trait ChecksumX {
    const TYPE: u16;
    const N: usize;

    #[throws(Error)]
    fn ser_type(&self, w: &mut impl Write) {
        w.write_all(&Self::TYPE.to_le_bytes())?;
    }
}

struct SHA3 {
    digest: [u8; 64],
}

impl ChecksumX for SHA3 {
    const TYPE: u16 = 0x0001;
    const N: usize = 64;
}

impl Ser for SHA3 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        w.write_all(&self.digest)?;
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
