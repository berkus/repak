use {
    crate::{
        Error,
        io::{Deser, Ser},
    },
    std::io::{Read, Write},
};

#[derive(Default)]
pub(crate) struct ChecksumHeader {
    size: u64,
    count: u64,
    checksums: Vec<Checksum>,
}

impl Ser for ChecksumHeader {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        leb128::write::unsigned(w, self.size)?;
        leb128::write::unsigned(w, self.count)?;
        for c in &self.checksums {
            c.ser(w)?;
        }
        Ok(())
    }
}

impl Deser for ChecksumHeader {
    fn deser(r: &mut impl Read) -> Result<Self, Error> {
        let size = leb128::read::unsigned(r)?;
        let count = leb128::read::unsigned(r)?;
        let mut checksums = Vec::with_capacity(count as usize);
        for _ in 0..count {
            checksums.push(Checksum::deser(r)?);
        }
        Ok(Self {
            size,
            count,
            checksums,
        })
    }
}

struct Checksum {
    kind: ChecksumKind,
    payload: Vec<u8>, // @todo
}

impl Ser for Checksum {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        leb128::write::unsigned(w, self.kind as u64)?;
        w.write_all(&self.payload)?;
        Ok(())
    }
}

impl Deser for Checksum {
    fn deser(r: &mut impl Read) -> Result<Self, Error> {
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
        Ok(Self { kind, payload })
    }
}

#[derive(Clone, Copy)]
pub enum ChecksumKind {
    SHA3 = 1,
    K12 = 2,
    BLAKE3 = 3,
    Xxhash3 = 4,
    MetroHash = 5,
    SeaHash = 6,
    CityHash = 7,
}

impl TryFrom<u64> for ChecksumKind {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::SHA3),
            2 => Ok(Self::K12),
            3 => Ok(Self::BLAKE3),
            4 => Ok(Self::Xxhash3),
            5 => Ok(Self::MetroHash),
            6 => Ok(Self::SeaHash),
            7 => Ok(Self::CityHash),
            _ => Err(Error::Deser(format!("Unknown checksum kind: {}", value))),
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

    fn ser_type(&self, w: &mut impl Write) -> Result<(), Error> {
        w.write_all(&Self::TYPE.to_le_bytes())?;
        Ok(())
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
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        w.write_all(&self.digest)?;
        Ok(())
    }
}
