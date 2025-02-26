use {
    crate::Error,
    std::io::{Read, Write},
};

pub trait Ser {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error>;
}

pub trait Deser: Sized {
    fn deser(r: &mut impl Read) -> Result<Self, Error>;
}

// Calculate written size of an unsigned leb128 representation.
pub fn leb128_usize(val: u64) -> Result<usize, std::io::Error> {
    let mut c = std::io::Cursor::new([0u8; 10]);
    leb128::write::unsigned(&mut c, val)
}
