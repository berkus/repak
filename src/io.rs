use {
    crate::Error,
    culpa::throws,
    std::io::{Read, Write},
};

pub trait Ser {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write);
}

pub trait Deser: Sized {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self;
}

// Calculate written size of an unsigned leb128 representation.
#[throws(std::io::Error)]
pub fn leb128_usize(val: u64) -> usize {
    let mut c = std::io::Cursor::new([0u8; 10]);
    leb128::write::unsigned(&mut c, val)?
}
