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
