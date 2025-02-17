pub trait Ser {
    fn ser(&self, w: impl Write) -> Result<(), Error>;
}

pub trait Deser {
    fn deser(r: impl Read) -> Result<Self, Error>;
}
