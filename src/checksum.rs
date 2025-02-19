use {
    crate::{Error, io::Ser},
    std::io::Write,
};

trait Checksum {
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

impl Checksum for SHA3 {
    const TYPE: u16 = 0x0001;
    const N: usize = 64;
}

impl Ser for SHA3 {
    fn ser(&self, w: &mut impl Write) -> Result<(), Error> {
        w.write_all(&self.digest)?;
        Ok(())
    }
}
