trait Checksum {
    const Type: u16;
    const N: usize;
}

struct SHA3 {
    digest: [u8; 64],
}

impl Checksum for SHA3 {
    const Type: u16 = 0x0001;
    const N: usize = 64;
}

impl SHA3 {
    fn ser_type(&self, w: impl Write) -> Result<(), Error> {
        w.write_all(&Self::Type.to_le_bytes())?;
        Ok(())
    }
}

impl Ser for SHA3 {
    fn ser(&self, w: impl Write) -> Result<(), Error> {
        w.write_all(&self.digest)?;
        Ok(())
    }
}
