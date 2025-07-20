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

#[throws(Error)]
pub(crate) fn ser_string(w: &mut impl Write, str: &str) {
    leb128::write::unsigned(w, str.len() as u64)?;
    w.write_all(str.as_bytes())?;
}

#[throws(Error)]
pub(crate) fn deser_string(r: &mut impl Read) -> String {
    let name_len = leb128::read::unsigned(r)?;
    let mut data = vec![0; usize::try_from(name_len)?]; // Attack vec: too long string
    r.read_exact(&mut data)?;
    String::from_utf8(data)?
}
