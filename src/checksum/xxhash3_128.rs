use {
    crate::{
        Error,
        io::{Deser, Ser},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[test]
fn test_xxhash3_128_checksummer() {
    use {
        super::{Checksummer, tests::TEST_DATA},
        std::io::Cursor,
    };

    let mut xxhash3 = Xxhash3::default();
    xxhash3.update(TEST_DATA);
    xxhash3.finalize();

    assert_eq!(xxhash3.digest.len(), 16);

    assert_eq!(
        const_hex::encode(xxhash3.digest),
        "8fd709a6307216e40ef92d653ff5e596"
    );

    // Test that the same input produces the same output
    let mut xxhash3_2 = Xxhash3::default();
    xxhash3_2.update(TEST_DATA);
    xxhash3_2.finalize();
    assert_eq!(xxhash3.digest, xxhash3_2.digest);

    // Test serialization/deserialization
    let mut buffer = Vec::new();
    xxhash3.ser(&mut buffer).unwrap();
    let deserialized = Xxhash3::deser(&mut Cursor::new(buffer)).unwrap();
    assert_eq!(xxhash3.digest, deserialized.digest);
}

#[derive(Clone)]
pub struct Xxhash3 {
    state: Option<twox_hash::XxHash3_128>,
    digest: [u8; 16],
}

impl std::fmt::Debug for Xxhash3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xxhash3")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Default for Xxhash3 {
    fn default() -> Self {
        Self {
            state: Some(twox_hash::XxHash3_128::default()),
            digest: [0u8; 16],
        }
    }
}

impl Ser for Xxhash3 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 16)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for Xxhash3 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 16 {
            throw!(Error::Deser(format!("Invalid Xxhash3 digest size: {size}")));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl super::Checksummer for Xxhash3 {
    fn update(&mut self, data: &[u8]) {
        if let Some(ref mut state) = self.state {
            state.write(data);
        }
    }

    fn finalize(&mut self) {
        if let Some(state) = self.state.take() {
            let hash = state.finish_128();
            self.digest = hash.to_le_bytes();
        }
    }
}
