use {
    crate::{
        Error,
        io::{Deser, Ser},
    },
    core::hash::Hasher,
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[test]
fn test_seahash_64_checksummer() {
    use {
        super::{Checksummer, tests::TEST_DATA},
        std::io::Cursor,
    };

    let mut seahash = SeaHash::default();
    seahash.update(TEST_DATA);
    seahash.finalize();

    assert_eq!(seahash.digest.len(), 8);

    assert_eq!(const_hex::encode(seahash.digest), "7302c33a9825ceb8");

    // Test that the same input produces the same output
    let mut seahash_2 = SeaHash::default();
    seahash_2.update(TEST_DATA);
    seahash_2.finalize();
    assert_eq!(seahash.digest, seahash_2.digest);

    // Test serialization/deserialization
    let mut buffer = Vec::new();
    seahash.ser(&mut buffer).unwrap();
    let deserialized = SeaHash::deser(&mut Cursor::new(buffer)).unwrap();
    assert_eq!(seahash.digest, deserialized.digest);
}

#[derive(Default, Clone)]
pub struct SeaHash {
    state: seahash::SeaHasher,
    digest: [u8; 8],
}

impl std::fmt::Debug for SeaHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeaHashWrapper")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Ser for SeaHash {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 8)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for SeaHash {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 8 {
            throw!(Error::Deser(format!("Invalid SeaHash digest size: {size}")));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl super::Checksummer for SeaHash {
    fn update(&mut self, data: &[u8]) {
        self.state.write(data);
    }

    fn finalize(&mut self) {
        let hash = self.state.finish();
        self.digest = hash.to_le_bytes();
    }
}
