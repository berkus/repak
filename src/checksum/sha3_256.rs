use {
    crate::{
        Error,
        io::{Load, Save},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
    tiny_keccak::Hasher as TinyKeccakHasher,
};

#[test]
fn test_sha3_256_checksummer() {
    use {
        super::{Checksummer, tests::TEST_DATA},
        std::io::Cursor,
    };

    let mut sha3 = SHA3::default();
    sha3.update(TEST_DATA);
    sha3.finalize();

    assert_eq!(sha3.digest.len(), 32);

    assert_eq!(
        const_hex::encode(sha3.digest),
        "250437a3f52595ecfbfcab1641d511c83c65f6314fa8c7d35924fe3e3c30cc62"
    );

    // Test that the same input produces the same output
    let mut sha3_2 = SHA3::default();
    sha3_2.update(TEST_DATA);
    sha3_2.finalize();
    assert_eq!(sha3.digest, sha3_2.digest);

    // Test serialization/deserialization
    let mut buffer = Vec::new();
    sha3.save(&mut buffer).unwrap();
    let deserialized = SHA3::load(&mut Cursor::new(buffer)).unwrap();
    assert_eq!(sha3.digest, deserialized.digest);
}

#[derive(Clone)]
pub struct SHA3 {
    state: Option<tiny_keccak::Sha3>,
    digest: [u8; 32],
}

impl std::fmt::Debug for SHA3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SHA3")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Default for SHA3 {
    fn default() -> Self {
        Self {
            state: Some(tiny_keccak::Sha3::v256()),
            digest: [0u8; 32],
        }
    }
}

impl Save for SHA3 {
    #[throws(Error)]
    fn save(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 32)?;
        w.write_all(&self.digest)?;
    }
}

impl Load for SHA3 {
    #[throws(Error)]
    fn load(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 32 {
            throw!(Error::Deser(format!("Invalid SHA3 digest size: {size}")));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl super::Checksummer for SHA3 {
    fn update(&mut self, data: &[u8]) {
        if let Some(ref mut state) = self.state {
            TinyKeccakHasher::update(state, data);
        }
    }

    fn finalize(&mut self) {
        if let Some(state) = self.state.take() {
            TinyKeccakHasher::finalize(state, &mut self.digest);
        }
    }
}
