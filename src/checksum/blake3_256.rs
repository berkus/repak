use {
    crate::{
        Error,
        io::{Load, Save},
    },
    culpa::{throw, throws},
    std::io::{Read, Write},
};

#[test]
fn test_blake3_256_checksummer() {
    use {
        super::{Checksummer, tests::TEST_DATA},
        std::io::Cursor,
    };

    let mut blake3 = BLAKE3::default();
    blake3.update(TEST_DATA);
    blake3.finalize();

    assert_eq!(blake3.digest.len(), 32);

    assert_eq!(
        const_hex::encode(blake3.digest),
        "dd00777d1c1d80caa995e65a0f3c8867ec5114bcf2d2db97d7471a7a3fc35ead"
    );

    // Test that the same input produces the same output
    let mut blake3_2 = BLAKE3::default();
    blake3_2.update(TEST_DATA);
    blake3_2.finalize();
    assert_eq!(blake3.digest, blake3_2.digest);

    // Test serialization/deserialization
    let mut buffer = Vec::new();
    blake3.save(&mut buffer).unwrap();
    let deserialized = BLAKE3::load(&mut Cursor::new(buffer)).unwrap();
    assert_eq!(blake3.digest, deserialized.digest);
}

#[derive(Clone)]
pub struct BLAKE3 {
    state: Option<Box<blake3::Hasher>>,
    digest: [u8; 32],
}

impl std::fmt::Debug for BLAKE3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BLAKE3")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Default for BLAKE3 {
    fn default() -> Self {
        Self {
            state: Some(Box::new(blake3::Hasher::new())),
            digest: [0u8; 32],
        }
    }
}

// this is for saving the HASH itself, not for passing data through it...
impl Save for BLAKE3 {
    #[throws(Error)]
    fn save(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 32)?;
        w.write_all(&self.digest)?;
    }
}

impl Load for BLAKE3 {
    #[throws(Error)]
    fn load(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 32 {
            throw!(Error::Deser(format!("Invalid BLAKE3 digest size: {size}")));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl super::Checksummer for BLAKE3 {
    fn update(&mut self, data: &[u8]) {
        if let Some(ref mut state) = self.state {
            state.update(data);
        }
    }

    fn finalize(&mut self) {
        if let Some(state) = self.state.take() {
            let hash = state.finalize();
            self.digest = *hash.as_bytes();
        }
    }
}
