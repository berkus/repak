use {
    crate::{
        Error,
        io::{Deser, Ser, deser_string, ser_string},
    },
    culpa::throws,
    std::io::{Read, Write},
    tiny_keccak::Hasher as TinyKeccakHasher,
};

#[test]
fn test_k12_256_checksummer() {
    use {
        super::{Checksummer, tests::TEST_DATA},
        std::io::Cursor,
    };

    let mut k12 = K12 {
        primer: "test_primer".to_string(),
        ..Default::default()
    };
    k12.update(TEST_DATA);
    k12.finalize();

    assert_eq!(k12.digest.len(), 32);

    assert_eq!(
        const_hex::encode(k12.digest),
        "1c43a25474a1106afe9b0a067d7f42f9b760cae8ff0001294ad3fd805dfed7f0"
    );

    // Test that the same input produces the same output
    let mut k12_2 = K12 {
        primer: "test_primer".to_string(),
        ..Default::default()
    };
    k12_2.update(TEST_DATA);
    k12_2.finalize();
    assert_eq!(k12.digest, k12_2.digest);

    // Test that different primer produces different output
    let mut k12_2 = K12 {
        primer: "another_test_primer".to_string(),
        ..Default::default()
    };
    k12_2.update(TEST_DATA);
    k12_2.finalize();
    assert_ne!(k12.digest, k12_2.digest);

    // Test serialization/deserialization
    let mut buffer = Vec::new();
    k12.ser(&mut buffer).unwrap();
    let deserialized = K12::deser(&mut Cursor::new(buffer)).unwrap();
    assert_eq!(k12.primer, deserialized.primer);
    assert_eq!(k12.digest, deserialized.digest);
}

#[derive(Clone, Default)]
pub struct K12 {
    state: Option<tiny_keccak::KangarooTwelve<String>>,
    primer: String,
    digest: [u8; 32],
}

impl std::fmt::Debug for K12 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K12")
            .field("primer", &self.primer)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Ser for K12 {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        ser_string(w, &self.primer)?;
        w.write_all(&self.digest)?;
    }
}

impl Deser for K12 {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let primer = deser_string(r)?;
        let mut digest = [0u8; 32];
        r.read_exact(&mut digest)?;
        Self {
            state: Some(tiny_keccak::KangarooTwelve::new(primer.clone())),
            primer,
            digest,
        }
    }
}

impl super::Checksummer for K12 {
    fn update(&mut self, data: &[u8]) {
        if self.state.is_none() {
            self.state = Some(tiny_keccak::KangarooTwelve::new(self.primer.clone()));
        }
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
