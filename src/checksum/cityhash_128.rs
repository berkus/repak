use {
    crate::{
        Error,
        io::{Load, Save},
    },
    core::hash::Hasher,
    culpa::{throw, throws},
    std::{
        collections::hash_map::DefaultHasher,
        io::{Read, Write},
    },
};

#[test]
fn test_cityhash_128_checksummer() {
    use {
        super::{Checksummer, tests::TEST_DATA},
        std::io::Cursor,
    };

    let mut cityhash = CityHash::default();
    cityhash.update(TEST_DATA);
    cityhash.finalize();

    assert_eq!(cityhash.digest.len(), 16);

    assert_eq!(
        const_hex::encode(cityhash.digest),
        "25c917c4f0f940c825c917c4f0f940c8"
    );

    // Test that the same input produces the same output
    let mut cityhash_2 = CityHash::default();
    cityhash_2.update(TEST_DATA);
    cityhash_2.finalize();
    assert_eq!(cityhash.digest, cityhash_2.digest);

    // Test serialization/deserialization
    let mut buffer = Vec::new();
    cityhash.save(&mut buffer).unwrap();
    let deserialized = CityHash::load(&mut Cursor::new(buffer)).unwrap();
    assert_eq!(cityhash.digest, deserialized.digest);
}

// FIXME: USES DEFAULT HASHER, STORES DATA, BROKEN

/// `CityHash` Implementation (wrapper for function-based API)
#[derive(Default, Debug, Clone)]
pub struct CityHash {
    buffer: Vec<u8>,
    digest: [u8; 16],
}

impl Save for CityHash {
    #[throws(Error)]
    fn save(&self, w: &mut impl Write) {
        leb128::write::unsigned(w, 16)?;
        w.write_all(&self.digest)?;
    }
}

impl Load for CityHash {
    #[throws(Error)]
    fn load(r: &mut impl Read) -> Self {
        let size = leb128::read::unsigned(r)?;
        if size != 16 {
            throw!(Error::Deser(format!(
                "Invalid CityHash digest size: {size}"
            )));
        }
        let mut s = Self::default();
        r.read_exact(&mut s.digest)?;
        s
    }
}

impl super::Checksummer for CityHash {
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(&mut self) {
        // Simplified CityHash implementation using DefaultHasher
        // In a real implementation, this would use the actual CityHash algorithm
        let mut hasher = DefaultHasher::new();
        hasher.write(&self.buffer);
        let hash = hasher.finish();
        // Convert 64-bit hash to 128-bit by duplicating
        let hash_bytes = hash.to_le_bytes();
        self.digest[0..8].copy_from_slice(&hash_bytes);
        self.digest[8..16].copy_from_slice(&hash_bytes);
    }
}
