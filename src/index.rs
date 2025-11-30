use {
    crate::{
        Error,
        checksum::ChecksumHeader,
        compress::CompressionHeader,
        encrypt::EncryptionHeader,
        io::{Deser, Ser, deser_string, ser_string},
    },
    byteorder::{ReadBytesExt, WriteBytesExt},
    culpa::{throw, throws},
    std::{
        collections::BTreeMap,
        io::{Read, Write},
        path::PathBuf,
    },
};

//==============================================================================
// IndexHeader
//==============================================================================

#[derive(Default)]
pub struct IndexHeader {
    entries: BTreeMap<(String, Vec<Attribute>), IndexEntry>,
    checksum: ChecksumHeader,
}

impl IndexHeader {
    #[throws]
    pub fn lookup(&self, id: impl AsRef<str>, attributes: &[Attribute]) -> Option<&IndexEntry> {
        self.entries.get((id.as_ref(), attributes))
    }
}

impl Ser for IndexHeader {
    // Serialize the index. If zstd compression is needed, pass a compressing writer as `w`.
    // Checksumming will be enabled automatically based on the selected checksumming options.
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        w.write_all(b"REPAK")?;
        w.write_u8(0x1)?; // Version 1
        self.checksum.ser(w)?; // need to run checksum calculations first...

        let w = self.checksum.build_ingress_pipeline(w);

        // starting from here, use the checksumming pipeline

        leb128::write::unsigned(w, self.entries.len() as u64)?;

        // Sort entries by name and attributes for easier lookup (see spec)
        let mut sorted = self.entries.values().collect::<Vec<_>>();
        sorted.sort_by(|a, b| a.name.cmp(&b.name)); // TODO: attributes!

        for entry in &mut sorted {
            eprintln!("Entry: {entry:?}");
            entry.ser(w)?;
        }
    }
}

impl Deser for IndexHeader {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let mut buf = [0u8; 5];
        r.read_exact(&mut buf)?; // peek exact!
        // if first four bytes are "0x28, 0xB5, 0x2F, 0xFD" then it's `zstd` compressed
        // if &buf == b"\x28\xb5\x2f\xfd" { // @todo
        //    let mut decoder = zstd::Decoder::new(r)?;
        //   let mut decoded = Vec::new();
        // decoder.read_to_end(&mut decoded)?;
        // r = Cursor::new(decoded);
        // return IndexHeader::deser(r); // call itself to parse decompressed data
        // }
        if &buf != b"REPAK" {
            throw!(Error::Deser("Not a REPAK archive".to_string()));
        }
        let version = r.read_u8()?;
        if version != 1 {
            throw!(Error::Deser(format!(
                "Unsupported REPAK version 0x{version:2x}"
            )));
        }

        let checksum = ChecksumHeader::deser(r)?;

        // wrap r into a ChecksummingRead with selected checksummers, verify the integrity of the index
        // @todo checksumming reader starting from here

        let count = leb128::read::unsigned(r)?;

        let mut entries = BTreeMap::new();
        // entries.extend_reserve(count);
        for _ in 0..count {
            let entry = IndexEntry::deser(r)?;
            entries.insert((entry.name.clone(), entry.attributes.clone()), entry);
        }

        IndexHeader { entries, checksum }
    }
}

//==============================================================================
// IndexEntry
//==============================================================================

#[derive(Default, Debug)] // temp?
pub struct IndexEntry {
    pub(crate) offset: u64,
    pub(crate) size: u64,
    pub(crate) name: String,
    pub(crate) attributes: Vec<Attribute>, // Sorted by key
    pub(crate) encryption: Option<EncryptionHeader>,
    pub(crate) compression: Option<CompressionHeader>,
    pub(crate) checksum: Option<ChecksumHeader>,

    path: PathBuf,
}

impl Ser for IndexEntry {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        let flags = u64::from(self.encryption.is_some())
            | (u64::from(self.compression.is_some()) << 1)
            | (u64::from(self.checksum.is_some()) << 2);

        leb128::write::unsigned(w, self.offset)?;
        leb128::write::unsigned(w, self.size)?;
        leb128::write::unsigned(w, flags)?;
        ser_string(w, &self.name)?;
        self.attributes.ser(w)?;
        if let Some(encryption) = &self.encryption {
            encryption.ser(w)?;
        }
        if let Some(compression) = &self.compression {
            compression.ser(w)?;
        }
        if let Some(checksum) = &self.checksum {
            checksum.ser(w)?;
        }
    }
}

impl Deser for IndexEntry {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let offset = leb128::read::unsigned(r)?;
        let size = leb128::read::unsigned(r)?;
        let flags = leb128::read::unsigned(r)?;
        let name = deser_string(r)?;
        let attributes = Vec::<Attribute>::deser(r)?;
        let encryption = if flags & 0x0001 != 0 {
            Some(EncryptionHeader::deser(r)?)
        } else {
            None
        };
        let compression = if flags & 0x0002 != 0 {
            Some(CompressionHeader::deser(r)?)
        } else {
            None
        };
        let checksum = if flags & 0x0004 != 0 {
            Some(ChecksumHeader::deser(r)?)
        } else {
            None
        };

        Self {
            offset,
            size,
            name: name.clone(),
            attributes,
            encryption,
            compression,
            checksum,
            path: PathBuf::from(name),
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Attribute {
    key: String,
    value: Vec<u8>,
}

impl Ser for Attribute {
    #[throws(Error)]
    fn ser(&self, w: &mut impl Write) {
        ser_string(w, &self.key)?;
        leb128::write::unsigned(w, u64::try_from(self.value.len())?)?;
        w.write_all(&self.value);
    }
}

impl Deser for Attribute {
    #[throws(Error)]
    fn deser(r: &mut impl Read) -> Self {
        let key = deser_string(r)?;
        let len = leb128::read::unsigned(r)?;
        let mut value = vec![0; usize::try_from(len)?]; // Attack vector: too long array
        r.read_exact(&mut value)?;
        Self { key, value }
    }
}
