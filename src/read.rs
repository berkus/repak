pub struct ReadPipeline {
    decrypt: Option<Decryptor>,
    decompress: Option<Decompressor>,
    checksum: Vec<Checksummer>,
}

impl Read for ReadPipeline {
    fn read() {
        self.decrypt.map(|e| e.load(buf)); // TODO: get the decrypted buf back
        self.decompress.map(|c| c.load(buf)); // TODO: get the decompressed buf back
        for checksum in self.checksum {
            checksum.update(buf);
        }
    }
}

// Before reading,
// we need to be able to read "serializable" parts of all checksummers, compressor and encryptor from the index entry
// and set it as pre-requisites on the pipeline elements.
// NB: decryption keys might need to be provided externally!

impl ReadPipeline {
    pub fn set_decryption_key() -> Result<()> {} // FIXME ....
}
