struct LoadPipeline {
    decrypt: Option<Decryptor>,
    decompress: Option<Decompressor>,
    checksum: Vec<Checksummer>,
}

impl Read for LoadPipeline {
    fn read() {
        self.decrypt.map(|e| e.load(buf)); // TODO: get the decrypted buf back
        self.decompress.map(|c| c.load(buf)); // TODO: get the decompressed buf back
        for checksum in self.checksum {
            checksum.update(buf);
        }
    }
}
