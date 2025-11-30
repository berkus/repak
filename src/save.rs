struct SavePipeline {
    checksum: Vec<Checksummer>,
    compress: Option<Compressor>,
    encrypt: Option<Encryptor>,
}

/// might need to use the framing from tokio here - the encryption usually wants blocks of certain size, which doesn't match the compression windows
/// might want to know windows sizes for both before setting up framed?
impl Write for SavePipeline {
    fn write() {
        for checksum in self.checksum {
            checksum.update(buf);
        }
        self.compress.map(|c| c.write(buf)); // TODO: get the compressed buf back
        self.encrypt.map(|e| e.write(buf));
    }
}
