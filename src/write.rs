use crate::{Checksum, CompressionAlgorithm, EncryptionAlgorithm};

pub struct WritePipeline {
    checksum: Vec<Checksum>,
    compress: Option<CompressionAlgorithm>,
    encrypt: Option<EncryptionAlgorithm>,
}

impl WritePipeline {
    pub fn new(
        checksummers: &[Checksum],
        compressor: Option<CompressionAlgorithm>,
        encryptor: Option<EncryptionAlgorithm>,
    ) -> Self {
        Self {
            checksum: checksummers.to_vec(),
            compress: compressor,
            encrypt: encryptor,
        }
    }

    fn encryption_header(&self) -> Option<EncryptionAlgorithm> {}
    fn compression_header(&self) -> Option<CompressionAlgorithm> {}
    fn checksum_header(&self) -> Vec<Checksum> {}
}

// Writing the source on this end will pass
// might need to use the framing from tokio here - the encryption usually wants blocks of certain size, which doesn't match the compression windows
// might want to know windows sizes for both before setting up framed?
// probably use AsyncRead and AsyncWrite instead of just Read and Write??
impl Write for WritePipeline {
    fn write() {
        for checksum in self.checksum {
            checksum.update(buf);
        }
        self.compress.map(|c| c.write(buf)); // TODO: get the compressed buf back
        self.encrypt.map(|e| e.write(buf));
    }
}

// After writing,
// we need to be able to access "serializable" parts of all checksummers, compressor and encryptor
// to be able to set them in the index entry.
