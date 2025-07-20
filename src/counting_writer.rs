use std::io::Write;

/// A writer that counts bytes written without storing them
pub(crate) struct CountingWriter {
    count: u64,
}

impl CountingWriter {
    pub fn new() -> Self {
        Self { count: 0 }
    }

    pub fn count(&self) -> u64 {
        self.count
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.count += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
