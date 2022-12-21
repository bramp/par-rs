use std::io::Read;
use std::mem;

pub trait ReadHasher : Read {
    /// Reset the currently computed hash.
    fn reset(&mut self);

    /// Computes the hash.
    fn compute(&mut self) -> md5::Digest;
}

/// Md5Reader wraps an existing Read and hashes all the data read.
pub struct Md5Reader<R: Read> {
    inner: R,
    hasher: md5::Context,
}

impl<R: Read> Md5Reader<R> {
    /// Create a new Md5Reader
    pub fn new(inner: R) -> Md5Reader<R> {
        Md5Reader {
            inner,
            hasher: md5::Context::new(),
        }
    }
}

impl<R: Read> ReadHasher for Md5Reader<R> {
    fn reset(&mut self) {
        self.hasher = md5::Context::new();
    }

    fn compute(&mut self) -> md5::Digest {
        // Swap out the hasher with a fresh one
        let hasher = mem::replace(&mut self.hasher, md5::Context::new());

        // and consume/finalise the old one
        hasher.compute()
    }
}

impl<R: Read> Read for Md5Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let amount = self.inner.read(buf)?;
        self.hasher.consume(&buf[0..amount]);
        Ok(amount)
    }
}

