use crate::{Error, PageStore, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

/// Bytes added by [`AeadPageStore`] to every physical page.
pub const AEAD_OVERHEAD: usize = 12 + 16;

/// AEAD wrapper for page storage.
///
/// Every write uses a fresh random nonce and stores `nonce || ciphertext || tag`
/// in the wrapped store. The page index is authenticated as associated data.
pub struct AeadPageStore<S> {
    inner: S,
    cipher: ChaCha20Poly1305,
    plaintext_page_size: usize,
}

impl<S: PageStore> AeadPageStore<S> {
    /// Wrap an existing physical page store.
    pub fn new(inner: S, key: [u8; 32], plaintext_page_size: usize) -> Result<Self> {
        if PageStore::page_size(&inner) != plaintext_page_size + AEAD_OVERHEAD {
            return Err(Error::InvalidInput(format!(
                "encrypted store page size {} != plaintext {} + overhead {}",
                PageStore::page_size(&inner),
                plaintext_page_size,
                AEAD_OVERHEAD
            )));
        }
        let cipher = ChaCha20Poly1305::new((&key).into());
        Ok(Self {
            inner,
            cipher,
            plaintext_page_size,
        })
    }

    /// Consume the wrapper.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn decrypt_page(&self, page_idx: usize, sealed: &mut [u8]) -> Result<Vec<u8>> {
        if sealed.len() != PageStore::page_size(&self.inner) {
            return Err(Error::InvalidInput(format!(
                "sealed page len {} != inner page_size {}",
                sealed.len(),
                PageStore::page_size(&self.inner)
            )));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&sealed[..12]);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = page_idx.to_le_bytes();
        let plaintext = self.cipher.decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &sealed[12..],
                aad: &aad,
            },
        );
        sealed.zeroize();
        let plaintext = plaintext?;
        if plaintext.len() != self.plaintext_page_size {
            return Err(Error::Aead);
        }
        Ok(plaintext)
    }

    fn encrypt_page(&self, page_idx: usize, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() != self.plaintext_page_size {
            return Err(Error::InvalidInput(format!(
                "plaintext input len {} != page_size {}",
                input.len(),
                self.plaintext_page_size
            )));
        }

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = page_idx.to_le_bytes();
        let ciphertext = self.cipher.encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: input,
                aad: &aad,
            },
        )?;
        debug_assert_eq!(ciphertext.len(), self.plaintext_page_size + 16);

        let mut sealed = Vec::with_capacity(PageStore::page_size(&self.inner));
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }
}

impl<S: PageStore> PageStore for AeadPageStore<S> {
    fn page_size(&self) -> usize {
        self.plaintext_page_size
    }

    fn page_count(&self) -> usize {
        PageStore::page_count(&self.inner)
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        if out.len() != self.plaintext_page_size {
            return Err(Error::InvalidInput(format!(
                "plaintext output len {} != page_size {}",
                out.len(),
                self.plaintext_page_size
            )));
        }
        let mut sealed = vec![0u8; PageStore::page_size(&self.inner)];
        self.inner.read_page(page_idx, &mut sealed)?;
        let plaintext = self.decrypt_page(page_idx, &mut sealed)?;
        out.copy_from_slice(&plaintext);
        Ok(())
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        let mut sealed = self.encrypt_page(page_idx, input)?;
        self.inner.write_page(page_idx, &sealed)?;
        sealed.zeroize();
        Ok(())
    }

    fn read_pages(&mut self, page_indices: &[usize]) -> Result<Vec<Vec<u8>>> {
        let mut sealed_pages = self.inner.read_pages(page_indices)?;
        let mut pages = Vec::with_capacity(page_indices.len());
        for (&page_idx, sealed) in page_indices.iter().zip(&mut sealed_pages) {
            pages.push(self.decrypt_page(page_idx, sealed)?);
        }
        Ok(pages)
    }

    fn write_pages(&mut self, page_indices: &[usize], pages: &[Vec<u8>]) -> Result<()> {
        if page_indices.len() != pages.len() {
            return Err(Error::InvalidInput(format!(
                "page index count {} != page count {}",
                page_indices.len(),
                pages.len()
            )));
        }

        let mut sealed_pages = Vec::with_capacity(pages.len());
        for (&page_idx, page) in page_indices.iter().zip(pages) {
            sealed_pages.push(self.encrypt_page(page_idx, page)?);
        }
        let result = self.inner.write_pages(page_indices, &sealed_pages);
        for sealed in &mut sealed_pages {
            sealed.zeroize();
        }
        result
    }

    fn flush(&mut self) -> Result<()> {
        PageStore::flush(&mut self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrontCachedPageStore, MemPageStore};

    #[derive(Debug)]
    struct BulkCountingStore {
        inner: MemPageStore,
        read_page_calls: usize,
        write_page_calls: usize,
        read_pages_calls: usize,
        write_pages_calls: usize,
        last_read_pages: Vec<usize>,
        last_write_pages: Vec<usize>,
    }

    impl BulkCountingStore {
        fn new(page_count: usize, page_size: usize) -> Self {
            Self {
                inner: MemPageStore::new(page_count, page_size).unwrap(),
                read_page_calls: 0,
                write_page_calls: 0,
                read_pages_calls: 0,
                write_pages_calls: 0,
                last_read_pages: Vec::new(),
                last_write_pages: Vec::new(),
            }
        }
    }

    impl PageStore for BulkCountingStore {
        fn page_size(&self) -> usize {
            PageStore::page_size(&self.inner)
        }

        fn page_count(&self) -> usize {
            PageStore::page_count(&self.inner)
        }

        fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
            self.read_page_calls += 1;
            self.inner.read_page(page_idx, out)
        }

        fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
            self.write_page_calls += 1;
            self.inner.write_page(page_idx, input)
        }

        fn read_pages(&mut self, page_indices: &[usize]) -> Result<Vec<Vec<u8>>> {
            self.read_pages_calls += 1;
            self.last_read_pages = page_indices.to_vec();
            self.inner.read_pages(page_indices)
        }

        fn write_pages(&mut self, page_indices: &[usize], pages: &[Vec<u8>]) -> Result<()> {
            self.write_pages_calls += 1;
            self.last_write_pages = page_indices.to_vec();
            self.inner.write_pages(page_indices, pages)
        }
    }

    #[test]
    fn aead_bulk_pages_use_inner_bulk_io() {
        let key = [7u8; 32];
        let inner = BulkCountingStore::new(4, 8 + AEAD_OVERHEAD);
        let mut encrypted = AeadPageStore::new(inner, key, 8).unwrap();

        encrypted
            .write_pages(&[2, 1], &[vec![22; 8], vec![11; 8]])
            .unwrap();
        let inner = encrypted.into_inner();
        assert_eq!(inner.write_pages_calls, 1);
        assert_eq!(inner.write_page_calls, 0);
        assert_eq!(inner.last_write_pages, vec![2, 1]);

        let mut encrypted = AeadPageStore::new(inner, key, 8).unwrap();
        let pages = encrypted.read_pages(&[1, 2]).unwrap();
        assert_eq!(pages, vec![vec![11; 8], vec![22; 8]]);
        let inner = encrypted.into_inner();
        assert_eq!(inner.read_pages_calls, 1);
        assert_eq!(inner.read_page_calls, 0);
        assert_eq!(inner.last_read_pages, vec![1, 2]);
    }

    #[test]
    fn aead_over_front_cache_preserves_inner_bulk_io() {
        let key = [9u8; 32];
        let inner = BulkCountingStore::new(6, 8 + AEAD_OVERHEAD);
        let cached = FrontCachedPageStore::new_zeroed(inner, 1).unwrap();
        let mut encrypted = AeadPageStore::new(cached, key, 8).unwrap();

        encrypted
            .write_pages(&[0, 2, 3], &[vec![10; 8], vec![20; 8], vec![30; 8]])
            .unwrap();
        let pages = encrypted.read_pages(&[0, 3, 2]).unwrap();
        assert_eq!(pages, vec![vec![10; 8], vec![30; 8], vec![20; 8]]);

        let cached = encrypted.into_inner();
        let inner = cached.into_inner();
        assert_eq!(inner.write_page_calls, 0);
        assert_eq!(inner.write_pages_calls, 1);
        assert_eq!(inner.last_write_pages, vec![2, 3]);
        assert_eq!(inner.read_page_calls, 0);
        assert_eq!(inner.read_pages_calls, 1);
        assert_eq!(inner.last_read_pages, vec![3, 2]);
    }
}
