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
        if inner.page_size() != plaintext_page_size + AEAD_OVERHEAD {
            return Err(Error::InvalidInput(format!(
                "encrypted store page size {} != plaintext {} + overhead {}",
                inner.page_size(),
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
}

impl<S: PageStore> PageStore for AeadPageStore<S> {
    fn page_size(&self) -> usize {
        self.plaintext_page_size
    }

    fn page_count(&self) -> usize {
        self.inner.page_count()
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        if out.len() != self.plaintext_page_size {
            return Err(Error::InvalidInput(format!(
                "plaintext output len {} != page_size {}",
                out.len(),
                self.plaintext_page_size
            )));
        }
        let mut sealed = vec![0u8; self.inner.page_size()];
        self.inner.read_page(page_idx, &mut sealed)?;

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
        )?;
        if plaintext.len() != self.plaintext_page_size {
            return Err(Error::Aead);
        }
        out.copy_from_slice(&plaintext);
        sealed.zeroize();
        Ok(())
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
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

        let mut sealed = Vec::with_capacity(self.inner.page_size());
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        self.inner.write_page(page_idx, &sealed)?;
        sealed.zeroize();
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}
