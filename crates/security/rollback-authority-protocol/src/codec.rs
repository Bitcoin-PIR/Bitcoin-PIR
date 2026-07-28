use sha2::{Digest, Sha256};

use crate::RollbackAuthorityProtocolErrorV1;

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn fixed<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], RollbackAuthorityProtocolErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(RollbackAuthorityProtocolErrorV1::InvalidLength)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(RollbackAuthorityProtocolErrorV1::InvalidLength)?;
        let mut value = [0_u8; N];
        value.copy_from_slice(source);
        self.offset = end;
        Ok(value)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, RollbackAuthorityProtocolErrorV1> {
        Ok(self.fixed::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, RollbackAuthorityProtocolErrorV1> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, RollbackAuthorityProtocolErrorV1> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    pub(crate) const fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn finish(self) -> Result<(), RollbackAuthorityProtocolErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(RollbackAuthorityProtocolErrorV1::NonCanonicalEncoding)
        }
    }
}

pub(crate) fn put_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u64(target: &mut Vec<u8>, value: u64) {
    target.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn domain_hash_v1(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

pub(crate) fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
