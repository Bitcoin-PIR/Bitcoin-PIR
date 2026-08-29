//! Small checked canonical-codec helpers.

use crate::ServiceProtocolError;

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn finish(self) -> Result<(), ServiceProtocolError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(ServiceProtocolError::TrailingBytes(
                self.bytes.len() - self.pos,
            ))
        }
    }

    pub(crate) fn u8(&mut self, field: &'static str) -> Result<u8, ServiceProtocolError> {
        Ok(self.take(1, field)?[0])
    }

    pub(crate) fn u16(&mut self, field: &'static str) -> Result<u16, ServiceProtocolError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u64(&mut self, field: &'static str) -> Result<u64, ServiceProtocolError> {
        let bytes = self.take(8, field)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("checked eight-byte slice"),
        ))
    }

    pub(crate) fn fixed<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ServiceProtocolError> {
        let bytes = self.take(N, field)?;
        Ok(bytes.try_into().expect("checked fixed-size slice"))
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], ServiceProtocolError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(ServiceProtocolError::Truncated(field))?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or(ServiceProtocolError::Truncated(field))?;
        self.pos = end;
        Ok(value)
    }
}

pub(crate) fn expect_v1(version: u8, kind: &'static str) -> Result<(), ServiceProtocolError> {
    if version == crate::SERVICE_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ServiceProtocolError::UnknownVersion { kind, version })
    }
}
