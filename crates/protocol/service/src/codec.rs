//! Small checked canonical-codec helpers.

use crate::ServiceProtocolError;

pub(crate) fn put_bytes_u16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn put_bytes_u32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

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

    pub(crate) fn u32(&mut self, field: &'static str) -> Result<u32, ServiceProtocolError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("checked four-byte slice"),
        ))
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

    pub(crate) fn bytes_u8(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        let len = self.u8(field)? as usize;
        self.bounded_bytes(field, len, max)
    }

    pub(crate) fn bytes_u16(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        let len = self.u16(field)? as usize;
        self.bounded_bytes(field, len, max)
    }

    pub(crate) fn bytes_u32(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        let len_u32 = self.u32(field)?;
        let len = usize::try_from(len_u32).map_err(|_| ServiceProtocolError::FieldTooLong {
            field,
            len: usize::MAX,
            max,
        })?;
        self.bounded_bytes(field, len, max)
    }

    pub(crate) fn string_u16(
        &mut self,
        field: &'static str,
        max: usize,
    ) -> Result<String, ServiceProtocolError> {
        let bytes = self.bytes_u16(field, max)?;
        String::from_utf8(bytes).map_err(|_| ServiceProtocolError::InvalidUtf8(field))
    }

    pub(crate) fn take_remaining(&mut self) -> &'a [u8] {
        let rest = &self.bytes[self.pos..];
        self.pos = self.bytes.len();
        rest
    }

    fn bounded_bytes(
        &mut self,
        field: &'static str,
        len: usize,
        max: usize,
    ) -> Result<Vec<u8>, ServiceProtocolError> {
        if len > max {
            return Err(ServiceProtocolError::FieldTooLong { field, len, max });
        }
        Ok(self.take(len, field)?.to_vec())
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
