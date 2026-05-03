use std::sync::Arc;

use parking_lot::RwLock;
use rawdb::Region;

use crate::{Bytes, Error, Result, Stamp, Version};

use super::Format;

const HEADER_VERSION: Version = Version::TWO;
pub const HEADER_OFFSET: usize = size_of::<HeaderInner>();

#[derive(Debug, Clone)]
pub struct Header {
    inner: Arc<RwLock<HeaderInner>>,
    modified: bool,
}

impl Header {
    pub fn create_and_write(region: &Region, vec_version: Version, format: Format) -> Result<Self> {
        let inner = HeaderInner::create_and_write(region, vec_version, format)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            modified: false,
        })
    }

    pub fn import_and_verify(
        region: &Region,
        vec_version: Version,
        format: Format,
    ) -> Result<Self> {
        let inner = HeaderInner::import_and_verify(region, vec_version, format)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
            modified: false,
        })
    }

    pub fn update_stamp(&mut self, stamp: Stamp) {
        let mut inner = self.inner.write();
        if inner.stamp != stamp {
            self.modified = true;
            inner.stamp = stamp;
        }
    }

    pub fn update_computed_version(&mut self, computed_version: Version) {
        let mut inner = self.inner.write();
        if inner.computed_version != computed_version {
            self.modified = true;
            inner.computed_version = computed_version;
        }
    }

    #[inline(always)]
    pub fn modified(&self) -> bool {
        self.modified
    }

    #[inline(always)]
    pub fn vec_version(&self) -> Version {
        self.inner.read().vec_version
    }

    #[inline(always)]
    pub fn computed_version(&self) -> Version {
        self.inner.read().computed_version
    }

    #[inline(always)]
    pub fn stamp(&self) -> Stamp {
        self.inner.read().stamp
    }

    pub fn write(&mut self, region: &Region) -> Result<()> {
        self.inner.read().write(region)?;
        self.modified = false;
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
struct HeaderInner {
    pub header_version: Version,
    pub vec_version: Version,
    pub computed_version: Version,
    pub stamp: Stamp,
    pub format: Format,
}

impl HeaderInner {
    pub fn create_and_write(region: &Region, vec_version: Version, format: Format) -> Result<Self> {
        let header = Self {
            header_version: HEADER_VERSION,
            vec_version,
            computed_version: Version::default(),
            stamp: Stamp::default(),
            format,
        };
        header.write(region)?;
        Ok(header)
    }

    pub fn write(&self, region: &Region) -> Result<()> {
        region.write_at(&self.to_bytes(), 0)?;
        Ok(())
    }

    pub fn import_and_verify(
        region: &Region,
        vec_version: Version,
        format: Format,
    ) -> Result<Self> {
        let len = region.meta().len();

        if len < HEADER_OFFSET {
            return Err(Error::WrongLength {
                expected: HEADER_OFFSET,
                received: len,
            });
        }

        let reader = region.create_reader();
        let vec = reader.unchecked_read(0, HEADER_OFFSET);
        let header = HeaderInner::from_bytes(vec)?;

        if header.header_version != HEADER_VERSION {
            return Err(Error::DifferentVersion {
                received: header.header_version,
                expected: HEADER_VERSION,
            });
        }
        if header.vec_version != vec_version {
            return Err(Error::DifferentVersion {
                received: header.vec_version,
                expected: vec_version,
            });
        }

        if header.format != format {
            return Err(Error::DifferentFormat {
                received: header.format,
                expected: format,
            });
        }

        Ok(header)
    }

    fn to_bytes(&self) -> [u8; HEADER_OFFSET] {
        let mut buf = [0u8; HEADER_OFFSET];
        let mut pos = 0;
        let hv = self.header_version.to_bytes();
        buf[pos..pos + hv.len()].copy_from_slice(&hv);
        pos += hv.len();
        let vv = self.vec_version.to_bytes();
        buf[pos..pos + vv.len()].copy_from_slice(&vv);
        pos += vv.len();
        let cv = self.computed_version.to_bytes();
        buf[pos..pos + cv.len()].copy_from_slice(&cv);
        pos += cv.len();
        let s = self.stamp.to_bytes();
        buf[pos..pos + s.len()].copy_from_slice(&s);
        pos += s.len();
        let f = self.format.to_bytes();
        buf[pos..pos + f.len()].copy_from_slice(&f);
        // remaining bytes are already zero (padding)
        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let len = bytes.len();
        if len < HEADER_OFFSET {
            return Err(Error::WrongLength {
                expected: HEADER_OFFSET,
                received: len,
            });
        }
        let header_version = Version::from_bytes(&bytes[0..4])?;
        let vec_version = Version::from_bytes(&bytes[4..8])?;
        let computed_version = Version::from_bytes(&bytes[8..12])?;
        let stamp = Stamp::from_bytes(&bytes[12..20])?;
        let format = Format::from_bytes(&bytes[20..21])?;
        Ok(Self {
            header_version,
            vec_version,
            computed_version,
            stamp,
            format,
        })
    }
}
