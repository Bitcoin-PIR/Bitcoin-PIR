use std::fs::File;

use crate::Result;

/// Actual disk usage (accounts for sparse files / holes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskUsage(u64);

impl DiskUsage {
    #[cfg(unix)]
    pub fn from_file(file: &File) -> Result<Self> {
        use std::os::unix::io::AsRawFd;

        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::fstat(file.as_raw_fd(), &mut stat) };
        if result == -1 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(stat.st_blocks as u64 * 512))
    }

    #[cfg(not(unix))]
    pub fn from_file(file: &File) -> Result<Self> {
        Ok(Self(file.metadata()?.len()))
    }

    #[inline]
    pub fn bytes(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for DiskUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const KIB: u64 = 1024;
        const MIB: u64 = KIB * 1024;
        const GIB: u64 = MIB * 1024;

        let bytes = self.0;
        if bytes >= GIB {
            write!(f, "{:.1} GiB", bytes as f64 / GIB as f64)
        } else if bytes >= MIB {
            write!(f, "{:.1} MiB", bytes as f64 / MIB as f64)
        } else if bytes >= KIB {
            write!(f, "{:.1} KiB", bytes as f64 / KIB as f64)
        } else {
            write!(f, "{} B", bytes)
        }
    }
}
