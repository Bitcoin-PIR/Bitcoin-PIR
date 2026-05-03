//! 192-bit unsigned integer type, equivalent to the C++ __m192i.

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct M192i {
    pub u: [u64; 3],
}

impl M192i {
    pub fn new() -> Self {
        Self { u: [0, 0, 0] }
    }

    pub fn set1(v: u64) -> Self {
        Self { u: [v, 0, 0] }
    }

    pub fn set_pwr2(pwr: u32) -> Self {
        let mut s = Self::new();
        let idx = (pwr >> 6) as usize;
        let bit = pwr & 0x3f;
        if idx < 3 {
            s.u[idx] = 1u64 << bit;
        }
        s
    }

    /// Add a u64 with carry propagation.
    pub fn addc(&mut self, v: u64) {
        let (r0, c0) = self.u[0].overflowing_add(v);
        self.u[0] = r0;
        let (r1, c1) = self.u[1].overflowing_add(c0 as u64);
        self.u[1] = r1;
        self.u[2] = self.u[2].wrapping_add(c1 as u64);
    }

    /// Subtract a u64 with borrow propagation.
    pub fn subc(&mut self, v: u64) {
        let (r0, b0) = self.u[0].overflowing_sub(v);
        self.u[0] = r0;
        let (r1, b1) = self.u[1].overflowing_sub(b0 as u64);
        self.u[1] = r1;
        self.u[2] = self.u[2].wrapping_sub(b1 as u64);
    }

    /// Multiply by a u64 with carry propagation.
    pub fn mulc(&mut self, v: u64) {
        let r0 = (self.u[0] as u128) * (v as u128);
        let r1 = (self.u[1] as u128) * (v as u128);
        let r2 = self.u[2].wrapping_mul(v);

        self.u[0] = r0 as u64;
        let hi0 = (r0 >> 64) as u64;

        let sum1 = r1 + (hi0 as u128);
        self.u[1] = sum1 as u64;
        let hi1 = (sum1 >> 64) as u64;

        self.u[2] = r2.wrapping_add(hi1);
    }

    /// Divide by v and return the remainder.
    pub fn divremc(&mut self, v: u64) -> u64 {
        let mut rem = self.u[2] % v;
        self.u[2] /= v;

        let num1 = ((rem as u128) << 64) | (self.u[1] as u128);
        self.u[1] = (num1 / (v as u128)) as u64;
        rem = (num1 % (v as u128)) as u64;

        let num0 = ((rem as u128) << 64) | (self.u[0] as u128);
        self.u[0] = (num0 / (v as u128)) as u64;
        rem = (num0 % (v as u128)) as u64;

        rem
    }

    /// Count significant bits.
    pub fn bitwidth(&self) -> u32 {
        if self.u[2] != 0 {
            return 128 + (64 - self.u[2].leading_zeros());
        }
        if self.u[1] != 0 {
            return 64 + (64 - self.u[1].leading_zeros());
        }
        if self.u[0] != 0 {
            return 64 - self.u[0].leading_zeros();
        }
        0
    }

    /// Population count across all 192 bits.
    pub fn popcnt(&self) -> u32 {
        self.u[0].count_ones() + self.u[1].count_ones() + self.u[2].count_ones()
    }

    pub fn is_zero(&self) -> bool {
        (self.u[0] | self.u[1] | self.u[2]) == 0
    }

    /// Returns true if self > other.
    pub fn cmpgt(&self, other: &M192i) -> bool {
        if self.u[2] != other.u[2] {
            return self.u[2] > other.u[2];
        }
        if self.u[1] != other.u[1] {
            return self.u[1] > other.u[1];
        }
        self.u[0] > other.u[0]
    }

    /// Get the byte representation (little-endian).
    pub fn as_bytes(&self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[0..8].copy_from_slice(&self.u[0].to_le_bytes());
        bytes[8..16].copy_from_slice(&self.u[1].to_le_bytes());
        bytes[16..24].copy_from_slice(&self.u[2].to_le_bytes());
        bytes
    }

    /// Load from a byte slice (little-endian, up to 24 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut s = Self::new();
        let len = bytes.len().min(24);
        let mut buf = [0u8; 24];
        buf[..len].copy_from_slice(&bytes[..len]);
        s.u[0] = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        s.u[1] = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        s.u[2] = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        s
    }
}
