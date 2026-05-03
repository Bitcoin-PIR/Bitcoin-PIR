//! KTM: Key/Tweak Management using SMAC.

use crate::bigint::M192i;
use crate::simd::*;
use crate::smac::*;

pub struct Ktm {
    pub a1: V128,
    pub a2: V128,
    pub a3: V128,
}

impl Ktm {
    pub unsafe fn new() -> Self {
        Self { a1: zero(), a2: zero(), a3: zero() }
    }

    pub unsafe fn key_init_m192(&mut self, key: &[u8; 16], app_id: u64, qmax: &M192i) {
        let a1 = from_u64x2(app_id, 1u64 | (qmax.u[2] << 48));
        let a2 = load128(key.as_ptr());
        let a3 = from_u64x2(qmax.u[0], qmax.u[1]);
        let (r1, r2, r3) = smac_initfinal1(a1, a2, a3);
        self.a1 = r1;
        self.a2 = r2;
        self.a3 = r3;
    }

    pub unsafe fn key_init_u64(&mut self, key: &[u8; 16], app_id: u64, qmax: u64) {
        let a1 = from_u64x2(app_id, 1u64);
        let a2 = load128(key.as_ptr());
        let a3 = from_u64x2(qmax, 0);
        let (r1, r2, r3) = smac_initfinal1(a1, a2, a3);
        self.a1 = r1;
        self.a2 = r2;
        self.a3 = r3;
    }

    pub unsafe fn tweak_init(
        &self,
        rk_out: &mut [V128],
        rk_num: usize,
        c: u32,
        tweak: &[u8; 16],
        ysz: u64,
        y: *const u16,
    ) {
        let sc = from_bytes(&SMAC_CONST_BYTES);
        let (mut a1, mut a2, mut a3) = (self.a1, self.a2, self.a3);

        let m = load128(tweak.as_ptr());
        (a1, a2, a3) = smac_round(a1, a2, a3, m);

        if ysz > 0 {
            (a1, a2, a3) = smac_round(a1, a2, a3, sc);
            smac_compress_u16(&mut a1, &mut a2, &mut a3, ysz as i64, y);
        }

        let mut m = from_u32_low(c);
        let mut idx = 0;

        loop {
            let (b1, b2, b3) = smac_initfinal(a1, a2, a3, m);
            rk_out[idx] = b1;
            rk_out[idx + 1] = b2;
            rk_out[idx + 2] = b3;
            idx += 3;
            if idx >= rk_num { break; }
            m = add8(m, sc);
        }
    }
}
