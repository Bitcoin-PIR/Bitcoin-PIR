//! ALF-n-t cipher core for n=[2..15], t=[0..7].
//! Handles moduli in the range [2^15+1 .. 2^127].
//!
//! Single-block operations use the platform-abstracted V128 type.
//! Batch operations use platform-specific wide types:
//!   - aarch64: 4 × V128 registers (hand-interleaved)
//!   - x86_64 AVX-512 VAES: V512 (4 lanes in one register)

use crate::bigint::M192i;
use crate::ktm::Ktm;
use crate::profile::ALF_PROFILES;
use crate::simd::*;

pub struct AlfNt {
    pub rk: [V128; 28],
    // Pre-cached profile vectors
    enc_sigma: V128,
    enc_beta: V128,
    dec_alpha: V128,
    dec_beta: V128,
    dec_sigma: V128,
    dec_tau: V128,
    rho: V128,
    a_const: V128,
    // Pre-computed composite shuffle masks
    enc_beta_sigma: V128,
    enc_rho_sigma: V128,
    dec_beta_sigma: V128,
    dec_rho_sigma: V128,
    // Cipher control vectors
    b: V128,
    m: V128,
    mask_n: V128,
    merge_xe: V128,
    pub qmax: M192i,
    m1: u64,
    m0: u64,
    pub n: usize,
    pub t: usize,
    pub rounds: usize,
    pub is_binary: bool,
}

impl AlfNt {
    pub unsafe fn new() -> Self {
        Self {
            rk: [zero(); 28],
            enc_sigma: zero(), enc_beta: zero(),
            dec_alpha: zero(), dec_beta: zero(),
            dec_sigma: zero(), dec_tau: zero(),
            rho: zero(), a_const: zero(),
            enc_beta_sigma: zero(), enc_rho_sigma: zero(),
            dec_beta_sigma: zero(), dec_rho_sigma: zero(),
            b: zero(), m: zero(),
            mask_n: zero(), merge_xe: zero(),
            qmax: M192i::new(),
            m1: 0, m0: 0,
            n: 0, t: 0, rounds: 0,
            is_binary: false,
        }
    }

    pub unsafe fn engine_init(&mut self, qmax: M192i, bit_width: u32) {
        let bw = if bit_width != 0 { bit_width as usize } else { qmax.bitwidth() as usize };
        assert!(bw >= 16 && bw <= 127);

        self.is_binary = bw as u32 == qmax.popcnt();
        self.n = bw >> 3;
        self.t = bw & 7;
        self.qmax = qmax;

        let f = &ALF_PROFILES[self.n - 2];
        self.rounds = if self.t != 0 { f.rounds1 } else { f.rounds0 };

        self.enc_sigma = from_bytes(&f.enc_sigma);
        self.enc_beta = from_bytes(&f.enc_beta);
        self.dec_alpha = from_bytes(&f.dec_alpha);
        self.dec_beta = from_bytes(&f.dec_beta);
        self.dec_sigma = from_bytes(&f.dec_sigma);
        self.dec_tau = from_bytes(&f.dec_tau);
        self.rho = from_bytes(&f.rho);
        self.a_const = from_bytes(&f.a);

        self.enc_beta_sigma = combine(self.enc_beta, self.enc_sigma);
        self.enc_rho_sigma = combine(self.rho, self.enc_sigma);
        self.dec_beta_sigma = combine(self.dec_beta, self.dec_sigma);
        self.dec_rho_sigma = combine(self.rho, self.dec_sigma);

        let m_val = if self.t > 0 { (((1u32 << self.t) - 1) << 24) as u32 } else { 0 };
        self.m = from_u32_low(m_val);
        self.b = if (self.n & 3) == 3 { splat8(0x52) } else { zero() };

        let mut mask_n_bytes = [0u8; 16];
        for i in 0..self.n { mask_n_bytes[i] = 0xFF; }
        self.mask_n = from_bytes(&mask_n_bytes);

        let q: u8 = 0xF3;
        let mut tmp = [0u8; 32];
        for i in 0..16 { tmp[i] = q; }
        for i in 0..16u8 { tmp[16 + i as usize] = i; }
        let mut merge1 = [0u8; 16];
        for i in 0..15 { merge1[i] = tmp[self.n + 1 + i]; }
        merge1[15] = q;
        let mut merge_rotated = [0u8; 16];
        for i in 0..16 { merge_rotated[i] = merge1[(i + 8) % 16]; }
        self.merge_xe = from_bytes(&merge_rotated);

        let qmax_bytes = qmax.as_bytes();
        if self.n >= 7 {
            let off = self.n - 7;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&qmax_bytes[off..off + 8]);
            self.m1 = u64::from_le_bytes(buf);
            let shift = ((15 - self.n) as u32) * 8;
            self.m0 = if shift >= 64 { 0 } else { qmax.u[0] << shift };
        } else {
            let shift = ((7 - self.n) as u32) * 8;
            self.m1 = if shift >= 64 { 0 } else { qmax.u[0] << shift };
            self.m0 = 0;
        }
    }

    pub unsafe fn key_init(&self, ktm: &mut Ktm, key: &[u8; 16], app_id: u64) {
        ktm.key_init_m192(key, app_id, &self.qmax);
    }

    pub unsafe fn tweak_init(&mut self, ktm: &Ktm, tweak: &[u8; 16]) {
        let bytes = self.n * self.rounds;
        let rk_num = (bytes + 15) >> 4;
        ktm.tweak_init(&mut self.rk, rk_num, 0x1, tweak, 0, std::ptr::null());
        let rk_bytes = &self.rk as *const _ as *const u8;
        for r in (0..self.rounds).rev().step_by(2) {
            self.rk[r] = and128(load128(rk_bytes.add(self.n * r)), self.mask_n);
            self.rk[r - 1] = and128(load128(rk_bytes.add(self.n * (r - 1))), self.mask_n);
        }
    }

    pub unsafe fn prepare_decrypt(&mut self) {
        let key_beta_alpha = combine(self.enc_beta, self.dec_alpha);
        for r in (0..self.rounds).step_by(2) {
            self.rk[r] = aesimc(xor3(
                shuffle(self.rk[r], key_beta_alpha),
                shuffle(self.rk[r], self.dec_alpha),
                self.a_const,
            ));
            self.rk[r + 1] = aesimc(xor3(
                shuffle(self.rk[r + 1], key_beta_alpha),
                shuffle(self.rk[r + 1], self.dec_alpha),
                self.a_const,
            ));
        }
    }

    // ================================================================
    // Helpers
    // ================================================================

    #[inline(always)]
    unsafe fn cmpgt_max_x(&self, x: V128, e: V128, tnz: bool) -> bool {
        let g = if tnz {
            xor2(shuffle(x, self.merge_xe), slli_epi64_32(e))
        } else {
            shuffle(x, self.merge_xe)
        };
        let v0 = extract_lo64(g);
        if v0 < self.m1 { return false; }
        if v0 > self.m1 { return true; }
        extract_hi64(g) > self.m0
    }

    #[inline(always)]
    unsafe fn update_e(&self, e: V128, u: V128) -> V128 {
        and128(xor2(e, clmul_lo(u, 0x01010101u64)), self.m)
    }

    #[inline(always)]
    unsafe fn srf(&self, x: V128, end_xor: V128) -> V128 {
        aesdeclast(shuffle(x, self.dec_tau), end_xor)
    }

    // ================================================================
    // Single-block encryption (platform-independent)
    // ================================================================

    #[inline]
    unsafe fn encrypt_00(&self, buf: &mut [u8]) {
        let mut x = load128(buf.as_ptr());
        for r in (0..self.rounds).step_by(2) {
            loop {
                x = aesenc(shuffle(x, self.enc_sigma), self.rk[r]);
                x = xor2(x, shuffle(x, self.enc_beta));
                x = aesenc(shuffle(x, self.enc_sigma), self.rk[r + 1]);
                x = xor2(x, shuffle(x, self.enc_beta));
                if !self.cmpgt_max_x(x, zero(), false) { break; }
            }
        }
        store128(buf.as_mut_ptr(), blend(load128(buf.as_ptr()), x, self.mask_n));
    }

    #[inline]
    unsafe fn encrypt_01(&self, buf: &mut [u8]) {
        let mut x = load128(buf.as_ptr());
        let mut e = and128(bslli_3(load128(buf.as_ptr().add(self.n))), self.m);
        for r in (0..self.rounds).step_by(2) {
            loop {
                let u = aesenc(shuffle(x, self.enc_sigma), self.rk[r]);
                x = xor3(u, shuffle(u, self.enc_beta), shuffle(e, self.rho));
                e = self.update_e(e, u);
                let u = aesenc(shuffle(x, self.enc_sigma), self.rk[r + 1]);
                x = xor3(u, shuffle(u, self.enc_beta), shuffle(e, self.rho));
                e = self.update_e(e, u);
                if !self.cmpgt_max_x(x, e, true) { break; }
            }
        }
        store128(buf.as_mut_ptr(), blend(load128(buf.as_ptr()), x, self.mask_n));
        buf[self.n] = extract_byte::<3>(e);
    }

    #[inline]
    unsafe fn encrypt_10(&self, buf: &mut [u8]) {
        let mut x = shuffle(load128(buf.as_ptr()), self.enc_sigma);
        for r in (0..self.rounds - 2).step_by(2) {
            let u = aesenc(x, self.rk[r]);
            x = xor2(shuffle(u, self.enc_sigma), shuffle(u, self.enc_beta_sigma));
            let u = aesenc(x, self.rk[r + 1]);
            x = xor2(shuffle(u, self.enc_sigma), shuffle(u, self.enc_beta_sigma));
        }
        let u = aesenc(x, self.rk[self.rounds - 2]);
        x = xor2(shuffle(u, self.enc_sigma), shuffle(u, self.enc_beta_sigma));
        let u = aesenc(x, self.rk[self.rounds - 1]);
        x = xor2(u, shuffle(u, self.enc_beta));
        store128(buf.as_mut_ptr(), blend(load128(buf.as_ptr()), x, self.mask_n));
    }

    #[inline]
    unsafe fn encrypt_11(&self, buf: &mut [u8]) {
        let mut x = shuffle(load128(buf.as_ptr()), self.enc_sigma);
        let mut e = and128(bslli_3(load128(buf.as_ptr().add(self.n))), self.m);
        for r in (0..self.rounds - 2).step_by(2) {
            let u = aesenc(x, self.rk[r]);
            x = xor3(shuffle(u, self.enc_sigma), shuffle(u, self.enc_beta_sigma), shuffle(e, self.enc_rho_sigma));
            e = self.update_e(e, u);
            let u = aesenc(x, self.rk[r + 1]);
            x = xor3(shuffle(u, self.enc_sigma), shuffle(u, self.enc_beta_sigma), shuffle(e, self.enc_rho_sigma));
            e = self.update_e(e, u);
        }
        let u = aesenc(x, self.rk[self.rounds - 2]);
        x = xor3(shuffle(u, self.enc_sigma), shuffle(u, self.enc_beta_sigma), shuffle(e, self.enc_rho_sigma));
        e = self.update_e(e, u);
        let u = aesenc(x, self.rk[self.rounds - 1]);
        x = xor3(u, shuffle(u, self.enc_beta), shuffle(e, self.rho));
        e = self.update_e(e, u);
        store128(buf.as_mut_ptr(), blend(load128(buf.as_ptr()), x, self.mask_n));
        buf[self.n] = extract_byte::<3>(e);
    }

    // ================================================================
    // Single-block decryption (platform-independent)
    // ================================================================

    #[inline]
    unsafe fn decrypt_00(&self, buf: &mut [u8]) {
        let mut x = aesenclast(shuffle(load128(buf.as_ptr()), self.enc_sigma), zero());
        let mut y = zero();
        let mut r = self.rounds as isize - 1;
        while r >= 1 {
            loop {
                x = aesdec(shuffle(x, self.dec_sigma), self.rk[r as usize]);
                x = xor2(x, shuffle(x, self.dec_beta));
                x = aesdec(shuffle(x, self.dec_sigma), self.rk[(r - 1) as usize]);
                x = xor2(x, shuffle(x, self.dec_beta));
                y = self.srf(x, zero());
                if !self.cmpgt_max_x(y, zero(), false) { break; }
            }
            r -= 2;
        }
        store128(buf.as_mut_ptr(), blend(load128(buf.as_ptr()), y, self.mask_n));
    }

    #[inline]
    unsafe fn decrypt_01(&self, buf: &mut [u8]) {
        let mut x = aesenclast(shuffle(load128(buf.as_ptr()), self.enc_sigma), zero());
        let mut e = bslli_3(load128(buf.as_ptr().add(self.n)));
        let mut y = zero();
        let mut r = self.rounds as isize - 1;
        while r >= 1 {
            loop {
                x = aesdec(shuffle(x, self.dec_sigma), zero());
                e = self.update_e(xor2(e, self.b), x);
                x = xor2(x, self.rk[r as usize]);
                x = xor3(x, shuffle(x, self.dec_beta), shuffle(e, self.rho));
                x = aesdec(shuffle(x, self.dec_sigma), zero());
                e = self.update_e(xor2(e, self.b), x);
                x = xor2(x, self.rk[(r - 1) as usize]);
                x = xor3(x, shuffle(x, self.dec_beta), shuffle(e, self.rho));
                y = self.srf(x, zero());
                if !self.cmpgt_max_x(y, e, true) { break; }
            }
            r -= 2;
        }
        store128(buf.as_mut_ptr(), blend(load128(buf.as_ptr()), y, self.mask_n));
        buf[self.n] = extract_byte::<3>(e);
    }

    #[inline]
    unsafe fn decrypt_10(&self, buf: &mut [u8]) {
        let mut x = shuffle(aesenclast(shuffle(load128(buf.as_ptr()), self.enc_sigma), zero()), self.dec_sigma);
        let mut r = self.rounds as isize - 1;
        while r > 1 {
            x = aesdec(x, self.rk[r as usize]);
            x = xor2(shuffle(x, self.dec_sigma), shuffle(x, self.dec_beta_sigma));
            x = aesdec(x, self.rk[(r - 1) as usize]);
            x = xor2(shuffle(x, self.dec_sigma), shuffle(x, self.dec_beta_sigma));
            r -= 2;
        }
        x = aesdec(x, self.rk[1]);
        x = xor2(shuffle(x, self.dec_sigma), shuffle(x, self.dec_beta_sigma));
        x = aesdec(x, self.rk[0]);
        x = xor2(x, shuffle(x, self.dec_beta));
        let y_pad = andnot(self.mask_n, xor2(load128(buf.as_ptr()), splat8(0x52)));
        store128(buf.as_mut_ptr(), self.srf(x, y_pad));
    }

    #[inline]
    unsafe fn decrypt_11(&self, buf: &mut [u8]) {
        let mut x = shuffle(aesenclast(shuffle(load128(buf.as_ptr()), self.enc_sigma), zero()), self.dec_sigma);
        let mut e = bslli_3(load128(buf.as_ptr().add(self.n)));
        let mut r = self.rounds as isize - 1;
        while r > 1 {
            x = aesdec(x, zero());
            e = self.update_e(xor2(e, self.b), x);
            x = xor2(x, self.rk[r as usize]);
            x = xor3(shuffle(x, self.dec_sigma), shuffle(x, self.dec_beta_sigma), shuffle(e, self.dec_rho_sigma));
            x = aesdec(x, zero());
            e = self.update_e(xor2(e, self.b), x);
            x = xor2(x, self.rk[(r - 1) as usize]);
            x = xor3(shuffle(x, self.dec_sigma), shuffle(x, self.dec_beta_sigma), shuffle(e, self.dec_rho_sigma));
            r -= 2;
        }
        x = aesdec(x, zero());
        e = self.update_e(xor2(e, self.b), x);
        x = xor2(x, self.rk[1]);
        x = xor3(shuffle(x, self.dec_sigma), shuffle(x, self.dec_beta_sigma), shuffle(e, self.dec_rho_sigma));
        x = aesdec(x, zero());
        e = self.update_e(xor2(e, self.b), x);
        x = xor2(x, self.rk[0]);
        x = xor3(x, shuffle(x, self.dec_beta), shuffle(e, self.rho));
        let y_pad = andnot(self.mask_n, xor2(load128(buf.as_ptr()), splat8(0x52)));
        store128(buf.as_mut_ptr(), self.srf(x, y_pad));
        buf[self.n] = extract_byte::<3>(e);
    }

    // ================================================================
    // Public single-block API
    // ================================================================

    pub unsafe fn encrypt(&self, buf: &mut [u8]) {
        match (self.is_binary, self.t > 0) {
            (false, false) => self.encrypt_00(buf),
            (false, true)  => self.encrypt_01(buf),
            (true, false)  => self.encrypt_10(buf),
            (true, true)   => self.encrypt_11(buf),
        }
    }

    pub unsafe fn decrypt(&self, buf: &mut [u8]) {
        match (self.is_binary, self.t > 0) {
            (false, false) => self.decrypt_00(buf),
            (false, true)  => self.decrypt_01(buf),
            (true, false)  => self.decrypt_10(buf),
            (true, true)   => self.decrypt_11(buf),
        }
    }

    // ================================================================
    // Batch API: dispatches to platform-specific interleaved versions
    // ================================================================

    pub unsafe fn encrypt_batch(&self, ptrs: &mut [*mut u8]) {
        let n = ptrs.len();
        if n == 0 { return; }
        if self.is_binary {
            let mut i = 0;
            while i + 4 <= n {
                self.encrypt_batch_4(ptrs[i], ptrs[i+1], ptrs[i+2], ptrs[i+3]);
                i += 4;
            }
            while i < n {
                self.encrypt(std::slice::from_raw_parts_mut(ptrs[i], 32));
                i += 1;
            }
        } else {
            for p in ptrs.iter() {
                self.encrypt(std::slice::from_raw_parts_mut(*p, 32));
            }
        }
    }

    pub unsafe fn decrypt_batch(&self, ptrs: &mut [*mut u8]) {
        let n = ptrs.len();
        if n == 0 { return; }
        if self.is_binary {
            let mut i = 0;
            while i + 4 <= n {
                self.decrypt_batch_4(ptrs[i], ptrs[i+1], ptrs[i+2], ptrs[i+3]);
                i += 4;
            }
            while i < n {
                self.decrypt(std::slice::from_raw_parts_mut(ptrs[i], 32));
                i += 1;
            }
        } else {
            for p in ptrs.iter() {
                self.decrypt(std::slice::from_raw_parts_mut(*p, 32));
            }
        }
    }

    /// Platform dispatch for 4-way batch encrypt.
    unsafe fn encrypt_batch_4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        if self.t > 0 {
            self.encrypt_11_x4(b0, b1, b2, b3);
        } else {
            self.encrypt_10_x4(b0, b1, b2, b3);
        }
    }

    /// Platform dispatch for 4-way batch decrypt.
    unsafe fn decrypt_batch_4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        if self.t > 0 {
            self.decrypt_11_x4(b0, b1, b2, b3);
        } else {
            self.decrypt_10_x4(b0, b1, b2, b3);
        }
    }
}

// ================================================================
// aarch64 NEON: 4-way interleaved batch (4 separate V128 registers)
// ================================================================

#[cfg(target_arch = "aarch64")]
impl AlfNt {
    unsafe fn encrypt_11_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        let es = self.enc_sigma; let ebs = self.enc_beta_sigma;
        let ers = self.enc_rho_sigma; let eb = self.enc_beta;
        let rho = self.rho; let m = self.m; let n = self.n;

        let mut x0 = shuffle(load128(b0), es); let mut x1 = shuffle(load128(b1), es);
        let mut x2 = shuffle(load128(b2), es); let mut x3 = shuffle(load128(b3), es);
        let mut e0 = and128(bslli_3(load128(b0.add(n))), m);
        let mut e1 = and128(bslli_3(load128(b1.add(n))), m);
        let mut e2 = and128(bslli_3(load128(b2.add(n))), m);
        let mut e3 = and128(bslli_3(load128(b3.add(n))), m);

        let mut r = 0usize;
        while r < self.rounds - 2 {
            let rk0 = *self.rk.get_unchecked(r);
            let rk1 = *self.rk.get_unchecked(r + 1);
            macro_rules! half_round { ($rk:expr) => {
                let u0 = aesenc(x0,$rk); let u1 = aesenc(x1,$rk);
                let u2 = aesenc(x2,$rk); let u3 = aesenc(x3,$rk);
                x0=xor3(shuffle(u0,es),shuffle(u0,ebs),shuffle(e0,ers));
                x1=xor3(shuffle(u1,es),shuffle(u1,ebs),shuffle(e1,ers));
                x2=xor3(shuffle(u2,es),shuffle(u2,ebs),shuffle(e2,ers));
                x3=xor3(shuffle(u3,es),shuffle(u3,ebs),shuffle(e3,ers));
                e0=and128(xor2(e0,clmul_lo(u0,0x01010101)),m);
                e1=and128(xor2(e1,clmul_lo(u1,0x01010101)),m);
                e2=and128(xor2(e2,clmul_lo(u2,0x01010101)),m);
                e3=and128(xor2(e3,clmul_lo(u3,0x01010101)),m);
            }}
            half_round!(rk0); half_round!(rk1);
            r += 2;
        }
        // Tail
        let rka = *self.rk.get_unchecked(self.rounds-2);
        let rkb = *self.rk.get_unchecked(self.rounds-1);
        { let u0=aesenc(x0,rka);let u1=aesenc(x1,rka);let u2=aesenc(x2,rka);let u3=aesenc(x3,rka);
          x0=xor3(shuffle(u0,es),shuffle(u0,ebs),shuffle(e0,ers));
          x1=xor3(shuffle(u1,es),shuffle(u1,ebs),shuffle(e1,ers));
          x2=xor3(shuffle(u2,es),shuffle(u2,ebs),shuffle(e2,ers));
          x3=xor3(shuffle(u3,es),shuffle(u3,ebs),shuffle(e3,ers));
          e0=and128(xor2(e0,clmul_lo(u0,0x01010101)),m);e1=and128(xor2(e1,clmul_lo(u1,0x01010101)),m);
          e2=and128(xor2(e2,clmul_lo(u2,0x01010101)),m);e3=and128(xor2(e3,clmul_lo(u3,0x01010101)),m); }
        { let u0=aesenc(x0,rkb);let u1=aesenc(x1,rkb);let u2=aesenc(x2,rkb);let u3=aesenc(x3,rkb);
          x0=xor3(u0,shuffle(u0,eb),shuffle(e0,rho));x1=xor3(u1,shuffle(u1,eb),shuffle(e1,rho));
          x2=xor3(u2,shuffle(u2,eb),shuffle(e2,rho));x3=xor3(u3,shuffle(u3,eb),shuffle(e3,rho));
          e0=and128(xor2(e0,clmul_lo(u0,0x01010101)),m);e1=and128(xor2(e1,clmul_lo(u1,0x01010101)),m);
          e2=and128(xor2(e2,clmul_lo(u2,0x01010101)),m);e3=and128(xor2(e3,clmul_lo(u3,0x01010101)),m); }

        let mn = self.mask_n;
        store128(b0,blend(load128(b0),x0,mn)); *b0.add(n)=extract_byte::<3>(e0);
        store128(b1,blend(load128(b1),x1,mn)); *b1.add(n)=extract_byte::<3>(e1);
        store128(b2,blend(load128(b2),x2,mn)); *b2.add(n)=extract_byte::<3>(e2);
        store128(b3,blend(load128(b3),x3,mn)); *b3.add(n)=extract_byte::<3>(e3);
    }

    unsafe fn encrypt_10_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        let es = self.enc_sigma; let ebs = self.enc_beta_sigma; let eb = self.enc_beta;
        let mut x0=shuffle(load128(b0),es);let mut x1=shuffle(load128(b1),es);
        let mut x2=shuffle(load128(b2),es);let mut x3=shuffle(load128(b3),es);

        let mut r = 0usize;
        while r < self.rounds - 2 {
            let rk0=*self.rk.get_unchecked(r); let rk1=*self.rk.get_unchecked(r+1);
            macro_rules! hr { ($rk:expr) => {
                let u0=aesenc(x0,$rk);let u1=aesenc(x1,$rk);let u2=aesenc(x2,$rk);let u3=aesenc(x3,$rk);
                x0=xor2(shuffle(u0,es),shuffle(u0,ebs));x1=xor2(shuffle(u1,es),shuffle(u1,ebs));
                x2=xor2(shuffle(u2,es),shuffle(u2,ebs));x3=xor2(shuffle(u3,es),shuffle(u3,ebs));
            }}
            hr!(rk0); hr!(rk1); r += 2;
        }
        let rka=*self.rk.get_unchecked(self.rounds-2); let rkb=*self.rk.get_unchecked(self.rounds-1);
        { let u0=aesenc(x0,rka);let u1=aesenc(x1,rka);let u2=aesenc(x2,rka);let u3=aesenc(x3,rka);
          x0=xor2(shuffle(u0,es),shuffle(u0,ebs));x1=xor2(shuffle(u1,es),shuffle(u1,ebs));
          x2=xor2(shuffle(u2,es),shuffle(u2,ebs));x3=xor2(shuffle(u3,es),shuffle(u3,ebs)); }
        { let u0=aesenc(x0,rkb);let u1=aesenc(x1,rkb);let u2=aesenc(x2,rkb);let u3=aesenc(x3,rkb);
          x0=xor2(u0,shuffle(u0,eb));x1=xor2(u1,shuffle(u1,eb));
          x2=xor2(u2,shuffle(u2,eb));x3=xor2(u3,shuffle(u3,eb)); }
        let mn=self.mask_n;
        store128(b0,blend(load128(b0),x0,mn));store128(b1,blend(load128(b1),x1,mn));
        store128(b2,blend(load128(b2),x2,mn));store128(b3,blend(load128(b3),x3,mn));
    }

    unsafe fn decrypt_11_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        let es=self.enc_sigma;let ds=self.dec_sigma;let dbs=self.dec_beta_sigma;
        let drs=self.dec_rho_sigma;let db=self.dec_beta;let rho=self.rho;
        let m=self.m;let bc=self.b;let n=self.n;let z=zero();

        let mut x0=shuffle(aesenclast(shuffle(load128(b0),es),z),ds);
        let mut x1=shuffle(aesenclast(shuffle(load128(b1),es),z),ds);
        let mut x2=shuffle(aesenclast(shuffle(load128(b2),es),z),ds);
        let mut x3=shuffle(aesenclast(shuffle(load128(b3),es),z),ds);
        let mut e0=bslli_3(load128(b0.add(n)));let mut e1=bslli_3(load128(b1.add(n)));
        let mut e2=bslli_3(load128(b2.add(n)));let mut e3=bslli_3(load128(b3.add(n)));

        let mut r = self.rounds as isize - 1;
        while r > 1 {
            let rkh=*self.rk.get_unchecked(r as usize);
            let rkl=*self.rk.get_unchecked((r-1) as usize);
            macro_rules! dhr { ($rk:expr) => {
                x0=aesdec(x0,z);x1=aesdec(x1,z);x2=aesdec(x2,z);x3=aesdec(x3,z);
                e0=and128(xor2(xor2(e0,bc),clmul_lo(x0,0x01010101)),m);
                e1=and128(xor2(xor2(e1,bc),clmul_lo(x1,0x01010101)),m);
                e2=and128(xor2(xor2(e2,bc),clmul_lo(x2,0x01010101)),m);
                e3=and128(xor2(xor2(e3,bc),clmul_lo(x3,0x01010101)),m);
                x0=xor2(x0,$rk);x1=xor2(x1,$rk);x2=xor2(x2,$rk);x3=xor2(x3,$rk);
                x0=xor3(shuffle(x0,ds),shuffle(x0,dbs),shuffle(e0,drs));
                x1=xor3(shuffle(x1,ds),shuffle(x1,dbs),shuffle(e1,drs));
                x2=xor3(shuffle(x2,ds),shuffle(x2,dbs),shuffle(e2,drs));
                x3=xor3(shuffle(x3,ds),shuffle(x3,dbs),shuffle(e3,drs));
            }}
            dhr!(rkh); dhr!(rkl); r -= 2;
        }
        // Post-loop: RK[1] with sigma, RK[0] with plain beta+rho
        { let rk1=self.rk[1];
          x0=aesdec(x0,z);x1=aesdec(x1,z);x2=aesdec(x2,z);x3=aesdec(x3,z);
          e0=and128(xor2(xor2(e0,bc),clmul_lo(x0,0x01010101)),m);
          e1=and128(xor2(xor2(e1,bc),clmul_lo(x1,0x01010101)),m);
          e2=and128(xor2(xor2(e2,bc),clmul_lo(x2,0x01010101)),m);
          e3=and128(xor2(xor2(e3,bc),clmul_lo(x3,0x01010101)),m);
          x0=xor2(x0,rk1);x1=xor2(x1,rk1);x2=xor2(x2,rk1);x3=xor2(x3,rk1);
          x0=xor3(shuffle(x0,ds),shuffle(x0,dbs),shuffle(e0,drs));
          x1=xor3(shuffle(x1,ds),shuffle(x1,dbs),shuffle(e1,drs));
          x2=xor3(shuffle(x2,ds),shuffle(x2,dbs),shuffle(e2,drs));
          x3=xor3(shuffle(x3,ds),shuffle(x3,dbs),shuffle(e3,drs)); }
        { let rk0=self.rk[0];
          x0=aesdec(x0,z);x1=aesdec(x1,z);x2=aesdec(x2,z);x3=aesdec(x3,z);
          e0=and128(xor2(xor2(e0,bc),clmul_lo(x0,0x01010101)),m);
          e1=and128(xor2(xor2(e1,bc),clmul_lo(x1,0x01010101)),m);
          e2=and128(xor2(xor2(e2,bc),clmul_lo(x2,0x01010101)),m);
          e3=and128(xor2(xor2(e3,bc),clmul_lo(x3,0x01010101)),m);
          x0=xor2(x0,rk0);x1=xor2(x1,rk0);x2=xor2(x2,rk0);x3=xor2(x3,rk0);
          x0=xor3(x0,shuffle(x0,db),shuffle(e0,rho));x1=xor3(x1,shuffle(x1,db),shuffle(e1,rho));
          x2=xor3(x2,shuffle(x2,db),shuffle(e2,rho));x3=xor3(x3,shuffle(x3,db),shuffle(e3,rho)); }

        let mn=self.mask_n;let dt=self.dec_tau;let s52=splat8(0x52);
        store128(b0,aesdeclast(shuffle(x0,dt),andnot(mn,xor2(load128(b0),s52)))); *b0.add(n)=extract_byte::<3>(e0);
        store128(b1,aesdeclast(shuffle(x1,dt),andnot(mn,xor2(load128(b1),s52)))); *b1.add(n)=extract_byte::<3>(e1);
        store128(b2,aesdeclast(shuffle(x2,dt),andnot(mn,xor2(load128(b2),s52)))); *b2.add(n)=extract_byte::<3>(e2);
        store128(b3,aesdeclast(shuffle(x3,dt),andnot(mn,xor2(load128(b3),s52)))); *b3.add(n)=extract_byte::<3>(e3);
    }

    unsafe fn decrypt_10_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        let es=self.enc_sigma;let ds=self.dec_sigma;let dbs=self.dec_beta_sigma;
        let db=self.dec_beta;let z=zero();

        let mut x0=shuffle(aesenclast(shuffle(load128(b0),es),z),ds);
        let mut x1=shuffle(aesenclast(shuffle(load128(b1),es),z),ds);
        let mut x2=shuffle(aesenclast(shuffle(load128(b2),es),z),ds);
        let mut x3=shuffle(aesenclast(shuffle(load128(b3),es),z),ds);

        let mut r = self.rounds as isize - 1;
        while r > 1 {
            let rkh=*self.rk.get_unchecked(r as usize);
            let rkl=*self.rk.get_unchecked((r-1) as usize);
            x0=aesdec(x0,rkh);x1=aesdec(x1,rkh);x2=aesdec(x2,rkh);x3=aesdec(x3,rkh);
            x0=xor2(shuffle(x0,ds),shuffle(x0,dbs));x1=xor2(shuffle(x1,ds),shuffle(x1,dbs));
            x2=xor2(shuffle(x2,ds),shuffle(x2,dbs));x3=xor2(shuffle(x3,ds),shuffle(x3,dbs));
            x0=aesdec(x0,rkl);x1=aesdec(x1,rkl);x2=aesdec(x2,rkl);x3=aesdec(x3,rkl);
            x0=xor2(shuffle(x0,ds),shuffle(x0,dbs));x1=xor2(shuffle(x1,ds),shuffle(x1,dbs));
            x2=xor2(shuffle(x2,ds),shuffle(x2,dbs));x3=xor2(shuffle(x3,ds),shuffle(x3,dbs));
            r -= 2;
        }
        let rk1=self.rk[1];let rk0=self.rk[0];
        x0=aesdec(x0,rk1);x1=aesdec(x1,rk1);x2=aesdec(x2,rk1);x3=aesdec(x3,rk1);
        x0=xor2(shuffle(x0,ds),shuffle(x0,dbs));x1=xor2(shuffle(x1,ds),shuffle(x1,dbs));
        x2=xor2(shuffle(x2,ds),shuffle(x2,dbs));x3=xor2(shuffle(x3,ds),shuffle(x3,dbs));
        x0=aesdec(x0,rk0);x1=aesdec(x1,rk0);x2=aesdec(x2,rk0);x3=aesdec(x3,rk0);
        x0=xor2(x0,shuffle(x0,db));x1=xor2(x1,shuffle(x1,db));
        x2=xor2(x2,shuffle(x2,db));x3=xor2(x3,shuffle(x3,db));

        let mn=self.mask_n;let dt=self.dec_tau;let s52=splat8(0x52);
        store128(b0,aesdeclast(shuffle(x0,dt),andnot(mn,xor2(load128(b0),s52))));
        store128(b1,aesdeclast(shuffle(x1,dt),andnot(mn,xor2(load128(b1),s52))));
        store128(b2,aesdeclast(shuffle(x2,dt),andnot(mn,xor2(load128(b2),s52))));
        store128(b3,aesdeclast(shuffle(x3,dt),andnot(mn,xor2(load128(b3),s52))));
    }
}

// ================================================================
// x86_64 AVX-512 VAES: 4-way interleaved batch (4 lanes in one V512)
// ================================================================

#[cfg(target_arch = "x86_64")]
impl AlfNt {
    /// AVX-512 VAES encrypt_11 batch: 4 blocks in one __m512i register.
    /// Falls back to scalar if AVX-512 VAES is not available at runtime.
    unsafe fn encrypt_11_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        if is_x86_feature_detected!("vaes") && is_x86_feature_detected!("avx512bw") {
            self.encrypt_11_x4_avx512(b0, b1, b2, b3);
        } else {
            // Fallback: 4 separate scalar encryptions
            self.encrypt(std::slice::from_raw_parts_mut(b0, 32));
            self.encrypt(std::slice::from_raw_parts_mut(b1, 32));
            self.encrypt(std::slice::from_raw_parts_mut(b2, 32));
            self.encrypt(std::slice::from_raw_parts_mut(b3, 32));
        }
    }

    #[target_feature(enable = "avx512f,avx512bw,vaes,vpclmulqdq")]
    unsafe fn encrypt_11_x4_avx512(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        use crate::simd::wide::*;

        let es = self.enc_sigma; let ebs = self.enc_beta_sigma;
        let ers = self.enc_rho_sigma; let eb = self.enc_beta;
        let rho_v = self.rho; let m_v = self.m; let n = self.n;
        let m_w = broadcast(m_v);
        let clk = from_u64x2(0x01010101, 0x01010101);

        let mut x = shuffle_x4(load_4x128(b0, b1, b2, b3), es);
        let mut e = and_x4(bslli_3_x4(load_4x128(b0.add(n), b1.add(n), b2.add(n), b3.add(n))), m_w);

        let mut r = 0usize;
        let limit = self.rounds - 2;
        while r < limit {
            let rk0 = *self.rk.get_unchecked(r);
            let rk1 = *self.rk.get_unchecked(r + 1);

            let u = aesenc_x4(x, rk0);
            x = xor3_x4(shuffle_x4(u, es), shuffle_x4(u, ebs), shuffle_x4(e, ers));
            e = and_x4(xor2_x4(e, clmul_lo_x4(u, clk)), m_w);

            let u = aesenc_x4(x, rk1);
            x = xor3_x4(shuffle_x4(u, es), shuffle_x4(u, ebs), shuffle_x4(e, ers));
            e = and_x4(xor2_x4(e, clmul_lo_x4(u, clk)), m_w);

            r += 2;
        }

        let u = aesenc_x4(x, *self.rk.get_unchecked(self.rounds - 2));
        x = xor3_x4(shuffle_x4(u, es), shuffle_x4(u, ebs), shuffle_x4(e, ers));
        e = and_x4(xor2_x4(e, clmul_lo_x4(u, clk)), m_w);

        let u = aesenc_x4(x, *self.rk.get_unchecked(self.rounds - 1));
        x = xor3_x4(u, shuffle_x4(u, eb), shuffle_x4(e, rho_v));
        e = and_x4(xor2_x4(e, clmul_lo_x4(u, clk)), m_w);

        let mn_w = broadcast(self.mask_n);
        let orig = load_4x128(b0, b1, b2, b3);
        x = blend_x4(orig, x, mn_w);
        store_4x128(x, b0, b1, b2, b3);

        // Extract E bytes from each lane
        *b0.add(n) = extract_byte::<3>(extract_lane(e, 0));
        *b1.add(n) = extract_byte::<3>(extract_lane(e, 1));
        *b2.add(n) = extract_byte::<3>(extract_lane(e, 2));
        *b3.add(n) = extract_byte::<3>(extract_lane(e, 3));
    }

    unsafe fn encrypt_10_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        if is_x86_feature_detected!("vaes") && is_x86_feature_detected!("avx512bw") {
            self.encrypt_10_x4_avx512(b0, b1, b2, b3);
        } else {
            self.encrypt(std::slice::from_raw_parts_mut(b0, 32));
            self.encrypt(std::slice::from_raw_parts_mut(b1, 32));
            self.encrypt(std::slice::from_raw_parts_mut(b2, 32));
            self.encrypt(std::slice::from_raw_parts_mut(b3, 32));
        }
    }

    #[target_feature(enable = "avx512f,avx512bw,vaes")]
    unsafe fn encrypt_10_x4_avx512(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        use crate::simd::wide::*;
        let es = self.enc_sigma; let ebs = self.enc_beta_sigma; let eb = self.enc_beta;

        let mut x = shuffle_x4(load_4x128(b0, b1, b2, b3), es);
        let mut r = 0usize;
        while r < self.rounds - 2 {
            let u = aesenc_x4(x, *self.rk.get_unchecked(r));
            x = xor2_x4(shuffle_x4(u, es), shuffle_x4(u, ebs));
            let u = aesenc_x4(x, *self.rk.get_unchecked(r + 1));
            x = xor2_x4(shuffle_x4(u, es), shuffle_x4(u, ebs));
            r += 2;
        }
        let u = aesenc_x4(x, *self.rk.get_unchecked(self.rounds - 2));
        x = xor2_x4(shuffle_x4(u, es), shuffle_x4(u, ebs));
        let u = aesenc_x4(x, *self.rk.get_unchecked(self.rounds - 1));
        x = xor2_x4(u, shuffle_x4(u, eb));

        let mn_w = broadcast(self.mask_n);
        x = blend_x4(load_4x128(b0, b1, b2, b3), x, mn_w);
        store_4x128(x, b0, b1, b2, b3);
    }

    unsafe fn decrypt_11_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        if is_x86_feature_detected!("vaes") && is_x86_feature_detected!("avx512bw") {
            self.decrypt_11_x4_avx512(b0, b1, b2, b3);
        } else {
            self.decrypt(std::slice::from_raw_parts_mut(b0, 32));
            self.decrypt(std::slice::from_raw_parts_mut(b1, 32));
            self.decrypt(std::slice::from_raw_parts_mut(b2, 32));
            self.decrypt(std::slice::from_raw_parts_mut(b3, 32));
        }
    }

    #[target_feature(enable = "avx512f,avx512bw,vaes,vpclmulqdq")]
    unsafe fn decrypt_11_x4_avx512(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        use crate::simd::wide::*;
        let es=self.enc_sigma; let ds=self.dec_sigma; let dbs=self.dec_beta_sigma;
        let drs=self.dec_rho_sigma; let db=self.dec_beta; let rho_v=self.rho;
        let m_w=broadcast(self.m); let bc_w=broadcast(self.b);
        let n=self.n; let z_v: V128 = zero();
        let clk=from_u64x2(0x01010101, 0x01010101);

        let mut x = shuffle_x4(aesenclast_x4(shuffle_x4(load_4x128(b0,b1,b2,b3), es), z_v), ds);
        let mut e = bslli_3_x4(load_4x128(b0.add(n),b1.add(n),b2.add(n),b3.add(n)));

        let mut r = self.rounds as isize - 1;
        while r > 1 {
            let rkh = *self.rk.get_unchecked(r as usize);
            let rkl = *self.rk.get_unchecked((r-1) as usize);

            x = aesdec_x4(x, z_v);
            e = and_x4(xor2_x4(xor2_x4(e, bc_w), clmul_lo_x4(x, clk)), m_w);
            x = xor2_x4(x, broadcast(rkh));
            x = xor3_x4(shuffle_x4(x, ds), shuffle_x4(x, dbs), shuffle_x4(e, drs));

            x = aesdec_x4(x, z_v);
            e = and_x4(xor2_x4(xor2_x4(e, bc_w), clmul_lo_x4(x, clk)), m_w);
            x = xor2_x4(x, broadcast(rkl));
            x = xor3_x4(shuffle_x4(x, ds), shuffle_x4(x, dbs), shuffle_x4(e, drs));

            r -= 2;
        }
        // Post-loop
        x = aesdec_x4(x, z_v);
        e = and_x4(xor2_x4(xor2_x4(e, bc_w), clmul_lo_x4(x, clk)), m_w);
        x = xor2_x4(x, broadcast(self.rk[1]));
        x = xor3_x4(shuffle_x4(x, ds), shuffle_x4(x, dbs), shuffle_x4(e, drs));

        x = aesdec_x4(x, z_v);
        e = and_x4(xor2_x4(xor2_x4(e, bc_w), clmul_lo_x4(x, clk)), m_w);
        x = xor2_x4(x, broadcast(self.rk[0]));
        x = xor3_x4(x, shuffle_x4(x, db), shuffle_x4(e, rho_v));

        let mn_w = broadcast(self.mask_n);
        let s52_w = splat8_x4(0x52);
        let orig = load_4x128(b0,b1,b2,b3);
        let ypad = andnot_x4(mn_w, xor2_x4(orig, s52_w));
        x = aesdeclast_x4(shuffle_x4(x, self.dec_tau), z_v);
        x = xor2_x4(x, ypad);
        store_4x128(x, b0, b1, b2, b3);
        *b0.add(n)=extract_byte::<3>(extract_lane(e,0));
        *b1.add(n)=extract_byte::<3>(extract_lane(e,1));
        *b2.add(n)=extract_byte::<3>(extract_lane(e,2));
        *b3.add(n)=extract_byte::<3>(extract_lane(e,3));
    }

    unsafe fn decrypt_10_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        if is_x86_feature_detected!("vaes") && is_x86_feature_detected!("avx512bw") {
            self.decrypt_10_x4_avx512(b0, b1, b2, b3);
        } else {
            self.decrypt(std::slice::from_raw_parts_mut(b0, 32));
            self.decrypt(std::slice::from_raw_parts_mut(b1, 32));
            self.decrypt(std::slice::from_raw_parts_mut(b2, 32));
            self.decrypt(std::slice::from_raw_parts_mut(b3, 32));
        }
    }

    #[target_feature(enable = "avx512f,avx512bw,vaes")]
    unsafe fn decrypt_10_x4_avx512(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        use crate::simd::wide::*;
        let es=self.enc_sigma;let ds=self.dec_sigma;let dbs=self.dec_beta_sigma;
        let db=self.dec_beta;let z_v:V128=zero();

        let mut x = shuffle_x4(aesenclast_x4(shuffle_x4(load_4x128(b0,b1,b2,b3), es), z_v), ds);
        let mut r = self.rounds as isize - 1;
        while r > 1 {
            x = aesdec_x4(x, *self.rk.get_unchecked(r as usize));
            x = xor2_x4(shuffle_x4(x, ds), shuffle_x4(x, dbs));
            x = aesdec_x4(x, *self.rk.get_unchecked((r-1) as usize));
            x = xor2_x4(shuffle_x4(x, ds), shuffle_x4(x, dbs));
            r -= 2;
        }
        x = aesdec_x4(x, self.rk[1]);
        x = xor2_x4(shuffle_x4(x, ds), shuffle_x4(x, dbs));
        x = aesdec_x4(x, self.rk[0]);
        x = xor2_x4(x, shuffle_x4(x, db));

        let mn_w=broadcast(self.mask_n); let s52_w=splat8_x4(0x52);
        let orig=load_4x128(b0,b1,b2,b3);
        let ypad=andnot_x4(mn_w, xor2_x4(orig, s52_w));
        x = aesdeclast_x4(shuffle_x4(x, self.dec_tau), z_v);
        x = xor2_x4(x, ypad);
        store_4x128(x, b0, b1, b2, b3);
    }
}

// ================================================================
// wasm32: scalar fallback for batch operations
// ================================================================

#[cfg(target_arch = "wasm32")]
impl AlfNt {
    unsafe fn encrypt_11_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        self.encrypt(std::slice::from_raw_parts_mut(b0, 32));
        self.encrypt(std::slice::from_raw_parts_mut(b1, 32));
        self.encrypt(std::slice::from_raw_parts_mut(b2, 32));
        self.encrypt(std::slice::from_raw_parts_mut(b3, 32));
    }
    unsafe fn encrypt_10_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        self.encrypt(std::slice::from_raw_parts_mut(b0, 32));
        self.encrypt(std::slice::from_raw_parts_mut(b1, 32));
        self.encrypt(std::slice::from_raw_parts_mut(b2, 32));
        self.encrypt(std::slice::from_raw_parts_mut(b3, 32));
    }
    unsafe fn decrypt_11_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        self.decrypt(std::slice::from_raw_parts_mut(b0, 32));
        self.decrypt(std::slice::from_raw_parts_mut(b1, 32));
        self.decrypt(std::slice::from_raw_parts_mut(b2, 32));
        self.decrypt(std::slice::from_raw_parts_mut(b3, 32));
    }
    unsafe fn decrypt_10_x4(&self, b0: *mut u8, b1: *mut u8, b2: *mut u8, b3: *mut u8) {
        self.decrypt(std::slice::from_raw_parts_mut(b0, 32));
        self.decrypt(std::slice::from_raw_parts_mut(b1, 32));
        self.decrypt(std::slice::from_raw_parts_mut(b2, 32));
        self.decrypt(std::slice::from_raw_parts_mut(b3, 32));
    }
}
