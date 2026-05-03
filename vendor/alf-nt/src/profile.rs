//! ALF-n-t permutation profiles for n=2..15.
//!
//! Each profile contains the shuffle masks and round counts for a given n value.

const FF: u8 = 0xFF;

pub struct AlfProfile {
    pub enc_beta: [u8; 16],
    pub enc_sigma: [u8; 16],
    pub dec_alpha: [u8; 16],
    pub dec_beta: [u8; 16],
    pub dec_sigma: [u8; 16],
    pub dec_tau: [u8; 16],
    pub rho: [u8; 16],
    pub a: [u8; 16],
    pub rounds0: usize,
    pub rounds1: usize,
}

/// 14 profiles indexed by (n - 2), covering n=2..15.
pub static ALF_PROFILES: [AlfProfile; 14] = [
    // n=2
    AlfProfile {
        enc_beta:  [ 2, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 0,FF,FF,FF,FF, 1,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_alpha: [ 0, 1,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_beta:  [ 2, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 0,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF, 1,FF,FF],
        dec_tau:   [ 0,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF, 1,FF,FF],
        rho:       [ 3, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        a:         [0x63,0x63,0x52,0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        rounds0: 20, rounds1: 28,
    },
    // n=3
    AlfProfile {
        enc_beta:  [ 3, 3, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 0,FF,FF,FF,FF, 2,FF,FF,FF,FF, 1,FF,FF,FF,FF,FF],
        dec_alpha: [ 0, 1, 2,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_beta:  [ 3, 3, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 0,FF,FF,FF,FF,FF,FF,FF,FF,FF, 1,FF,FF, 2,FF,FF],
        dec_tau:   [ 0,FF,FF,FF,FF,FF,FF,FF,FF,FF, 1,FF,FF, 2,FF,FF],
        rho:       [ 3,FF, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        a:         [0xA5,0xA5,0x63,0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        rounds0: 16, rounds1: 24,
    },
    // n=4
    AlfProfile {
        enc_beta:  [FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 0,FF,FF,FF,FF, 1,FF,FF,FF,FF, 2,FF,FF,FF,FF, 3],
        dec_alpha: [ 0, 1, 2, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_beta:  [FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 0,FF,FF,FF,FF,FF,FF, 3,FF,FF, 2,FF,FF, 1,FF,FF],
        dec_tau:   [ 0,FF,FF,FF,FF,FF,FF, 3,FF,FF, 2,FF,FF, 1,FF,FF],
        rho:       [ 3, 3, 3, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        a:         [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        rounds0: 14, rounds1: 18,
    },
    // n=5
    AlfProfile {
        enc_beta:  [ 4, 4, 4, 4, 7,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 1,FF,FF, 0, 3, 0,FF,FF,FF, 0, 4,FF,FF,FF,FF, 2],
        dec_alpha: [ 0, 1, 2, 3, 4,FF, 4,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_beta:  [ 5, 5, 7, 5, 1,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 1,FF,FF,FF, 2,FF,FF, 4,FF,FF, 3,FF,FF, 0, 2,FF],
        dec_tau:   [ 1,FF,FF,FF, 2,FF,FF, 4,FF,FF, 3,FF,FF, 0,FF,FF],
        rho:       [ 3,FF, 3,FF, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        a:         [0x63,0x63,0x63,0x63, 0,0x52, 0,0x52, 0, 0, 0, 0, 0, 0, 0, 0],
        rounds0: 14, rounds1: 18,
    },
    // n=6
    AlfProfile {
        enc_beta:  [ 2, 3, 6, 7, 2, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 2,FF,FF,FF, 4, 1,FF,FF,FF, 3, 0,FF,FF,FF,FF, 5],
        dec_alpha: [ 0, 1,FF,FF, 2, 3, 4, 5,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_beta:  [ 4, 5, 4, 5, 6, 7,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 2, 5,FF,FF, 0,FF,FF,FF,FF,FF,FF, 3,FF, 1, 4,FF],
        dec_tau:   [ 2, 3,FF,FF, 4,FF,FF, 5,FF,FF, 0,FF,FF, 1,FF,FF],
        rho:       [ 3, 3,FF,FF, 3, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        a:         [ 0, 0,0x52,0x52,0x63,0xA5, 0,0xC6, 0, 0, 0, 0, 0, 0, 0, 0],
        rounds0: 14, rounds1: 16,
    },
    // n=7
    AlfProfile {
        enc_beta:  [ 1, 7, 1, 1, 1, 1, 1,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 0,FF,FF,FF, 2, 4,FF,FF,FF, 5, 3,FF,FF,FF, 1, 6],
        dec_alpha: [ 0,FF, 2, 3, 4, 5, 6, 1,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_beta:  [ 7, 7, 7, 7, 7, 7, 7,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 0, 5,FF,FF, 1,FF,FF, 2,FF,FF, 4, 6,FF,FF, 3,FF],
        dec_tau:   [ 0, 5,FF,FF, 1,FF,FF, 2,FF,FF, 4,FF,FF, 6, 3,FF],
        rho:       [ 3,FF, 3,FF, 3,FF, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        a:         [ 0,0x52, 0, 0,0x63,0x63,0xA5,0xC6, 0, 0, 0, 0, 0, 0, 0, 0],
        rounds0: 14, rounds1: 16,
    },
    // n=8
    AlfProfile {
        enc_beta:  [FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 0,FF,FF, 7, 2, 1,FF,FF,FF, 3, 4,FF,FF,FF, 6, 5],
        dec_alpha: [ 0, 1, 2, 3, 4, 5, 6, 7,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_beta:  [FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 0, 3,FF,FF, 2,FF,FF, 5,FF,FF, 4, 7,FF, 1, 6,FF],
        dec_tau:   [ 0, 3,FF,FF, 2,FF,FF, 5,FF,FF, 4, 7,FF, 1, 6,FF],
        rho:       [ 3, 3, 3, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        a:         [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        rounds0: 12, rounds1: 16,
    },
    // n=9
    AlfProfile {
        enc_beta:  [ 8, 8, 8, 8,FF,FF,FF,FF, 11,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 2,FF,FF, 8, 3, 4,FF, 4, 0, 6, 1,FF,FF, 4, 7, 5],
        dec_alpha: [ 0, 1, 2, 3, 4, 5, 6, 7, 8,FF, 8,FF,FF,FF,FF,FF],
        dec_beta:  [ 9, 9, 11, 9,FF,FF,FF,FF, 1,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 8, 3, 7,FF, 1,FF,FF, 4, 7,FF, 0, 6,FF, 2, 5,FF],
        dec_tau:   [ 8, 3,FF,FF, 1,FF,FF, 4, 7,FF, 0, 6,FF, 2, 5,FF],
        rho:       [ 3,FF, 3,FF,FF,FF,FF,FF, 3,FF,FF,FF,FF,FF,FF,FF],
        a:         [0x63,0x63,0x63,0x63, 0, 0, 0, 0, 0,0x52, 0,0x52, 0, 0, 0, 0],
        rounds0: 12, rounds1: 16,
    },
    // n=10
    AlfProfile {
        enc_beta:  [ 2, 3, 10, 11,FF,FF,FF,FF, 2, 3,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 7,FF,FF, 9, 0, 4,FF,FF, 6, 2, 1,FF,FF, 8, 5, 3],
        dec_alpha: [ 0, 1,FF,FF, 4, 5, 6, 7, 2, 3, 8, 9,FF,FF,FF,FF],
        dec_beta:  [ 8, 9, 8, 9,FF,FF,FF,FF, 10, 11,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 4, 6, 9,FF, 1, 3,FF,FF, 5,FF,FF, 0,FF, 2, 8, 7],
        dec_tau:   [ 4, 6,FF,FF, 1, 7,FF, 3, 9,FF, 5, 0,FF, 2, 8,FF],
        rho:       [ 3, 3,FF,FF,FF,FF,FF,FF, 3, 3,FF,FF,FF,FF,FF,FF],
        a:         [ 0, 0,0x52,0x52, 0, 0, 0, 0,0x63,0xA5, 0,0xC6, 0, 0, 0, 0],
        rounds0: 12, rounds1: 14,
    },
    // n=11
    AlfProfile {
        enc_beta:  [ 1, 11, 1, 1,FF,FF,FF,FF, 1, 1, 1,FF,FF,FF,FF,FF],
        enc_sigma: [ 5,FF, 10, 4, 1, 7,FF,FF, 6, 0, 9,FF,FF, 3, 2, 8],
        dec_alpha: [ 0,FF, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1,FF,FF,FF,FF],
        dec_beta:  [ 11, 11, 11, 11,FF,FF,FF,FF, 11, 11, 11,FF,FF,FF,FF,FF],
        dec_sigma: [ 5, 0, 10,FF, 7, 2,FF, 9, 3,FF, 6, 1,FF,FF, 8, 4],
        dec_tau:   [ 5, 0, 10,FF, 7, 2,FF, 9, 3,FF, 6, 1,FF, 4, 8,FF],
        rho:       [ 3,FF, 3,FF,FF,FF,FF,FF, 3,FF, 3,FF,FF,FF,FF,FF],
        a:         [ 0,0x52, 0, 0, 0, 0, 0, 0,0x63,0x63,0xA5,0xC6, 0, 0, 0, 0],
        rounds0: 12, rounds1: 14,
    },
    // n=12
    AlfProfile {
        enc_beta:  [FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        enc_sigma: [ 0,FF, 3, 11, 4, 5,FF, 7, 8, 9, 6,FF,FF, 1, 2, 10],
        dec_alpha: [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,FF,FF,FF,FF],
        dec_beta:  [FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        dec_sigma: [ 0, 1, 3,FF, 4, 5,FF, 10, 8,FF, 6, 11,FF, 9, 2, 7],
        dec_tau:   [ 0, 1, 3,FF, 4, 5,FF, 10, 8,FF, 6, 11,FF, 9, 2, 7],
        rho:       [ 3, 3, 3, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF],
        a:         [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        rounds0: 12, rounds1: 14,
    },
    // n=13
    AlfProfile {
        enc_beta:  [ 12, 12, 12, 12, 8, 9, 10, 11,FF,FF,FF,FF, 15,FF,FF,FF],
        enc_sigma: [ 5, 7, 6, 10, 2, 7,FF, 12, 11, 9, 8, 7, 3, 0, 4, 1],
        dec_alpha: [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,FF, 12,FF],
        dec_beta:  [ 13, 13, 15, 13, 8, 9, 10, 11,FF,FF,FF,FF, 1,FF,FF,FF],
        dec_sigma: [ 9, 0, 7,FF, 6, 5, 11, 12, 2,FF, 4, 1, 11, 3, 10, 8],
        dec_tau:   [ 9, 0, 7,FF, 6, 5,FF, 12, 2,FF, 4, 1, 11, 3, 10, 8],
        rho:       [ 3,FF, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF, 3,FF,FF,FF],
        a:         [0x63,0x63,0x63,0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0,0x52, 0,0x52],
        rounds0: 12, rounds1: 14,
    },
    // n=14
    AlfProfile {
        enc_beta:  [ 2, 3, 14, 15,FF,FF,FF,FF,FF,FF,FF,FF, 2, 3,FF,FF],
        enc_sigma: [ 4, 12, 10, 2, 5, 11,FF, 13, 6, 1, 8,FF, 7, 0, 9, 3],
        dec_alpha: [ 0, 1,FF,FF, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 12, 13],
        dec_beta:  [ 12, 13, 12, 13,FF,FF,FF,FF,FF,FF,FF,FF, 14, 15,FF,FF],
        dec_sigma: [ 9, 4, 10, 11, 0, 6, 13,FF, 2, 3,FF, 12, 7, 5, 8, 1],
        dec_tau:   [ 9, 4, 10,FF, 0, 6,FF, 3, 2, 11, 7, 12, 13, 5, 8, 1],
        rho:       [ 3, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF,FF, 3, 3,FF,FF],
        a:         [ 0, 0,0x52,0x52, 0, 0, 0, 0, 0, 0, 0, 0,0x63,0xA5, 0,0xC6],
        rounds0: 12, rounds1: 14,
    },
    // n=15
    AlfProfile {
        enc_beta:  [ 1, 15, 1, 1,FF,FF,FF,FF,FF,FF,FF,FF, 1, 1, 1,FF],
        enc_sigma: [ 4, 0, 1, 2, 5, 8, 11, 3, 6, 9, 12,FF, 14, 10, 13, 7],
        dec_alpha: [ 0,FF, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 1],
        dec_beta:  [ 15, 15, 15, 15,FF,FF,FF,FF,FF,FF,FF,FF, 15, 15, 15,FF],
        dec_sigma: [ 13, 4, 9, 10, 0, 5, 12, 11, 1, 6, 7, 3, 2,FF, 8, 14],
        dec_tau:   [ 13, 4, 9,FF, 0, 5, 12, 11, 1, 6, 7, 3, 2, 10, 8, 14],
        rho:       [ 3,FF, 3,FF,FF,FF,FF,FF,FF,FF,FF,FF, 3,FF, 3,FF],
        a:         [ 0,0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0x63,0x63,0xA5,0xC6],
        rounds0: 12, rounds1: 12,
    },
];
