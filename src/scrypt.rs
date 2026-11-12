//! scrypt (RFC 7914), with PBKDF2-HMAC-SHA-256 (RFC 8018). It turns the Operator's
//! words into the key that opens a secret, slowly and with much memory, so that
//! guessing words is expensive.

use crate::sha2::hmac_sha256;

pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let index = (i as u32 + 1).to_be_bytes();
        let mut u = hmac_sha256(password, &[salt, &index]);
        let mut t = u;
        for _ in 1..rounds {
            u = hmac_sha256(password, &[&u]);
            for (a, b) in t.iter_mut().zip(u) {
                *a ^= b;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
        crate::wipe(&mut u);
        crate::wipe(&mut t);
    }
}

fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    macro_rules! q {
        ($a:expr, $b:expr, $c:expr, $n:expr) => {
            x[$a] ^= x[$b].wrapping_add(x[$c]).rotate_left($n)
        };
    }
    for _ in 0..4 {
        q!(4, 0, 12, 7);
        q!(8, 4, 0, 9);
        q!(12, 8, 4, 13);
        q!(0, 12, 8, 18);
        q!(9, 5, 1, 7);
        q!(13, 9, 5, 9);
        q!(1, 13, 9, 13);
        q!(5, 1, 13, 18);
        q!(14, 10, 6, 7);
        q!(2, 14, 10, 9);
        q!(6, 2, 14, 13);
        q!(10, 6, 2, 18);
        q!(3, 15, 11, 7);
        q!(7, 3, 15, 9);
        q!(11, 7, 3, 13);
        q!(15, 11, 7, 18);
        q!(1, 0, 3, 7);
        q!(2, 1, 0, 9);
        q!(3, 2, 1, 13);
        q!(0, 3, 2, 18);
        q!(6, 5, 4, 7);
        q!(7, 6, 5, 9);
        q!(4, 7, 6, 13);
        q!(5, 4, 7, 18);
        q!(11, 10, 9, 7);
        q!(8, 11, 10, 9);
        q!(9, 8, 11, 13);
        q!(10, 9, 8, 18);
        q!(12, 15, 14, 7);
        q!(13, 12, 15, 9);
        q!(14, 13, 12, 13);
        q!(15, 14, 13, 18);
    }
    for (a, v) in b.iter_mut().zip(x) {
        *a = a.wrapping_add(v);
    }
}

/// BlockMix: `b` has 2r blocks of 16 words; the result goes to `out`.
fn block_mix(b: &[u32], out: &mut [u32], r: usize) {
    let mut x: [u32; 16] = b[(2 * r - 1) * 16..2 * r * 16].try_into().unwrap();
    for i in 0..2 * r {
        for (k, v) in x.iter_mut().enumerate() {
            *v ^= b[i * 16 + k];
        }
        salsa20_8(&mut x);
        let dest = if i % 2 == 0 { i / 2 } else { r + i / 2 };
        out[dest * 16..dest * 16 + 16].copy_from_slice(&x);
    }
}

fn ro_mix(block: &mut [u32], n: usize, r: usize, v: &mut [u32]) {
    let len = 32 * r;
    let mut x = block.to_vec();
    let mut y = vec![0u32; len];
    for i in 0..n {
        v[i * len..(i + 1) * len].copy_from_slice(&x);
        block_mix(&x, &mut y, r);
        std::mem::swap(&mut x, &mut y);
    }
    for _ in 0..n {
        let j = (x[(2 * r - 1) * 16] as usize) & (n - 1);
        for (k, w) in x.iter_mut().enumerate() {
            *w ^= v[j * len + k];
        }
        block_mix(&x, &mut y, r);
        std::mem::swap(&mut x, &mut y);
    }
    block.copy_from_slice(&x);
    x.fill(0);
    y.fill(0);
}

/// The work asked of scrypt: N = 2^log_n, r, p.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Labor {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl Labor {
    /// What a real wand uses: 2^17 rounds over 128 MiB.
    pub const VERA: Labor = Labor {
        log_n: 17,
        r: 8,
        p: 1,
    };

    /// The most any wand file may ask for, so that a doctored file cannot exhaust memory.
    pub fn admissible(&self) -> bool {
        (1..=20).contains(&self.log_n) && (1..=16).contains(&self.r) && (1..=4).contains(&self.p)
    }
}

pub fn scrypt(password: &[u8], salt: &[u8], labor: Labor, out: &mut [u8]) -> Result<(), String> {
    let n = 1usize << labor.log_n;
    let r = labor.r as usize;
    let p = labor.p as usize;
    let mut bytes = vec![0u8; p * 128 * r];
    pbkdf2_sha256(password, salt, 1, &mut bytes);
    let mut words: Vec<u32> = bytes
        .chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let mut v = vec![0u32; 32 * r * n];
    for chunk in words.chunks_mut(32 * r) {
        ro_mix(chunk, n, r, &mut v);
    }
    v.fill(0);
    for (c, w) in bytes.chunks_mut(4).zip(&words) {
        c.copy_from_slice(&w.to_le_bytes());
    }
    words.fill(0);
    pbkdf2_sha256(password, &bytes, 1, out);
    crate::wipe(&mut bytes);
    Ok(())
}
