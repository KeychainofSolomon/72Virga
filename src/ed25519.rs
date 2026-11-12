//! Ed25519 signatures (RFC 8032, section 5.1), written from the RFC.
//!
//! Field elements are five 51-bit limbs. Every operation on secret data (the signing
//! scalar, the nonce) runs the same instructions whatever the data: the scalar
//! multiplication selects with masks instead of branching, and scalar reduction is a
//! masked long division. Verification is cofactorless, as RFC 8032 permits: it checks
//! that `[S]B - [k]A` encodes to exactly the `R` given, so a non-canonical `R` fails.

use crate::sha2::Sha512;
use std::sync::OnceLock;

const MASK: u64 = (1 << 51) - 1;

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn small(n: u64) -> Fe {
        Fe([n, 0, 0, 0, 0])
    }

    /// Reads 255 bits, little-endian; the top bit is ignored.
    fn from_bytes(b: &[u8; 32]) -> Fe {
        Fe([
            le64(&b[0..]) & MASK,
            (le64(&b[6..]) >> 3) & MASK,
            (le64(&b[12..]) >> 6) & MASK,
            (le64(&b[19..]) >> 1) & MASK,
            (le64(&b[24..]) >> 12) & MASK,
        ])
    }

    fn carry(mut l: [u64; 5]) -> Fe {
        let mut c;
        c = l[0] >> 51;
        l[0] &= MASK;
        l[1] += c;
        c = l[1] >> 51;
        l[1] &= MASK;
        l[2] += c;
        c = l[2] >> 51;
        l[2] &= MASK;
        l[3] += c;
        c = l[3] >> 51;
        l[3] &= MASK;
        l[4] += c;
        c = l[4] >> 51;
        l[4] &= MASK;
        l[0] += c * 19;
        Fe(l)
    }

    /// The unique representative below p, as 32 bytes.
    fn to_bytes(self) -> [u8; 32] {
        let mut l = Fe::carry(self.0).0;
        l = Fe::carry(l).0;
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK;
        l[2] += l[1] >> 51;
        l[1] &= MASK;
        l[3] += l[2] >> 51;
        l[2] &= MASK;
        l[4] += l[3] >> 51;
        l[3] &= MASK;
        l[4] &= MASK;
        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut bits = 0;
        let mut k = 0;
        for limb in l {
            acc |= (limb as u128) << bits;
            bits += 51;
            while bits >= 8 && k < 32 {
                out[k] = acc as u8;
                acc >>= 8;
                bits -= 8;
                k += 1;
            }
        }
        if k < 32 {
            out[k] = acc as u8;
        }
        out
    }

    fn add(self, o: Fe) -> Fe {
        let mut l = [0u64; 5];
        for (i, v) in l.iter_mut().enumerate() {
            *v = self.0[i] + o.0[i];
        }
        Fe::carry(l)
    }

    fn sub(self, o: Fe) -> Fe {
        // add 4p so that no limb underflows
        const P4: [u64; 5] = [4 * ((1 << 51) - 19), 4 * MASK, 4 * MASK, 4 * MASK, 4 * MASK];
        let mut l = [0u64; 5];
        for (i, v) in l.iter_mut().enumerate() {
            *v = self.0[i] + P4[i] - o.0[i];
        }
        Fe::carry(l)
    }

    fn neg(self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(self, o: Fe) -> Fe {
        let a = self.0;
        let b = o.0;
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let b1 = b[1] * 19;
        let b2 = b[2] * 19;
        let b3 = b[3] * 19;
        let b4 = b[4] * 19;
        let c0 = m(a[0], b[0]) + m(a[4], b1) + m(a[3], b2) + m(a[2], b3) + m(a[1], b4);
        let mut c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2) + m(a[3], b3) + m(a[2], b4);
        let mut c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3) + m(a[3], b4);
        let mut c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4);
        let mut c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);
        let mut l = [0u64; 5];
        c1 += c0 >> 51;
        l[0] = (c0 as u64) & MASK;
        c2 += c1 >> 51;
        l[1] = (c1 as u64) & MASK;
        c3 += c2 >> 51;
        l[2] = (c2 as u64) & MASK;
        c4 += c3 >> 51;
        l[3] = (c3 as u64) & MASK;
        let carry = (c4 >> 51) as u64;
        l[4] = (c4 as u64) & MASK;
        l[0] += carry * 19;
        l[1] += l[0] >> 51;
        l[0] &= MASK;
        Fe(l)
    }

    fn square(self) -> Fe {
        self.mul(self)
    }

    /// `self` to a public exponent, given little-endian.
    fn pow(self, e: &[u8; 32]) -> Fe {
        let mut r = Fe::ONE;
        for i in (0..256).rev() {
            r = r.square();
            if (e[i / 8] >> (i % 8)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    fn invert(self) -> Fe {
        // p - 2 = 2^255 - 21
        let mut e = [0xffu8; 32];
        e[0] = 0xeb;
        e[31] = 0x7f;
        self.pow(&e)
    }

    fn pow_p58(self) -> Fe {
        // (p - 5) / 8 = 2^252 - 3
        let mut e = [0xffu8; 32];
        e[0] = 0xfd;
        e[31] = 0x0f;
        self.pow(&e)
    }

    fn is_zero(self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    fn eq(self, o: Fe) -> bool {
        self.to_bytes() == o.to_bytes()
    }

    fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    fn select(mask: u64, a: Fe, b: Fe) -> Fe {
        // mask all ones: a; mask zero: b
        let mut l = [0u64; 5];
        for (i, v) in l.iter_mut().enumerate() {
            *v = (a.0[i] & mask) | (b.0[i] & !mask);
        }
        Fe(l)
    }
}

struct Consts {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
    base: Point,
}

fn consts() -> &'static Consts {
    static C: OnceLock<Consts> = OnceLock::new();
    C.get_or_init(|| {
        let d = Fe::small(121665).neg().mul(Fe::small(121666).invert());
        // (p - 1) / 4 = 2^253 - 5
        let mut e = [0xffu8; 32];
        e[0] = 0xfb;
        e[31] = 0x1f;
        let sqrt_m1 = Fe::small(2).pow(&e);
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        let partial = Consts {
            d,
            d2: d.add(d),
            sqrt_m1,
            base: Point::IDENTITY,
        };
        let base = Point::decode_with(&b, &partial).expect("the base point decodes");
        Consts { base, ..partial }
    })
}

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    fn decode_with(b: &[u8; 32], c: &Consts) -> Option<Point> {
        let y = Fe::from_bytes(b);
        let mut canonical = y.to_bytes();
        canonical[31] |= b[31] & 0x80;
        if canonical != *b {
            return None; // y >= p
        }
        let sign = b[31] >> 7 == 1;
        let y2 = y.square();
        let u = y2.sub(Fe::ONE);
        let v = c.d.mul(y2).add(Fe::ONE);
        let v3 = v.square().mul(v);
        let v7 = v3.square().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v7).pow_p58());
        let vx2 = v.mul(x.square());
        if vx2.eq(u) {
        } else if vx2.eq(u.neg()) {
            x = x.mul(c.sqrt_m1);
        } else {
            return None;
        }
        if x.is_zero() && sign {
            return None;
        }
        if x.is_negative() != sign {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    fn decode(b: &[u8; 32]) -> Option<Point> {
        Point::decode_with(b, consts())
    }

    fn encode(self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(zi);
        let y = self.y.mul(zi);
        let mut out = y.to_bytes();
        if x.is_negative() {
            out[31] |= 0x80;
        }
        out
    }

    /// Unified addition for a = -1 (add-2008-hwcd-3); also correct for doubling.
    fn add(self, o: Point) -> Point {
        let c = consts();
        let a = self.y.sub(self.x).mul(o.y.sub(o.x));
        let b = self.y.add(self.x).mul(o.y.add(o.x));
        let cc = self.t.mul(c.d2).mul(o.t);
        let d = self.z.add(self.z).mul(o.z);
        let e = b.sub(a);
        let f = d.sub(cc);
        let g = d.add(cc);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    fn neg(self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    fn select(mask: u64, a: Point, b: Point) -> Point {
        Point {
            x: Fe::select(mask, a.x, b.x),
            y: Fe::select(mask, a.y, b.y),
            z: Fe::select(mask, a.z, b.z),
            t: Fe::select(mask, a.t, b.t),
        }
    }

    /// `[s]self`, the same instructions for every `s`.
    fn mul(self, s: &[u8; 32]) -> Point {
        let mut r = Point::IDENTITY;
        for i in (0..256).rev() {
            r = r.add(r);
            let sum = r.add(self);
            let bit = ((s[i / 8] >> (i % 8)) & 1) as u64;
            r = Point::select(0u64.wrapping_sub(bit), sum, r);
        }
        r
    }
}

// The group order L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// A 512-bit little-endian integer reduced mod L, by masked long division.
fn reduce(wide: &[u8; 64]) -> [u8; 32] {
    let mut rem = [0u64; 4];
    for i in (0..512).rev() {
        let bit = ((wide[i / 8] >> (i % 8)) & 1) as u64;
        // rem = rem * 2 + bit (rem < L < 2^253, so this cannot overflow 256 bits)
        rem[3] = (rem[3] << 1) | (rem[2] >> 63);
        rem[2] = (rem[2] << 1) | (rem[1] >> 63);
        rem[1] = (rem[1] << 1) | (rem[0] >> 63);
        rem[0] = (rem[0] << 1) | bit;
        // t = rem - L
        let mut t = [0u64; 4];
        let mut borrow = 0u64;
        for k in 0..4 {
            let (d1, b1) = rem[k].overflowing_sub(L[k]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            t[k] = d2;
            borrow = (b1 | b2) as u64;
        }
        let keep = 0u64.wrapping_sub(borrow); // all ones if rem < L
        for k in 0..4 {
            rem[k] = (rem[k] & keep) | (t[k] & !keep);
        }
    }
    let mut out = [0u8; 32];
    for k in 0..4 {
        out[8 * k..8 * k + 8].copy_from_slice(&rem[k].to_le_bytes());
    }
    out
}

/// (r + k * a) mod L.
fn mul_add(k: &[u8; 32], a: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let words = |b: &[u8; 32]| -> [u64; 4] { std::array::from_fn(|i| le64(&b[8 * i..])) };
    let (kw, aw, rw) = (words(k), words(a), words(r));
    let mut prod = [0u128; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let cur = prod[i + j] + (kw[i] as u128) * (aw[j] as u128) + carry;
            prod[i + j] = cur & (u64::MAX as u128);
            carry = cur >> 64;
        }
        prod[i + 4] += carry;
    }
    let mut carry: u128 = 0;
    for i in 0..8 {
        let add = if i < 4 { rw[i] as u128 } else { 0 };
        let cur = prod[i] + add + carry;
        prod[i] = cur & (u64::MAX as u128);
        carry = cur >> 64;
    }
    let mut wide = [0u8; 64];
    for i in 0..8 {
        wide[8 * i..8 * i + 8].copy_from_slice(&(prod[i] as u64).to_le_bytes());
    }
    let out = reduce(&wide);
    crate::wipe(&mut wide);
    out
}

fn below_l(s: &[u8; 32]) -> bool {
    for k in (0..4).rev() {
        let w = le64(&s[8 * k..]);
        if w != L[k] {
            return w < L[k];
        }
    }
    false
}

fn hash_mod_l(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let mut wide = h.finish();
    let out = reduce(&wide);
    crate::wipe(&mut wide);
    out
}

/// The expanded secret: the clamped scalar and the nonce prefix.
pub(crate) struct Expanded {
    a: [u8; 32],
    prefix: [u8; 32],
    pub public: [u8; 32],
}

impl Drop for Expanded {
    fn drop(&mut self) {
        crate::wipe(&mut self.a);
        crate::wipe(&mut self.prefix);
    }
}

pub(crate) fn expand(seed: &[u8; 32]) -> Expanded {
    let mut h = Sha512::new();
    h.update(seed);
    let mut digest = h.finish();
    let mut a = [0u8; 32];
    let mut prefix = [0u8; 32];
    a.copy_from_slice(&digest[..32]);
    prefix.copy_from_slice(&digest[32..]);
    crate::wipe(&mut digest);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let public = consts().base.mul(&a).encode();
    Expanded { a, prefix, public }
}

pub(crate) fn sign(key: &Expanded, msg: &[u8]) -> [u8; 64] {
    let mut r = hash_mod_l(&[&key.prefix, msg]);
    let big_r = consts().base.mul(&r).encode();
    let k = hash_mod_l(&[&big_r, &key.public, msg]);
    let s = mul_add(&k, &key.a, &r);
    crate::wipe(&mut r);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&s);
    sig
}

pub(crate) fn decodes(public: &[u8; 32]) -> bool {
    Point::decode(public).is_some()
}

pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Some(a) = Point::decode(public) else {
        return false;
    };
    let r: [u8; 32] = sig[..32].try_into().unwrap();
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if !below_l(&s) {
        return false;
    }
    let k = hash_mod_l(&[&r, public, msg]);
    let check = consts().base.mul(&s).add(a.neg().mul(&k)).encode();
    check == r
}
