//! ChaCha20-Poly1305 (RFC 8439): the lock on each secret. The words open it; any change
//! to the locked secret, or to what it is bound to, makes it refuse to open.

fn chacha_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let le = |b: &[u8]| u32::from_le_bytes(b[..4].try_into().unwrap());
    let mut s = [0u32; 16];
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    for i in 0..8 {
        s[4 + i] = le(&key[4 * i..]);
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = le(&nonce[4 * i..]);
    }
    let mut x = s;
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            x[$a] = x[$a].wrapping_add(x[$b]);
            x[$d] = (x[$d] ^ x[$a]).rotate_left(16);
            x[$c] = x[$c].wrapping_add(x[$d]);
            x[$b] = (x[$b] ^ x[$c]).rotate_left(12);
            x[$a] = x[$a].wrapping_add(x[$b]);
            x[$d] = (x[$d] ^ x[$a]).rotate_left(8);
            x[$c] = x[$c].wrapping_add(x[$d]);
            x[$b] = (x[$b] ^ x[$c]).rotate_left(7);
        };
    }
    for _ in 0..10 {
        qr!(0, 4, 8, 12);
        qr!(1, 5, 9, 13);
        qr!(2, 6, 10, 14);
        qr!(3, 7, 11, 15);
        qr!(0, 5, 10, 15);
        qr!(1, 6, 11, 12);
        qr!(2, 7, 8, 13);
        qr!(3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&x[i].wrapping_add(s[i]).to_le_bytes());
    }
    x.fill(0);
    s.fill(0);
    out
}

fn chacha_xor(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let mut ks = chacha_block(key, 1 + i as u32, nonce);
        for (b, k) in chunk.iter_mut().zip(ks) {
            *b ^= k;
        }
        crate::wipe(&mut ks);
    }
}

fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let le = |b: &[u8]| u32::from_le_bytes(b[..4].try_into().unwrap());
    let m26 = 0x3ffffffu32;
    let r0 = le(&key[0..]) & 0x3ffffff;
    let r1 = (le(&key[3..]) >> 2) & 0x3ffff03;
    let r2 = (le(&key[6..]) >> 4) & 0x3ffc0ff;
    let r3 = (le(&key[9..]) >> 6) & 0x3f03fff;
    let r4 = (le(&key[12..]) >> 8) & 0x00fffff;
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);
    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        let hibit = if chunk.len() == 16 {
            1u32 << 24
        } else {
            block[chunk.len()] = 1;
            0
        };
        h0 += le(&block[0..]) & m26;
        h1 += (le(&block[3..]) >> 2) & m26;
        h2 += (le(&block[6..]) >> 4) & m26;
        h3 += (le(&block[9..]) >> 6) & m26;
        h4 += (le(&block[12..]) >> 8) | hibit;
        let w = |a: u32, b: u32| (a as u64) * (b as u64);
        let d0 = w(h0, r0) + w(h1, s4) + w(h2, s3) + w(h3, s2) + w(h4, s1);
        let mut d1 = w(h0, r1) + w(h1, r0) + w(h2, s4) + w(h3, s3) + w(h4, s2);
        let mut d2 = w(h0, r2) + w(h1, r1) + w(h2, r0) + w(h3, s4) + w(h4, s3);
        let mut d3 = w(h0, r3) + w(h1, r2) + w(h2, r1) + w(h3, r0) + w(h4, s4);
        let mut d4 = w(h0, r4) + w(h1, r3) + w(h2, r2) + w(h3, r1) + w(h4, r0);
        let mut c = d0 >> 26;
        h0 = (d0 as u32) & m26;
        d1 += c;
        c = d1 >> 26;
        h1 = (d1 as u32) & m26;
        d2 += c;
        c = d2 >> 26;
        h2 = (d2 as u32) & m26;
        d3 += c;
        c = d3 >> 26;
        h3 = (d3 as u32) & m26;
        d4 += c;
        c = d4 >> 26;
        h4 = (d4 as u32) & m26;
        h0 += (c as u32) * 5;
        let c2 = h0 >> 26;
        h0 &= m26;
        h1 += c2;
    }
    let mut c = h1 >> 26;
    h1 &= m26;
    h2 += c;
    c = h2 >> 26;
    h2 &= m26;
    h3 += c;
    c = h3 >> 26;
    h3 &= m26;
    h4 += c;
    c = h4 >> 26;
    h4 &= m26;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= m26;
    h1 += c;

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= m26;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= m26;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= m26;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= m26;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
    let mask = (g4 >> 31).wrapping_sub(1); // all ones if h >= p
    h0 = (h0 & !mask) | (g0 & mask);
    h1 = (h1 & !mask) | (g1 & mask);
    h2 = (h2 & !mask) | (g2 & mask);
    h3 = (h3 & !mask) | (g3 & mask);
    h4 = (h4 & !mask) | (g4 & mask);

    let f0 = h0 | (h1 << 26);
    let f1 = (h1 >> 6) | (h2 << 20);
    let f2 = (h2 >> 12) | (h3 << 14);
    let f3 = (h3 >> 18) | (h4 << 8);
    let mut out = [0u8; 16];
    let mut acc: u64 = 0;
    for (i, f) in [f0, f1, f2, f3].into_iter().enumerate() {
        acc += f as u64 + le(&key[16 + 4 * i..]) as u64;
        out[4 * i..4 * i + 4].copy_from_slice(&(acc as u32).to_le_bytes());
        acc >>= 32;
    }
    out
}

fn tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut block0 = chacha_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);
    crate::wipe(&mut block0);
    let pad = |n: usize| (16 - n % 16) % 16;
    let mut mac = Vec::with_capacity(aad.len() + ct.len() + 48);
    mac.extend_from_slice(aad);
    mac.extend(std::iter::repeat_n(0u8, pad(aad.len())));
    mac.extend_from_slice(ct);
    mac.extend(std::iter::repeat_n(0u8, pad(ct.len())));
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    let t = poly1305(&otk, &mac);
    crate::wipe(&mut otk);
    t
}

pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut out = plain.to_vec();
    chacha_xor(key, nonce, &mut out);
    let t = tag(key, nonce, aad, &out);
    out.extend_from_slice(&t);
    out
}

pub fn open(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 16 {
        return None;
    }
    let (ct, given) = sealed.split_at(sealed.len() - 16);
    let expected = tag(key, nonce, aad, ct);
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(given) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }
    let mut out = ct.to_vec();
    chacha_xor(key, nonce, &mut out);
    Some(out)
}
