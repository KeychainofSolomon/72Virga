//! The wand's cryptography against published vectors and against an independent
//! implementation (`data/mod.rs`, made with Python's hashlib and `cryptography`).

mod data;
use data::*;
use virga::{hex, unhex, Clavis};

fn fields(line: &str) -> Vec<Vec<u8>> {
    line.split(' ')
        .map(|f| unhex(f).unwrap_or_else(|| panic!("bad hex {f}")))
        .collect()
}

#[test]
fn sha256_fips_and_independent() {
    assert_eq!(
        hex(&virga::sha2::sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    for l in SHA256 {
        let f = fields(l);
        assert_eq!(virga::sha2::sha256(&f[0]).to_vec(), f[1]);
    }
}

#[test]
fn sha512_fips_and_independent() {
    assert_eq!(
        hex(&virga::sha2::sha512(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    for l in SHA512 {
        let f = fields(l);
        assert_eq!(virga::sha2::sha512(&f[0]).to_vec(), f[1]);
    }
}

#[test]
fn hmac_rfc4231_case_2() {
    assert_eq!(
        hex(&virga::sha2::hmac_sha256(
            b"Jefe",
            &[b"what do ya want ", b"for nothing?"]
        )),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn ed25519_rfc8032_section_7_1() {
    let cases = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ];
    for (seed, pk, msg, sig) in cases {
        let k = Clavis::ex_semine(unhex(seed).unwrap().try_into().unwrap());
        assert_eq!(k.publica(), pk);
        let m = unhex(msg).unwrap();
        assert_eq!(k.signa(&m), sig);
        assert!(virga::verifica(pk, &m, sig));
    }
}

#[test]
fn ed25519_independent() {
    for l in ED25519 {
        let f = fields(l);
        let k = Clavis::ex_semine(f[0].clone().try_into().unwrap());
        assert_eq!(k.publica(), hex(&f[1]));
        assert_eq!(k.signa(&f[2]), hex(&f[3]));
        assert!(virga::verifica(&hex(&f[1]), &f[2], &hex(&f[3])));
    }
}

#[test]
fn ed25519_refuses_forgeries() {
    let k = Clavis::ex_semine([7u8; 32]);
    let pk = k.publica();
    let sig = k.signa(b"the faculty");
    assert!(virga::verifica(&pk, b"the faculty", &sig));
    assert!(!virga::verifica(&pk, b"the faculty!", &sig));
    let other = Clavis::ex_semine([8u8; 32]).publica();
    assert!(!virga::verifica(&other, b"the faculty", &sig));
    // every single-bit change to the signature is refused
    let raw = unhex(&sig).unwrap();
    for i in 0..raw.len() * 8 {
        let mut b = raw.clone();
        b[i / 8] ^= 1 << (i % 8);
        assert!(!virga::verifica(&pk, b"the faculty", &hex(&b)), "bit {i}");
    }
    // S + L (non-canonical S) is refused
    let mut s = raw.clone();
    let l = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap();
    let mut carry = 0u16;
    for i in 0..32 {
        let v = s[32 + i] as u16 + l[i] as u16 + carry;
        s[32 + i] = v as u8;
        carry = v >> 8;
    }
    assert!(!virga::verifica(&pk, b"the faculty", &hex(&s)));
    // malformed input is refused, not a panic
    assert!(!virga::verifica("zz", b"x", &sig));
    assert!(!virga::verifica(&pk, b"x", "00"));
    assert!(!virga::verifica(&"ff".repeat(32), b"x", &sig));
}

#[test]
fn scrypt_rfc7914_and_independent() {
    for l in SCRYPT {
        let parts: Vec<&str> = l.split(' ').collect();
        let pw = unhex(parts[0]).unwrap();
        let salt = unhex(parts[1]).unwrap();
        let labor = virga::Labor {
            log_n: parts[2].parse().unwrap(),
            r: parts[3].parse().unwrap(),
            p: parts[4].parse().unwrap(),
        };
        let want = unhex(parts[5]).unwrap();
        let mut out = vec![0u8; want.len()];
        virga::scrypt::scrypt(&pw, &salt, labor, &mut out).unwrap();
        assert_eq!(out, want, "{l}");
    }
}

#[test]
fn chacha20_poly1305_independent() {
    for l in AEAD {
        let f = fields(l);
        let key: [u8; 32] = f[0].clone().try_into().unwrap();
        let nonce: [u8; 12] = f[1].clone().try_into().unwrap();
        let sealed = virga::aead::seal(&key, &nonce, &f[2], &f[3]);
        assert_eq!(sealed, f[4]);
        assert_eq!(
            virga::aead::open(&key, &nonce, &f[2], &sealed).unwrap(),
            f[3]
        );
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(virga::aead::open(&key, &nonce, &f[2], &bad).is_none());
        let mut aad = f[2].clone();
        aad.push(0);
        assert!(virga::aead::open(&key, &nonce, &aad, &sealed).is_none());
    }
}

#[test]
fn ed25519_refuses_small_order_keys_and_nonces() {
    // the identity as a public key, with R = identity and S = 0, satisfies the equation
    // for every message (audit V03)
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut sig = [0u8; 64];
    sig[0] = 1;
    assert!(!virga::verifica(&hex(&identity), b"anything", &hex(&sig)));
    assert!(!virga::publica_valida(&hex(&identity)));
    // a point of order 2, (0, -1): y = p - 1
    let mut minus_one = [0xffu8; 32];
    minus_one[0] = 0xec;
    minus_one[31] = 0x7f;
    assert!(!virga::publica_valida(&hex(&minus_one)));
    // an honest signature whose R is swapped for a small-order point is refused
    let k = Clavis::ex_semine([11; 32]);
    let mut s = unhex(&k.signa(b"m")).unwrap();
    s[..32].copy_from_slice(&identity);
    assert!(!virga::verifica(&k.publica(), b"m", &hex(&s)));
    assert!(virga::publica_valida(&k.publica()));
}
