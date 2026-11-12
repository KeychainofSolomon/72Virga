# 72Virga — the wand (`virga`)

The Operator's wand for [Annulus](https://github.com/KeychainofSolomon/Annulus). It is the
only key: every act of authority in Annulus is signed by it, and nothing else can sign.

The wand is a folder `VIRGA` on a plain USB stick, about 20 KB. Any stick will do.

## What is on the stick

| File | What it is |
|---|---|
| `VIRGA/virga.txt` | the wand: its two public keys, and its two secrets, each locked by your words |
| `VIRGA/stirps.txt` | the lineage: which wands are yours, signed (the making, revocations, new spares) |
| `VIRGA/ancorae/` | anchors: for each house (Annulus's stores), the last state this wand saw |

The two secrets (`operator.md` §8):

- the **master secret** proves you yourself. Annulus asks for its words only outside a rite:
  at launch, before any Circle opens, to sign what the program may touch, and for the
  second key, ratifying the Constitution and adopting a house. It is laid down before the
  first Circle opens, and Annulus refuses to launch while it is held.
- the **rite secret** proves only that the wand is present. Its words are asked when the
  rite begins; it lets `GERE VIRGAM` take up the wand, and seals the stores afterwards.

The two sets of words must differ, so words spoken during a rite can never open the master.

## Using it (Windows)

```
virga fac E:\ F:\ --nomen "my wand"     make the wand on E: and its spare on F:, at one stroke
virga inspice                            show the wand plugged in, and its lineage
virga proba                              check that your words open both secrets
virga revoca D85E-25B4 F:\               the spare on F: revokes the lost wand D85E-25B4…
virga adde G:\ F:\                       the wand on F: makes a new spare on G:
virga quaere                             list the wands plugged in
```

Then, in Annulus: `annulus sanci` once per house (ratifies the Constitution with your
wand), then `annulus ritus program.annulus` as usual. Annulus finds the plugged-in wand by
itself, or take `--virga E:\`.

Keep the spare apart from the wand. Write down both fingerprints.

## How the tradition is kept

| The tradition | Here |
|---|---|
| Wands are **virgin** and **cut at one stroke** (Clavicula, BnF Ital. 1524, II.7) | `fac` makes the wand and its spare in one act: both are written in full, then both put in place, or neither. A stick that already holds a wand is refused: a wand is never re-cut. The secrets come fresh from the system's randomness, never from your words. |
| The instruments command only with the magician's **words** | each secret is sealed by your words (scrypt, 128 MiB); the stick alone opens nothing |
| Beleth requires the magician to hold a **hazel wand** (Goetia) | `GERE VIRGAM` is possible only with the rite secret opened |
| The Operator is not God (`authority.md`) | the wand grants only what the program declares, and Annulus still examines every work |

## The honest limit

Anyone who has a stick **and** your words holds the wand (`operator.md` §8.6). A thief
with both could also revoke the spare before you revoke the stolen wand. A hardware key
would keep the secret inside the device; `virga` may support one later without changing
these rules. Your words, in a program's memory, are not wiped (only the opened keys are).

## How it is built

No outside crates. Everything is written from the standards and checked against their
vectors and against an independent implementation (Python's `cryptography`):

- Ed25519 signatures (RFC 8032): the wand's fingerprint is its master public key
- scrypt (RFC 7914) with PBKDF2-HMAC-SHA-256 to turn words into a key
- ChaCha20-Poly1305 (RFC 8439) to lock each secret; a secret moved to another slot or
  another wand does not open
- SHA-256 and SHA-512 (FIPS 180-4), round constants computed from the primes

Randomness comes from the operating system (`BCryptGenRandom` on Windows, `/dev/urandom`
elsewhere); the only `unsafe` code is those two Windows calls and the console echo switch.

```
cargo test        # the vectors and the attacks on the wand
cargo build --release
```

Released into the public domain (`UNLICENSE`).
