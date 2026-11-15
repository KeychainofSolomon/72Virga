# Plan: a wand that resists quantum attack

Draft, 2026-11-15, asked for by the owner. Nothing here is built. No wand in use changes until §7 is done.

## 1. What is at risk, and what is not

| Part of the wand | Today | Against a large quantum computer |
|---|---|---|
| Locking the secrets | ChaCha20-Poly1305, 256-bit key (RFC 8439) | **Holds.** The best known attack halves its strength, to about 128 bits |
| Words into a key | scrypt with PBKDF2-HMAC-SHA-256 (RFC 7914) | **Holds**, as far as the words are strong. Guessing gets faster, so long words matter more |
| Signatures | Ed25519 (RFC 8032) | **Broken.** The private key can be worked out from the public key, and the fingerprint *is* the public key. An attacker could then sign as the wand: audits, sealed stores, the lineage, the ratification |
| Hashes in fingerprints and chains | SHA-256 | **Weakened** for finding two inputs with one hash. SHA-512 restores the margin |

Nothing encrypted becomes readable. The risk is impersonation of the wand.

## 2. The decisions (owner, 2026-11-15)

1. **The cipher stays.** ChaCha20 has no 512-bit form, and none is standard for any cipher. A home-made one would have no published analysis and no vectors to test against.
2. **Signatures: Ed25519 and SLH-DSA together**, at the top strength the standard defines.
3. **Hashes: SHA-512** wherever a fingerprint or a chain is made. The wand already has it.

## 3. The new signature

**SLH-DSA** (FIPS 205, August 2024; formerly SPHINCS+), with SHA-2, at security category 5.

- **Why this one.** It is built from hashes alone, which the wand already has in its own code, so the rule of no outside crates holds. Its safety rests on the hash, not on newer mathematics. And it keeps no counter: the schemes that do (LMS, XMSS) fail badly if a stick is copied and rolled back, which is a known weakness of a plain stick.
- **Both signatures, always.** Every signature the wand makes becomes a pair: Ed25519 and SLH-DSA over the same bytes. A verifier accepts only if both are good. So a fault in the new code cannot make the wand weaker than it is today, and a quantum computer cannot forge the pair.
- **Both secrets.** The master secret and the rite secret each get an SLH-DSA key beside their Ed25519 key, locked by the same words in the same way.
- **Signing is hedged:** fresh randomness from the operating system goes into each signature, as the standard allows, so a repeated message does not repeat a signature.

**Which of the two top sets** is decided by measuring on the owner's PC (§8, 1):

| Set | Public key | Signature | Signing |
|---|---|---|---|
| SLH-DSA-SHA2-256s | 64 bytes | 29,792 bytes | slow |
| SLH-DSA-SHA2-256f | 64 bytes | 49,856 bytes | several times faster |

Ed25519 signatures are 64 bytes, so every signed record grows by about 30 or 50 KB. On a 20 GB stick this is of no account; the question is how long a rite waits for its seals.

## 4. The fingerprint

Today the fingerprint is the master Ed25519 public key. It becomes the SHA-512 of both master public keys together, shown in the same short form. A wand of the new kind therefore has a new fingerprint: it is a new wand.

## 5. Hashes

SHA-512 replaces SHA-256 where the wand, Annulus or Spiri72 makes a fingerprint or chains one record to the last: the lineage, the anchors, the audit, the seals of the stores, the fingerprints of the Constitution and its validators, each spirit's book. scrypt's inner hash stays as RFC 7914 fixes it.

Each such format gets a version mark. A program reads the old form to check old records, and writes only the new.

## 6. Moving from the wand in use

A wand is virgin and cut at one stroke, and is never re-cut (Clavicula, BnF Ital. 1524, II.7). So the wand in use is not altered. It is succeeded, by the rites the wand already has:

1. **Make a new wand and its spare** on virgin sticks, of the new kind (`virga fac`).
2. **The old wand admits the new one to the lineage** (as `virga adde` admits a spare), and the new wand signs the same act with its pair.
3. **The new wand adopts each house** (the master's act that already exists) and ratifies the Constitution for it again (`annulus sanci`). The house re-seals its stores under the new fingerprint and records the succession once.
4. **The old wand and its spare are revoked** in the lineage.

**The rule that closes the gap.** The act of step 2 carries the old wand's Ed25519 signature alone on the old side, which a quantum computer could one day forge. So: a house accepts a succession once, records it under the new wand's pair, and from then on accepts nothing signed by a revoked wand. In the lineage, an act after the succession counts only with a pair.

**Old audits** stay as they are, readable and checkable by the old rule, and are shown as signed before the change (§8, 2).

## 7. Building it

1. `slh.rs`, written from FIPS 205, in the wand's own code.
2. Checked three ways, as the rest of the wand is: the standard's own test vectors; an independent implementation; and the pair refusing when either half is wrong.
3. The pair in `virga.rs` and `stirps.rs`; the new wand file and lineage forms, with their version marks.
4. Annulus and Spiri72 verify the pair and move their hashes (§5), pinned to the new wand's revision.
5. Measure signing on the owner's PC; settle §8, 1.
6. **An outside review of `slh.rs` before any real wand is made with it.** Hand-written cryptography is where mistakes hide.
7. Only then: the owner makes the new wand (§6).

Until step 7 the wand in use keeps working unchanged.

## 8. For the owner to rule

1. `256s` or `256f`, once signing has been timed. Proposed: `256s` if a seal takes under a second, otherwise `256f`.
2. Old audits: leave them as signed before the change (proposed), or have the new wand countersign each one.
3. When to do the succession. Every house sealed before it is one more to adopt.

## 9. What this does not fix

- Words that are short or guessable. They are the key.
- A stick copied together with its words.
- The two known limits of a plain stick: a copied stick rolled back, and a lost wand that never learned of its revocation.
- A house or a container while it is open: what is being used is readable on that PC.
- "Quantum-proof" claims more than anyone can. The claim here is: resistant to every quantum attack now known.

## Sources

FIPS 205, *Stateless Hash-Based Digital Signature Standard* (NIST, 2024), Table 2 for the sizes; FIPS 180-4 (SHA-2); RFC 8032, RFC 8439, RFC 7914.
