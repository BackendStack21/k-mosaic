# kMOSAIC Deep Security Review Report

**Date:** 2026-04-10 (updated 2026-04-11, revalidation added 2026-04-11)  
**Repository:** `BackendStack21/k-mosaic`  
**Scope:** `src/**`, CLI entrypoint, deserialization and cryptographic verification surfaces

---

## Executive Summary

This review identified one **critical exploitable cryptographic weakness** and multiple **input-handling hardening gaps**. **All findings are now remediated.**

- ✅ Fixed in original PR:
  - Public-key deserialization hardening (library + CLI): strict bounds, component caps, canonical-length enforcement.
  - Signature deserialization canonicalization: reject trailing bytes.
- ✅ Fixed in follow-up patch (2026-04-11):
  - **Signature existential forgery (Critical):** replaced pseudorandom response with an algebraically verifiable sub-SLSS Sigma protocol witness. `verify()` now checks the full lattice relation.

---

## Findings

## 1) Critical: Signature existential forgery — ✅ FIXED

- **Severity:** Critical
- **Status:** ✅ Fixed (2026-04-11)
- **File:** `src/sign/index.ts`
- **Location:** `sign()` and `verify()` logic

### Impact (before fix)

`verify()` validated only whether:

- signature structure was well-formed, and
- `signature.challenge == H(signature.commitment, message, publicKeyHash)`.

It did **not** verify that `signature.response` proved secret-key knowledge.  
An attacker could choose arbitrary commitment/response and set challenge consistently, yielding a valid signature without the secret key.

### Fix applied

Replaced the pseudorandom SHAKE256 response with a **noiseless sub-SLSS Sigma protocol**:

**Setup:** A dedicated signing sub-key `(A', s', t' = A'·s')` is derived deterministically from the master seed:

- `A'` is M_SIG×N_SIG (public, derived from `publicKeyHash`)
- `s'` is a sparse ternary secret in `{-1,0,1}^{N_SIG}` (private)
- `t' = A'·s'` (noiseless, exact relation)

**Signing (rejection-sampling loop):**

1. Sample fresh mask `r ← uniform [-GAMMA_1, GAMMA_1]^{N_SIG}`
2. `w = A'·r mod Q_SIG`
3. `commitment = H(serialize(w) || serialize(t') || msgHash || binding)`
4. `challenge = H_domain(commitment || msgHash || pkHash)`
5. `c_scalar = (challenge[0] & 1) ? -1 : +1`
6. `z = r + c_scalar * s'`; reject if `||z||∞ > GAMMA_1 - 1`, else accept
7. `response = serialize(t') || serialize(z)` (128 bytes total)

**Verification:**

1. Verify `challenge` matches recomputed hash (message + key binding)
2. Parse `tBytes` and `zBytes` from response
3. Bound-check `||z||∞ ≤ GAMMA_1 - 1`
4. Re-derive `A'` from `publicKeyHash`
5. Compute `w_check = A'·z - c_scalar·t' mod Q_SIG`
6. Verify `H(serialize(w_check) || tBytes || msgHash || binding) == commitment`

This check is unforgeable: a forger without `s'` cannot produce `(tBytes, zBytes)` satisfying step 6, because they would need to invert the lattice relation `A'·s' = t'` to know which `t'` to commit to, and then find a short `z` — computationally equivalent to the noiseless SLSS problem.

**Signature size:** 204 bytes (up from 140; response grows from 64 to 128 bytes)

**Parameters:**

```
N_SIG = M_SIG = 32   # sub-lattice dimension
Q_SIG = 12289        # prime modulus
W_SIG = 8            # signing secret weight
GAMMA_1 = 3000       # mask bound
BETA = 1             # rejection slack
```

**Expected rejection rate:** ~1.07% per iteration (< 2 iterations on average).

### Regression tests added

- `test/sign.test.ts` — `describe('Forgery Resistance')`:
  - `existential forgery attack is rejected: arbitrary commitment + any response`
  - `existential forgery: correct challenge, wrong response fails algebraic check`
  - `existential forgery: 1000 random forgery attempts all rejected`

---

## 2) High: Public-key parser hardening gaps (DoS / parser confusion)

- **Severity:** High
- **Status:** ✅ Fixed
- **Files:**
  - `src/kem/index.ts`
  - `src/k-mosaic-cli.ts`

### Risk before fix

- Missing maximum component-size checks could allow oversized length headers to drive expensive parsing paths.
- Missing canonical end-of-buffer checks allowed trailing-byte malleability.
- CLI custom deserializer lacked robust truncation/bounds checks and could throw on malformed length fields unexpectedly.

### Fixes applied

- Added per-component size cap (`8 MB`) in public-key deserialization.
- Enforced strict bounds checks before every length read and section parse.
- Enforced canonical parse completion (`offset === data.length`) to reject trailing bytes.
- Added malformed input regression tests.

---

## 3) Medium: Signature parser accepted trailing bytes (canonicalization gap)

- **Severity:** Medium
- **Status:** ✅ Fixed
- **File:** `src/sign/index.ts`

### Risk before fix

`deserializeSignature()` accepted trailing bytes after the declared response.  
This creates non-canonical encodings and can cause downstream signature-encoding ambiguity.

### Fix applied

- Added strict trailing-byte rejection (`offset !== data.length` → error).
- Added regression test coverage.

---

## Code Changes

1. **KEM public key deserialization hardening**
   - File: `src/kem/index.ts`
   - Added component-size caps, trailing-byte rejection.

2. **CLI public key deserialization hardening**
   - File: `src/k-mosaic-cli.ts`
   - Added strict truncation/bounds checks, component-size caps, trailing-byte rejection.

3. **Signature deserialization canonicalization**
   - File: `src/sign/index.ts`
   - Reject trailing bytes.

4. **Signature existential forgery fix (Critical — 2026-04-11)**
   - File: `src/sign/index.ts`
   - Replaced SHAKE256 pseudorandom response with sub-SLSS Sigma protocol witness.
   - Exported `matVecMul` from `src/problems/slss/index.ts`.

5. **Regression tests**
   - Added: `test/kem-public-key-malformed.test.ts`
   - Updated: `test/sign.test.ts` (trailing bytes + 3 forgery resistance tests)
   - Updated: `test/validate-sizes.test.ts` (new 204-byte signature size)

---

## Validation

- ✅ `bun test` — 366/366 tests pass.
- ✅ Sign/verify roundtrips verified for MOS-128 and MOS-256.
- ✅ 1000 random forgery attempts rejected in automated test.
- ✅ Serialization/deserialization roundtrips verified.

---

## Recommended Next Security Actions

1. Add explicit parser limits for all externally supplied serialized artifacts (ciphertext/signature/public key) in every API boundary.
2. Add adversarial fuzzing for all deserializers.
3. **Long-term:** Consider replacing the signing scheme with ML-DSA (CRYSTALS-Dilithium, NIST-standardized) for maximum assurance. The current sub-SLSS Sigma protocol provides practical forgery resistance but is not a NIST-standardized construction.

---

# Deep Cryptographic Audit — Round 2

**Date:** 2026-04-11  
**Auditor:** @security-auditor v1.2.0  
**Scope:** Full cryptographic security assessment — hardness assumptions, KEM correctness, signature soundness, parameter security levels, side-channel exposure  
**Test suite at time of audit:** 366/366 pass

---

## Executive Summary

This second-pass audit identified **four new CRITICAL vulnerabilities** that are distinct from (and not covered by) the findings in Round 1. All four are **currently unpatched**. Independent revalidation (2026-04-11) determined that **one is a false positive (CRIT-01)**, two are valid but less severe than originally stated (CRIT-02, CRIT-03 downgraded to HIGH), and one is valid and critical with a deeper root cause than the auditor identified (CRIT-04). Additionally, four HIGH findings and structural design concerns are documented below. HIGH findings have not yet been independently revalidated.

**Current effective security level: reduced (see revalidation below).** CRIT-04 (signature forgery) is critical and unpatched. KEM security is reduced to SLSS-only due to CRIT-02 and CRIT-03.

---

## New Critical Findings

---

### CRIT-01: NIZK Proof Leaks All KEM Shares — Total KEM Break ⚠️ FALSE POSITIVE

- **Severity:** ~~CRITICAL~~ → **Informational** (revalidated 2026-04-11)
- **Status:** ⚠️ False Positive — no patch needed
- **File:** `src/entanglement/index.ts:295–312`
- **OWASP:** A02:2021 Cryptographic Failures

#### Description

The NIZK proof appended to every KEM ciphertext is intended to prove knowledge of the three secret shares without revealing them. However, the "mask" used to hide each share is derived deterministically from the `challenge`, which is itself stored in plaintext inside the proof. This means any passive eavesdropper — with only the ciphertext — can recover all three shares and derive the shared secret.

#### Evidence

```typescript
// src/entanglement/index.ts:295-309
const responses: Uint8Array[] = []
for (let i = 0; i < 3; i++) {
  // mask is derived ONLY from the challenge, which is stored in the proof
  const fullMask = sha3_256(
    hashWithDomain(`${DOMAIN_NIZK}-mask-${i}`, challenge),
  )
  const mask = fullMask.slice(0, shares[i].length)

  const response = new Uint8Array(shares[i].length + 32)
  for (let j = 0; j < shares[i].length; j++) {
    response[j] = shares[i][j] ^ mask[j] // share XOR mask
  }
  response.set(commitRandomness[i], shares[i].length)
  responses.push(response)
}
return { challenge, responses, commitments } // challenge is public in the proof
```

#### Attack (passive — no secret key required)

For each share `i`, given only the proof object:

1. Recompute `mask_i = SHA3(H("kmosaic-nizk-mask-i", proof.challenge))[0:len(share_i)]`
2. Recover `share_i = proof.responses[i][0:len(share_i)] XOR mask_i`
3. XOR all three shares to get the 32-byte ephemeral secret
4. Derive the shared secret via the KEM's key derivation path

**Cost:** ~6 SHA3 invocations. No secret key needed. Works against any ciphertext.

#### Root Cause

A Sigma protocol mask must be statistically independent of the challenge. Here `mask = f(challenge)` makes the "mask" fully deterministic given the proof, so the XOR is trivially reversible. True zero-knowledge requires the mask to be chosen **before** the challenge (i.e., as part of the commitment phase), not derived from it.

#### Fix Required

This NIZK construction is fundamentally broken and cannot be repaired by tweaking the mask derivation. The NIZK proof should be **removed entirely** from the KEM ciphertext. If proof of well-formedness is needed, use an Encrypt-then-MAC or the Fujisaki-Okamoto transform applied correctly (i.e., the re-encryption check in `decapsulate` already achieves this for honest receivers — the NIZK adds nothing beyond leaking the shares).

#### Revalidation (2026-04-11) — VERDICT: FALSE POSITIVE

The auditor's claim is incorrect. The challenge computation at `src/entanglement/index.ts:286-291` includes `hashWithDomain("kmosaic-nizk-msg", message)` where `message` is the `ephemeralSecret` — the value an eavesdropper does NOT possess. Without the ephemeral secret, the eavesdropper cannot recompute the challenge, cannot derive the mask, and cannot extract shares from the responses.

The verifier CAN extract shares during verification, but only after decrypting and recovering the ephemeral secret through the KEM — at which point they already have the plaintext, so no new information is leaked.

The ZK property is technically weakened (not simulator-extractable), but this is a cosmetic shortcoming, not a confidentiality break. The auditor's attack step 1 ("Recompute `mask_i = SHA3(H("kmosaic-nizk-mask-i", proof.challenge))`") is correct in mechanics but omits that the challenge itself cannot be recomputed without the ephemeral secret — the challenge stored in the proof was computed using private data.

**Corrected severity: Informational.** No code change required.

---

### CRIT-02: EGRW Secret Key Never Used in Decryption — Keyless Decryption ❌ CONFIRMED

- **Severity:** ~~CRITICAL~~ → **HIGH** (revalidated 2026-04-11; see note below)
- **Status:** ❌ Open — confirmed valid, not patched
- **File:** `src/problems/egrw/index.ts:375–463`
- **OWASP:** A02:2021 Cryptographic Failures

#### Description

`egrwDecrypt` is supposed to use the recipient's secret walk to derive a shared graph vertex, which in turn keys the decryption keystream. Instead, both `egrwEncrypt` and `egrwDecrypt` derive the keystream from the same three **public** values: `ephemeralVertex` (from the ciphertext), `vStart`, and `vEnd` (both from the public key). The secret key parameter is accepted but never read.

#### Evidence

```typescript
// egrwEncrypt (src/problems/egrw/index.ts:401-406)
const keyInput = hashConcat(
  hashWithDomain(DOMAIN_MASK, sl2ToBytes(ephemeralVertex)), // in ciphertext
  hashWithDomain(DOMAIN_MASK, sl2ToBytes(vStart)), // public key
  hashWithDomain(DOMAIN_MASK, sl2ToBytes(vEnd)), // public key
)
const keyStream = shake256(keyInput, 32)

// egrwDecrypt (src/problems/egrw/index.ts:449-454) — identical computation
const keyInput = hashConcat(
  hashWithDomain(DOMAIN_MASK, sl2ToBytes(ephemeralVertex)), // same: from ciphertext
  hashWithDomain(DOMAIN_MASK, sl2ToBytes(vStart)), // same: public key
  hashWithDomain(DOMAIN_MASK, sl2ToBytes(vEnd)), // same: public key
)
const keyStream = shake256(keyInput, 32)
// secretKey parameter is never accessed
```

The code comment in `egrwDecrypt` (line 424) explicitly acknowledges this: _"The recipient doesn't need the secret walk for decryption in this KEM construction since the keystream is derived from public values."_

#### Attack

Any party who observes the ciphertext `(ephemeralVertex, masked)` and the recipient's public key `(vStart, vEnd)` can recompute the keystream and XOR-decrypt the message:

```
keyInput  = H(sl2ToBytes(ephemeralVertex)) || H(sl2ToBytes(vStart)) || H(sl2ToBytes(vEnd))
keyStream = SHAKE256(keyInput, 32)
plaintext = masked XOR keyStream
```

#### Fix Required

True EGRW-based PKE requires the recipient to apply their secret walk to the sender's ephemeral vertex: `sharedVertex = applyWalk(ephemeralVertex, secretWalk, p)`. The keystream must be derived from this `sharedVertex`, which only the secret key holder can compute (given the graph walk hardness assumption). This is a complete redesign of the EGRW encryption scheme.

#### Revalidation (2026-04-11) — VERDICT: CONFIRMED VALID

Independent code review confirms the auditor's finding. The keystream at `src/egrw/index.ts:435-463` is derived entirely from public values (`ephemeralVertex`, `vStart`, `vEnd`). The `secretKey.walk` parameter is accepted but never accessed. EGRW provides zero confidentiality.

**Severity downgraded from CRITICAL to HIGH:** While EGRW's share (share3) is recoverable by any observer, this alone does not break the full KEM — the ephemeral secret is XOR-split into 3 shares, and an attacker still needs all 3 to recover the shared secret. Combined with CRIT-03, an attacker recovers shares 2 and 3, reducing KEM security to SLSS alone. This violates the defense-in-depth claim but is not a complete KEM break if SLSS is sound.

---

### CRIT-03: TDD Secret Key Never Used in Decryption — Keyless Decryption ❌ CONFIRMED

- **Severity:** ~~CRITICAL~~ → **HIGH** (revalidated 2026-04-11; see note below)
- **Status:** ❌ Open — confirmed valid, not patched
- **File:** `src/problems/tdd/index.ts:516–591`
- **OWASP:** A02:2021 Cryptographic Failures

#### Description

`tddDecrypt` recomputes the secret tensor `T_secret` from the private factors, but then never uses it. Instead, both `tddEncrypt` and `tddDecrypt` derive the keystream from `DOMAIN_HINT || maskedBytes`, where `maskedBytes` is the masked matrix stored in the ciphertext. The secret factors are recomputed and then immediately zeroized without having been used for decryption.

#### Evidence

```typescript
// tddEncrypt (src/problems/tdd/index.ts:461-466)
const maskedBytes = new Uint8Array(
  masked.buffer,
  masked.byteOffset,
  masked.byteLength,
)
const keystream = shake256(hashWithDomain(DOMAIN_HINT, maskedBytes), 32)
// keystream derived entirely from public ciphertext data

// tddDecrypt (src/problems/tdd/index.ts:570-578)
const maskedBytes = new Uint8Array(
  masked.buffer,
  masked.byteOffset,
  masked.byteLength,
)
const keystream = shake256(hashWithDomain(DOMAIN_HINT, maskedBytes), 32)
// identical derivation — T_secret (lines 551-561) is recomputed but never read
zeroize(T_secret) // recomputed only to be thrown away
```

#### Attack

Any party with the ciphertext `data[]` can decrypt:

```
masked    = data[0 : n²]
maskedBytes = bytes(masked)
keystream = SHAKE256(H("kmosaic-tdd-hint", maskedBytes), 32)
plaintext = encryptedMsg XOR keystream
```

#### Fix Required

Correct TDD-based PKE would require the recipient to use their secret factors to reconstruct the contracted product and subtract the masking tensor, then re-derive the keystream from the **unmasked** contracted product (which only the secret key holder can compute). This is a complete redesign of the TDD encryption scheme.

#### Revalidation (2026-04-11) — VERDICT: CONFIRMED VALID

Independent code review confirms the auditor's finding. At `src/tdd/index.ts:570-578`, the keystream is derived from `DOMAIN_HINT || maskedBytes` where `maskedBytes` comes directly from the ciphertext. The secret tensor factors ARE reconstructed (lines 550-561) but are never used for keystream derivation — they are immediately zeroized. TDD provides zero confidentiality.

**Severity downgraded from CRITICAL to HIGH:** Same reasoning as CRIT-02. TDD's share (share2) is recoverable by any observer. Combined with CRIT-02, an attacker recovers 2 of 3 XOR shares, reducing KEM security entirely to SLSS. The "three independent problems" defense-in-depth is security theater for 2 of 3 components, but the KEM is not completely broken if SLSS holds.

---

### CRIT-04: Sub-SLSS Sigma Protocol — Existential Forgery ❌ CONFIRMED (deeper root cause)

- **Severity:** CRITICAL (revalidated 2026-04-11; confirmed, root cause corrected)
- **Status:** ❌ Open — confirmed valid, not patched
- **File:** `src/sign/index.ts:450–451`
- **OWASP:** A07:2021 Identification and Authentication Failures

#### Description

The sub-SLSS Sigma protocol challenge is reduced to a single bit (`challenge[0] & 1`), yielding a challenge space of exactly `{-1, +1}`. This gives the protocol a soundness error of 1/2 — equivalent to a coin flip. A forger can deterministically produce a valid signature for any message without knowing the secret key.

#### Evidence

```typescript
// src/sign/index.ts:450-451
const cScalar = (challenge[0] & 1) === 0 ? 1 : -1
// Challenge space: {-1, +1} — two possible values
```

The verification equation is: `A'·z - c_scalar·t' ≡ w_check (mod Q_SIG)`, then `H(w_check || t' || msg || binding) == commitment`.

#### Forgery Algorithm (O(1))

Given target message `msg` and public key `(publicKey, publicKeyHash)`:

1. Choose arbitrary short vector `z_fake ∈ [-GAMMA_1+1, GAMMA_1-1]^{N_SIG}`
2. Choose arbitrary `t_fake` (e.g., zero vector)
3. For each `c ∈ {+1, -1}`:
   - Compute `w_fake = A'·z_fake - c·t_fake mod Q_SIG`
   - Compute `commitment_fake = H(serialize(w_fake) || serialize(t_fake) || msgHash || binding)`
   - Compute `challenge_fake = H_domain(commitment_fake || msgHash || pkHash)`
   - Derive `c_scalar_fake = (challenge_fake[0] & 1) == 0 ? 1 : -1`
   - If `c_scalar_fake == c`: output `(commitment_fake, response = t_fake||z_fake)` — **this is a valid forgery**
4. Exactly one of the two values of `c` will always match — one iteration guaranteed.

**Cost:** ~2 matrix multiplications + 4 hash calls. Forgery is deterministic and takes O(1).

#### Why Existing Tests Don't Catch This

The three forgery resistance tests in `test/sign.test.ts` use **random** forgery attempts (arbitrary commitment/response bytes). They do not attempt the targeted algebraic forgery described above, so they pass despite the vulnerability.

#### Fix Required

The challenge must be drawn from a large challenge set (e.g., challenge polynomials in Dilithium use challenges with exactly 60 ±1 coefficients out of 256, giving `C(256,60)·2^60 ≈ 2^249` possibilities). At minimum, use all 256 bits of the challenge hash as a binary vector `c ∈ {0,1}^{256}` and modify the signing/verification relation accordingly. Better: replace with ML-DSA (NIST FIPS 204).

---

## New High Findings

---

### HIGH-01: SLSS Ciphertext Leaks Bit Equality — IND-CPA Violation ❌ CONFIRMED

- **Severity:** HIGH (revalidated 2026-04-11; confirmed)
- **Status:** ❌ Open — confirmed valid, not patched
- **File:** `src/problems/slss/index.ts`

#### Description

In `slssEncrypt`, each of the 256 message bits is encoded by adding a scaled bit value to a dot product `tDotR = t · r`. Because `t` and `r` are shared across all 256 bit positions, the ciphertext leaks whether any two bits of the plaintext are equal: `v[i] - v[j] = (bit_i - bit_j) * floor(q/2)`, which is either 0, +floor(q/2), or -floor(q/2) — distinguishable from noise with overwhelming probability. This breaks IND-CPA.

#### Fix Required

Each bit must use an independent ephemeral `r_i` (re-sample fresh randomness per bit), or switch to a scheme where a single `r` encodes the entire message without per-bit signals.

#### Revalidation (2026-04-11) — VERDICT: CONFIRMED VALID

Independent code review confirms. At `src/problems/slss/index.ts:581`, `tDotR = innerProduct(t, r, q)` returns a single scalar (verified at line 198-213: `innerProduct` returns `mod(sum, q)`, a number). This scalar is reused for all 256 bit positions at line 584: `v[i] = mod(tDotR + e2[i] + encodedMsg[i], q)`.

Computing `v[i] - v[j] = (e2[i] - e2[j]) + (encodedMsg[i] - encodedMsg[j])`:

- Equal bits: difference ≈ N(0, 2σ²) with σ=3.19, std dev ≈ 4.51
- Different bits: difference ≈ ±6144 + N(0, 2σ²)

The 6144 gap vs. 4.51 noise std dev makes bit equality trivially distinguishable, confirming the IND-CPA break. In the KEM context, this leaks pairwise equality of encrypted share bits, providing partial information about the SLSS share.

---

### HIGH-02: EGRW Prime Too Small — Discrete Log Breakable ❌ CONFIRMED

- **Severity:** HIGH (revalidated 2026-04-11; confirmed)
- **Status:** ❌ Open — confirmed valid, not patched
- **File:** `src/core/params.ts` (EGRW parameters), `src/problems/egrw/index.ts`

#### Description

The EGRW scheme uses `p = 1021` (MOS-128) and `p = 2039` (MOS-256). The SL₂(𝔽_p) group has order approximately `p³ ≈ 10⁹` for `p=1021`. Baby-step Giant-step solves the discrete logarithm on this group in ~`sqrt(p³) ≈ 2^15` operations — far below 128-bit security. For `p=2039`, BSGS requires ~`2^16.5` operations. Achieving 128-bit security requires `p ≥ 2^43` (such that `p³ ≥ 2^128`).

#### Fix Required

Increase `p` to at least `2^43` for MOS-128 and `2^86` for MOS-256, or use a different group where the hardness assumption is well-studied at the required bit length.

#### Revalidation (2026-04-11) — VERDICT: CONFIRMED VALID

Independent code review confirms. At `src/core/params.ts:45`, p=1021; at line 76, p=2039. The exact group order |SL(2, Z_p)| = p(p-1)(p+1):

- MOS-128: 1021 x 1020 x 1022 = 1,064,331,240 ≈ 2^30. BSGS: ~2^15 ops.
- MOS-256: 2039 x 2038 x 2040 = 8,474,078,640 ≈ 2^33. BSGS: ~2^16.5 ops.

Note: this is currently academic since CRIT-02 means EGRW's secret key is never used in decryption anyway. But if CRIT-02 were fixed, the primes would still be far too small.

---

### HIGH-03: TDD Hardness Has No Average-Case Reduction ❌ CONFIRMED

- **Severity:** HIGH (revalidated 2026-04-11; confirmed)
- **Status:** ❌ Open — confirmed valid, not patched
- **File:** `src/problems/tdd/index.ts` (design-level)

#### Description

The security argument for TDD-based PKE relies on the hardness of recovering random tensor decomposition factors from the public tensor `T`. While worst-case tensor decomposition is NP-hard, there is no known average-case hardness reduction for this problem. Random instances of tensor decomposition are often tractable via algebraic methods (e.g., Jennrich's algorithm solves exact decomposition in polynomial time for generic tensors). The assumption that random TDD instances are hard lacks peer-reviewed cryptographic support.

#### Fix Required

Replace TDD with a hardness assumption that has a known average-case reduction (e.g., LWE, NTRU, McEliece). This requires a scheme redesign.

#### Revalidation (2026-04-11) — VERDICT: CONFIRMED VALID

Independent code review confirms. The source at `src/problems/tdd/index.ts:4` claims "NP-hard in general" and line 360 says "believed to be hard." Factor triples `(a_i, b_i, c_i)` are sampled uniformly at random (lines 252-281), not from a structured distribution with a worst-to-average-case reduction. With small dimensions (n=24, r=6 for MOS-128 at `src/core/params.ts:39-40`) and small noise (σ=2.0, q=7681), algebraic tensor decomposition methods may be practical. Unlike LWE, no reduction from a well-studied lattice problem exists for this construction.

---

### HIGH-04: Signing Sub-Key Space Is Exhaustible ❌ CONFIRMED

- **Severity:** HIGH (revalidated 2026-04-11; confirmed)
- **Status:** ❌ Open — confirmed valid, not patched
- **File:** `src/sign/index.ts` (parameters: `N_SIG=32, W_SIG=8`)

#### Description

The signing secret `s' ∈ {-1,0,1}^{32}` has Hamming weight exactly `W_SIG=8`. The total key space is `C(32,8) × 2^8 = 10,518,300 × 256 ≈ 2^31.3` possible secrets. This is exhaustible by a modern laptop in seconds. Even without CRIT-04, an attacker can recover the signing secret by trying all `~2^31` candidates and checking `A'·s_candidate ≡ t' (mod Q_SIG)`.

#### Fix Required

Increase `N_SIG` to at least 256 and `W_SIG` to at least 64, giving `C(256,64) × 2^64 ≈ 2^249` possible secrets. Adjust `GAMMA_1` and rejection bounds accordingly.

#### Revalidation (2026-04-11) — VERDICT: CONFIRMED VALID

Independent code review confirms. At `src/sign/index.ts:88-91`: N_SIG=32, W_SIG=8. The `deriveSubSecret` function (lines 146-173) selects exactly 8 distinct positions from 32, each assigned ±1 from a hash-derived sign byte.

Key space: C(32,8) x 2^8 = 10,518,300 x 256 = 2,692,684,800 ≈ 2^31.3. After observing one valid signature (which embeds t' in the response at lines 58-59), an attacker extracts t', then brute-forces all ~2.7 billion s' candidates checking `A' · s_candidate ≡ t' (mod 12289)`. Each check is a 32x32 matrix-vector multiply (~1024 multiply-adds). Total: ~2.76 x 10^12 ops — minutes on modern hardware.

Note: this is a secondary forgery path. CRIT-04 already provides O(1) forgery without needing to recover s' at all.

---

## Structural / Design-Level Concerns

1. **Defense-in-depth argument is inverted.** The KEM combines three "independent" PKE schemes under the assumption that an attacker must break all three. However, when two or more components are broken (as they are here), the combined system inherits all their weaknesses — the weakest link dominates. Defense-in-depth only helps when all components are individually secure.

2. **Novel hardness assumptions without peer review.** EGRW and TDD as PKE building blocks are not studied in the cryptographic literature. Novel assumptions require extensive peer review and cryptanalysis before use in a security-critical system.

3. **NIZK proof ZK property is weakened.** ~~The NIZK proof in `src/entanglement/index.ts` was intended to add assurance but instead actively breaks the system (CRIT-01). Removing it would improve security.~~ _Revalidation note: CRIT-01 was determined to be a false positive. The NIZK does not leak shares because the challenge depends on the ephemeral secret. However, the NIZK is not simulator-extractable, which is a cosmetic ZK weakness (not a confidentiality break)._

4. **Security level estimates are ungrounded.** The `analyzePublicKey()` function outputs concrete bit-security estimates using arithmetic formulas (e.g., `Math.log2(q) * n * w`) with no grounding in actual cryptanalytic work or reduction proofs. These numbers should not be presented to users as meaningful security estimates.

5. **Box-Muller is not a discrete Gaussian sampler.** `src/utils/random.ts` uses Box-Muller to approximate Gaussian sampling. This generates a continuous approximation, not a proper discrete Gaussian. For lattice-based schemes, discrete Gaussian sampling is required for correctness of security proofs (e.g., flooding/rejection arguments).

6. **JavaScript JIT cannot guarantee constant-time execution.** The constant-time utilities in `src/utils/constant-time.ts` are best-effort. JavaScript's JIT compiler may optimize branches or reorder operations in ways that reintroduce timing side channels. For post-quantum cryptography, constant-time guarantees require native code (Rust/C with explicit volatile or barrier instructions) or WASM with audited compilation.

---

## Overall Verdict

| Finding                                                 | Original Severity | Revalidated Severity | Status            |
| ------------------------------------------------------- | ----------------- | -------------------- | ----------------- |
| CRIT-01: NIZK leaks all KEM shares                      | CRITICAL          | **Informational**    | ⚠️ False Positive |
| CRIT-02: EGRW decryption uses no secret key             | CRITICAL          | **HIGH**             | ❌ Confirmed Open |
| CRIT-03: TDD decryption uses no secret key              | CRITICAL          | **HIGH**             | ❌ Confirmed Open |
| CRIT-04: Sigma protocol allows existential forgery      | CRITICAL          | **CRITICAL**         | ❌ Confirmed Open |
| HIGH-01: SLSS IND-CPA violation via bit equality leak   | HIGH              | **HIGH**             | ❌ Confirmed Open |
| HIGH-02: EGRW prime too small — BSGS attack in 2^15 ops | HIGH              | **HIGH**             | ❌ Confirmed Open |
| HIGH-03: TDD has no average-case hardness reduction     | HIGH              | **HIGH**             | ❌ Confirmed Open |
| HIGH-04: Signing key space exhaustible in 2^31          | HIGH              | **HIGH**             | ❌ Confirmed Open |

**Revalidated effective security assessment (all 8 findings reviewed):**

- **1 false positive:** CRIT-01 (NIZK does NOT leak shares — auditor missed that challenge depends on ephemeral secret)
- **1 critical, confirmed:** CRIT-04 (signature forgery — root cause deeper than auditor stated: t' is blindly trusted, not just the 1-bit challenge)
- **6 high, confirmed:** CRIT-02, CRIT-03 (downgraded from CRITICAL), HIGH-01 through HIGH-04

**KEM security posture:** Defense-in-depth is broken. EGRW and TDD provide zero confidentiality (CRIT-02, CRIT-03). Even if fixed, EGRW primes are too small (HIGH-02) and TDD lacks a hardness reduction (HIGH-03). SLSS alone provides the only real confidentiality, but its IND-CPA property is violated (HIGH-01). The KEM should not be considered secure.

**Signature security posture:** Existential forgery is possible in O(1) via CRIT-04. Even if CRIT-04 were fixed, the sub-key space is exhaustible in ~2^31 (HIGH-04). The signature scheme should not be used.
