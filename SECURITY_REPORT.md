# kMOSAIC Deep Security Review Report

**Date:** 2026-04-10  
**Repository:** `BackendStack21/k-mosaic`  
**Scope:** `src/**`, CLI entrypoint, deserialization and cryptographic verification surfaces

---

## Executive Summary

This review identified one **critical exploitable cryptographic weakness** and multiple **input-handling hardening gaps**.

- ✅ Fixed in this PR:
  - Public-key deserialization hardening (library + CLI): strict bounds, component caps, canonical-length enforcement.
  - Signature deserialization canonicalization: reject trailing bytes.
- ⚠️ Critical issue still requiring architectural redesign:
  - Signature verification does not validate `response` against secret-derived algebraic relation, enabling existential forgeries.

---

## Findings

## 1) Critical: Signature existential forgery (architectural)

- **Severity:** Critical
- **Status:** Not fully remediated in this PR (design-level)
- **File:** `/home/runner/work/k-mosaic/k-mosaic/src/sign/index.ts`
- **Location:** `verify()` logic

### Impact

`verify()` currently validates only whether:

- signature structure is well-formed, and
- `signature.challenge == H(signature.commitment, message, publicKeyHash)`.

It does **not** verify that `signature.response` proves secret-key knowledge.  
An attacker can choose arbitrary commitment/response and set challenge consistently, yielding a valid signature without the secret key.

### Exploitability

This is directly exploitable as signature forgery in any consumer trusting `verify()` for authenticity.

### Required long-term fix

Replace the current signing system with a publicly verifiable construction where response validity is mathematically tied to the public key (e.g., a standard PQ signature construction or a correctly implemented Fiat-Shamir proof with verifiable response equations).

---

## 2) High: Public-key parser hardening gaps (DoS / parser confusion)

- **Severity:** High
- **Status:** ✅ Fixed
- **Files:**
  - `/home/runner/work/k-mosaic/k-mosaic/src/kem/index.ts`
  - `/home/runner/work/k-mosaic/k-mosaic/src/k-mosaic-cli.ts`

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
- **File:** `/home/runner/work/k-mosaic/k-mosaic/src/sign/index.ts`

### Risk before fix

`deserializeSignature()` accepted trailing bytes after the declared response.  
This creates non-canonical encodings and can cause downstream signature-encoding ambiguity.

### Fix applied

- Added strict trailing-byte rejection (`offset !== data.length` -> error).
- Added regression test coverage.

---

## Code Changes in This PR

1. **KEM public key deserialization hardening**
   - File: `/home/runner/work/k-mosaic/k-mosaic/src/kem/index.ts`
   - Added component-size caps.
   - Added trailing-byte rejection.

2. **CLI public key deserialization hardening**
   - File: `/home/runner/work/k-mosaic/k-mosaic/src/k-mosaic-cli.ts`
   - Added strict truncation/bounds checks.
   - Added component-size caps.
   - Added trailing-byte rejection.

3. **Signature deserialization canonicalization**
   - File: `/home/runner/work/k-mosaic/k-mosaic/src/sign/index.ts`
   - Reject trailing bytes.

4. **Regression tests**
   - Added: `/home/runner/work/k-mosaic/k-mosaic/test/kem-public-key-malformed.test.ts`
   - Updated: `/home/runner/work/k-mosaic/k-mosaic/test/sign.test.ts`

---

## Validation

- ✅ `npm run build` succeeded.
- ⚠️ Full test suite could not be executed in this runner because project tests require Bun (`bun test`) and Bun is unavailable in the environment.

---

## Recommended Next Security Actions

1. **Priority 0:** Redesign and replace the signature scheme (current verify path is forgeable).
2. Add explicit parser limits for all externally supplied serialized artifacts (ciphertext/signature/public key) in every API boundary.
3. Add adversarial fuzzing for all deserializers.
4. Add negative tests proving no unverifiable signature can pass without secret knowledge once signature redesign is complete.
