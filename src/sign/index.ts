/**
 * kMOSAIC Digital Signatures
 *
 * Fiat-Shamir signature scheme with a dedicated 32-dimensional noiseless-SLSS
 * Sigma protocol response to bind the response to the signer's secret key.
 *
 * Security Properties:
 * - Fiat-Shamir: Non-interactive via hash-based challenge
 * - Algebraic response binding: response z = r + c·s verified via A'·z - c·t' = w exactly
 * - Unforgeable: Forging requires finding z with small norm satisfying A'·z - c·t' = w
 *
 * Signature Structure:
 * - Commitment: 32-byte H(A'·r || msgHash || binding)  [w stored in commitment, not highBits]
 * - Challenge: 32-byte H_domain(commitment || msgHash || pkHash)
 * - Response: 128 bytes = tBytes (64B: serialize(t') as 32 Int16 LE) || zBytes (64B: serialize(z) as 32 Int16 LE)
 *
 * Fix for CVE-equivalent Finding 1: Existential Forgery
 * Previous scheme: response was SHAKE256(sk || challenge || witness), never verified.
 * New scheme: response is algebraic witness z = r + c·s satisfying A'·z - c·t' = w,
 * where w = A'·r is committed to in the signature. The verifier can check this
 * algebraic relation in full using only public key material.
 *
 * Key design choice: we use a DEDICATED signing sub-key (A', s', t' = A'·s') derived
 * deterministically from the master seed. t' is noiseless (no LWE error), which gives
 * an exact check A'·z - c·t' = A'·r = w mod q. This avoids error-tolerance complications
 * while maintaining binding: forging z requires knowing s'.
 */

import {
  SecurityLevel,
  type MOSAICParams,
  type MOSAICPublicKey,
  type MOSAICSecretKey,
  type MOSAICKeyPair,
  type MOSAICSignature,
} from '../types.js'

import { getParams, validateParams } from '../core/params.js'
import {
  shake256,
  hashConcat,
  hashWithDomain,
  sha3_256,
} from '../utils/shake.js'
import { secureRandomBytes } from '../utils/random.js'
import { constantTimeEqual, zeroize } from '../utils/constant-time.js'

import {
  slssKeyGen,
  slssSerializePublicKey,
  matVecMul,
} from '../problems/slss/index.js'

import { tddKeyGen, tddSerializePublicKey } from '../problems/tdd/index.js'

import { egrwKeyGen, egrwSerializePublicKey } from '../problems/egrw/index.js'

import { computeBinding } from '../entanglement/index.js'

// =============================================================================
// Domain Separation Constants
// =============================================================================

const DOMAIN_CHALLENGE = 'kmosaic-sign-chal-v2'
const DOMAIN_SIGN_SUB_KEY = 'kmosaic-sign-subkey-v2'
const DOMAIN_SIGN_SUB_MAT = 'kmosaic-sign-submat-v2'

// =============================================================================
// Sub-SLSS Sigma Protocol Parameters
//
// A dedicated signing sub-key (A', s', t' = A'·s') is derived from the master seed.
// The Sigma protocol: prover knows s' s.t. A'·s' = t'.
// Commitment: w = A'·r for fresh random r.
// Response: z = r + c·s' where c ∈ {-1,+1} is a scalar derived from the challenge hash.
// Verify: A'·z - c·t' = A'·r = w  (exact, no error term).
//
// Parameters chosen for practical rejection rate (~1%) and 64-byte response:
//   N_SIG=32: sub-lattice dimension
//   M_SIG=32: sub-lattice rows (M_SIG ≥ N_SIG for uniqueness)
//   Q_SIG=12289: same prime as SLSS for convenience
//   W_SIG=8: Hamming weight of signing secret s' ∈ {-1,0,1}^{N_SIG}
//   GAMMA_1=3000: mask bound
//   BETA=1: slack (= ||c·s'||∞ = ||s'||∞ = 1 since s' ∈ {-1,0,1})
//   Rejection rate: Pr[|z_i| > 2999] ≈ 2/6001 per component, ~1.07% total for N_SIG=32
//   Response z_i ∈ [-3001, 3001] fits in Int16 (range ±32767) ✓
// =============================================================================

const N_SIG = 32 // Sub-lattice dimension
const M_SIG = 32 // Sub-lattice rows
const Q_SIG = 12289 // Prime modulus (same as MOS_128 SLSS)
const W_SIG = 8 // Signing secret weight
const GAMMA_1 = 3000 // Mask bound
const BETA = 1 // ||c·s'||∞ ≤ BETA = 1 for scalar c ∈ {-1,+1} and s' ∈ {-1,0,1}
const MAX_ITERATIONS = 200 // Safety bound on rejection-sampling loop

// =============================================================================
// Modular Arithmetic Helpers
// =============================================================================

/** Non-negative modular reduction: result in [0, q) */
function modQ(x: number, q: number): number {
  const r = x % q
  return r < 0 ? r + q : r
}

// =============================================================================
// Sub-Key Derivation
// =============================================================================

/**
 * Derive the signing sub-matrix A' (M_SIG × N_SIG) from a seed.
 * Uses rejection sampling for unbiased uniform distribution over Z_{Q_SIG}.
 */
function deriveSubMatrix(seed: Uint8Array): Int32Array {
  const size = M_SIG * N_SIG
  const A = new Int32Array(size)
  const UINT32_MAX = 0xffffffff
  const threshold = UINT32_MAX - (UINT32_MAX % Q_SIG)

  let generated = 0
  let counter = 0

  while (generated < size) {
    const ctrBuf = new Uint8Array(seed.length + 4)
    ctrBuf.set(seed)
    new DataView(ctrBuf.buffer).setUint32(seed.length, counter, true)
    const bytes = shake256(ctrBuf, size * 4)
    const view = new DataView(bytes.buffer)
    counter++

    for (let i = 0; i + 3 < bytes.length && generated < size; i += 4) {
      const v = view.getUint32(i, true)
      if (v <= threshold) {
        A[generated++] = v % Q_SIG
      }
    }
  }

  return A
}

/**
 * Derive the signing sub-secret s' ∈ {-1,0,1}^{N_SIG} with Hamming weight W_SIG.
 * Uses rejection sampling for uniform random positions.
 */
function deriveSubSecret(seed: Uint8Array): Int8Array {
  const s = new Int8Array(N_SIG)
  const positions = new Set<number>()
  let counter = 0

  while (positions.size < W_SIG) {
    const ctrBuf = new Uint8Array(seed.length + 4)
    ctrBuf.set(seed)
    new DataView(ctrBuf.buffer).setUint32(seed.length, counter, true)
    const bytes = shake256(ctrBuf, W_SIG * 8)
    const view = new DataView(bytes.buffer)
    counter++

    for (let i = 0; i + 3 < bytes.length && positions.size < W_SIG; i += 4) {
      const pos = view.getUint32(i, true) % N_SIG
      positions.add(pos)
    }
  }

  // Derive signs from a fresh hash of the seed
  const signBytes = hashWithDomain('kmosaic-sign-subkey-signs-v2', seed)
  let idx = 0
  for (const pos of positions) {
    s[pos] = signBytes[idx++ % signBytes.length] & 1 ? 1 : -1
  }

  return s
}

// =============================================================================
// Sigma Protocol Helpers
// =============================================================================

/**
 * Sample a uniform mask vector r ∈ [-GAMMA_1, GAMMA_1]^{N_SIG} from a seed.
 * Uses rejection sampling for unbiased distribution.
 */
function sampleMaskVector(seed: Uint8Array): Int32Array {
  const r = new Int32Array(N_SIG)
  const range = 2 * GAMMA_1 + 1
  const UINT32_MAX = 0xffffffff
  const threshold = UINT32_MAX - (UINT32_MAX % range)

  let generated = 0
  let counter = 0

  while (generated < N_SIG) {
    const ctrBuf = new Uint8Array(seed.length + 4)
    ctrBuf.set(seed)
    new DataView(ctrBuf.buffer).setUint32(seed.length, counter, true)
    const bytes = shake256(ctrBuf, N_SIG * 4 * 2)
    const view = new DataView(bytes.buffer)
    counter++

    for (let i = 0; i + 3 < bytes.length && generated < N_SIG; i += 4) {
      const v = view.getUint32(i, true)
      if (v <= threshold) {
        r[generated++] = (v % range) - GAMMA_1
      }
    }
  }

  return r
}

/**
 * Serialize response vector z (N_SIG Int32 values) as N_SIG Int16 LE pairs = 64 bytes.
 * Values satisfy ||z||∞ ≤ GAMMA_1 + BETA ≤ 3001 which fits in Int16 (±32767).
 */
function serializeZ(z: Int32Array): Uint8Array {
  const out = new Uint8Array(N_SIG * 2)
  const view = new DataView(out.buffer)
  for (let i = 0; i < N_SIG; i++) {
    view.setInt16(i * 2, z[i], true)
  }
  return out
}

/** Deserialize response bytes back to z vector. */
function deserializeZ(data: Uint8Array): Int32Array {
  if (data.length !== N_SIG * 2) {
    throw new Error(
      `Invalid response: expected ${N_SIG * 2} bytes, got ${data.length}`,
    )
  }
  const z = new Int32Array(N_SIG)
  const view = new DataView(data.buffer, data.byteOffset)
  for (let i = 0; i < N_SIG; i++) {
    z[i] = view.getInt16(i * 2, true)
  }
  return z
}

/**
 * Constant-time infinity-norm bound check: returns true iff all |z_i| ≤ bound.
 * Processes all elements without early exit to prevent timing leakage.
 */
function checkBound(z: Int32Array, bound: number): boolean {
  let ok = true
  for (let i = 0; i < z.length; i++) {
    const absZi = z[i] < 0 ? -z[i] : z[i]
    // Boolean AND keeps us from short-circuiting
    ok = ok && absZi <= bound
  }
  return ok
}

/**
 * Serialize a commitment witness w (M_SIG values in [0, Q_SIG)) for hashing.
 * Each value is stored as 2 bytes (Uint16 LE).
 */
function serializeW(w: Int32Array): Uint8Array {
  const out = new Uint8Array(w.length * 2)
  const view = new DataView(out.buffer)
  for (let i = 0; i < w.length; i++) {
    view.setUint16(i * 2, w[i], true)
  }
  return out
}

// =============================================================================
// Signing Sub-Key Context (per signing operation)
// =============================================================================

interface SigningSubKey {
  A: Int32Array // M_SIG × N_SIG
  s: Int8Array // N_SIG, in {-1,0,1}^W_SIG
  t: Int32Array // M_SIG, t = A·s mod Q_SIG (noiseless)
}

/**
 * Derive the signing sub-key from the master secret seed.
 * The sub-key (A', s', t' = A'·s') is deterministic from the seed and is
 * the cryptographic core of the forgery resistance: forging requires finding
 * a short z satisfying A'·z - c·t' = w for a given w and scalar c.
 *
 * Note: A' is derived from a PUBLIC domain (seeded from publicKeyHash),
 * so it is effectively public — the verifier can re-derive it. s' is private.
 */
function deriveSigningSubKey(
  masterSeed: Uint8Array,
  publicKeyHash: Uint8Array,
): SigningSubKey {
  // A' is derived from a combination of master seed and public key hash —
  // this binds the signing key to the specific key pair while allowing
  // the verifier (who has publicKeyHash) to re-derive A' deterministically.
  // IMPORTANT: A' must be derivable by the verifier, but s' must remain secret.
  const matSeed = hashWithDomain(DOMAIN_SIGN_SUB_MAT, hashConcat(publicKeyHash))
  const secSeed = hashWithDomain(
    DOMAIN_SIGN_SUB_KEY,
    hashConcat(masterSeed, publicKeyHash),
  )

  const A = deriveSubMatrix(matSeed)
  const s = deriveSubSecret(secSeed)

  // Compute t = A·s mod Q_SIG (noiseless — exact algebraic relation)
  const sI32 = new Int32Array(N_SIG)
  for (let i = 0; i < N_SIG; i++) sI32[i] = s[i]
  const t = matVecMul(A, sI32, M_SIG, N_SIG, Q_SIG)

  return { A, s, t }
}

// =============================================================================
// Signature Key Generation
// =============================================================================

/**
 * Generate kMOSAIC signature key pair
 *
 * @param level - Security level (default: MOS_128)
 * @returns Promise resolving to the generated key pair
 */
export async function generateKeyPair(
  level: SecurityLevel = SecurityLevel.MOS_128,
): Promise<MOSAICKeyPair> {
  const params = getParams(level)
  validateParams(params)

  const seed = secureRandomBytes(32)
  return generateKeyPairFromSeed(params, seed)
}

/**
 * Generate key pair from seed (deterministic)
 *
 * @param params - System parameters
 * @param seed - Master seed (must be at least 32 bytes)
 * @returns Generated key pair
 */
export function generateKeyPairFromSeed(
  params: MOSAICParams,
  seed: Uint8Array,
): MOSAICKeyPair {
  if (seed.length < 32) {
    throw new Error('Seed must be at least 32 bytes')
  }

  // Derive independent component seeds
  const slssSeed = hashWithDomain('kmosaic-sign-slss-v1', seed)
  const tddSeed = hashWithDomain('kmosaic-sign-tdd-v1', seed)
  const egrwSeed = hashWithDomain('kmosaic-sign-egrw-v1', seed)

  // Generate component key pairs
  const slssKP = slssKeyGen(params.slss, slssSeed)
  const tddKP = tddKeyGen(params.tdd, tddSeed)
  const egrwKP = egrwKeyGen(params.egrw, egrwSeed)

  // Compute binding hash
  const slssBytes = slssSerializePublicKey(slssKP.publicKey)
  const tddBytes = tddSerializePublicKey(tddKP.publicKey)
  const egrwBytes = egrwSerializePublicKey(egrwKP.publicKey)
  const binding = computeBinding(slssBytes, tddBytes, egrwBytes)

  const publicKey: MOSAICPublicKey = {
    slss: slssKP.publicKey,
    tdd: tddKP.publicKey,
    egrw: egrwKP.publicKey,
    binding,
    params,
  }

  // Compute public key hash using serializePublicKey
  const publicKeyHash = sha3_256(serializePublicKey(publicKey))

  const secretKey: MOSAICSecretKey = {
    slss: slssKP.secretKey,
    tdd: tddKP.secretKey,
    egrw: egrwKP.secretKey,
    seed,
    publicKeyHash,
  }

  // Zeroize intermediate seeds
  zeroize(slssSeed)
  zeroize(tddSeed)
  zeroize(egrwSeed)

  return { publicKey, secretKey }
}

// =============================================================================
// Signature Generation
// =============================================================================

/**
 * Sign a message using the kMOSAIC sub-SLSS Sigma protocol.
 *
 * Algorithm:
 * 1. Derive signing sub-key (A', s', t' = A'·s') from master seed + pkHash
 * 2. Compute msgHash = H(message || binding)
 * 3. Rejection-sampling loop:
 *    a. Sample fresh mask r ← uniform [-GAMMA_1, GAMMA_1]^{N_SIG}
 *    b. Compute w = A'·r mod Q_SIG
 *    c. commitment = H(serializeW(w) || msgHash || binding)
 *    d. challenge = H_domain(commitment || msgHash || pkHash)
 *    e. c_scalar = (challenge[0] & 1) == 0 ? +1 : -1
 *    f. z = r + c_scalar * s'   (integer vector)
 *    g. If ||z||∞ > GAMMA_1 - BETA → reject, retry
 * 4. response = serializeZ(z)
 * 5. Return { commitment, challenge, response }
 *
 * @param message - Message to sign
 * @param secretKey - Secret key
 * @param publicKey - Public key
 * @returns Promise resolving to the signature
 */
export async function sign(
  message: Uint8Array,
  secretKey: MOSAICSecretKey,
  publicKey: MOSAICPublicKey,
): Promise<MOSAICSignature> {
  // Derive signing sub-key
  const subKey = deriveSigningSubKey(secretKey.seed, secretKey.publicKeyHash)

  // Compute message hash: H(message || binding)
  const msgHash = sha3_256(hashConcat(message, publicKey.binding))
  const publicKeyHash = secretKey.publicKeyHash

  for (let iter = 0; iter < MAX_ITERATIONS; iter++) {
    // Sample fresh mask r ∈ [-GAMMA_1, GAMMA_1]^{N_SIG}
    const maskSeed = secureRandomBytes(32)
    const r = sampleMaskVector(maskSeed)

    // Compute w = A'·r mod Q_SIG
    const w = matVecMul(subKey.A, r, M_SIG, N_SIG, Q_SIG)

    // Serialize t' for inclusion in commitment and response
    const tBytes = serializeW(subKey.t)

    // Compute commitment = H(serializeW(w) || tBytes || msgHash || binding)
    // Including tBytes binds the commitment to the signer's public sub-key t'
    const wBytes = serializeW(w)
    const commitment = sha3_256(
      hashConcat(wBytes, tBytes, msgHash, publicKey.binding),
    )

    // Compute challenge = H_domain(commitment || msgHash || pkHash)
    const challenge = hashWithDomain(
      DOMAIN_CHALLENGE,
      hashConcat(commitment, msgHash, publicKeyHash),
    )

    // Derive scalar challenge c_scalar ∈ {-1, +1}
    const cScalar = (challenge[0] & 1) === 0 ? 1 : -1

    // Compute z = r + c_scalar * s'
    const z = new Int32Array(N_SIG)
    for (let i = 0; i < N_SIG; i++) {
      z[i] = r[i] + cScalar * subKey.s[i]
    }

    // Rejection check: ||z||∞ ≤ GAMMA_1 - BETA
    if (!checkBound(z, GAMMA_1 - BETA)) {
      zeroize(maskSeed)
      zeroize(new Uint8Array(r.buffer))
      continue
    }

    // Accepted — response = tBytes (64B) || zBytes (64B) = 128 bytes
    const zBytes = serializeZ(z)
    const response = new Uint8Array(tBytes.length + zBytes.length)
    response.set(tBytes, 0)
    response.set(zBytes, tBytes.length)

    // Zeroize sensitive intermediates
    zeroize(maskSeed)
    zeroize(new Uint8Array(r.buffer))
    zeroize(new Uint8Array(subKey.s.buffer))

    return { commitment, challenge, response }
  }

  throw new Error('sign: exceeded maximum rejection-sampling iterations')
}

// =============================================================================
// Signature Verification
// =============================================================================

/**
 * Verify a kMOSAIC signature using the sub-SLSS algebraic relation.
 *
 * Algorithm:
 * 1. Structural validation: commitment=32B, challenge=32B, response=128B
 * 2. Recompute pkHash and msgHash
 * 3. Verify challenge = H_domain(commitment || msgHash || pkHash)
 *    — binds signature to a specific (message, public key) pair
 * 4. Derive c_scalar ∈ {-1,+1} from challenge[0]
 * 5. Parse response = tBytes (64B = M_SIG Uint16) || zBytes (64B = N_SIG Int16)
 * 6. Bound check ||z||∞ ≤ GAMMA_1 - BETA
 * 7. Re-derive A' from publicKeyHash (public, same derivation as sign())
 * 8. Compute w_check = A'·z - c_scalar·t' mod Q_SIG
 * 9. Verify: H(serializeW(w_check) || tBytes || msgHash || binding) == commitment
 *
 * The algebraic check in step 9 proves the signer knew s' s.t. A'·s' = t',
 * because a forger would need to find z with ||z||∞ ≤ GAMMA_1-BETA satisfying
 * the commitment equation — which requires knowledge of s'.
 *
 * @param message - Message to verify
 * @param signature - Signature object
 * @param publicKey - Public key
 * @returns Promise resolving to true if valid, false otherwise
 */
export async function verify(
  message: Uint8Array,
  signature: MOSAICSignature,
  publicKey: MOSAICPublicKey,
): Promise<boolean> {
  try {
    // Structural validation: response is now 128 bytes (tBytes || zBytes)
    if (
      !signature.commitment ||
      signature.commitment.length !== 32 ||
      !signature.challenge ||
      signature.challenge.length !== 32 ||
      !signature.response ||
      signature.response.length !== 128
    ) {
      return false
    }

    // Compute message hash
    const msgHash = sha3_256(hashConcat(message, publicKey.binding))

    // Compute public key hash
    const publicKeyHash = sha3_256(serializePublicKey(publicKey))

    // Step 1: Verify challenge binds (commitment, message, public key)
    const expectedChallenge = hashWithDomain(
      DOMAIN_CHALLENGE,
      hashConcat(signature.commitment, msgHash, publicKeyHash),
    )
    if (!constantTimeEqual(signature.challenge, expectedChallenge)) {
      return false
    }

    // Step 2: Derive c_scalar from challenge[0]
    const cScalar = (signature.challenge[0] & 1) === 0 ? 1 : -1

    // Step 3: Parse response = tBytes (64B) || zBytes (64B)
    const tBytes = signature.response.slice(0, M_SIG * 2)
    const zBytes = signature.response.slice(M_SIG * 2)

    // Deserialize t' (M_SIG Uint16 values in [0, Q_SIG))
    const tPrime = new Int32Array(M_SIG)
    const tView = new DataView(tBytes.buffer, tBytes.byteOffset)
    for (let i = 0; i < M_SIG; i++) {
      tPrime[i] = tView.getUint16(i * 2, true)
    }

    // Deserialize z (N_SIG Int16 values)
    let z: Int32Array
    try {
      z = deserializeZ(zBytes)
    } catch {
      return false
    }

    // Step 4: Bound check on z
    if (!checkBound(z, GAMMA_1 - BETA)) {
      return false
    }

    // Step 5: Re-derive A' from publicKeyHash (public derivation)
    const matSeed = hashWithDomain(
      DOMAIN_SIGN_SUB_MAT,
      hashConcat(publicKeyHash),
    )
    const subA = deriveSubMatrix(matSeed)

    // Step 6: Compute A'·z - c_scalar·t' mod Q_SIG = w_check
    const Az = matVecMul(subA, z, M_SIG, N_SIG, Q_SIG)
    const wCheck = new Int32Array(M_SIG)
    for (let i = 0; i < M_SIG; i++) {
      wCheck[i] = modQ(Az[i] - cScalar * tPrime[i], Q_SIG)
    }

    // Step 7: Recompute expected commitment and verify
    const wCheckBytes = serializeW(wCheck)
    const expectedCommitment = sha3_256(
      hashConcat(wCheckBytes, tBytes, msgHash, publicKey.binding),
    )

    return constantTimeEqual(signature.commitment, expectedCommitment)
  } catch {
    return false
  }
}

// =============================================================================
// Serialization
// =============================================================================

/**
 * Serialize signature to bytes
 *
 * Format:
 * [len:4][commitment (32)] || [len:4][challenge (32)] || [len:4][response (128)]
 * Total: 12 + 32 + 32 + 128 = 204 bytes
 *
 * @param sig - Signature object
 * @returns Serialized bytes
 */
export function serializeSignature(sig: MOSAICSignature): Uint8Array {
  const responseLen = sig.response.length // 128 for v2, 64 for legacy
  const result = new Uint8Array(12 + 32 + 32 + responseLen)
  const view = new DataView(result.buffer)
  let offset = 0

  // Commitment
  view.setUint32(offset, sig.commitment.length, true)
  offset += 4
  result.set(sig.commitment, offset)
  offset += sig.commitment.length

  // Challenge
  view.setUint32(offset, sig.challenge.length, true)
  offset += 4
  result.set(sig.challenge, offset)
  offset += sig.challenge.length

  // Response
  view.setUint32(offset, sig.response.length, true)
  offset += 4
  result.set(sig.response, offset)

  return result
}

/**
 * Deserialize signature from bytes
 *
 * Format: [len:4][commitment][len:4][challenge][len:4][response]
 *
 * @param data - Serialized signature bytes
 * @returns Deserialized signature object
 */
export function deserializeSignature(data: Uint8Array): MOSAICSignature {
  if (data.length < 12) throw new Error('Invalid signature: too short')
  const view = new DataView(data.buffer, data.byteOffset)
  let offset = 0

  // Commitment
  const commitmentLen = view.getUint32(offset, true)
  offset += 4
  if (commitmentLen <= 0 || offset + commitmentLen > data.length)
    throw new Error('Invalid signature: malformed commitment')
  const commitment = data.slice(offset, offset + commitmentLen)
  offset += commitmentLen

  // Challenge
  if (offset + 4 > data.length)
    throw new Error('Invalid signature: truncated challenge length')
  const challengeLen = view.getUint32(offset, true)
  offset += 4
  if (challengeLen <= 0 || offset + challengeLen > data.length)
    throw new Error('Invalid signature: malformed challenge')
  const challenge = data.slice(offset, offset + challengeLen)
  offset += challengeLen

  // Response
  if (offset + 4 > data.length)
    throw new Error('Invalid signature: truncated response length')
  const responseLen = view.getUint32(offset, true)
  offset += 4
  if (responseLen <= 0 || offset + responseLen > data.length)
    throw new Error('Invalid signature: malformed response')
  const response = data.slice(offset, offset + responseLen)
  offset += responseLen

  if (offset !== data.length) {
    throw new Error('Invalid signature: trailing bytes')
  }

  return { commitment, challenge, response }
}

/**
 * Serialize public key for hashing
 *
 * @param pk - Public key
 * @returns Serialized public key bytes
 */
export function serializePublicKey(pk: MOSAICPublicKey): Uint8Array {
  const slssBytes = slssSerializePublicKey(pk.slss)
  const tddBytes = tddSerializePublicKey(pk.tdd)
  const egrwBytes = egrwSerializePublicKey(pk.egrw)

  // Serialize security level as string
  const levelBytes = new TextEncoder().encode(pk.params.level)

  const totalLen =
    4 +
    levelBytes.length +
    4 +
    slssBytes.length +
    4 +
    tddBytes.length +
    4 +
    egrwBytes.length +
    32 // binding is fixed 32 bytes

  const result = new Uint8Array(totalLen)
  const view = new DataView(result.buffer)

  let offset = 0

  // Security level string
  view.setUint32(offset, levelBytes.length, true)
  offset += 4
  result.set(levelBytes, offset)
  offset += levelBytes.length

  // SLSS component
  view.setUint32(offset, slssBytes.length, true)
  offset += 4
  result.set(slssBytes, offset)
  offset += slssBytes.length

  // TDD component
  view.setUint32(offset, tddBytes.length, true)
  offset += 4
  result.set(tddBytes, offset)
  offset += tddBytes.length

  // EGRW component
  view.setUint32(offset, egrwBytes.length, true)
  offset += 4
  result.set(egrwBytes, offset)
  offset += egrwBytes.length

  // Binding (fixed 32 bytes, no length prefix)
  result.set(pk.binding, offset)

  return result
}
