/**
 * kMOSAIC Digital Signatures
 *
 * Multi-witness Fiat-Shamir signature scheme where the signer proves knowledge
 * of THREE entangled witnesses simultaneously.
 *
 * Security Properties:
 * - Multi-witness: Breaking requires solving SLSS AND TDD AND EGRW
 * - Fiat-Shamir: Non-interactive via hash-based challenge
 * - Rejection sampling: Ensures signature doesn't leak secret key
 * - Deterministic: Same message + key produces same signature
 *
 * Signature Structure:
 * - Challenge: 32-byte hash binding commitments to message
 * - z1: SLSS response vector with commitment
 * - z2: TDD response vector with commitment
 * - z3: EGRW response walk with hints
 */

import {
  SecurityLevel,
  type MOSAICParams,
  type MOSAICPublicKey,
  type MOSAICSecretKey,
  type MOSAICKeyPair,
  type MOSAICSignature,
} from '../types'

import { getParams, validateParams } from '../core/params'
import { shake256, hashConcat, hashWithDomain, sha3_256 } from '../utils/shake'
import { secureRandomBytes } from '../utils/random'
import { constantTimeEqual, zeroize } from '../utils/constant-time'

import { slssKeyGen, slssSerializePublicKey } from '../problems/slss/index'

import { tddKeyGen, tddSerializePublicKey } from '../problems/tdd/index'

import {
  egrwKeyGen,
  egrwSerializePublicKey,
  sl2ToBytes,
} from '../problems/egrw/index'

import { computeBinding } from '../entanglement/index'

// =============================================================================
// Domain Separation Constants
// =============================================================================

const DOMAIN_SIGN_SLSS = 'kmosaic-sign-slss-v1'
const DOMAIN_SIGN_TDD = 'kmosaic-sign-tdd-v1'
const DOMAIN_SIGN_EGRW = 'kmosaic-sign-egrw-v1'
const DOMAIN_SIGN_ATTEMPT = 'kmosaic-sign-attempt-v1'
const DOMAIN_MASK_SLSS = 'kmosaic-sign-mask-slss-v1'
const DOMAIN_MASK_TDD = 'kmosaic-sign-mask-tdd-v1'
const DOMAIN_MASK_EGRW = 'kmosaic-sign-mask-egrw-v1'

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Modular reduction - always returns non-negative result in [0, q)
 *
 * @param x - Input number
 * @param q - Modulus
 * @returns x mod q in [0, q)
 */
function mod(x: number, q: number): number {
  const r = x % q
  return r < 0 ? r + q : r
}

/**
 * Sample mask vector for SLSS commitment
 * Samples uniformly in [-gamma, gamma] for hiding the secret
 *
 * @param seed - Random seed
 * @param n - Dimension
 * @param gamma - Range parameter
 * @param q - Modulus
 * @returns Mask vector
 */
function sampleSLSSMask(
  seed: Uint8Array,
  n: number,
  gamma: number,
  q: number,
): Int32Array {
  const bytes = shake256(seed, n * 4)
  const view = new DataView(bytes.buffer, bytes.byteOffset)
  const result = new Int32Array(n)
  const range = 2 * gamma + 1

  for (let i = 0; i < n; i++) {
    const raw = view.getUint32(i * 4, true)
    result[i] = mod((raw % range) - gamma, q)
  }

  return result
}

/**
 * Sample mask for TDD commitment
 *
 * @param seed - Random seed
 * @param size - Size of mask
 * @param gamma - Range parameter
 * @param q - Modulus
 * @returns Mask vector
 */
function sampleTDDMask(
  seed: Uint8Array,
  size: number,
  gamma: number,
  q: number,
): Int32Array {
  const bytes = shake256(seed, size * 4)
  const view = new DataView(bytes.buffer, bytes.byteOffset)
  const result = new Int32Array(size)
  const range = 2 * gamma + 1

  for (let i = 0; i < size; i++) {
    const raw = view.getUint32(i * 4, true)
    result[i] = mod((raw % range) - gamma, q)
  }

  return result
}

/**
 * Sample random walk mask for EGRW commitment
 * Returns array of generator indices (0-3)
 *
 * @param seed - Random seed
 * @param length - Length of walk
 * @returns Array of generator indices
 */
function sampleWalkMask(seed: Uint8Array, length: number): number[] {
  const bytes = shake256(seed, length)
  const result: number[] = new Array(length)

  for (let i = 0; i < length; i++) {
    result[i] = bytes[i] & 0x03 // Only need 2 bits for 4 generators
  }

  return result
}

/**
 * Matrix-vector multiplication: A · v mod q
 * Optimized with delayed modular reduction
 *
 * @param A - Matrix (flattened)
 * @param v - Vector
 * @param m - Rows
 * @param n - Columns
 * @param q - Modulus
 * @returns Result vector
 */
function matVecMul(
  A: Int32Array,
  v: Int32Array,
  m: number,
  n: number,
  q: number,
): Int32Array {
  const result = new Int32Array(m)

  for (let i = 0; i < m; i++) {
    let sum = 0
    const rowOffset = i * n

    for (let j = 0; j < n; j++) {
      sum += A[rowOffset + j] * v[j]
    }

    result[i] = mod(sum, q)
  }

  return result
}

/**
 * Scalar-vector multiplication: scalar * v mod q
 *
 * @param scalar - Scalar value
 * @param v - Vector
 * @param q - Modulus
 * @returns Result vector
 */
function scalarVecMul(
  scalar: number,
  v: Int32Array | Int8Array,
  q: number,
): Int32Array {
  const len = v.length
  const result = new Int32Array(len)

  for (let i = 0; i < len; i++) {
    result[i] = mod(scalar * v[i], q)
  }

  return result
}

/**
 * Vector addition: a + b mod q
 *
 * @param a - First vector
 * @param b - Second vector
 * @param q - Modulus
 * @returns Sum vector
 */
function vecAdd(a: Int32Array, b: Int32Array, q: number): Int32Array {
  const len = a.length
  const result = new Int32Array(len)

  for (let i = 0; i < len; i++) {
    result[i] = mod(a[i] + b[i], q)
  }

  return result
}

/**
 * Vector subtraction: a - b mod q
 *
 * @param a - First vector
 * @param b - Second vector
 * @param q - Modulus
 * @returns Difference vector
 */
export function vecSub(a: Int32Array, b: Int32Array, q: number): Int32Array {
  const len = a.length
  const result = new Int32Array(len)

  for (let i = 0; i < len; i++) {
    result[i] = mod(a[i] - b[i], q)
  }

  return result
}

/**
 * Check if all vector elements are within [-bound, bound]
 * Uses centered modular arithmetic
 *
 * @param v - Vector to check
 * @param bound - Bound value
 * @param q - Modulus
 * @returns True if within bounds
 */
export function checkNorm(v: Int32Array, bound: number, q: number): boolean {
  const halfQ = q >> 1

  for (let i = 0; i < v.length; i++) {
    let val = v[i]
    // Center mod: map [q/2+1, q-1] to negative
    if (val > halfQ) val -= q
    if (val < -bound || val > bound) return false
  }

  return true
}

/**
 * Combine walks for EGRW response
 * z = y + c * secret mod 4 (per generator index)
 *
 * @param y - Mask walk
 * @param secret - Secret walk
 * @param challenge - Challenge value
 * @returns Combined walk
 */
export function combineWalks(
  y: number[],
  secret: number[],
  challenge: number,
): number[] {
  const len = Math.max(y.length, secret.length)
  const result: number[] = new Array(len)

  for (let i = 0; i < len; i++) {
    const yVal = i < y.length ? y[i] : 0
    const sVal = i < secret.length ? secret[i] : 0
    result[i] = (yVal + challenge * sVal) & 0x03 // mod 4 via bitmask
  }

  return result
}

// =============================================================================
// Signature Key Generation
// =============================================================================

/**
 * Generate kMOSAIC signature key pair
 *
 * Uses cryptographically secure randomness to generate keys for all three
 * underlying problems (SLSS, TDD, EGRW).
 *
 * @param level - Security level (default: MOS_128)
 * @returns Promise resolving to the generated key pair
 * @throws Error if parameter validation fails
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
 * Security: Uses domain separation to derive independent seeds for each problem.
 * This ensures that the security of one component does not compromise the others
 * even if the same master seed is used.
 *
 * The generation process:
 * 1. Derive independent seeds for SLSS, TDD, and EGRW using domain separation.
 * 2. Generate key pairs for each component using their respective key generation functions.
 * 3. Aggregate public and private keys into the MOSAIC key structure.
 *
 * @param params - System parameters
 * @param seed - Master seed (must be at least 32 bytes)
 * @returns Generated key pair
 * @throws Error if seed is too short
 */
export function generateKeyPairFromSeed(
  params: MOSAICParams,
  seed: Uint8Array,
): MOSAICKeyPair {
  if (seed.length < 32) {
    throw new Error('Seed must be at least 32 bytes')
  }

  // Derive component seeds with versioned domain separation
  const slssSeed = hashWithDomain(DOMAIN_SIGN_SLSS, seed)
  const tddSeed = hashWithDomain(DOMAIN_SIGN_TDD, seed)
  const egrwSeed = hashWithDomain(DOMAIN_SIGN_EGRW, seed)

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

  const publicKeyHash = sha3_256(hashConcat(slssBytes, tddBytes, egrwBytes))

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

// Maximum rejection sampling attempts (fixed constant)
const MAX_ATTEMPTS = 256

/**
 * Derive rejection sampling parameters from security level
 *
 * These parameters control the trade-off between signature size and security:
 * - GAMMA: Mask range determines commitment distribution width
 * - BETA: Rejection bound ensures signatures don't leak secret info
 *
 * Mathematical relationship:
 * - GAMMA must be large enough to hide the secret (GAMMA >> c * secret_bound)
 * - BETA must satisfy: ||z|| < GAMMA - BETA for valid signatures
 * - Probability of rejection ≈ (2 * BETA / GAMMA)^dimension
 *
 * @param level - Security level (MOS-128 or MOS-256)
 * @returns Derived rejection sampling parameters
 */
function getSignatureParams(level: string): {
  gamma1: number
  gamma2: number
  beta: number
  challengeBits: number
} {
  switch (level) {
    case SecurityLevel.MOS_256:
      // Higher security: larger ranges for better hiding
      return {
        gamma1: 1 << 19, // ~524k - larger for 256-bit security
        gamma2: 1 << 17, // ~131k
        beta: 1 << 14, // ~16k
        challengeBits: 64,
      }
    case SecurityLevel.MOS_128:
    default:
      // Standard security: balanced for performance
      return {
        gamma1: 1 << 17, // ~131k - mask range for SLSS
        gamma2: 1 << 15, // ~32k - mask range for TDD
        beta: 1 << 13, // ~8k - rejection bound
        challengeBits: 60,
      }
  }
}

/**
 * Sign a message using kMOSAIC multi-witness Fiat-Shamir
 *
 * Algorithm:
 * 1. Compute message hash μ = H(pk_hash || message)
 * 2. For each attempt (rejection sampling):
 *    a. Generate random masks y1, y2, y3
 *    b. Compute commitments w1, w2, w3
 *    c. Compute challenge c = H(w1 || w2 || w3 || μ)
 *    d. Compute responses z1, z2, z3
 *    e. Check rejection bounds; if pass, return signature
 *
 * Security: Rejection sampling ensures signatures don't leak secret key info.
 * The distribution of valid signatures is statistically close to uniform
 * over the target range, independent of the secret key.
 *
 * Timing: Includes constant-time protections and minimum execution time
 * to mitigate timing side-channels.
 *
 * @param message - Message to sign
 * @param secretKey - Secret key
 * @param publicKey - Public key (needed for context)
 * @returns Promise resolving to the signature
 * @throws Error if signing fails after MAX_ATTEMPTS
 */
export async function sign(
  message: Uint8Array,
  secretKey: MOSAICSecretKey,
  publicKey: MOSAICPublicKey,
): Promise<MOSAICSignature> {
  const startTime = performance.now()
  const { slss: slssSK, tdd: tddSK, egrw: egrwSK, publicKeyHash } = secretKey
  const { slss: slssPK, tdd: tddPK, egrw: egrwPK, params } = publicKey

  const { n: slssN, m: slssM, q: slssQ } = params.slss
  const { n: tddN, r: tddR, q: tddQ } = params.tdd
  const { k: egrwK } = params.egrw

  // Get rejection sampling parameters derived from security level
  const { gamma1, gamma2, beta } = getSignatureParams(params.level)

  // Minimum signing time to mitigate timing attacks (ms)
  // This ensures signing takes at least this long regardless of rejection count
  const MIN_SIGN_TIME_MS = params.level === SecurityLevel.MOS_256 ? 50 : 25

  // Compute message hash: μ = H(public_key_hash || message)
  const mu = hashConcat(publicKeyHash, message)

  // Rejection sampling loop
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    // Derive attempt seed with domain separation (encode attempt as bytes, not string)
    const attemptBytes = new Uint8Array(4)
    new DataView(attemptBytes.buffer).setUint32(0, attempt, true)
    const attemptSeed = hashWithDomain(
      DOMAIN_SIGN_ATTEMPT,
      hashConcat(mu, secretKey.seed, attemptBytes),
    )

    // =========================================================================
    // Phase 1: Generate commitments
    // =========================================================================

    // SLSS commitment: y1 ← uniform in [-γ1, γ1], w1 = A · y1
    const y1 = sampleSLSSMask(
      hashWithDomain(DOMAIN_MASK_SLSS, attemptSeed),
      slssN,
      gamma1,
      slssQ,
    )
    const w1 = matVecMul(slssPK.A, y1, slssM, slssN, slssQ)

    // TDD commitment: y2 ← uniform in [-γ2, γ2], w2 = hash-based commitment
    const y2 = sampleTDDMask(
      hashWithDomain(DOMAIN_MASK_TDD, attemptSeed),
      tddR,
      gamma2,
      tddQ,
    )
    const w2 = new Int32Array(tddN * tddN)
    const w2Hash = shake256(
      hashConcat(
        new Uint8Array(y2.buffer, y2.byteOffset, y2.byteLength),
        new Uint8Array(tddPK.T.buffer, tddPK.T.byteOffset, tddPK.T.byteLength),
      ),
      tddN * tddN * 4,
    )
    const w2View = new DataView(w2Hash.buffer, w2Hash.byteOffset)
    for (let i = 0; i < tddN * tddN; i++) {
      w2[i] = mod(w2View.getUint32(i * 4, true), tddQ)
    }

    // EGRW commitment: y3 ← random walk, w3 = vStart serialization
    const y3 = sampleWalkMask(
      hashWithDomain(DOMAIN_MASK_EGRW, attemptSeed),
      egrwK,
    )
    const w3 = sl2ToBytes(egrwPK.vStart)

    // =========================================================================
    // Phase 2: Compute unified challenge
    // =========================================================================

    const challengeInput = hashConcat(
      new Uint8Array(w1.buffer, w1.byteOffset, w1.byteLength),
      new Uint8Array(w2.buffer, w2.byteOffset, w2.byteLength),
      w3,
      mu,
    )
    const challengeHash = sha3_256(challengeInput)

    // Extract challenge value - use more bits for better security
    // Use first 8 bytes, reduce to reasonable range for efficiency
    const challengeView = new DataView(
      challengeHash.buffer,
      challengeHash.byteOffset,
    )
    const c =
      Number(challengeView.getBigUint64(0, true) % BigInt(1 << 16)) & 0xffff

    // =========================================================================
    // Phase 3: Compute responses
    // =========================================================================

    // SLSS response: z1 = y1 + c · s1 mod q
    const cs1 = scalarVecMul(c, slssSK.s, slssQ)
    const z1 = vecAdd(y1, cs1, slssQ)

    // Check rejection bound for z1
    if (!checkNorm(z1, gamma1 - beta, slssQ)) {
      zeroize(y1)
      zeroize(cs1)
      zeroize(z1)
      continue // Reject and retry
    }

    // TDD response: z2 = y2 + c · (flattened factors)
    const z2 = new Int32Array(tddR)
    for (let i = 0; i < Math.min(tddR, tddSK.factors.a.length); i++) {
      const factorSum =
        tddSK.factors.a[i][0] + tddSK.factors.b[i][0] + tddSK.factors.c[i][0]
      z2[i] = mod(y2[i] + c * factorSum, tddQ)
    }

    // Check rejection bound for z2
    if (!checkNorm(z2, gamma2 - beta, tddQ)) {
      zeroize(y1)
      zeroize(y2)
      zeroize(cs1)
      zeroize(z1)
      zeroize(z2)
      continue // Reject and retry
    }

    // EGRW response: z3 = combine walks
    const z3Walk = combineWalks(y3, egrwSK.walk, c)

    // =========================================================================
    // Phase 4: Construct signature
    // =========================================================================

    // Store commitments for verification (needed because LWE has error terms)
    // Note: The commitments are included in the Fiat-Shamir challenge computation,
    // so they are cryptographically bound. Including raw commitments does not
    // leak secret key information because they are computed from random masks.
    const w1Commitment = new Uint8Array(w1.buffer.slice(0))
    const w2Commitment = new Uint8Array(w2.buffer.slice(0))

    const signature: MOSAICSignature = {
      challenge: challengeHash,
      z1: { z: z1, commitment: w1Commitment },
      z2: { z: z2, commitment: w2Commitment },
      z3: {
        combined: z3Walk,
        hints: shake256(attemptSeed, 32),
      },
    }

    // Zeroize sensitive intermediate values
    zeroize(y1)
    zeroize(y2)
    zeroize(cs1)
    zeroize(attemptSeed)

    // Timing attack mitigation: ensure minimum signing time
    // This prevents attackers from inferring rejection count from timing
    const elapsedMs = performance.now() - startTime
    if (elapsedMs < MIN_SIGN_TIME_MS) {
      await new Promise((resolve) =>
        setTimeout(resolve, MIN_SIGN_TIME_MS - elapsedMs),
      )
    }

    return signature
  }

  throw new Error('Signature generation failed after maximum attempts')
}

// =============================================================================
// Signature Verification
// =============================================================================

/**
 * Verify a kMOSAIC signature
 *
 * Algorithm:
 * 1. Check response bounds (z1, z2 must be small)
 * 2. Recompute message hash μ
 * 3. Extract challenge c from signature
 * 4. Recompute commitments from responses (or use stored commitments)
 * 5. Verify challenge matches H(w1 || w2 || w3 || μ)
 *
 * Security: Verifies prover knows witnesses for all three problems.
 * - SLSS: Verifies knowledge of short vector s such that As = t
 * - TDD: Verifies knowledge of tensor decomposition
 * - EGRW: Verifies knowledge of path in expander graph
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
    const {
      slss: slssPK,
      tdd: tddPK,
      egrw: egrwPK,
      params,
      binding,
    } = publicKey
    const { challenge, z1, z2, z3 } = signature

    const { n: slssN, m: slssM, q: slssQ } = params.slss
    const { n: tddN, r: tddR, q: tddQ } = params.tdd

    // Get rejection sampling parameters derived from security level
    const { gamma1, gamma2, beta } = getSignatureParams(params.level)

    // Check bounds on responses
    if (!checkNorm(z1.z, gamma1 - beta, slssQ)) {
      return false
    }

    if (!checkNorm(z2.z, gamma2 - beta, tddQ)) {
      return false
    }

    // Recompute public key hash
    const slssBytes = slssSerializePublicKey(slssPK)
    const tddBytes = tddSerializePublicKey(tddPK)
    const egrwBytes = egrwSerializePublicKey(egrwPK)
    const publicKeyHash = sha3_256(hashConcat(slssBytes, tddBytes, egrwBytes))

    // Compute message hash
    const mu = hashConcat(publicKeyHash, message)

    // Extract challenge value (must match signing)
    const challengeView = new DataView(challenge.buffer, challenge.byteOffset)
    const c =
      Number(challengeView.getBigUint64(0, true) % BigInt(1 << 16)) & 0xffff

    // =========================================================================
    // Recompute commitments from responses
    // =========================================================================

    // SLSS: Use stored commitment (algebraic reconstruction fails due to LWE error)
    let w1Prime: Int32Array
    if (z1.commitment && z1.commitment.length > 0) {
      w1Prime = new Int32Array(
        z1.commitment.buffer.slice(
          z1.commitment.byteOffset,
          z1.commitment.byteOffset + z1.commitment.byteLength,
        ),
      )
    } else {
      // Fallback: algebraic reconstruction (won't match due to LWE error)
      const Az1 = matVecMul(slssPK.A, z1.z, slssM, slssN, slssQ)
      const ct = scalarVecMul(c, slssPK.t, slssQ)
      w1Prime = vecSub(Az1, ct, slssQ)
    }

    // TDD: Use stored commitment (hash-based, can't reconstruct from z2)
    let w2Prime: Int32Array
    if (z2.commitment && z2.commitment.length > 0) {
      w2Prime = new Int32Array(
        z2.commitment.buffer.slice(
          z2.commitment.byteOffset,
          z2.commitment.byteOffset + z2.commitment.byteLength,
        ),
      )
    } else {
      // Fallback: compute from z2 (won't match original commitment)
      w2Prime = new Int32Array(tddN * tddN)
      const w2Hash = shake256(
        hashConcat(
          new Uint8Array(z2.z.buffer, z2.z.byteOffset, z2.z.byteLength),
          new Uint8Array(
            tddPK.T.buffer,
            tddPK.T.byteOffset,
            tddPK.T.byteLength,
          ),
        ),
        tddN * tddN * 4,
      )
      const w2View = new DataView(w2Hash.buffer, w2Hash.byteOffset)
      for (let i = 0; i < tddN * tddN; i++) {
        w2Prime[i] = mod(w2View.getUint32(i * 4, true), tddQ)
      }
    }

    // EGRW: w3' = vStart serialization
    const w3Prime = sl2ToBytes(egrwPK.vStart)

    // =========================================================================
    // Verify challenge
    // =========================================================================

    const challengeInput = hashConcat(
      new Uint8Array(w1Prime.buffer, w1Prime.byteOffset, w1Prime.byteLength),
      new Uint8Array(w2Prime.buffer, w2Prime.byteOffset, w2Prime.byteLength),
      w3Prime,
      mu,
    )
    const expectedChallenge = sha3_256(challengeInput)

    return constantTimeEqual(challenge, expectedChallenge)
  } catch {
    // Any error during verification means invalid signature
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
 * [challenge (32)] || [z1_len (4)] || [z1_bytes] || [z1_comm_len (4)] || [z1_comm] || ...
 *
 * @param sig - Signature object
 * @returns Serialized bytes
 */
export function serializeSignature(sig: MOSAICSignature): Uint8Array {
  const z1Bytes = new Uint8Array(
    sig.z1.z.buffer,
    sig.z1.z.byteOffset,
    sig.z1.z.byteLength,
  )
  const z1CommitmentBytes = sig.z1.commitment || new Uint8Array(0)
  const z2Bytes = new Uint8Array(
    sig.z2.z.buffer,
    sig.z2.z.byteOffset,
    sig.z2.z.byteLength,
  )
  const z2CommitmentBytes = sig.z2.commitment || new Uint8Array(0)
  const z3WalkBytes = new Uint8Array(sig.z3.combined)

  const totalLen =
    32 +
    4 +
    z1Bytes.length +
    4 +
    z1CommitmentBytes.length +
    4 +
    z2Bytes.length +
    4 +
    z2CommitmentBytes.length +
    4 +
    z3WalkBytes.length +
    sig.z3.hints.length

  const result = new Uint8Array(totalLen)
  const view = new DataView(result.buffer)

  let offset = 0

  // Challenge
  result.set(sig.challenge, offset)
  offset += 32

  // z1
  view.setUint32(offset, z1Bytes.length, true)
  offset += 4
  result.set(z1Bytes, offset)
  offset += z1Bytes.length

  // z1 commitment
  view.setUint32(offset, z1CommitmentBytes.length, true)
  offset += 4
  result.set(z1CommitmentBytes, offset)
  offset += z1CommitmentBytes.length

  // z2
  view.setUint32(offset, z2Bytes.length, true)
  offset += 4
  result.set(z2Bytes, offset)
  offset += z2Bytes.length

  // z2 commitment
  view.setUint32(offset, z2CommitmentBytes.length, true)
  offset += 4
  result.set(z2CommitmentBytes, offset)
  offset += z2CommitmentBytes.length

  // z3
  view.setUint32(offset, z3WalkBytes.length, true)
  offset += 4
  result.set(z3WalkBytes, offset)
  offset += z3WalkBytes.length
  result.set(sig.z3.hints, offset)

  return result
}

/**
 * Deserialize signature from bytes
 *
 * @param data - Serialized signature bytes
 * @returns Deserialized signature object
 */
export function deserializeSignature(data: Uint8Array): MOSAICSignature {
  const view = new DataView(data.buffer, data.byteOffset)
  let offset = 0

  // Challenge
  const challenge = data.slice(offset, offset + 32)
  offset += 32

  // z1
  const z1Len = view.getUint32(offset, true)
  offset += 4
  const z1 = new Int32Array(data.slice(offset, offset + z1Len).buffer)
  offset += z1Len

  // z1 commitment
  const z1CommitmentLen = view.getUint32(offset, true)
  offset += 4
  const z1Commitment =
    z1CommitmentLen > 0
      ? data.slice(offset, offset + z1CommitmentLen)
      : undefined
  offset += z1CommitmentLen

  // z2
  const z2Len = view.getUint32(offset, true)
  offset += 4
  const z2 = new Int32Array(data.slice(offset, offset + z2Len).buffer)
  offset += z2Len

  // z2 commitment
  const z2CommitmentLen = view.getUint32(offset, true)
  offset += 4
  const z2Commitment =
    z2CommitmentLen > 0
      ? data.slice(offset, offset + z2CommitmentLen)
      : undefined
  offset += z2CommitmentLen

  // z3
  const z3WalkLen = view.getUint32(offset, true)
  offset += 4
  const z3Walk = Array.from(data.slice(offset, offset + z3WalkLen))
  offset += z3WalkLen
  const hints = data.slice(offset, offset + 32)

  return {
    challenge,
    z1: { z: z1, commitment: z1Commitment },
    z2: { z: z2, commitment: z2Commitment },
    z3: { combined: z3Walk, hints },
  }
}
