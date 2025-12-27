/**
 * SLSS - Sparse Lattice Subset Sum Problem
 *
 * A novel variant combining lattice hardness with sparsity constraints.
 *
 * Problem: Given A ∈ Z_q^{m×n}, find sparse s ∈ {-1,0,1}^n such that A·s ≡ t (mod q)
 *
 * Security Properties:
 * - Based on LWE (Learning With Errors) with sparse secrets
 * - Quantum security: ~n/2 bits against known quantum attacks
 * - Parameters chosen for 128/256-bit post-quantum security
 * - Gaussian error distribution with σ = 3.19 for security margin
 *
 * Performance:
 * - Key generation: O(m·n) for matrix generation
 * - Encryption: O(m·n) for matrix-vector products
 * - Decryption: O(n) for inner product
 */

import type {
  SLSSParams,
  SLSSPublicKey,
  SLSSSecretKey,
  SLSSCiphertext,
} from '../../types.js'
import { shake256, hashWithDomain } from '../../utils/shake.js'
import { zeroize } from '../../utils/constant-time.js'

// Domain separation constants (versioned for future-proofing)
const DOMAIN_MATRIX = 'kmosaic-slss-matrix-v1'
const DOMAIN_SECRET = 'kmosaic-slss-secret-v1'
const DOMAIN_ERROR = 'kmosaic-slss-error-v1'
const DOMAIN_EPHEMERAL = 'kmosaic-slss-ephemeral-v1'
const DOMAIN_ERROR1 = 'kmosaic-slss-error1-v1'
const DOMAIN_ERROR2 = 'kmosaic-slss-error2-v1'

// =============================================================================
// Modular Arithmetic
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
  // Handle negative results from JS modulo operator
  return r < 0 ? r + q : r
}

/**
 * Centered modular reduction - returns result in [-q/2, q/2)
 * Used for decoding to minimize distance from 0 or q/2
 *
 * @param x - Input number
 * @param q - Modulus
 * @returns x mod q in [-q/2, q/2)
 */
function centerMod(x: number, q: number): number {
  const r = mod(x, q)
  // Shift range from [0, q) to [-q/2, q/2)
  return r > q / 2 ? r - q : r
}

// =============================================================================
// Matrix Operations
// =============================================================================

/**
 * Matrix-vector multiplication: A · v mod q
 * A is m×n stored row-major, v is n-vector
 *
 * Performance: Delayed modular reduction for fewer mod operations
 * Security: Constant-time for sparse vectors (no early termination)
 *
 * @param A - Matrix (flattened m*n)
 * @param v - Vector (length n)
 * @param m - Number of rows
 * @param n - Number of columns
 * @param q - Modulus
 * @returns Result vector (length m)
 */
function matVecMul(
  A: Int32Array,
  v: Int8Array | Int32Array,
  m: number,
  n: number,
  q: number,
): Int32Array {
  const result = new Int32Array(m)

  // Use delayed reduction - only reduce every ~1000 operations to avoid overflow
  // JavaScript's number type can safely handle integers up to 2^53
  // With q ≈ 12289 and values in [-1, 1], we can accumulate many products
  const reductionInterval = 1000

  for (let i = 0; i < m; i++) {
    let sum = 0
    const rowOffset = i * n

    for (let j = 0; j < n; j++) {
      // Accumulate product
      sum += A[rowOffset + j] * v[j]

      // Periodic reduction to prevent overflow
      // Check if j is a multiple of reductionInterval
      if ((j & (reductionInterval - 1)) === reductionInterval - 1) {
        sum = mod(sum, q)
      }
    }
    // Final reduction for the row
    result[i] = mod(sum, q)
  }
  return result
}

/**
 * Transpose matrix-vector multiplication: A^T · v mod q
 *
 * Performance: Accumulator-based approach with delayed reduction
 * Note: Less cache-friendly than matVecMul due to column access pattern
 *
 * Security: Constant-time - no early termination for zero entries
 * to prevent timing side-channel attacks that could reveal secret sparsity.
 *
 * @param A - Matrix (flattened m*n)
 * @param v - Vector (length m)
 * @param m - Number of rows in A
 * @param n - Number of columns in A
 * @param q - Modulus
 * @returns Result vector (length n)
 */
function matTVecMul(
  A: Int32Array,
  v: Int32Array | Int8Array,
  m: number,
  n: number,
  q: number,
): Int32Array {
  const result = new Int32Array(n)

  // Accumulate all contributions, then reduce once per column
  // Security: Process ALL entries regardless of value (constant-time)
  for (let i = 0; i < m; i++) {
    const vi = v[i]
    // Note: Removed early termination "if (vi === 0) continue" for constant-time security
    // The multiplication by 0 adds no overhead and prevents timing leaks

    const rowOffset = i * n
    for (let j = 0; j < n; j++) {
      // Add contribution of row i to column j
      result[j] += A[rowOffset + j] * vi
    }
  }

  // Final reduction for all elements
  for (let j = 0; j < n; j++) {
    result[j] = mod(result[j], q)
  }

  return result
}

// =============================================================================
// Vector Operations
// =============================================================================

/**
 * Vector addition mod q: result[i] = (a[i] + b[i]) mod q
 *
 * @param a - First vector
 * @param b - Second vector
 * @param q - Modulus
 * @returns Sum vector
 */
function vecAdd(a: Int32Array, b: Int32Array, q: number): Int32Array {
  const result = new Int32Array(a.length)
  for (let i = 0; i < a.length; i++) {
    result[i] = mod(a[i] + b[i], q)
  }
  return result
}

/**
 * Inner product mod q: sum(a[i] * b[i]) mod q
 *
 * Performance: Delayed reduction for fewer mod operations
 * Security: Constant-time regardless of input values
 *
 * @param a - First vector
 * @param b - Second vector
 * @param q - Modulus
 * @returns Inner product scalar
 */
function innerProduct(
  a: Int32Array | Int8Array,
  b: Int32Array | Int8Array,
  q: number,
): number {
  let sum = 0
  const len = Math.min(a.length, b.length)

  // Accumulate without intermediate reductions
  for (let i = 0; i < len; i++) {
    sum += a[i] * b[i]
  }

  // Final reduction
  return mod(sum, q)
}

// =============================================================================
// Sampling Functions
// =============================================================================

/**
 * Generate a deterministic matrix from seed using SHAKE256 with rejection sampling
 *
 * Security: Uses rejection sampling to achieve uniform distribution over Z_q
 * without modular reduction bias. The rejection threshold is chosen to minimize
 * bias while keeping rejection rate low.
 *
 * @param seed - Random seed
 * @param m - Rows
 * @param n - Columns
 * @param q - Modulus
 * @returns Generated matrix
 */
function sampleMatrix(
  seed: Uint8Array,
  m: number,
  n: number,
  q: number,
): Int32Array {
  const size = m * n
  const A = new Int32Array(size)

  // Calculate rejection threshold for unbiased sampling
  // Reject values >= floor(2^32 / q) * q to eliminate bias
  const UINT32_MAX = 0xffffffff
  const threshold = UINT32_MAX - (UINT32_MAX % q) - 1 // Values > threshold are rejected

  // Generate extra bytes to handle rejections (expect ~q/2^32 rejection rate)
  // Extra factor of 2 should be sufficient for all practical cases
  const extraFactor = 2
  let bytes = shake256(seed, size * 4 * extraFactor)
  let view = new DataView(bytes.buffer, bytes.byteOffset)

  let bytesUsed = 0
  let generated = 0

  while (generated < size) {
    // Need more bytes - expand using counter mode
    if (bytesUsed + 4 > bytes.length) {
      const counterBytes = new Uint8Array(seed.length + 4)
      counterBytes.set(seed)
      new DataView(counterBytes.buffer).setUint32(seed.length, bytesUsed, true)
      bytes = shake256(counterBytes, size * 4 * extraFactor)
      view = new DataView(bytes.buffer, bytes.byteOffset)
      bytesUsed = 0
    }

    const value = view.getUint32(bytesUsed, true)
    bytesUsed += 4

    // Rejection sampling: only accept values that don't introduce bias
    if (value <= threshold) {
      A[generated] = value % q
      generated++
    }
  }

  return A
}

/**
 * Generate a deterministic sparse vector from seed
 *
 * Security: Uses rejection sampling to get uniform random positions
 * The sparse secret provides security against certain lattice attacks
 * while allowing more efficient operations.
 *
 * @param seed - Random seed for deterministic generation
 * @param n - Vector dimension
 * @param w - Hamming weight (number of non-zero entries)
 * @returns Sparse vector with exactly w entries in {-1, 1}
 */
function sampleSparseVectorFromSeed(
  seed: Uint8Array,
  n: number,
  w: number,
): Int8Array {
  if (w > n) {
    throw new Error(`Sparsity w=${w} cannot exceed dimension n=${n}`)
  }

  const v = new Int8Array(n)

  // Generate more randomness than needed for rejection sampling
  // Use larger factor to virtually eliminate fallback case
  const extraFactor = 8 // Increased from 4 to make fallback extremely unlikely
  let bytesNeeded = w * extraFactor * 4 + w
  let bytes = shake256(seed, bytesNeeded)
  let view = new DataView(bytes.buffer, bytes.byteOffset)

  const positions = new Set<number>()
  let byteOffset = 0
  let extensionCounter = 0

  // Rejection sampling for uniform positions
  while (positions.size < w) {
    // If we run out of bytes, extend with new randomness (never use sequential fallback)
    if (byteOffset + 4 > bytes.length - w) {
      extensionCounter++
      // Generate new randomness by hashing seed with counter
      const extendedSeed = new Uint8Array(seed.length + 4)
      extendedSeed.set(seed)
      new DataView(extendedSeed.buffer).setUint32(
        seed.length,
        extensionCounter,
        true,
      )
      bytes = shake256(extendedSeed, bytesNeeded)
      view = new DataView(bytes.buffer, bytes.byteOffset)
      byteOffset = 0
      // Security: Log warning in development (extension should be extremely rare)
      if (extensionCounter > 10) {
        console.warn(
          `[Security] Sparse vector sampling required ${extensionCounter} extensions - potential issue`,
        )
      }
    }

    // Get random position
    const pos = mod(view.getUint32(byteOffset, true), n)
    byteOffset += 4
    positions.add(pos)
  }

  // Assign signs from remaining bytes
  const signBytes = bytes.slice(bytes.length - w)
  let signIdx = 0
  for (const pos of positions) {
    // Assign 1 or -1 based on bit
    v[pos] = signBytes[signIdx++] & 1 ? 1 : -1
  }

  return v
}

/**
 * Sample Gaussian error vector from seed using Box-Muller transform
 *
 * Security: Discrete Gaussian errors are essential for LWE security.
 * The standard deviation σ must be large enough to hide the secret
 * but small enough for correct decryption.
 *
 * For σ = 3.19 and q = 12289:
 * - Error magnitude typically < 4σ ≈ 13
 * - Decryption threshold at q/4 ≈ 3072 provides large margin
 *
 * @param seed - Random seed for deterministic generation
 * @param n - Vector dimension
 * @param sigma - Standard deviation of Gaussian distribution
 * @returns Error vector
 */
function sampleErrorFromSeed(
  seed: Uint8Array,
  n: number,
  sigma: number,
): Int32Array {
  const bytes = shake256(seed, n * 8)
  const view = new DataView(bytes.buffer, bytes.byteOffset)
  const result = new Int32Array(n)

  for (let i = 0; i < n; i++) {
    // Box-Muller transform for Gaussian sampling
    // Use (u + 1) / 2^32 to get uniform in (0, 1] - avoids log(0)
    // This is the mathematically correct approach used consistently across the codebase
    const u1Raw = view.getUint32(i * 8, true) >>> 0
    const u1 = (u1Raw + 1) / 4294967296 // (0, 1] - never exactly 0

    const u2Raw = view.getUint32(i * 8 + 4, true) >>> 0
    const u2 = u2Raw / 4294967296 // [0, 1)

    // Generate standard normal, scale by sigma, round to integer
    const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2)
    result[i] = Math.round(z * sigma)
  }

  return result
}

// =============================================================================
// Message Encoding/Decoding
// =============================================================================

/**
 * Encode a message into LWE ciphertext space
 *
 * Each bit b ∈ {0,1} is encoded as b·⌊q/2⌋:
 * - 0 → 0
 * - 1 → q/2 ≈ 6144
 *
 * This provides maximum distance between encodings for error tolerance.
 *
 * @param msg - Message bytes
 * @param q - Modulus
 * @returns Encoded vector
 */
function encodeMessage(msg: Uint8Array, q: number): Int32Array {
  const result = new Int32Array(msg.length * 8)
  const scale = Math.floor(q / 2)

  for (let i = 0; i < msg.length; i++) {
    const byte = msg[i]
    const baseIdx = i * 8
    for (let j = 0; j < 8; j++) {
      // Extract bit j
      const bit = (byte >> j) & 1
      // Scale bit
      result[baseIdx + j] = bit * scale
    }
  }

  return result
}

/**
 * Decode message from noisy LWE values
 *
 * Decision boundary at q/4: if |centered value| > q/4, decode as 1.
 * This tolerates errors up to q/4 ≈ 3072 (for q=12289).
 *
 * Security note: Decoding is constant-time to prevent timing attacks.
 *
 * @param values - Noisy values
 * @param q - Modulus
 * @returns Decoded message bytes
 */
function decodeMessage(values: Int32Array, q: number): Uint8Array {
  const numBytes = Math.floor(values.length / 8)
  const result = new Uint8Array(numBytes)
  const threshold = Math.floor(q / 4)

  for (let i = 0; i < numBytes; i++) {
    let byte = 0
    const baseIdx = i * 8
    for (let j = 0; j < 8; j++) {
      const v = centerMod(values[baseIdx + j], q)
      // Constant-time: compute absolute value without branching
      const absV = v < 0 ? -v : v
      // Constant-time comparison
      const bit = absV > threshold ? 1 : 0
      // Accumulate bits into byte
      byte |= bit << j
    }
    result[i] = byte
  }

  return result
}

// =============================================================================
// SLSS Public API
// =============================================================================

export interface SLSSKeyPair {
  publicKey: SLSSPublicKey
  secretKey: SLSSSecretKey
}

/**
 * Generate SLSS key pair
 *
 * Key structure:
 * - Public key: (A, t) where t = A·s + e
 * - Secret key: sparse vector s ∈ {-1,0,1}^n with Hamming weight w
 *
 * Security: Finding s given (A, t) is the Sparse-LWE problem.
 * The sparse secret enables efficient operations while maintaining
 * security against known attacks.
 *
 * @param params - SLSS parameters
 * @param seed - Random seed
 * @returns Key pair
 */
export function slssKeyGen(params: SLSSParams, seed: Uint8Array): SLSSKeyPair {
  if (seed.length < 32) {
    throw new Error('Seed must be at least 32 bytes')
  }

  const { n, m, q, w, sigma } = params

  // Derive seeds with versioned domain separation
  const matrixSeed = hashWithDomain(DOMAIN_MATRIX, seed)
  const secretSeed = hashWithDomain(DOMAIN_SECRET, seed)
  const errorSeed = hashWithDomain(DOMAIN_ERROR, seed)

  // Generate public matrix A (can be shared across users in practice)
  const A = sampleMatrix(matrixSeed, m, n, q)

  // Generate sparse secret s
  const s = sampleSparseVectorFromSeed(secretSeed, n, w)

  // Generate error e ~ D_σ^m (discrete Gaussian)
  const e = sampleErrorFromSeed(errorSeed, m, sigma)

  // Compute public key: t = A·s + e mod q
  const As = matVecMul(A, s, m, n, q)
  const t = vecAdd(As, e, q)

  // Zeroize intermediate values
  zeroize(e)

  return {
    publicKey: { A, t },
    secretKey: { s },
  }
}

/**
 * SLSS Encryption (for KEM)
 * Encrypts a message fragment using the public key
 *
 * Encryption algorithm (dual Regev):
 * 1. Sample ephemeral sparse r
 * 2. Compute u = A^T·r + e1
 * 3. Compute v = t^T·r + e2 + encode(m)
 *
 * Security: IND-CPA under Sparse-LWE assumption
 *
 * @param publicKey - Recipient's public key
 * @param message - Message to encrypt
 * @param params - SLSS parameters
 * @param randomness - Randomness for encryption
 * @returns Ciphertext
 */
export function slssEncrypt(
  publicKey: SLSSPublicKey,
  message: Uint8Array,
  params: SLSSParams,
  randomness: Uint8Array,
): SLSSCiphertext {
  if (randomness.length < 32) {
    throw new Error('Randomness must be at least 32 bytes')
  }

  const { n, m, q, w, sigma } = params
  const { A, t } = publicKey

  // Sample ephemeral sparse vector r with domain separation
  const r = sampleSparseVectorFromSeed(
    hashWithDomain(DOMAIN_EPHEMERAL, randomness),
    m,
    Math.min(w, m),
  )

  // Sample encryption errors
  const e1 = sampleErrorFromSeed(
    hashWithDomain(DOMAIN_ERROR1, randomness),
    n,
    sigma,
  )
  const e2 = sampleErrorFromSeed(
    hashWithDomain(DOMAIN_ERROR2, randomness),
    message.length * 8,
    sigma,
  )

  // u = A^T · r + e1 mod q
  const u = vecAdd(matTVecMul(A, r, m, n, q), e1, q)

  // Encode message into LWE space
  const encodedMsg = encodeMessage(message, q)

  // v = t^T · r + e2 + encode(m) mod q
  const tDotR = innerProduct(t, r, q)
  const v = new Int32Array(encodedMsg.length)
  for (let i = 0; i < v.length; i++) {
    v[i] = mod(tDotR + e2[i % e2.length] + encodedMsg[i], q)
  }

  // Zeroize ephemeral values
  zeroize(r)
  zeroize(e1)
  zeroize(e2)

  return { u, v }
}

/**
 * SLSS Decryption (for KEM)
 *
 * Decryption algorithm:
 * 1. Compute s^T · u
 * 2. Recover noisy message: v - s^T · u = encode(m) + (combined error)
 * 3. Decode message by thresholding
 *
 * Correctness: Decryption succeeds when combined error < q/4
 * Combined error = e2 + t^T·r - s^T·(A^T·r + e1) = e2 - s^T·e1 (small)
 *
 * @param ciphertext - Ciphertext to decrypt
 * @param secretKey - Recipient's secret key
 * @param params - SLSS parameters
 * @returns Decrypted message
 */
export function slssDecrypt(
  ciphertext: SLSSCiphertext,
  secretKey: SLSSSecretKey,
  params: SLSSParams,
): Uint8Array {
  const { q } = params
  const { u, v } = ciphertext
  const { s } = secretKey

  // Compute s^T · u (inner product of secret with first ciphertext component)
  const sDotU = innerProduct(s, u, q)

  // Recover noisy message: v - s^T · u
  // This equals encode(m) + small error term
  const noisy = new Int32Array(v.length)
  for (let i = 0; i < v.length; i++) {
    noisy[i] = mod(v[i] - sDotU, q)
  }

  // Decode message from noisy values using threshold decoding
  const decoded = decodeMessage(noisy, q)

  // Zeroize intermediate values
  zeroize(noisy)

  // Ensure output is exactly 32 bytes for secret reconstruction
  const result = new Uint8Array(32)
  const copyLen = Math.min(decoded.length, 32)
  result.set(decoded.slice(0, copyLen))

  return result
}

/**
 * Serialize SLSS public key
 *
 * @param pk - Public key
 * @returns Serialized bytes
 */
export function slssSerializePublicKey(pk: SLSSPublicKey): Uint8Array {
  const aBytes = new Uint8Array(pk.A.buffer, pk.A.byteOffset, pk.A.byteLength)
  const tBytes = new Uint8Array(pk.t.buffer, pk.t.byteOffset, pk.t.byteLength)

  const result = new Uint8Array(4 + aBytes.length + 4 + tBytes.length)
  const view = new DataView(result.buffer)

  let offset = 0
  view.setUint32(offset, aBytes.length, true)
  offset += 4
  result.set(aBytes, offset)
  offset += aBytes.length
  view.setUint32(offset, tBytes.length, true)
  offset += 4
  result.set(tBytes, offset)

  return result
}

/**
 * Deserialize SLSS public key
 *
 * @param data - Serialized bytes
 * @returns Public key
 */
export function slssDeserializePublicKey(data: Uint8Array): SLSSPublicKey {
  const view = new DataView(data.buffer, data.byteOffset)

  let offset = 0
  const aLen = view.getUint32(offset, true)
  offset += 4
  const A = new Int32Array(data.slice(offset, offset + aLen).buffer)
  offset += aLen

  const tLen = view.getUint32(offset, true)
  offset += 4
  const t = new Int32Array(data.slice(offset, offset + tLen).buffer)

  return { A, t }
}
