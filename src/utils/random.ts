/**
 * Secure random number generation using Node.js crypto (Bun compatible)
 *
 * Security considerations:
 * - All random generation uses CSPRNG (crypto.randomBytes)
 * - Rejection sampling ensures uniform distribution
 * - Domain separation prevents seed reuse across contexts
 * - Sensitive intermediate values are zeroized
 * - Enhanced entropy validation detects weak seeds
 */

import { randomBytes } from 'crypto'
import { zeroize } from './constant-time'
import { shake256 } from './shake'

// ============================================================================
// Domain Separation Constants (versioned for future compatibility)
// ============================================================================

// Domain separator for deterministic random generation
const DOMAIN_DETERMINISTIC = new TextEncoder().encode('kMOSAIC-random-det-v1')

// Domain separator for seed expansion
const DOMAIN_EXPAND_SEED = new TextEncoder().encode('kMOSAIC-random-expand-v1')

// ============================================================================
// Entropy Validation
// ============================================================================

/**
 * Validate that a seed has sufficient entropy
 *
 * Detects common low-entropy patterns that could compromise security:
 * - All bytes identical (all zeros, all 0xFF, etc.)
 * - Sequential patterns (0,1,2,3,... or 255,254,253,...)
 * - Repeating short patterns (ABAB, ABCABC, etc.)
 * - Very low byte diversity (< 8 unique bytes in 32+ byte seed)
 *
 * @param seed - The seed to validate
 * @throws Error if seed appears to have low entropy
 */
export function validateSeedEntropy(seed: Uint8Array): void {
  // Check minimum length requirement
  if (seed.length < 32) {
    throw new Error('Seed must be at least 32 bytes')
  }

  // Check 1: All bytes identical
  const first = seed[0]
  let allSame = true
  for (let i = 1; i < seed.length; i++) {
    if (seed[i] !== first) {
      allSame = false
      break
    }
  }
  if (allSame) {
    throw new Error('Seed has low entropy: all bytes are identical')
  }

  // Check 2: Sequential patterns (ascending or descending)
  let isAscending = true
  let isDescending = true
  for (let i = 1; i < seed.length; i++) {
    // Check for ascending sequence (wrapping at 256)
    if (seed[i] !== (seed[i - 1] + 1) % 256) isAscending = false
    // Check for descending sequence (wrapping at 256)
    if (seed[i] !== (seed[i - 1] - 1 + 256) % 256) isDescending = false
    // If neither, we can stop checking
    if (!isAscending && !isDescending) break
  }
  if (isAscending || isDescending) {
    throw new Error('Seed has low entropy: sequential pattern detected')
  }

  // Check 3: Short repeating patterns (period 1-8)
  for (let period = 2; period <= 8; period++) {
    let isRepeating = true
    for (let i = period; i < seed.length; i++) {
      // Check if current byte matches byte 'period' positions ago
      if (seed[i] !== seed[i % period]) {
        isRepeating = false
        break
      }
    }
    if (isRepeating) {
      throw new Error(
        `Seed has low entropy: repeating pattern with period ${period}`,
      )
    }
  }

  // Check 4: Low byte diversity (need at least 8 unique bytes for 32+ byte seed)
  const uniqueBytes = new Set<number>()
  for (let i = 0; i < seed.length; i++) {
    uniqueBytes.add(seed[i])
    // Early exit once threshold met to avoid scanning full array if not needed
    if (uniqueBytes.size >= 8) break
  }
  if (uniqueBytes.size < 8) {
    throw new Error(
      `Seed has low entropy: only ${uniqueBytes.size} unique byte values`,
    )
  }
}

/**
 * Generate cryptographically secure random bytes
 *
 * @param length - Number of bytes to generate
 * @returns Uint8Array of random bytes
 */
export function secureRandomBytes(length: number): Uint8Array {
  // Use Node.js crypto.randomBytes for CSPRNG
  return new Uint8Array(randomBytes(length))
}

/**
 * Generate a random integer in [0, max)
 * Uses rejection sampling for uniform distribution (no modular bias)
 *
 * @param max - Upper bound (exclusive)
 * @returns Random integer in [0, max)
 */
export function randomInt(max: number): number {
  // Validate input
  if (max <= 0) throw new Error('max must be positive')
  // Handle trivial case
  if (max === 1) return 0

  // Find number of bytes needed - use bit-based calculation for accuracy
  // Math.clz32 returns number of leading zeros in 32-bit integer
  const bitsNeeded = 32 - Math.clz32(max - 1) || 1
  const bytesNeeded = Math.ceil(bitsNeeded / 8)

  // Create mask to remove excess bits
  const mask = (1 << bitsNeeded) - 1

  // Rejection sampling for uniform distribution
  // Expected iterations: < 2 (since we mask to nearest power of 2)
  while (true) {
    // Generate random bytes
    const bytes = secureRandomBytes(bytesNeeded)
    let value = 0

    // Convert bytes to integer
    for (let i = 0; i < bytesNeeded; i++) {
      value = (value << 8) | bytes[i]
    }

    // Mask to exact bit width for faster rejection
    value &= mask

    // Check if value is within range
    if (value < max) {
      return value
    }
    // If not, loop and try again (rejection)
  }
}

/**
 * Generate a random integer in [min, max]
 *
 * @param min - Lower bound (inclusive)
 * @param max - Upper bound (inclusive)
 * @returns Random integer in [min, max]
 */
export function randomIntRange(min: number, max: number): number {
  // Shift range to [0, max - min + 1) and add min
  return min + randomInt(max - min + 1)
}

/**
 * Generate random element in Z_q
 *
 * @param q - Modulus
 * @returns Random integer in [0, q)
 */
export function randomZq(q: number): number {
  return randomInt(q)
}

/**
 * Generate random vector in Z_q^n
 * Optimized: generates random bytes in batches when q is power of 2
 *
 * @param n - Vector dimension
 * @param q - Modulus
 * @returns Random vector in Z_q^n
 */
export function randomVectorZq(n: number, q: number): Int32Array {
  const v = new Int32Array(n)

  // Check if q is a power of 2 (allows simple masking)
  // (q & (q - 1)) === 0 is a standard trick to check for power of 2
  const isPowerOf2 = (q & (q - 1)) === 0

  if (isPowerOf2 && q <= 65536) {
    // Fast path: batch generate with masking
    const mask = q - 1
    // Determine bytes per element (1 or 2)
    const bytesPerElement = q <= 256 ? 1 : 2
    // Generate all needed bytes at once
    const bytes = secureRandomBytes(n * bytesPerElement)

    if (bytesPerElement === 1) {
      // 1 byte per element
      for (let i = 0; i < n; i++) {
        v[i] = bytes[i] & mask
      }
    } else {
      // 2 bytes per element
      for (let i = 0; i < n; i++) {
        v[i] = ((bytes[i * 2] << 8) | bytes[i * 2 + 1]) & mask
      }
    }
    // Zeroize sensitive intermediate buffer
    zeroize(bytes)
  } else {
    // General case: use rejection sampling per element
    for (let i = 0; i < n; i++) {
      v[i] = randomZq(q)
    }
  }
  return v
}

/**
 * Generate random sparse vector in {-1, 0, 1}^n with exactly w non-zero entries
 * Uses Fisher-Yates partial shuffle for O(w) position selection
 *
 * @param n - Vector dimension
 * @param w - Hamming weight (number of non-zero entries)
 * @returns Sparse vector
 */
export function randomSparseVector(n: number, w: number): Int8Array {
  // Validate inputs
  if (w > n) throw new Error('Sparsity weight cannot exceed dimension')
  if (w === 0) return new Int8Array(n)

  const v = new Int8Array(n)

  // Fisher-Yates partial shuffle: O(w) instead of O(n log n) for Set approach
  // Create index array for positions we might select
  const indices = new Uint32Array(n)
  for (let i = 0; i < n; i++) {
    indices[i] = i
  }

  // Generate sign bits in batch for efficiency
  // We need w bits, so ceil(w/8) bytes
  const signBytesNeeded = Math.ceil(w / 8)
  const signBytes = secureRandomBytes(signBytesNeeded)

  // Partial shuffle: select first w positions
  for (let i = 0; i < w; i++) {
    // Pick random index from remaining positions [i, n)
    const j = i + randomInt(n - i)

    // Swap indices[i] and indices[j]
    const temp = indices[i]
    indices[i] = indices[j]
    indices[j] = temp

    // Assign sign based on bit from signBytes
    const byteIdx = i >>> 3 // i / 8
    const bitIdx = i & 7 // i % 8
    // Extract bit and map 0 -> -1, 1 -> 1
    const sign = ((signBytes[byteIdx] >>> bitIdx) & 1) === 0 ? -1 : 1

    // Set value at selected position
    v[indices[i]] = sign
  }

  // Zeroize sensitive data
  zeroize(signBytes)

  return v
}

/**
 * Sample from discrete Gaussian distribution (rounded)
 * Uses Box-Muller transform with high-precision uniform sampling
 *
 * Security: Uses 2^32 resolution for uniform samples to minimize
 * statistical bias in the Gaussian output.
 *
 * @param sigma - Standard deviation
 * @returns Sample from discrete Gaussian
 */
export function sampleGaussian(sigma: number): number {
  // Box-Muller transform with 32-bit precision uniforms
  // Using 2^32 samples instead of 10^6 for better precision
  const bytes = secureRandomBytes(8)

  // First uniform in (0, 1] - never exactly 0 to avoid log(0)
  // Construct 32-bit integer from 4 bytes
  const u1Raw =
    ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0
  // Normalize to (0, 1]
  const u1 = (u1Raw + 1) / 4294967296

  // Second uniform in [0, 1)
  // Construct 32-bit integer from 4 bytes
  const u2Raw =
    ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]) >>> 0
  // Normalize to [0, 1)
  const u2 = u2Raw / 4294967296

  // Zeroize intermediate buffer
  zeroize(bytes)

  // Box-Muller transform
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2)

  // Round to nearest integer
  return Math.round(z * sigma)
}

/**
 * Sample Gaussian error vector
 * Optimized: generates pairs using Box-Muller (both outputs used)
 *
 * @param n - Vector dimension
 * @param sigma - Standard deviation
 * @returns Vector of Gaussian samples
 */
export function sampleGaussianVector(n: number, sigma: number): Int32Array {
  const v = new Int32Array(n)

  // Box-Muller produces 2 samples per iteration - use both
  const pairs = Math.floor(n / 2)
  // Need 8 bytes per pair (4 bytes per uniform, 2 uniforms per pair)
  const bytes = secureRandomBytes(pairs * 8)

  for (let i = 0; i < pairs; i++) {
    const offset = i * 8

    // First uniform in (0, 1]
    const u1Raw =
      ((bytes[offset] << 24) |
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3]) >>>
      0
    const u1 = (u1Raw + 1) / 4294967296

    // Second uniform in [0, 1)
    const u2Raw =
      ((bytes[offset + 4] << 24) |
        (bytes[offset + 5] << 16) |
        (bytes[offset + 6] << 8) |
        bytes[offset + 7]) >>>
      0
    const u2 = u2Raw / 4294967296

    // Box-Muller produces two independent samples
    const r = Math.sqrt(-2 * Math.log(u1)) * sigma
    const theta = 2 * Math.PI * u2

    // Store both samples
    v[i * 2] = Math.round(r * Math.cos(theta))
    v[i * 2 + 1] = Math.round(r * Math.sin(theta))
  }

  // Handle odd n (generate one more sample)
  if (n % 2 === 1) {
    v[n - 1] = sampleGaussian(sigma)
  }

  // Zeroize intermediate buffer
  zeroize(bytes)
  return v
}

/**
 * Deterministic random bytes from seed using SHAKE256
 * Includes domain separation to prevent cross-context seed reuse attacks
 *
 * @param seed - Input seed
 * @param length - Desired output length
 * @param context - Optional context string/bytes for domain separation
 * @returns Deterministic random bytes
 */
export function deterministicBytes(
  seed: Uint8Array,
  length: number,
  context?: Uint8Array,
): Uint8Array {
  // Domain separation: combine domain prefix + optional context + seed
  const contextBytes = context ?? new Uint8Array(0)

  // Allocate input buffer
  const input = new Uint8Array(
    DOMAIN_DETERMINISTIC.length + 1 + contextBytes.length + seed.length,
  )

  let offset = 0
  // Copy domain prefix
  input.set(DOMAIN_DETERMINISTIC, offset)
  offset += DOMAIN_DETERMINISTIC.length

  // Length prefix for context (single byte, max 255)
  input[offset] = contextBytes.length
  offset += 1

  // Copy context bytes
  input.set(contextBytes, offset)
  offset += contextBytes.length

  // Copy seed bytes
  input.set(seed, offset)

  // Generate output using SHAKE256
  const result = shake256(input, length)

  // Zeroize input buffer
  zeroize(input)

  return result
}

/**
 * Expand seed into multiple independent seeds
 * Uses domain separation to ensure cryptographic independence
 *
 * @param seed - Master seed
 * @param count - Number of seeds to generate
 * @param seedLength - Length of each generated seed (default 32)
 * @returns Array of derived seeds
 */
export function expandSeed(
  seed: Uint8Array,
  count: number,
  seedLength: number = 32,
): Uint8Array[] {
  // Domain separation: prefix + count encoding + seed
  const input = new Uint8Array(DOMAIN_EXPAND_SEED.length + 4 + seed.length)

  let offset = 0
  // Copy domain prefix
  input.set(DOMAIN_EXPAND_SEED, offset)
  offset += DOMAIN_EXPAND_SEED.length

  // Encode count as 4 bytes (little-endian)
  input[offset] = count & 0xff
  input[offset + 1] = (count >>> 8) & 0xff
  input[offset + 2] = (count >>> 16) & 0xff
  input[offset + 3] = (count >>> 24) & 0xff
  offset += 4

  // Copy master seed
  input.set(seed, offset)

  // Generate all needed bytes at once using SHAKE256
  const expanded = shake256(input, count * seedLength)

  // Zeroize input buffer
  zeroize(input)

  // Split expanded output into individual seeds
  const seeds: Uint8Array[] = []
  for (let i = 0; i < count; i++) {
    seeds.push(expanded.slice(i * seedLength, (i + 1) * seedLength))
  }

  return seeds
}
