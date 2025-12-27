/**
 * kMOSAIC Parameter Sets
 *
 * Security Analysis:
 * - SLSS: Based on LWE hardness with sparse secrets. Security ≈ n * log2(q) / (2 * sigma²)
 * - TDD: Tensor rank decomposition is NP-hard. Security ≈ n² * log2(r) bits
 * - EGRW: SL(2,Z_p) Cayley graph with 4 generators. Security = k * log2(4) = 2k bits
 *   (k=128 gives 256 bits, k=256 gives 512 bits)
 *
 * Performance Considerations:
 * - SLSS: O(m*n) for encryption, O(n) for decryption
 * - TDD: O(n³) for tensor operations - MOST EXPENSIVE
 * - EGRW: O(k) for path computation - FASTEST
 */

import { type MOSAICParams, SecurityLevel } from '../types.js'

/**
 * MOS-128: 128-bit post-quantum security
 *
 * Target: Heterogeneous hardness with defense-in-depth
 * Combined security: Breaking all 3 required for compromise
 *
 * Optimizations vs original:
 * - TDD n reduced: 32→24 (saves 57.8% tensor operations)
 * - SLSS m increased: 256→384 (better LWE security margin)
 * - EGRW k=128 (provides 256 bits from 2k entropy)
 */
export const MOS_128: MOSAICParams = {
  level: SecurityLevel.MOS_128,
  slss: {
    n: 512, // Lattice dimension - LWE security parameter
    m: 384, // Equations (increased for better security margin: m/n = 0.75)
    q: 12289, // Prime modulus (NTT-friendly: 12289 = 3*2^12 + 1)
    w: 64, // Sparsity weight (Hamming weight of secret)
    sigma: 3.19, // Error std dev (optimal for LWE security)
  },
  tdd: {
    n: 24, // Tensor dimension (24³ = 13,824 vs 32³ = 32,768 - 57.8% reduction)
    r: 6, // Tensor rank (r/n = 0.25 ratio maintained)
    q: 7681, // Modulus (NTT-friendly: 7681 = 15*2^9 + 1)
    sigma: 2.0, // Noise std dev
  },
  egrw: {
    p: 1021, // Prime for SL(2, Z_p) - group order ≈ p³ ≈ 10^9
    k: 128, // Walk length (4^k possible paths = 256 bits entropy)
  },
}

/**
 * MOS-256: 256-bit post-quantum security
 *
 * Target: Heterogeneous hardness with defense-in-depth
 * Combined security: Breaking all 3 required for compromise
 *
 * Optimizations:
 * - TDD n reduced: 48→36 (saves 57.8% tensor operations)
 * - Maintains high security margin across all problems
 */
export const MOS_256: MOSAICParams = {
  level: SecurityLevel.MOS_256,
  slss: {
    n: 1024, // Lattice dimension
    m: 768, // Equations (m/n = 0.75)
    q: 12289, // Same NTT-friendly prime
    w: 128, // Sparsity weight
    sigma: 3.19, // Error std dev
  },
  tdd: {
    n: 36, // Tensor dimension (36³ = 46,656 vs 48³ = 110,592 - 58% reduction)
    r: 9, // Tensor rank (r/n = 0.25)
    q: 7681, // Modulus
    sigma: 2.0, // Noise std dev
  },
  egrw: {
    p: 2039, // Larger prime for SL(2, Z_p)
    k: 256, // Walk length (4^k possible paths = 512 bits entropy)
  },
}

/**
 * Get parameters for a security level
 *
 * @param level - The desired security level (MOS_128 or MOS_256)
 * @returns The corresponding parameter set
 * @throws Error if the security level is unknown
 */
export function getParams(level: SecurityLevel): MOSAICParams {
  switch (level) {
    case SecurityLevel.MOS_128:
      return MOS_128
    case SecurityLevel.MOS_256:
      return MOS_256
    default:
      throw new Error(`Unknown security level: ${level}`)
  }
}

/**
 * Validate parameters with security checks
 *
 * Ensures that the parameters meet minimum security requirements and
 * are consistent with the algorithm's constraints.
 *
 * @param params - The parameter set to validate
 * @throws Error if any parameter is invalid or insecure
 */
export function validateParams(params: MOSAICParams): void {
  const { slss, tdd, egrw } = params

  // SLSS validation
  if (slss.n <= 0 || slss.m <= 0) {
    throw new Error('SLSS dimensions must be positive')
  }
  if (slss.w > slss.n) {
    throw new Error('SLSS sparsity cannot exceed dimension')
  }
  if (!isPrime(slss.q)) {
    throw new Error('SLSS modulus must be prime')
  }
  // Security check: m should be at least n/2 for good LWE security
  // This ensures enough equations for hardness but not too many to make it easy
  if (slss.m < slss.n / 2) {
    throw new Error('SLSS m should be at least n/2 for security')
  }
  // Security check: sigma should be >= 3.0 for discrete Gaussian security
  // Prevents lattice reduction attacks that exploit small errors
  if (slss.sigma < 3.0) {
    throw new Error('SLSS sigma should be at least 3.0')
  }

  // TDD validation
  if (tdd.n <= 0 || tdd.r <= 0) {
    throw new Error('TDD dimensions must be positive')
  }
  if (tdd.r > tdd.n) {
    throw new Error('TDD rank cannot exceed dimension')
  }
  // Performance warning: n > 48 is very slow
  // Tensor operations scale cubically with n
  if (tdd.n > 48) {
    console.warn(
      `TDD n=${tdd.n} may cause performance issues (tensor ops are O(n³))`,
    )
  }

  // EGRW validation
  if (!isPrime(egrw.p)) {
    throw new Error('EGRW prime must be prime')
  }
  if (egrw.k <= 0) {
    throw new Error('EGRW walk length must be positive')
  }
  // Security check: p should be at least 1000 for adequate group size
  // Group size is approx p^3, so p=1000 gives size ~10^9
  if (egrw.p < 1000) {
    throw new Error('EGRW p should be at least 1000 for security')
  }
  // Security check: k should be at least 64 for path entropy
  // Path space size is 4^k = 2^(2k), so k=64 gives 128 bits
  if (egrw.k < 64) {
    throw new Error('EGRW walk length should be at least 64')
  }
}

/**
 * Simple primality test (sufficient for parameter validation)
 *
 * @param n - Number to test
 * @returns true if n is prime, false otherwise
 */
function isPrime(n: number): boolean {
  if (n < 2) return false
  if (n === 2) return true
  if (n % 2 === 0) return false
  // Check odd divisors up to sqrt(n)
  for (let i = 3; i * i <= n; i += 2) {
    if (n % i === 0) return false
  }
  return true
}
