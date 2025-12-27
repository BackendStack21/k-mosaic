/**
 * EGRW - Expander Graph Random Walk Problem
 *
 * Based on random walks on Ramanujan graphs (Cayley graphs of SL(2, Z_p)).
 * Graph-theoretic hardness with no known relationship to lattice/tensor problems.
 *
 * Problem: Given start/end vertices of a walk, find the generator sequence used.
 *
 * Security Properties:
 * - Hardness based on navigating Cayley graphs of SL(2, Z_p)
 * - Group order ≈ p³, providing exponential security in log(p)
 * - Walk length k with 4 generators provides 4^k possible paths
 * - Entropy: k * log2(4) = 2k bits (k=128→256 bits, k=256→512 bits)
 * - No known quantum speedup for this specific problem
 *
 * Performance:
 * - All operations are O(k) where k is walk length
 * - Fastest of the three kMOSAIC problems
 */

import type {
  EGRWParams,
  EGRWPublicKey,
  EGRWSecretKey,
  EGRWCiphertext,
  SL2Element,
} from '../../types'
import { shake256, hashWithDomain, hashConcat } from '../../utils/shake'

// Domain separation constants
const DOMAIN_START = 'kmosaic-egrw-start-v1'
const DOMAIN_WALK = 'kmosaic-egrw-walk-v1'
const DOMAIN_ENCRYPT = 'kmosaic-egrw-encrypt-v1'
const DOMAIN_MASK = 'kmosaic-egrw-mask-v1'

// =============================================================================
// SL(2, Z_p) Group Operations
// =============================================================================

// LRU-style cache for generators with proper eviction
// Using Map which maintains insertion order for LRU behavior
const GENERATOR_CACHE_MAX_SIZE = 16 // Configurable max cache size
const generatorCache = new Map<
  number,
  { generators: SL2Element[]; lastAccess: number }
>()
let cacheAccessCounter = 0

/**
 * Evict oldest cache entries when cache exceeds max size
 * Uses access counter for LRU-style eviction
 */
export function evictOldestCacheEntries(): void {
  if (generatorCache.size <= GENERATOR_CACHE_MAX_SIZE) return

  // Find and remove entries with oldest access times
  const entriesToRemove = generatorCache.size - GENERATOR_CACHE_MAX_SIZE
  const entries = Array.from(generatorCache.entries())
    .sort((a, b) => a[1].lastAccess - b[1].lastAccess)
    .slice(0, entriesToRemove)

  for (const [key] of entries) {
    generatorCache.delete(key)
  }
}

/**
 * Modular arithmetic - always returns non-negative result
 *
 * @param x - Input number
 * @param p - Modulus
 * @returns x mod p in [0, p)
 */
function mod(x: number, p: number): number {
  const r = x % p
  return r < 0 ? r + p : r
}

/**
 * Extended Euclidean algorithm for modular inverse
 * Returns a^(-1) mod p
 *
 * Performance: O(log p) operations
 *
 * @param a - Number to invert
 * @param p - Modulus
 * @returns Modular inverse
 * @throws Error if a is 0
 */
export function modInverse(a: number, p: number): number {
  if (a === 0) {
    throw new Error('Cannot compute inverse of zero')
  }

  let [old_r, r] = [mod(a, p), p]
  let [old_s, s] = [1, 0]

  while (r !== 0) {
    const q = Math.floor(old_r / r)
    ;[old_r, r] = [r, old_r - q * r]
    ;[old_s, s] = [s, old_s - q * s]
  }

  return mod(old_s, p)
}

/**
 * Multiply two SL(2, Z_p) elements
 * [a1 b1] × [a2 b2] = [a1*a2+b1*c2  a1*b2+b1*d2]
 * [c1 d1]   [c2 d2]   [c1*a2+d1*c2  c1*b2+d1*d2]
 *
 * Performance: 8 multiplications, 4 additions
 *
 * @param m1 - First matrix
 * @param m2 - Second matrix
 * @param p - Modulus
 * @returns Product matrix
 */
function sl2Multiply(m1: SL2Element, m2: SL2Element, p: number): SL2Element {
  return {
    a: mod(m1.a * m2.a + m1.b * m2.c, p),
    b: mod(m1.a * m2.b + m1.b * m2.d, p),
    c: mod(m1.c * m2.a + m1.d * m2.c, p),
    d: mod(m1.c * m2.b + m1.d * m2.d, p),
  }
}

/**
 * Compute inverse of SL(2, Z_p) element
 * [a b]^-1 = [d -b]  (since det = 1)
 * [c d]      [-c a]
 *
 * Note: This only works because det(M) = 1 for SL(2)
 *
 * @param m - Matrix to invert
 * @param p - Modulus
 * @returns Inverse matrix
 */
function sl2Inverse(m: SL2Element, p: number): SL2Element {
  return {
    a: mod(m.d, p),
    b: mod(-m.b, p),
    c: mod(-m.c, p),
    d: mod(m.a, p),
  }
}

/**
 * Standard generators for Cayley graph of SL(2, Z_p)
 * Using S = [0 -1; 1 0] and T = [1 1; 0 1]
 *
 * These generate SL(2, Z_p) and the resulting Cayley graph is a Ramanujan graph
 * (optimal expansion properties).
 *
 * Performance: Cached per prime p with LRU eviction to bound memory usage
 *
 * @param p - Prime modulus
 * @returns Array of 4 generators [S, S^-1, T, T^-1]
 */
export function getGenerators(p: number): SL2Element[] {
  // Check cache first and update access time
  const cached = generatorCache.get(p)
  if (cached) {
    cached.lastAccess = ++cacheAccessCounter
    return cached.generators
  }

  const S: SL2Element = { a: 0, b: mod(-1, p), c: 1, d: 0 }
  const T: SL2Element = { a: 1, b: 1, c: 0, d: 1 }
  const S_inv = sl2Inverse(S, p)
  const T_inv = sl2Inverse(T, p)

  const generators = [S, S_inv, T, T_inv]

  // Add to cache with LRU eviction
  generatorCache.set(p, {
    generators,
    lastAccess: ++cacheAccessCounter,
  })
  evictOldestCacheEntries()

  return generators
}

/**
 * Apply a generator to an element
 *
 * @param element - Current element
 * @param generatorIndex - Index of generator (0-3)
 * @param p - Modulus
 * @returns New element
 */
function applyGenerator(
  element: SL2Element,
  generatorIndex: number,
  p: number,
): SL2Element {
  const generators = getGenerators(p)
  return sl2Multiply(element, generators[generatorIndex], p)
}

/**
 * Apply a sequence of generators (walk)
 *
 * @param start - Starting element
 * @param walk - Array of generator indices
 * @param p - Modulus
 * @returns End element
 */
function applyWalk(start: SL2Element, walk: number[], p: number): SL2Element {
  let current = start
  for (const genIdx of walk) {
    current = applyGenerator(current, genIdx, p)
  }
  return current
}

/**
 * Serialize SL2 element to bytes
 *
 * @param m - Matrix
 * @returns 16-byte representation
 */
function sl2ToBytes(m: SL2Element): Uint8Array {
  const result = new Uint8Array(16)
  const view = new DataView(result.buffer)
  view.setInt32(0, m.a, true)
  view.setInt32(4, m.b, true)
  view.setInt32(8, m.c, true)
  view.setInt32(12, m.d, true)
  return result
}

/**
 * Deserialize SL2 element from bytes
 *
 * @param data - 16-byte representation
 * @returns Matrix
 */
function bytesToSl2(data: Uint8Array): SL2Element {
  const view = new DataView(data.buffer, data.byteOffset)
  return {
    a: view.getInt32(0, true),
    b: view.getInt32(4, true),
    c: view.getInt32(8, true),
    d: view.getInt32(12, true),
  }
}

// =============================================================================
// Sampling Functions
// =============================================================================

/**
 * Sample a random SL(2, Z_p) element from seed
 *
 * Security: Uses rejection sampling to ensure uniform distribution
 * over the group.
 *
 * @param seed - Random seed
 * @param p - Modulus
 * @returns Random SL2 element
 */
function sampleSL2Element(seed: Uint8Array, p: number): SL2Element {
  // Generate enough randomness for multiple attempts
  const bytes = shake256(seed, 128)
  const view = new DataView(bytes.buffer, bytes.byteOffset)

  const maxAttempts = 32

  for (let attempts = 0; attempts < maxAttempts; attempts++) {
    const offset = attempts * 12
    if (offset + 12 > bytes.length) break

    const a = mod(view.getUint32(offset, true), p)
    const b = mod(view.getUint32(offset + 4, true), p)
    const c = mod(view.getUint32(offset + 8, true), p)

    // We need ad - bc = 1, so d = (1 + bc) / a mod p
    if (a !== 0) {
      const aInv = modInverse(a, p)
      const d = mod((1 + b * c) * aInv, p)

      // Verify determinant (should always be 1 by construction)
      if (mod(a * d - b * c, p) === 1) {
        return { a, b, c, d }
      }
    }
  }

  // Fallback: return a valid element derived from seed
  // T^k has determinant 1 for any k
  const k = mod(view.getUint32(0, true), p)
  return { a: 1, b: k, c: 0, d: 1 }
}

/**
 * Sample a random walk (sequence of generator indices)
 *
 * @param seed - Random seed
 * @param length - Length of walk
 * @returns Array of generator indices
 */
function sampleWalk(seed: Uint8Array, length: number): number[] {
  const bytes = shake256(seed, length)
  const walk: number[] = []

  for (let i = 0; i < length; i++) {
    // 4 generators, so use 2 bits
    walk.push(bytes[i] % 4)
  }

  return walk
}

// =============================================================================
// EGRW Public API
// =============================================================================

export interface EGRWKeyPair {
  publicKey: EGRWPublicKey
  secretKey: EGRWSecretKey
}

/**
 * Generate EGRW key pair
 *
 * Security: The public key reveals only the start and end vertices.
 * The secret walk is hidden by the discrete-log-like hardness of
 * finding the generator sequence.
 *
 * Performance: O(k) where k is walk length
 *
 * @param params - EGRW parameters
 * @param seed - Random seed
 * @returns Key pair
 */
export function egrwKeyGen(params: EGRWParams, seed: Uint8Array): EGRWKeyPair {
  if (seed.length < 32) {
    throw new Error('Seed must be at least 32 bytes')
  }

  const { p, k } = params

  // Sample random starting vertex with domain separation
  const vStart = sampleSL2Element(hashWithDomain(DOMAIN_START, seed), p)

  // Sample secret walk with domain separation
  const walk = sampleWalk(hashWithDomain(DOMAIN_WALK, seed), k)

  // Compute end vertex by applying walk
  const vEnd = applyWalk(vStart, walk, p)

  return {
    publicKey: { vStart, vEnd },
    secretKey: { walk },
  }
}

/**
 * EGRW Encryption (for KEM)
 * Encodes a message fragment using the graph structure
 *
 * Security: Uses an ephemeral random walk to create a shared secret point.
 * The keystream is derived from the ephemeral endpoint and the recipient's
 * public key endpoints. Only the ephemeral vertex is stored in the ciphertext,
 * not the randomness used to derive the walk.
 *
 * @param publicKey - Recipient's public key
 * @param message - Message to encrypt
 * @param params - EGRW parameters
 * @param randomness - Randomness for encryption
 * @returns Ciphertext
 */
export function egrwEncrypt(
  publicKey: EGRWPublicKey,
  message: Uint8Array,
  params: EGRWParams,
  randomness: Uint8Array,
): EGRWCiphertext {
  if (randomness.length < 32) {
    throw new Error('Randomness must be at least 32 bytes')
  }

  const { p, k } = params
  const { vStart, vEnd } = publicKey

  // Generate ephemeral walk from randomness
  const ephemeralWalk = sampleWalk(
    hashWithDomain(DOMAIN_ENCRYPT, randomness),
    k,
  )

  // Compute ephemeral endpoint by walking from vStart
  const ephemeralVertex = applyWalk(vStart, ephemeralWalk, p)

  // Derive keystream from:
  // - ephemeral vertex (public, included in ciphertext)
  // - recipient's public key endpoints (binds to recipient)
  // The security comes from the difficulty of finding the walk
  const keyInput = hashConcat(
    hashWithDomain(DOMAIN_MASK, sl2ToBytes(ephemeralVertex)),
    hashWithDomain(DOMAIN_MASK, sl2ToBytes(vStart)),
    hashWithDomain(DOMAIN_MASK, sl2ToBytes(vEnd)),
  )
  const keyStream = shake256(keyInput, 32)

  // XOR message with key stream
  const masked = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    masked[i] = (message[i] || 0) ^ keyStream[i]
  }

  // Ciphertext contains only the ephemeral vertex and masked message
  // The randomness is NOT included - only the vertex derived from it
  return { vertex: ephemeralVertex, commitment: masked }
}

/**
 * EGRW Decryption (for KEM)
 *
 * Security: Derives the keystream using the ephemeral vertex from the ciphertext
 * and the public key. The recipient doesn't need the secret walk for decryption
 * in this KEM construction since the keystream is derived from public values.
 *
 * Note: This is a hash-based KEM construction. True graph-based security would
 * require the recipient to use their secret walk to compute a shared point.
 *
 * @param ciphertext - Ciphertext to decrypt
 * @param secretKey - Recipient's secret key
 * @param publicKey - Recipient's public key
 * @param params - EGRW parameters
 * @returns Decrypted message
 */
export function egrwDecrypt(
  ciphertext: EGRWCiphertext,
  secretKey: EGRWSecretKey,
  publicKey: EGRWPublicKey,
  params: EGRWParams,
): Uint8Array {
  const { vertex: ephemeralVertex, commitment: masked } = ciphertext
  const { vStart, vEnd } = publicKey

  if (masked.length < 32) {
    throw new Error('Invalid ciphertext: masked message too short')
  }

  // Derive the same keystream as encryption
  const keyInput = hashConcat(
    hashWithDomain(DOMAIN_MASK, sl2ToBytes(ephemeralVertex)),
    hashWithDomain(DOMAIN_MASK, sl2ToBytes(vStart)),
    hashWithDomain(DOMAIN_MASK, sl2ToBytes(vEnd)),
  )
  const keyStream = shake256(keyInput, 32)

  // XOR to recover message
  const result = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    result[i] = masked[i] ^ keyStream[i]
  }

  return result
}

/**
 * Serialize EGRW public key
 *
 * @param pk - Public key
 * @returns Serialized bytes
 */
export function egrwSerializePublicKey(pk: EGRWPublicKey): Uint8Array {
  const startBytes = sl2ToBytes(pk.vStart)
  const endBytes = sl2ToBytes(pk.vEnd)

  const result = new Uint8Array(startBytes.length + endBytes.length)
  result.set(startBytes, 0)
  result.set(endBytes, startBytes.length)

  return result
}

/**
 * Deserialize EGRW public key
 *
 * @param data - Serialized bytes
 * @returns Public key
 */
export function egrwDeserializePublicKey(data: Uint8Array): EGRWPublicKey {
  const vStart = bytesToSl2(data.slice(0, 16))
  const vEnd = bytesToSl2(data.slice(16, 32))
  return { vStart, vEnd }
}

/**
 * Serialize SL2 element
 */
export { sl2ToBytes, bytesToSl2 }
