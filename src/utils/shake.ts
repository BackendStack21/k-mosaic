/**
 * Cryptographic hash utilities using Node.js crypto (Bun compatible)
 *
 * Security considerations:
 * - Uses native SHAKE256 XOF when available (Node.js 12+)
 * - Falls back to counter-mode SHA3-256 construction
 * - Intermediate buffers are zeroized
 * - Domain separation uses length-prefixed encoding to prevent collisions
 */

import { createHash } from 'crypto'
import { zeroize } from './constant-time.js'

// ============================================================================
// Domain Separation Constants (versioned for future compatibility)
// ============================================================================

// Domain separator for fallback SHAKE256 implementation
const DOMAIN_SHAKE_FALLBACK = new TextEncoder().encode('kMOSAIC-shake256-v1')

// Domain separator for concatenated hashing
const DOMAIN_HASH_CONCAT = new TextEncoder().encode('kMOSAIC-concat-v1')

// Check if native SHAKE256 is available
let hasNativeShake256: boolean | null = null
let shake256FallbackWarned = false // Track if warning has been shown

/**
 * Checks if the runtime supports native SHAKE256
 * Caches the result to avoid repeated checks
 *
 * @returns true if native SHAKE256 is available, false otherwise
 */
function checkNativeShake256(): boolean {
  // If check hasn't been performed yet
  if (hasNativeShake256 === null) {
    try {
      // Attempt to create a SHAKE256 hash instance
      const hash = createHash('shake256', { outputLength: 32 })
      // Update with dummy data
      hash.update(new Uint8Array([0]))
      // Finalize digest
      hash.digest()
      // If successful, mark as available
      hasNativeShake256 = true
    } catch {
      // If error occurs (e.g., algorithm not supported), mark as unavailable
      hasNativeShake256 = false
    }
  }
  return hasNativeShake256
}

/**
 * SHAKE256 extendable output function (XOF)
 * Uses native SHAKE256 when available, falls back to counter-mode SHA3-256
 *
 * @param input - Input data to hash
 * @param outputLength - Desired length of output in bytes
 * @returns Hash output of specified length
 */
export function shake256(input: Uint8Array, outputLength: number): Uint8Array {
  // Validate output length
  if (outputLength < 0) {
    throw new Error('Output length must be non-negative')
  }
  // Handle zero length request
  if (outputLength === 0) {
    return new Uint8Array(0)
  }

  // Try native SHAKE256 first (much faster and more secure)
  if (checkNativeShake256()) {
    // Create hash, update with input, and digest to desired length
    return new Uint8Array(
      createHash('shake256', { outputLength }).update(input).digest(),
    )
  }

  // Fallback: Counter-mode SHA3-256 construction
  // Domain-separated to distinguish from other uses
  return shake256Fallback(input, outputLength)
}

/**
 * Fallback SHAKE256 implementation using counter-mode SHA3-256
 * Only used when native SHAKE256 is unavailable
 *
 * SECURITY WARNING: This fallback construction:
 * - Is not a standard XOF and lacks formal security proofs
 * - May not provide the full security margin of native SHAKE256
 * - Should only be used for compatibility; prefer native SHAKE256
 *
 * For high-security applications, ensure native SHAKE256 is available.
 *
 * @param input - Input data to hash
 * @param outputLength - Desired length of output in bytes
 * @returns Hash output of specified length
 */
export function shake256Fallback(
  input: Uint8Array,
  outputLength: number,
): Uint8Array {
  // Emit one-time warning about fallback usage
  if (!shake256FallbackWarned) {
    shake256FallbackWarned = true
    console.warn(
      '[kMOSAIC Security Warning] Using fallback SHAKE256 implementation. ' +
        'Native SHAKE256 is unavailable. This fallback uses counter-mode SHA3-256 ' +
        'which may not provide equivalent security margins. Consider using Node.js 12+ ' +
        'or a runtime with native SHAKE256 support for production use.',
    )
  }

  // Allocate output buffer
  const output = new Uint8Array(outputLength)
  let offset = 0
  let counter = 0

  // Pre-allocate input buffer: domain + length(4) + input + counter(4)
  // This structure ensures domain separation and prevents length extension attacks
  const hashInput = new Uint8Array(
    DOMAIN_SHAKE_FALLBACK.length + 4 + input.length + 4,
  )

  // Set domain prefix at the beginning
  hashInput.set(DOMAIN_SHAKE_FALLBACK, 0)

  // Create DataView for writing integers
  const view = new DataView(hashInput.buffer)

  // Set output length (prevents length extension issues)
  // Written as little-endian 32-bit integer
  view.setUint32(DOMAIN_SHAKE_FALLBACK.length, outputLength, true)

  // Set input data after domain and length
  hashInput.set(input, DOMAIN_SHAKE_FALLBACK.length + 4)

  // Calculate offset where counter will be written
  const counterOffset = DOMAIN_SHAKE_FALLBACK.length + 4 + input.length

  // Generate output blocks until we have enough data
  while (offset < outputLength) {
    // Set counter value (incrementing for each block)
    view.setUint32(counterOffset, counter, true)

    // Hash the constructed input using SHA3-256
    const hash = createHash('sha3-256').update(hashInput).digest()

    // Calculate how many bytes to copy from this block
    const toCopy = Math.min(hash.length, outputLength - offset)

    // Copy hash bytes to output buffer
    output.set(new Uint8Array(hash.buffer, hash.byteOffset, toCopy), offset)

    // Advance offset and counter
    offset += toCopy
    counter++
  }

  // Zeroize intermediate buffer to clear sensitive data
  zeroize(hashInput)

  return output
}

/**
 * SHA3-256 hash
 *
 * @param input - Input data to hash
 * @returns 32-byte hash output
 */
export function sha3_256(input: Uint8Array): Uint8Array {
  // Create SHA3-256 hash, update with input, and return digest
  return new Uint8Array(createHash('sha3-256').update(input).digest())
}

/**
 * Hash multiple inputs with length-prefixed encoding
 * Uses length prefixes to prevent collision attacks from concatenation
 * e.g., H("AB", "C") != H("A", "BC")
 *
 * @param inputs - Variable number of Uint8Array inputs
 * @returns Hash of concatenated inputs
 */
export function hashConcat(...inputs: Uint8Array[]): Uint8Array {
  // Calculate total size: domain + count(4) + sum of (length(4) + data)
  const totalLength =
    DOMAIN_HASH_CONCAT.length +
    4 +
    inputs.reduce((sum, arr) => sum + 4 + arr.length, 0)

  // Allocate combined buffer
  const combined = new Uint8Array(totalLength)
  const view = new DataView(combined.buffer)
  let offset = 0

  // Domain prefix
  combined.set(DOMAIN_HASH_CONCAT, offset)
  offset += DOMAIN_HASH_CONCAT.length

  // Number of inputs
  view.setUint32(offset, inputs.length, true)
  offset += 4

  // Each input with length prefix
  for (const input of inputs) {
    // Write length of current input
    view.setUint32(offset, input.length, true)
    offset += 4

    // Write input data
    combined.set(input, offset)
    offset += input.length
  }

  // Hash the combined buffer
  const result = sha3_256(combined)

  // Zeroize intermediate buffer
  zeroize(combined)

  return result
}

/**
 * Domain-separated hash with length-prefixed encoding
 * Prevents domain/input boundary ambiguity
 *
 * @param domain - Domain string
 * @param input - Input data
 * @returns Hash output
 */
export function hashWithDomain(domain: string, input: Uint8Array): Uint8Array {
  // Encode domain string to bytes
  const domainBytes = new TextEncoder().encode(domain)

  // Length-prefixed encoding: domainLen(4) + domain + inputLen(4) + input
  const combined = new Uint8Array(4 + domainBytes.length + 4 + input.length)
  const view = new DataView(combined.buffer)

  let offset = 0

  // Write domain length
  view.setUint32(offset, domainBytes.length, true)
  offset += 4

  // Write domain bytes
  combined.set(domainBytes, offset)
  offset += domainBytes.length

  // Write input length
  view.setUint32(offset, input.length, true)
  offset += 4

  // Write input bytes
  combined.set(input, offset)

  // Hash the combined buffer
  const result = sha3_256(combined)

  // Zeroize intermediate buffer
  zeroize(combined)

  return result
}
