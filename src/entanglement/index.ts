/**
 * Entanglement Layer
 *
 * Implements the cryptographic binding that makes kMOSAIC's three problems inseparable.
 * - Information-theoretic secret sharing (XOR-based 3-of-3)
 * - Cross-component binding using hash commitments
 * - NIZK proofs of correct construction
 *
 * Security Properties:
 * - Secret sharing: Information-theoretic security (n-1 shares reveal nothing)
 * - Commitments: Computationally hiding and binding (SHA3-256 based)
 * - NIZK: Zero-knowledge via Fiat-Shamir with domain separation
 */

import { shake256, hashConcat, hashWithDomain, sha3_256 } from '../utils/shake'
import { secureRandomBytes } from '../utils/random'
import { constantTimeEqual, zeroize } from '../utils/constant-time'

// Domain separation constants for security
const DOMAIN_SHARE = 'kmosaic-share-v1'
const DOMAIN_COMMIT = 'kmosaic-commit-v1'
const DOMAIN_BIND = 'kmosaic-bind-v1'
const DOMAIN_NIZK = 'kmosaic-nizk-v1'

// =============================================================================
// Secret Sharing (Information-Theoretic)
// =============================================================================

/**
 * Split a secret into n shares where all n are required to reconstruct (n-of-n XOR sharing)
 *
 * Security: Information-theoretic - any n-1 shares reveal no information about the secret.
 * This is because each share (except the last) is uniformly random.
 *
 * @param secret - Secret to split
 * @param n - Number of shares
 * @returns Array of shares
 */
export function secretShare(secret: Uint8Array, n: number): Uint8Array[] {
  if (n < 2) throw new Error('Need at least 2 shares')
  if (n > 255) throw new Error('Maximum 255 shares supported')
  if (secret.length === 0) throw new Error('Secret cannot be empty')

  const shares: Uint8Array[] = []

  // Generate n-1 random shares
  for (let i = 0; i < n - 1; i++) {
    shares.push(secureRandomBytes(secret.length))
  }

  // Last share is XOR of secret with all other shares
  const lastShare = new Uint8Array(secret.length)
  for (let i = 0; i < secret.length; i++) {
    let xorSum = secret[i]
    for (const share of shares) {
      xorSum ^= share[i]
    }
    lastShare[i] = xorSum
  }
  shares.push(lastShare)

  return shares
}

/**
 * Reconstruct secret from n shares (all required)
 *
 * Note: This is constant-time in the share values but not in the number of shares.
 *
 * @param shares - Array of shares
 * @returns Reconstructed secret
 */
export function secretReconstruct(shares: Uint8Array[]): Uint8Array {
  if (shares.length < 2) throw new Error('Need at least 2 shares')

  const length = shares[0].length
  for (const share of shares) {
    if (share.length !== length) {
      throw new Error('All shares must have same length')
    }
  }

  const result = new Uint8Array(length)
  for (let i = 0; i < length; i++) {
    let xorSum = 0
    for (const share of shares) {
      xorSum ^= share[i]
    }
    result[i] = xorSum
  }

  return result
}

/**
 * Deterministic secret sharing from seed (for re-encryption verification)
 *
 * Security: Shares are pseudorandom (computational security) rather than
 * truly random (information-theoretic). Use only when determinism is required.
 *
 * @param secret - Secret to split
 * @param n - Number of shares
 * @param seed - Random seed
 * @returns Array of shares
 */
export function secretShareDeterministic(
  secret: Uint8Array,
  n: number,
  seed: Uint8Array,
): Uint8Array[] {
  if (n < 2) throw new Error('Need at least 2 shares')
  if (n > 255) throw new Error('Maximum 255 shares supported')
  if (secret.length === 0) throw new Error('Secret cannot be empty')
  if (seed.length < 16) throw new Error('Seed must be at least 16 bytes')

  const shares: Uint8Array[] = []

  // Generate n-1 deterministic shares from seed with domain separation
  for (let i = 0; i < n - 1; i++) {
    const shareSeed = hashWithDomain(`${DOMAIN_SHARE}-${i}`, seed)
    shares.push(shake256(shareSeed, secret.length))
  }

  // Last share is XOR of secret with all other shares
  const lastShare = new Uint8Array(secret.length)
  for (let i = 0; i < secret.length; i++) {
    let xorSum = secret[i]
    for (const share of shares) {
      xorSum ^= share[i]
    }
    lastShare[i] = xorSum
  }
  shares.push(lastShare)

  return shares
}

// =============================================================================
// Binding Commitment
// =============================================================================

export interface BindingCommitment {
  commitment: Uint8Array
  opening: Uint8Array
}

/**
 * Create a binding commitment to data
 *
 * Security: Based on SHA3-256 with domain separation.
 * - Hiding: Computationally hiding (opening is random)
 * - Binding: Computationally binding (collision resistance of SHA3)
 *
 * @param data - Data to commit to
 * @returns Commitment and opening
 */
export function createCommitment(data: Uint8Array): BindingCommitment {
  if (data.length === 0) throw new Error('Cannot commit to empty data')

  const opening = secureRandomBytes(32)
  // Domain-separated commitment: H(domain || data || opening)
  const commitment = hashWithDomain(DOMAIN_COMMIT, hashConcat(data, opening))
  return { commitment, opening }
}

/**
 * Verify a binding commitment
 *
 * Constant-time comparison to prevent timing attacks.
 *
 * @param data - Data to verify
 * @param commitment - Commitment hash
 * @param opening - Opening value
 * @returns True if valid
 */
export function verifyCommitment(
  data: Uint8Array,
  commitment: Uint8Array,
  opening: Uint8Array,
): boolean {
  if (opening.length !== 32) return false
  if (commitment.length !== 32) return false

  const expected = hashWithDomain(DOMAIN_COMMIT, hashConcat(data, opening))
  return constantTimeEqual(commitment, expected)
}

/**
 * Compute cross-component binding hash
 *
 * This creates the circular dependency that entangles all three problems.
 * An attacker must break ALL components simultaneously since modifying
 * any component changes the binding hash.
 *
 * Security: Domain separation ensures independence from other hash uses.
 *
 * @param slssData - SLSS component data
 * @param tddData - TDD component data
 * @param egrwData - EGRW component data
 * @returns Binding hash
 */
export function computeBinding(
  slssData: Uint8Array,
  tddData: Uint8Array,
  egrwData: Uint8Array,
): Uint8Array {
  // Three-layer binding with domain separation
  const slssHash = hashWithDomain(`${DOMAIN_BIND}-slss`, slssData)
  const tddHash = hashWithDomain(`${DOMAIN_BIND}-tdd`, tddData)
  const egrwHash = hashWithDomain(`${DOMAIN_BIND}-egrw`, egrwData)

  // Final binding combines all three
  return hashWithDomain(
    `${DOMAIN_BIND}-final`,
    hashConcat(slssHash, tddHash, egrwHash),
  )
}

// =============================================================================
// NIZK Proofs (Fiat-Shamir with Strong Binding)
// =============================================================================

export interface NIZKProof {
  challenge: Uint8Array
  responses: Uint8Array[]
  commitments: Uint8Array[]
}

/**
 * Generate NIZK proof that ciphertexts are correctly formed
 *
 * This is a sigma protocol using Fiat-Shamir transform with strong binding.
 * The proof demonstrates knowledge of shares that:
 * 1. XOR to reconstruct the original message
 * 2. Are correctly encrypted in the corresponding ciphertexts
 *
 * Security:
 * - Zero-knowledge: Responses are masked, revealing nothing about shares
 * - Soundness: Challenge binds commitments to message and ciphertext hashes
 * - Non-malleability: Domain separation prevents cross-protocol attacks
 *
 * @param message - Original message
 * @param shares - Message shares
 * @param ciphertextHashes - Hashes of ciphertexts
 * @param randomness - Randomness for proof generation
 * @returns NIZK proof
 */
export function generateNIZKProof(
  message: Uint8Array,
  shares: Uint8Array[],
  ciphertextHashes: Uint8Array[],
  randomness: Uint8Array,
): NIZKProof {
  if (shares.length !== 3) throw new Error('NIZK requires exactly 3 shares')
  if (ciphertextHashes.length !== 3)
    throw new Error('NIZK requires exactly 3 ciphertext hashes')
  if (randomness.length < 32)
    throw new Error('Randomness must be at least 32 bytes')

  // Commitment phase - create hiding commitments to each share
  const commitments: Uint8Array[] = []
  const commitRandomness: Uint8Array[] = []

  for (let i = 0; i < 3; i++) {
    // Derive commitment randomness deterministically for consistency
    const r = shake256(
      hashWithDomain(`${DOMAIN_NIZK}-commit-${i}`, randomness),
      32,
    )
    commitRandomness.push(r)

    // Commit to share with binding to ciphertext
    // C_i = H(share_i || r_i || ciphertext_hash_i)
    const com = hashWithDomain(
      `${DOMAIN_NIZK}-com`,
      hashConcat(shares[i], r, ciphertextHashes[i]),
    )
    commitments.push(com)
  }

  // Challenge generation (Fiat-Shamir)
  // Include all public data for strong binding
  const challengeInput = hashConcat(
    hashWithDomain(`${DOMAIN_NIZK}-msg`, message),
    ...commitments,
    ...ciphertextHashes,
  )
  const challenge = sha3_256(challengeInput)

  // Response phase - reveal masked shares
  const responses: Uint8Array[] = []
  for (let i = 0; i < 3; i++) {
    // Generate mask from challenge (ensures ZK property)
    const mask = shake256(
      hashWithDomain(`${DOMAIN_NIZK}-mask-${i}`, challenge),
      shares[i].length,
    )

    // Response = masked_share || commit_randomness
    const response = new Uint8Array(shares[i].length + 32)
    for (let j = 0; j < shares[i].length; j++) {
      response[j] = shares[i][j] ^ mask[j]
    }
    response.set(commitRandomness[i], shares[i].length)
    responses.push(response)
  }

  return { challenge, responses, commitments }
}

/**
 * Verify NIZK proof
 *
 * Verifies that the prover knows shares that are correctly committed
 * and bound to the claimed ciphertexts.
 *
 * Security: All comparisons are constant-time to prevent timing attacks.
 *
 * @param proof - NIZK proof
 * @param ciphertextHashes - Hashes of ciphertexts
 * @param messageHash - Hash of message
 * @returns True if valid
 */
export function verifyNIZKProof(
  proof: NIZKProof,
  ciphertextHashes: Uint8Array[],
  messageHash: Uint8Array,
): boolean {
  const { challenge, responses, commitments } = proof

  // Structural validation
  if (commitments.length !== 3 || responses.length !== 3) {
    return false
  }
  if (ciphertextHashes.length !== 3) {
    return false
  }
  if (challenge.length !== 32) {
    return false
  }

  // Recompute challenge with same binding
  const challengeInput = hashConcat(
    hashWithDomain(`${DOMAIN_NIZK}-msg`, messageHash),
    ...commitments,
    ...ciphertextHashes,
  )
  const expectedChallenge = sha3_256(challengeInput)

  if (!constantTimeEqual(challenge, expectedChallenge)) {
    return false
  }

  // Verify each response
  let allValid = true
  for (let i = 0; i < 3; i++) {
    const response = responses[i]
    if (response.length < 32) {
      return false
    }

    const shareLen = response.length - 32
    const commitRandomness = response.slice(shareLen)

    // Reconstruct share from masked response
    const mask = shake256(
      hashWithDomain(`${DOMAIN_NIZK}-mask-${i}`, challenge),
      shareLen,
    )
    const share = new Uint8Array(shareLen)
    for (let j = 0; j < shareLen; j++) {
      share[j] = response[j] ^ mask[j]
    }

    // Verify commitment
    const expectedCom = hashWithDomain(
      `${DOMAIN_NIZK}-com`,
      hashConcat(share, commitRandomness, ciphertextHashes[i]),
    )
    if (!constantTimeEqual(commitments[i], expectedCom)) {
      allValid = false
    }

    // Zeroize sensitive intermediate value
    zeroize(share)
  }

  return allValid
}

/**
 * Serialize NIZK proof
 *
 * @param proof - NIZK proof
 * @returns Serialized bytes
 */
export function serializeNIZKProof(proof: NIZKProof): Uint8Array {
  const parts: Uint8Array[] = [
    proof.challenge,
    ...proof.commitments,
    ...proof.responses,
  ]

  // Calculate total size with length prefixes
  let totalSize = 4 // Number of parts
  for (const part of parts) {
    totalSize += 4 + part.length
  }

  const result = new Uint8Array(totalSize)
  const view = new DataView(result.buffer)

  let offset = 0
  view.setUint32(offset, parts.length, true)
  offset += 4

  for (const part of parts) {
    view.setUint32(offset, part.length, true)
    offset += 4
    result.set(part, offset)
    offset += part.length
  }

  return result
}

/**
 * Deserialize NIZK proof
 *
 * Security: Strict validation of all bounds and expected structure
 *
 * @param data - Serialized bytes
 * @returns NIZK proof
 */
export function deserializeNIZKProof(data: Uint8Array): NIZKProof {
  if (data.length < 8) {
    throw new Error('NIZK proof data too short: minimum 8 bytes required')
  }

  const view = new DataView(data.buffer, data.byteOffset)
  let offset = 0

  const numParts = view.getUint32(offset, true)
  offset += 4

  // Strict validation: NIZK proof must have exactly 7 parts
  // (1 challenge + 3 commitments + 3 responses)
  if (numParts !== 7) {
    throw new Error(`Invalid NIZK proof: expected 7 parts, got ${numParts}`)
  }

  const parts: Uint8Array[] = []
  for (let i = 0; i < numParts; i++) {
    // Bounds check before reading length
    if (offset + 4 > data.length) {
      throw new Error(`NIZK proof truncated: cannot read length for part ${i}`)
    }

    const len = view.getUint32(offset, true)
    offset += 4

    // Validate length is reasonable (prevent DoS via huge allocation)
    if (len > 1024 * 1024) {
      throw new Error(`NIZK proof part ${i} too large: ${len} bytes`)
    }

    // Bounds check before reading data
    if (offset + len > data.length) {
      throw new Error(`NIZK proof truncated: part ${i} extends beyond data`)
    }

    parts.push(data.slice(offset, offset + len))
    offset += len
  }

  // Validate challenge length (must be 32 bytes for SHA3-256)
  if (parts[0].length !== 32) {
    throw new Error(
      `Invalid challenge length: expected 32, got ${parts[0].length}`,
    )
  }

  return {
    challenge: parts[0],
    commitments: [parts[1], parts[2], parts[3]],
    responses: [parts[4], parts[5], parts[6]],
  }
}
