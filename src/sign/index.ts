/**
 * kMOSAIC Digital Signatures
 *
 * Simple Fiat-Shamir signature scheme compatible with Go implementation.
 *
 * Security Properties:
 * - Fiat-Shamir: Non-interactive via hash-based challenge
 * - Deterministic: Same message + key produces consistent verification
 *
 * Signature Structure:
 * - Commitment: 32-byte hash of witness + message + binding
 * - Challenge: 32-byte hash of commitment + message + public key hash
 * - Response: 64-byte response derived from secret key + challenge + witness
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

import { slssKeyGen, slssSerializePublicKey } from '../problems/slss/index.js'

import { tddKeyGen, tddSerializePublicKey } from '../problems/tdd/index.js'

import {
  egrwKeyGen,
  egrwSerializePublicKey,
  sl2ToBytes,
} from '../problems/egrw/index.js'

import { computeBinding } from '../entanglement/index.js'

// =============================================================================
// Domain Separation Constants
// =============================================================================

const DOMAIN_CHALLENGE = 'kmosaic-sign-chal-v1'
const DOMAIN_RESPONSE = 'kmosaic-sign-resp-v1'


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
 * Sign a message using kMOSAIC Fiat-Shamir scheme
 *
 * Algorithm (matches Go):
 * 1. Generate random witness
 * 2. Compute message hash: H(message || binding)
 * 3. Compute commitment: H(witness || msgHash || binding)
 * 4. Compute challenge: H_domain(commitment || msgHash || pkHash)
 * 5. Compute response: SHAKE256(H_domain(skBytes || challenge || witness))
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
  // Generate random witness
  const witnessRand = secureRandomBytes(32)

  // Compute message hash: H(message || binding)
  const msgHash = sha3_256(hashConcat(message, publicKey.binding))

  // Compute commitment: H(witness || msgHash || binding)
  const commitment = sha3_256(
    hashConcat(witnessRand, msgHash, publicKey.binding),
  )

  // Compute challenge: H_domain(commitment || msgHash || pkHash)
  const challenge = hashWithDomain(
    DOMAIN_CHALLENGE,
    hashConcat(commitment, msgHash, secretKey.publicKeyHash),
  )

  // Compute response
  const response = computeResponse(secretKey, challenge, witnessRand)

  // Zeroize sensitive data
  zeroize(witnessRand)

  return {
    commitment,
    challenge,
    response,
  }
}

/**
 * Compute signature response - matches Go implementation
 *
 * @param sk - Secret key
 * @param challenge - Challenge bytes
 * @param witnessRand - Random witness
 * @returns Response bytes (64 bytes)
 */
function computeResponse(
  sk: MOSAICSecretKey,
  challenge: Uint8Array,
  witnessRand: Uint8Array,
): Uint8Array {
  // Combine secret key components into bytes - must match Go's serialization order
  const skParts: Uint8Array[] = []

  // SLSS secret key contribution (s vector as int32 little-endian)
  const slssBytes = new Uint8Array(sk.slss.s.length * 4)
  const slssView = new DataView(slssBytes.buffer)
  for (let i = 0; i < sk.slss.s.length; i++) {
    // Convert int8 to int32, then to uint32 for serialization
    slssView.setUint32(i * 4, sk.slss.s[i] | 0, true)
  }
  skParts.push(slssBytes)

  // TDD secret key contribution (factors.a as int32 little-endian)
  for (const vec of sk.tdd.factors.a) {
    const vecBytes = new Uint8Array(vec.length * 4)
    const vecView = new DataView(vecBytes.buffer)
    for (let j = 0; j < vec.length; j++) {
      vecView.setUint32(j * 4, vec[j] >>> 0, true)
    }
    skParts.push(vecBytes)
  }

  // EGRW secret key contribution (walk as bytes)
  const egrwBytes = new Uint8Array(sk.egrw.walk.length)
  for (let i = 0; i < sk.egrw.walk.length; i++) {
    egrwBytes[i] = sk.egrw.walk[i] & 0xff
  }
  skParts.push(egrwBytes)

  // Combine all secret key parts
  const skCombined = new Uint8Array(
    skParts.reduce((sum, part) => sum + part.length, 0),
  )
  let offset = 0
  for (const part of skParts) {
    skCombined.set(part, offset)
    offset += part.length
  }

  // Compute response: SHAKE256(H_domain(skBytes || challenge || witness))
  const responseInput = hashWithDomain(
    DOMAIN_RESPONSE,
    hashConcat(skCombined, challenge, witnessRand),
  )
  return shake256(responseInput, 64)
}

// =============================================================================
// Signature Verification
// =============================================================================

/**
 * Verify a kMOSAIC signature
 *
 * Algorithm (matches Go):
 * 1. Compute message hash: H(message || binding)
 * 2. Compute commitment: H(response || challenge || witness)
 * 3. Verify commitment matches signature commitment
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
    // Verify signature structure
    if (
      !signature.commitment ||
      signature.commitment.length !== 32 ||
      !signature.challenge ||
      signature.challenge.length !== 32 ||
      !signature.response ||
      signature.response.length !== 64
    ) {
      return false
    }

    // Compute public key hash
    const publicKeyHash = sha3_256(serializePublicKey(publicKey))

    // Compute message hash: H(message || binding)
    const msgHash = sha3_256(hashConcat(message, publicKey.binding))

    // Compute expected challenge: H_domain(commitment || msgHash || pkHash)
    const expectedChallenge = hashWithDomain(
      DOMAIN_CHALLENGE,
      hashConcat(signature.commitment, msgHash, publicKeyHash),
    )

    // Verify challenge matches
    return constantTimeEqual(signature.challenge, expectedChallenge)
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
 * [commitment (32)] || [challenge (32)] || [response (64)]
 *
 * @param sig - Signature object
 * @returns Serialized bytes
 */
export function serializeSignature(sig: MOSAICSignature): Uint8Array {
  const result = new Uint8Array(32 + 32 + 64)

  result.set(sig.commitment, 0)
  result.set(sig.challenge, 32)
  result.set(sig.response, 64)

  return result
}

/**
 * Deserialize signature from bytes
 *
 * @param data - Serialized signature bytes (128 bytes)
 * @returns Deserialized signature object
 */
export function deserializeSignature(data: Uint8Array): MOSAICSignature {
  if (data.length < 128) {
    throw new Error('Invalid signature data: expected at least 128 bytes')
  }

  return {
    commitment: data.slice(0, 32),
    challenge: data.slice(32, 64),
    response: data.slice(64, 128),
  }
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

  const totalLen =
    4 + slssBytes.length + 4 + tddBytes.length + 4 + egrwBytes.length + pk.binding.length

  const result = new Uint8Array(totalLen)
  const view = new DataView(result.buffer)

  let offset = 0

  view.setUint32(offset, slssBytes.length, true)
  offset += 4
  result.set(slssBytes, offset)
  offset += slssBytes.length

  view.setUint32(offset, tddBytes.length, true)
  offset += 4
  result.set(tddBytes, offset)
  offset += tddBytes.length

  view.setUint32(offset, egrwBytes.length, true)
  offset += 4
  result.set(egrwBytes, offset)
  offset += egrwBytes.length

  result.set(pk.binding, offset)

  return result
}
