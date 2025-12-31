/**
 * kMOSAIC Key Encapsulation Mechanism (KEM)
 *
 * Combines three heterogeneous hard problems with cryptographic entanglement
 * for post-quantum security with defense in depth.
 *
 * Security Properties:
 * - IND-CCA2 security via Fujisaki-Okamoto transform
 * - Implicit rejection on decapsulation failure
 * - Three independent hard problems for defense-in-depth
 * - Cryptographic entanglement prevents partial breaks
 *
 * Performance Considerations:
 * - TDD operations are O(n³) - most expensive component
 * - EGRW operations are O(k) - fastest component
 * - Parallelization opportunities in encapsulation
 */

import {
  SecurityLevel,
  type MOSAICParams,
  type MOSAICPublicKey,
  type MOSAICSecretKey,
  type MOSAICKeyPair,
  type MOSAICCiphertext,
  type EncapsulationResult,
  type SecurityAnalysis,
} from '../types.js'

import { getParams, validateParams } from '../core/params.js'
import {
  shake256,
  hashConcat,
  hashWithDomain,
  sha3_256,
} from '../utils/shake.js'
import { secureRandomBytes, validateSeedEntropy } from '../utils/random.js'
import {
  constantTimeEqual,
  constantTimeSelect,
  zeroize,
} from '../utils/constant-time.js'

import {
  slssKeyGen,
  slssEncrypt,
  slssDecrypt,
  slssSerializePublicKey,
} from '../problems/slss/index.js'

import {
  tddKeyGen,
  tddEncrypt,
  tddDecrypt,
  tddSerializePublicKey,
} from '../problems/tdd/index.js'

import {
  egrwKeyGen,
  egrwEncrypt,
  egrwDecrypt,
  egrwSerializePublicKey,
  sl2ToBytes,
} from '../problems/egrw/index.js'

import {
  secretShareDeterministic,
  secretReconstruct,
  computeBinding,
  generateNIZKProof,
  verifyNIZKProof,
  serializeNIZKProof,
  deserializeNIZKProof,
} from '../entanglement/index.js'

// Domain separation constants for security
const DOMAIN_SLSS = 'kmosaic-kem-slss-v1'
const DOMAIN_TDD = 'kmosaic-kem-tdd-v1'
const DOMAIN_EGRW = 'kmosaic-kem-egrw-v1'
const DOMAIN_SHARED_SECRET = 'kmosaic-kem-ss-v1'
const DOMAIN_ENC_KEY = 'kmosaic-enc-key-v1'
const DOMAIN_NONCE = 'kmosaic-nonce-v1'
const DOMAIN_IMPLICIT_REJECT = 'kmosaic-kem-reject-v1'

// =============================================================================
// KEM Key Generation
// =============================================================================

/**
 * Generate kMOSAIC key pair
 *
 * Uses cryptographically secure randomness to generate keys for all three
 * underlying problems (SLSS, TDD, EGRW).
 *
 * Security:
 * - Uses secure random number generator for master seed
 * - Ensures full entropy for all component keys
 *
 * Performance:
 * - Key generation is dominated by TDD tensor operations (O(n³))
 * - SLSS and EGRW generation are relatively fast
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

  // Generate master seed with full entropy
  const seed = secureRandomBytes(32)

  const keyPair = generateKeyPairFromSeed(params, seed)

  // Zeroize seed after use (seed is copied into secret key)
  zeroize(seed)

  return keyPair
}

/**
 * Generate key pair from seed (deterministic)
 *
 * Security notes:
 * - Domain-separated key derivation prevents related-key attacks
 * - This function is DETERMINISTIC: same seed produces same key pair
 * - Caller is responsible for ensuring seed has sufficient entropy (32+ bytes of randomness)
 * - For production use, prefer generateKeyPair() which uses secure system randomness
 * - For testing/reproducibility, this function enables deterministic key generation
 *
 * WARNING: Using a low-entropy seed (e.g., derived from password, predictable values)
 * will result in weak keys. Only use seeds from cryptographically secure sources.
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

  // Enhanced entropy validation: detect common low-entropy patterns
  validateSeedEntropy(seed)

  // Derive component seeds with domain separation
  const slssSeed = hashWithDomain(DOMAIN_SLSS, seed)
  const tddSeed = hashWithDomain(DOMAIN_TDD, seed)
  const egrwSeed = hashWithDomain(DOMAIN_EGRW, seed)

  // Generate component key pairs
  const slssKP = slssKeyGen(params.slss, slssSeed)
  const tddKP = tddKeyGen(params.tdd, tddSeed)
  const egrwKP = egrwKeyGen(params.egrw, egrwSeed)

  // Compute binding hash (entangles all components)
  const slssBytes = slssSerializePublicKey(slssKP.publicKey)
  const tddBytes = tddSerializePublicKey(tddKP.publicKey)
  const egrwBytes = egrwSerializePublicKey(egrwKP.publicKey)
  const binding = computeBinding(slssBytes, tddBytes, egrwBytes)

  // Compose public key
  const publicKey: MOSAICPublicKey = {
    slss: slssKP.publicKey,
    tdd: tddKP.publicKey,
    egrw: egrwKP.publicKey,
    binding,
    params,
  }

  // Compute public key hash (for CCA security)
  const publicKeyHash = sha3_256(serializePublicKey(publicKey))

  // Compose secret key
  const secretKey: MOSAICSecretKey = {
    slss: slssKP.secretKey,
    tdd: tddKP.secretKey,
    egrw: egrwKP.secretKey,
    seed,
    publicKeyHash,
  }

  return { publicKey, secretKey }
}

// =============================================================================
// KEM Encapsulation
// =============================================================================

/**
 * Encapsulate: Generate shared secret and ciphertext for recipient
 *
 * Security:
 * - Ephemeral secret provides forward secrecy
 * - Shared secret is bound to the ciphertext via hash
 * - Uses full entropy for ephemeral secret
 *
 * @param publicKey - Recipient's public key
 * @returns Promise resolving to shared secret and ciphertext
 */
export async function encapsulate(
  publicKey: MOSAICPublicKey,
): Promise<EncapsulationResult> {
  // Generate ephemeral secret with full entropy
  const ephemeralSecret = secureRandomBytes(32)

  const result = encapsulateDeterministic(publicKey, ephemeralSecret)

  // Zeroize ephemeral secret (it's hashed into the result)
  zeroize(ephemeralSecret)

  return result
}

/**
 * Deterministic encapsulation (for CCA re-encryption check)
 *
 * Security:
 * - All randomness is derived from ephemeral secret and public key
 * - This enables the Fujisaki-Okamoto re-encryption check in decapsulation
 * - Secret sharing ensures all three problems must be broken to recover secret
 * - NIZK proof proves correct construction without leaking secret
 *
 * Algorithm:
 * 1. Derive randomness from ephemeral secret and public key binding
 * 2. Split secret into 3 shares (information-theoretic security)
 * 3. Encrypt each share with different problem (SLSS, TDD, EGRW)
 * 4. Generate NIZK proof of correct construction
 * 5. Derive shared secret from ephemeral secret and ciphertext hash
 *
 * @param publicKey - Recipient's public key
 * @param ephemeralSecret - Ephemeral secret (32 bytes)
 * @returns Encapsulation result (shared secret + ciphertext)
 * @throws Error if ephemeral secret is invalid
 */
export function encapsulateDeterministic(
  publicKey: MOSAICPublicKey,
  ephemeralSecret: Uint8Array,
): EncapsulationResult {
  if (ephemeralSecret.length !== 32) {
    throw new Error('Ephemeral secret must be exactly 32 bytes')
  }

  const { slss, tdd, egrw, binding, params } = publicKey

  // Derive randomness from ephemeral secret and public key binding
  // Binding ensures ciphertext is tied to this specific public key
  const randomness = hashConcat(ephemeralSecret, binding)

  // Split secret into 3 shares (information-theoretic security)
  const shares = secretShareDeterministic(ephemeralSecret, 3, randomness)

  // Encrypt each share with different problem
  // Fragment 1: SLSS (lattice-based)
  const c1 = slssEncrypt(
    slss,
    shares[0],
    params.slss,
    hashWithDomain(`${DOMAIN_SLSS}-rand`, randomness),
  )

  // Fragment 2: TDD (tensor-based)
  const c2 = tddEncrypt(
    tdd,
    shares[1],
    params.tdd,
    hashWithDomain(`${DOMAIN_TDD}-rand`, randomness),
  )

  // Fragment 3: EGRW (graph-based)
  const c3 = egrwEncrypt(
    egrw,
    shares[2],
    params.egrw,
    hashWithDomain(`${DOMAIN_EGRW}-rand`, randomness),
  )

  // Generate NIZK proof of correct construction
  const ciphertextHashes = [
    sha3_256(serializeSLSSCiphertext(c1)),
    sha3_256(serializeTDDCiphertext(c2)),
    sha3_256(serializeEGRWCiphertext(c3)),
  ]

  const proof = generateNIZKProof(
    ephemeralSecret,
    shares,
    ciphertextHashes,
    hashWithDomain(`${DOMAIN_SLSS}-nizk`, randomness),
  )

  // Compose ciphertext
  const ciphertext: MOSAICCiphertext = {
    c1,
    c2,
    c3,
    proof: serializeNIZKProof(proof),
  }

  // Derive shared secret with domain separation
  // Include ciphertext hash to bind secret to this specific ciphertext
  const ciphertextHash = sha3_256(serializeCiphertext(ciphertext))
  const sharedSecret = shake256(
    hashWithDomain(
      DOMAIN_SHARED_SECRET,
      hashConcat(ephemeralSecret, ciphertextHash),
    ),
    32,
  )

  return { sharedSecret, ciphertext }
}

// =============================================================================
// KEM Decapsulation
// =============================================================================

/**
 * Decapsulate: Recover shared secret from ciphertext
 *
 * Security:
 * - Implements Fujisaki-Okamoto transform for IND-CCA2 security
 * - Uses implicit rejection: on failure, returns pseudorandom value
 * - Constant-time execution path to prevent timing attacks
 * - Verifies NIZK proof to ensure ciphertext validity
 *
 * Algorithm:
 * 1. Compute implicit rejection value (for constant-time return)
 * 2. Decrypt all three fragments (SLSS, TDD, EGRW)
 * 3. Reconstruct candidate ephemeral secret
 * 4. Re-encapsulate with candidate secret (FO transform)
 * 5. Verify re-encapsulated ciphertext matches input
 * 6. Verify NIZK proof
 * 7. Return shared secret if valid, else implicit rejection value
 *
 * @param ciphertext - Ciphertext to decapsulate
 * @param secretKey - Recipient's secret key
 * @param publicKey - Recipient's public key (needed for re-encapsulation)
 * @returns Promise resolving to shared secret
 */
export async function decapsulate(
  ciphertext: MOSAICCiphertext,
  secretKey: MOSAICSecretKey,
  publicKey: MOSAICPublicKey,
): Promise<Uint8Array> {
  const {
    slss: slssSK,
    tdd: tddSK,
    egrw: egrwSK,
    seed,
    publicKeyHash,
  } = secretKey
  const { slss: slssPK, tdd: tddPK, egrw: egrwPK, binding, params } = publicKey
  const { c1, c2, c3, proof: proofBytes } = ciphertext

  // Compute implicit rejection value first (constant-time protection)
  // This is returned if any validation fails
  const ciphertextBytes = serializeCiphertext(ciphertext)
  const implicitRejectSecret = shake256(
    hashWithDomain(DOMAIN_IMPLICIT_REJECT, hashConcat(seed, ciphertextBytes)),
    32,
  )

  let validDecapsulation = 1 // 1 = valid, 0 = invalid

  // Decrypt each fragment
  const share1 = slssDecrypt(c1, slssSK, params.slss)
  const share2 = tddDecrypt(c2, tddSK, params.tdd)
  const share3 = egrwDecrypt(c3, egrwSK, egrwPK, params.egrw)

  // Reconstruct ephemeral secret
  const recoveredSecret = secretReconstruct([share1, share2, share3])

  // Fujisaki-Okamoto re-encryption check
  // Re-encapsulate with recovered secret and verify ciphertext matches
  const reEncapsulated = encapsulateDeterministic(publicKey, recoveredSecret)
  const reEncapsulatedBytes = serializeCiphertext(reEncapsulated.ciphertext)

  // Constant-time comparison of ciphertexts
  if (!constantTimeEqual(ciphertextBytes, reEncapsulatedBytes)) {
    validDecapsulation = 0
  }

  // Verify NIZK proof (additional check)
  const proof = deserializeNIZKProof(proofBytes)
  const ciphertextHashes = [
    sha3_256(serializeSLSSCiphertext(c1)),
    sha3_256(serializeTDDCiphertext(c2)),
    sha3_256(serializeEGRWCiphertext(c3)),
  ]

  if (!verifyNIZKProof(proof, ciphertextHashes, recoveredSecret)) {
    validDecapsulation = 0
  }

  // Derive the correct shared secret
  const ciphertextHash = sha3_256(ciphertextBytes)
  const correctSecret = shake256(
    hashWithDomain(
      DOMAIN_SHARED_SECRET,
      hashConcat(recoveredSecret, ciphertextHash),
    ),
    32,
  )

  // Constant-time select between correct secret and implicit reject
  const result = constantTimeSelect(
    validDecapsulation,
    correctSecret,
    implicitRejectSecret,
  )

  // Zeroize sensitive intermediates
  zeroize(share1)
  zeroize(share2)
  zeroize(share3)
  zeroize(recoveredSecret)
  zeroize(correctSecret)
  zeroize(implicitRejectSecret)

  return result
}

// =============================================================================
// High-Level Encryption API
// =============================================================================

/**
 * Encrypt data using kMOSAIC KEM + AES-256-GCM
 *
 * Security:
 * - KEM-DEM composition (Key Encapsulation Mechanism + Data Encapsulation Mechanism)
 * - Provides authenticated encryption (confidentiality + integrity)
 * - Symmetric key is derived from the KEM shared secret
 * - Uses AES-256-GCM for high performance and security
 *
 * @param plaintext - Data to encrypt
 * @param publicKey - Recipient's public key
 * @returns Promise resolving to encrypted data (KEM ciphertext + AES ciphertext)
 */
export async function encrypt(
  plaintext: Uint8Array,
  publicKey: MOSAICPublicKey,
): Promise<Uint8Array> {
  // Use KEM to get shared secret
  const { sharedSecret, ciphertext } = await encapsulate(publicKey)

  // Derive encryption key and nonce from shared secret with domain separation
  const encKey = shake256(hashWithDomain(DOMAIN_ENC_KEY, sharedSecret), 32)
  const nonce = shake256(hashWithDomain(DOMAIN_NONCE, sharedSecret), 12)

  // Import for Web Crypto (Bun supports this)
  const key = await crypto.subtle.importKey(
    'raw',
    encKey.buffer.slice(
      encKey.byteOffset,
      encKey.byteOffset + encKey.byteLength,
    ) as ArrayBuffer,
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  )

  // Encrypt plaintext
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce.buffer.slice(
        nonce.byteOffset,
        nonce.byteOffset + nonce.byteLength,
      ) as ArrayBuffer,
    },
    key,
    plaintext.buffer.slice(
      plaintext.byteOffset,
      plaintext.byteOffset + plaintext.byteLength,
    ) as ArrayBuffer,
  )

  // Combine KEM ciphertext with symmetric ciphertext
  const kemCt = serializeCiphertext(ciphertext)
  const result = new Uint8Array(4 + kemCt.length + encrypted.byteLength)
  const view = new DataView(result.buffer)

  view.setUint32(0, kemCt.length, true)
  result.set(kemCt, 4)
  result.set(new Uint8Array(encrypted), 4 + kemCt.length)

  // Zeroize sensitive data
  zeroize(encKey)
  zeroize(sharedSecret)

  return result
}

/**
 * Decrypt data using kMOSAIC KEM + AES-256-GCM
 *
 * Security:
 * - Authenticated decryption prevents tampering
 * - Implicit rejection from KEM protects against oracle attacks
 * - Constant-time operations where critical
 *
 * @param encrypted - Encrypted data
 * @param secretKey - Recipient's secret key
 * @param publicKey - Recipient's public key
 * @returns Promise resolving to decrypted plaintext
 * @throws Error if decryption fails (authentication tag mismatch)
 */
export async function decrypt(
  encrypted: Uint8Array,
  secretKey: MOSAICSecretKey,
  publicKey: MOSAICPublicKey,
): Promise<Uint8Array> {
  if (encrypted.length < 4) {
    throw new Error('Invalid ciphertext: too short')
  }

  const view = new DataView(encrypted.buffer, encrypted.byteOffset)

  // Extract KEM ciphertext
  const kemCtLen = view.getUint32(0, true)
  if (4 + kemCtLen > encrypted.length) {
    throw new Error('Invalid ciphertext: KEM length exceeds data')
  }

  const kemCt = deserializeCiphertext(encrypted.slice(4, 4 + kemCtLen))
  const symCt = encrypted.slice(4 + kemCtLen)

  // Decapsulate to get shared secret
  const sharedSecret = await decapsulate(kemCt, secretKey, publicKey)

  // Derive decryption key with domain separation
  const decKey = shake256(hashWithDomain(DOMAIN_ENC_KEY, sharedSecret), 32)
  const nonce = shake256(hashWithDomain(DOMAIN_NONCE, sharedSecret), 12)

  // Import for Web Crypto
  const key = await crypto.subtle.importKey(
    'raw',
    decKey.buffer.slice(
      decKey.byteOffset,
      decKey.byteOffset + decKey.byteLength,
    ) as ArrayBuffer,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  )

  // Decrypt
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce.buffer.slice(
        nonce.byteOffset,
        nonce.byteOffset + nonce.byteLength,
      ) as ArrayBuffer,
    },
    key,
    symCt.buffer.slice(
      symCt.byteOffset,
      symCt.byteOffset + symCt.byteLength,
    ) as ArrayBuffer,
  )

  // Zeroize sensitive data
  zeroize(decKey)
  zeroize(sharedSecret)

  return new Uint8Array(decrypted)
}

// =============================================================================
// Analysis
// =============================================================================

/**
 * Analyze security properties of a public key
 *
 * Provides estimates of security bits against classical and quantum attacks.
 * Note: These are heuristic estimates based on current best known attacks.
 *
 * @param publicKey - Public key to analyze
 * @returns Security analysis report
 */
export function analyzePublicKey(publicKey: MOSAICPublicKey): SecurityAnalysis {
  const { params } = publicKey

  // Estimate security levels (simplified heuristics)
  const slssSecurity = Math.floor(
    (params.slss.n * Math.log2(params.slss.q)) / 10,
  )
  const tddSecurity = Math.floor(
    (params.tdd.n * params.tdd.n * Math.log2(params.tdd.q)) / 50,
  )
  const egrwSecurity = Math.floor(
    params.egrw.k * Math.log2(4) + Math.log2(params.egrw.p * params.egrw.p),
  )

  // Combined security (multiplicative for independent problems)
  const combined = slssSecurity + tddSecurity + egrwSecurity
  const quantum = Math.floor(combined / 2) // Grover-adjusted

  return {
    slss: {
      dimension: params.slss.n,
      sparsity: params.slss.w,
      estimatedSecurity: slssSecurity,
    },
    tdd: {
      tensorDim: params.tdd.n,
      rank: params.tdd.r,
      estimatedSecurity: tddSecurity,
    },
    egrw: {
      graphSize:
        params.egrw.p * params.egrw.p * (params.egrw.p * params.egrw.p - 1),
      walkLength: params.egrw.k,
      estimatedSecurity: egrwSecurity,
    },
    combined: {
      estimatedSecurity: combined,
      quantumSecurity: quantum,
    },
  }
}

// =============================================================================
// Serialization Helpers
// =============================================================================

/**
 * Serialize SLSS ciphertext component
 */
function serializeSLSSCiphertext(ct: MOSAICCiphertext['c1']): Uint8Array {
  const uBytes = new Uint8Array(ct.u.buffer, ct.u.byteOffset, ct.u.byteLength)
  const vBytes = new Uint8Array(ct.v.buffer, ct.v.byteOffset, ct.v.byteLength)

  const result = new Uint8Array(8 + uBytes.length + vBytes.length)
  const view = new DataView(result.buffer)

  view.setUint32(0, uBytes.length, true)
  result.set(uBytes, 4)
  view.setUint32(4 + uBytes.length, vBytes.length, true)
  result.set(vBytes, 8 + uBytes.length)

  return result
}

/**
 * Serialize TDD ciphertext component
 */
function serializeTDDCiphertext(ct: MOSAICCiphertext['c2']): Uint8Array {
  const dataBytes = new Uint8Array(
    ct.data.buffer,
    ct.data.byteOffset,
    ct.data.byteLength,
  )
  const result = new Uint8Array(4 + dataBytes.length)
  const view = new DataView(result.buffer)
  view.setUint32(0, dataBytes.length, true)
  result.set(dataBytes, 4)
  return result
}

/**
 * Serialize EGRW ciphertext component
 */
function serializeEGRWCiphertext(ct: MOSAICCiphertext['c3']): Uint8Array {
  const vertexBytes = sl2ToBytes(ct.vertex)
  const result = new Uint8Array(vertexBytes.length + ct.commitment.length)
  result.set(vertexBytes, 0)
  result.set(ct.commitment, vertexBytes.length)
  return result
}

/**
 * Serialize full MOSAIC ciphertext
 *
 * Format:
 * [c1_len] [c1_bytes] [c2_len] [c2_bytes] [c3_len] [c3_bytes] [proof_bytes]
 *
 * @param ct - Ciphertext object
 * @returns Serialized bytes
 */
export function serializeCiphertext(ct: MOSAICCiphertext): Uint8Array {
  const c1Bytes = serializeSLSSCiphertext(ct.c1)
  const c2Bytes = serializeTDDCiphertext(ct.c2)
  const c3Bytes = serializeEGRWCiphertext(ct.c3)

  const result = new Uint8Array(
    12 + c1Bytes.length + c2Bytes.length + c3Bytes.length + ct.proof.length,
  )
  const view = new DataView(result.buffer)

  let offset = 0
  view.setUint32(offset, c1Bytes.length, true)
  offset += 4
  result.set(c1Bytes, offset)
  offset += c1Bytes.length

  view.setUint32(offset, c2Bytes.length, true)
  offset += 4
  result.set(c2Bytes, offset)
  offset += c2Bytes.length

  view.setUint32(offset, c3Bytes.length, true)
  offset += 4
  result.set(c3Bytes, offset)
  offset += c3Bytes.length

  result.set(ct.proof, offset)

  return result
}

/**
 * Deserialize full MOSAIC ciphertext
 *
 * @param data - Serialized ciphertext bytes
 * @returns Ciphertext object
 */
export function deserializeCiphertext(data: Uint8Array): MOSAICCiphertext {
  const view = new DataView(data.buffer, data.byteOffset)
  let offset = 0

  // c1
  const c1Len = view.getUint32(offset, true)
  offset += 4
  const c1Start = offset
  const c1View = new DataView(data.buffer, data.byteOffset + c1Start)
  const uLen = c1View.getUint32(0, true)
  const u = new Int32Array(data.buffer, data.byteOffset + c1Start + 4, uLen / 4)
  const vLen = c1View.getUint32(4 + uLen, true)
  const v = new Int32Array(data.buffer, data.byteOffset + c1Start + 8 + uLen, vLen / 4)
  offset += c1Len

  // c2
  const c2Len = view.getUint32(offset, true)
  offset += 4
  const c2Start = offset
  const c2DataLen = new DataView(data.buffer, data.byteOffset + c2Start).getUint32(0, true)
  const tddData = new Int32Array(data.buffer, data.byteOffset + c2Start + 4, c2DataLen / 4)
  offset += c2Len

  // c3
  const c3Len = view.getUint32(offset, true)
  offset += 4
  const c3Start = offset
  const vertexView = new DataView(data.buffer, data.byteOffset + c3Start)
  const vertex = {
    a: vertexView.getInt32(0, true),
    b: vertexView.getInt32(4, true),
    c: vertexView.getInt32(8, true),
    d: vertexView.getInt32(12, true),
  }
  const commitment = data.slice(c3Start + 16, c3Start + c3Len)
  offset += c3Len

  // proof
  const proof = data.slice(offset)

  return {
    c1: { u, v },
    c2: { data: tddData },
    c3: { vertex, commitment },
    proof,
  }
}

export function serializePublicKey(pk: MOSAICPublicKey): Uint8Array {
  const slssBytes = slssSerializePublicKey(pk.slss)
  const tddBytes = tddSerializePublicKey(pk.tdd)
  const egrwBytes = egrwSerializePublicKey(pk.egrw)

  // Simplified - just concatenate with length prefixes
  const paramsJson = JSON.stringify(pk.params)
  const paramsBytes = new TextEncoder().encode(paramsJson)

  const totalLen =
    16 +
    slssBytes.length +
    tddBytes.length +
    egrwBytes.length +
    pk.binding.length +
    paramsBytes.length

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
  offset += pk.binding.length

  view.setUint32(offset, paramsBytes.length, true)
  offset += 4
  result.set(paramsBytes, offset)

  return result
}
