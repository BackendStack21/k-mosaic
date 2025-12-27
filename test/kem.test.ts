/**
 * Unit tests for KEM (Key Encapsulation Mechanism)
 */

import { describe, test, expect } from 'bun:test'
import {
  generateKeyPair,
  generateKeyPairFromSeed,
  encapsulate,
  encapsulateDeterministic,
  decapsulate,
  encrypt,
  decrypt,
  serializePublicKey,
  serializeCiphertext,
  deserializeCiphertext,
  analyzePublicKey,
} from '../src/kem/index.ts'
import { getParams, MOS_128, MOS_256 } from '../src/core/params.ts'
import { secureRandomBytes } from '../src/utils/random.ts'
import { constantTimeEqual } from '../src/utils/constant-time.ts'
import { SecurityLevel } from '../src/types.ts'

// =============================================================================
// Key Generation Tests
// =============================================================================

describe('KEM generateKeyPair', () => {
  test('generates key pair with correct structure', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)

    expect(keyPair.publicKey).toBeDefined()
    expect(keyPair.secretKey).toBeDefined()
    expect(keyPair.publicKey.slss).toBeDefined()
    expect(keyPair.publicKey.tdd).toBeDefined()
    expect(keyPair.publicKey.egrw).toBeDefined()
    expect(keyPair.publicKey.binding).toBeDefined()
    expect(keyPair.publicKey.params).toBeDefined()
    expect(keyPair.secretKey.slss).toBeDefined()
    expect(keyPair.secretKey.tdd).toBeDefined()
    expect(keyPair.secretKey.egrw).toBeDefined()
    expect(keyPair.secretKey.seed).toBeDefined()
    expect(keyPair.secretKey.publicKeyHash).toBeDefined()
  })

  test('generates different keys each time', async () => {
    const kp1 = await generateKeyPair(SecurityLevel.MOS_128)
    const kp2 = await generateKeyPair(SecurityLevel.MOS_128)

    const pk1Bytes = serializePublicKey(kp1.publicKey)
    const pk2Bytes = serializePublicKey(kp2.publicKey)

    expect(constantTimeEqual(pk1Bytes, pk2Bytes)).toBe(false)
  })

  test('works with MOS-256 security level', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_256)

    expect(keyPair.publicKey.params.level).toBe(SecurityLevel.MOS_256)
    expect(keyPair.publicKey.slss.A.length).toBe(
      MOS_256.slss.m * MOS_256.slss.n,
    )
  })

  test('binding has correct length', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    expect(keyPair.publicKey.binding.length).toBe(32)
  })

  test('public key hash has correct length', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    expect(keyPair.secretKey.publicKeyHash.length).toBe(32)
  })
})

describe('KEM generateKeyPairFromSeed', () => {
  test('is deterministic for same seed', () => {
    const seed = secureRandomBytes(32)
    const kp1 = generateKeyPairFromSeed(MOS_128, seed)
    const kp2 = generateKeyPairFromSeed(MOS_128, seed)

    const pk1Bytes = serializePublicKey(kp1.publicKey)
    const pk2Bytes = serializePublicKey(kp2.publicKey)

    expect(constantTimeEqual(pk1Bytes, pk2Bytes)).toBe(true)
    expect(
      constantTimeEqual(
        kp1.secretKey.publicKeyHash,
        kp2.secretKey.publicKeyHash,
      ),
    ).toBe(true)
  })

  test('produces different keys for different seeds', () => {
    const seed1 = secureRandomBytes(32)
    const seed2 = secureRandomBytes(32)
    const kp1 = generateKeyPairFromSeed(MOS_128, seed1)
    const kp2 = generateKeyPairFromSeed(MOS_128, seed2)

    const pk1Bytes = serializePublicKey(kp1.publicKey)
    const pk2Bytes = serializePublicKey(kp2.publicKey)

    expect(constantTimeEqual(pk1Bytes, pk2Bytes)).toBe(false)
  })
})

// =============================================================================
// Encapsulation/Decapsulation Tests
// =============================================================================

describe('encapsulate/decapsulate', () => {
  test('roundtrip produces matching shared secrets', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const { sharedSecret, ciphertext } = await encapsulate(keyPair.publicKey)
    const recovered = await decapsulate(
      ciphertext,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(constantTimeEqual(sharedSecret, recovered)).toBe(true)
  })

  test('shared secret has 32 bytes', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const { sharedSecret } = await encapsulate(keyPair.publicKey)

    expect(sharedSecret.length).toBe(32)
  })

  test('each encapsulation produces unique shared secret', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const { sharedSecret: ss1 } = await encapsulate(keyPair.publicKey)
    const { sharedSecret: ss2 } = await encapsulate(keyPair.publicKey)

    expect(constantTimeEqual(ss1, ss2)).toBe(false)
  })

  test('works with MOS-256', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_256)
    const { sharedSecret, ciphertext } = await encapsulate(keyPair.publicKey)
    const recovered = await decapsulate(
      ciphertext,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(constantTimeEqual(sharedSecret, recovered)).toBe(true)
  })

  test('ciphertext has correct structure', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const { ciphertext } = await encapsulate(keyPair.publicKey)

    expect(ciphertext.c1).toBeDefined()
    expect(ciphertext.c2).toBeDefined()
    expect(ciphertext.c3).toBeDefined()
    expect(ciphertext.proof).toBeDefined()
    expect(ciphertext.c1.u).toBeInstanceOf(Int32Array)
    expect(ciphertext.c1.v).toBeInstanceOf(Int32Array)
    expect(ciphertext.c2.data).toBeInstanceOf(Int32Array)
    expect(ciphertext.proof).toBeInstanceOf(Uint8Array)
  })

  test('wrong key produces different shared secret', async () => {
    const keyPair1 = await generateKeyPair(SecurityLevel.MOS_128)
    const keyPair2 = await generateKeyPair(SecurityLevel.MOS_128)

    const { sharedSecret, ciphertext } = await encapsulate(keyPair1.publicKey)
    const wrongRecovered = await decapsulate(
      ciphertext,
      keyPair2.secretKey,
      keyPair2.publicKey,
    )

    expect(constantTimeEqual(sharedSecret, wrongRecovered)).toBe(false)
  })
})

describe('encapsulateDeterministic', () => {
  test('is deterministic for same ephemeral secret', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const ephemeralSecret = secureRandomBytes(32)

    const result1 = encapsulateDeterministic(keyPair.publicKey, ephemeralSecret)
    const result2 = encapsulateDeterministic(keyPair.publicKey, ephemeralSecret)

    expect(constantTimeEqual(result1.sharedSecret, result2.sharedSecret)).toBe(
      true,
    )
    expect(
      constantTimeEqual(
        serializeCiphertext(result1.ciphertext),
        serializeCiphertext(result2.ciphertext),
      ),
    ).toBe(true)
  })

  test('different ephemeral secrets produce different results', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const es1 = secureRandomBytes(32)
    const es2 = secureRandomBytes(32)

    const result1 = encapsulateDeterministic(keyPair.publicKey, es1)
    const result2 = encapsulateDeterministic(keyPair.publicKey, es2)

    expect(constantTimeEqual(result1.sharedSecret, result2.sharedSecret)).toBe(
      false,
    )
  })
})

// =============================================================================
// Encryption/Decryption Tests
// =============================================================================

describe('encrypt/decrypt', () => {
  test('roundtrip with small message', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const plaintext = new TextEncoder().encode('Hello, World!')

    const encrypted = await encrypt(plaintext, keyPair.publicKey)
    const decrypted = await decrypt(
      encrypted,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(new TextDecoder().decode(decrypted)).toBe('Hello, World!')
  })

  test('roundtrip with larger message', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const plaintext = new Uint8Array(1000)
    for (let i = 0; i < 1000; i++) {
      plaintext[i] = i % 256
    }

    const encrypted = await encrypt(plaintext, keyPair.publicKey)
    const decrypted = await decrypt(
      encrypted,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(constantTimeEqual(decrypted, plaintext)).toBe(true)
  })

  test('roundtrip with binary data', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const plaintext = secureRandomBytes(256)

    const encrypted = await encrypt(plaintext, keyPair.publicKey)
    const decrypted = await decrypt(
      encrypted,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(constantTimeEqual(decrypted, plaintext)).toBe(true)
  })

  test('encrypted ciphertext is larger than plaintext', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const plaintext = new Uint8Array(100)

    const encrypted = await encrypt(plaintext, keyPair.publicKey)

    expect(encrypted.length).toBeGreaterThan(plaintext.length)
  })

  test('each encryption produces different ciphertext', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const plaintext = new TextEncoder().encode('Same message')

    const encrypted1 = await encrypt(plaintext, keyPair.publicKey)
    const encrypted2 = await encrypt(plaintext, keyPair.publicKey)

    expect(constantTimeEqual(encrypted1, encrypted2)).toBe(false)
  })

  test('wrong key fails to decrypt', async () => {
    const keyPair1 = await generateKeyPair(SecurityLevel.MOS_128)
    const keyPair2 = await generateKeyPair(SecurityLevel.MOS_128)
    const plaintext = new TextEncoder().encode('Secret message')

    const encrypted = await encrypt(plaintext, keyPair1.publicKey)

    // This should throw because GCM authentication will fail
    await expect(
      decrypt(encrypted, keyPair2.secretKey, keyPair2.publicKey),
    ).rejects.toThrow()
  })

  test('works with empty message', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const plaintext = new Uint8Array(0)

    const encrypted = await encrypt(plaintext, keyPair.publicKey)
    const decrypted = await decrypt(
      encrypted,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(decrypted.length).toBe(0)
  })
})

// =============================================================================
// Serialization Tests
// =============================================================================

describe('serializeCiphertext/deserializeCiphertext', () => {
  test('roundtrip preserves ciphertext', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const { ciphertext } = await encapsulate(keyPair.publicKey)

    const serialized = serializeCiphertext(ciphertext)
    const deserialized = deserializeCiphertext(serialized)

    // Verify structure is preserved
    expect(deserialized.c1.u.length).toBe(ciphertext.c1.u.length)
    expect(deserialized.c1.v.length).toBe(ciphertext.c1.v.length)
    expect(deserialized.c2.data.length).toBe(ciphertext.c2.data.length)
    expect(deserialized.proof.length).toBe(ciphertext.proof.length)
  })

  test('deserialized ciphertext can be decapsulated', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const { sharedSecret, ciphertext } = await encapsulate(keyPair.publicKey)

    const serialized = serializeCiphertext(ciphertext)
    const deserialized = deserializeCiphertext(serialized)
    const recovered = await decapsulate(
      deserialized,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(constantTimeEqual(sharedSecret, recovered)).toBe(true)
  })
})

describe('serializePublicKey', () => {
  test('produces consistent output for same key', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const serialized1 = serializePublicKey(keyPair.publicKey)
    const serialized2 = serializePublicKey(keyPair.publicKey)

    expect(constantTimeEqual(serialized1, serialized2)).toBe(true)
  })

  test('produces different output for different keys', async () => {
    const kp1 = await generateKeyPair(SecurityLevel.MOS_128)
    const kp2 = await generateKeyPair(SecurityLevel.MOS_128)

    const serialized1 = serializePublicKey(kp1.publicKey)
    const serialized2 = serializePublicKey(kp2.publicKey)

    expect(constantTimeEqual(serialized1, serialized2)).toBe(false)
  })
})

// =============================================================================
// Security Analysis Tests
// =============================================================================

describe('analyzePublicKey', () => {
  test('returns valid analysis structure', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const analysis = analyzePublicKey(keyPair.publicKey)

    expect(analysis.slss).toBeDefined()
    expect(analysis.slss.dimension).toBeDefined()
    expect(analysis.slss.sparsity).toBeDefined()
    expect(analysis.slss.estimatedSecurity).toBeDefined()

    expect(analysis.tdd).toBeDefined()
    expect(analysis.tdd.tensorDim).toBeDefined()
    expect(analysis.tdd.rank).toBeDefined()
    expect(analysis.tdd.estimatedSecurity).toBeDefined()

    expect(analysis.egrw).toBeDefined()
    expect(analysis.egrw.graphSize).toBeDefined()
    expect(analysis.egrw.walkLength).toBeDefined()
    expect(analysis.egrw.estimatedSecurity).toBeDefined()

    expect(analysis.combined).toBeDefined()
    expect(analysis.combined.estimatedSecurity).toBeDefined()
    expect(analysis.combined.quantumSecurity).toBeDefined()
  })

  test('MOS-256 has higher security than MOS-128', async () => {
    const kp128 = await generateKeyPair(SecurityLevel.MOS_128)
    const kp256 = await generateKeyPair(SecurityLevel.MOS_256)

    const analysis128 = analyzePublicKey(kp128.publicKey)
    const analysis256 = analyzePublicKey(kp256.publicKey)

    expect(analysis256.combined.estimatedSecurity).toBeGreaterThan(
      analysis128.combined.estimatedSecurity,
    )
    expect(analysis256.combined.quantumSecurity).toBeGreaterThan(
      analysis128.combined.quantumSecurity,
    )
  })

  test('security estimates are positive', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const analysis = analyzePublicKey(keyPair.publicKey)

    expect(analysis.slss.estimatedSecurity).toBeGreaterThan(0)
    expect(analysis.tdd.estimatedSecurity).toBeGreaterThan(0)
    expect(analysis.egrw.estimatedSecurity).toBeGreaterThan(0)
    expect(analysis.combined.estimatedSecurity).toBeGreaterThan(0)
    expect(analysis.combined.quantumSecurity).toBeGreaterThan(0)
  })

  test('reflects correct parameter values', async () => {
    const keyPair = await generateKeyPair(SecurityLevel.MOS_128)
    const analysis = analyzePublicKey(keyPair.publicKey)

    expect(analysis.slss.dimension).toBe(MOS_128.slss.n)
    expect(analysis.slss.sparsity).toBe(MOS_128.slss.w)
    expect(analysis.tdd.tensorDim).toBe(MOS_128.tdd.n)
    expect(analysis.tdd.rank).toBe(MOS_128.tdd.r)
    expect(analysis.egrw.walkLength).toBe(MOS_128.egrw.k)
  })
})
