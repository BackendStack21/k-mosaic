/**
 * Unit tests for EGRW problem implementation
 */

import { describe, test, expect } from 'bun:test'
import {
  egrwKeyGen,
  egrwEncrypt,
  egrwDecrypt,
  egrwSerializePublicKey,
  egrwDeserializePublicKey,
  sl2ToBytes,
  bytesToSl2,
} from '../src/problems/egrw/index.ts'
import { MOS_128, MOS_256 } from '../src/core/params.ts'
import { secureRandomBytes } from '../src/utils/random.ts'
import { constantTimeEqual } from '../src/utils/constant-time.ts'

// =============================================================================
// Key Generation Tests
// =============================================================================

describe('egrwKeyGen', () => {
  test('generates key pair with correct structure', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)

    expect(keyPair.publicKey).toBeDefined()
    expect(keyPair.secretKey).toBeDefined()
    expect(keyPair.publicKey.vStart).toBeDefined()
    expect(keyPair.publicKey.vEnd).toBeDefined()
    expect(keyPair.secretKey.walk).toBeInstanceOf(Array)
  })

  test('generates SL2 elements with required fields', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)

    expect(typeof keyPair.publicKey.vStart.a).toBe('number')
    expect(typeof keyPair.publicKey.vStart.b).toBe('number')
    expect(typeof keyPair.publicKey.vStart.c).toBe('number')
    expect(typeof keyPair.publicKey.vStart.d).toBe('number')

    expect(typeof keyPair.publicKey.vEnd.a).toBe('number')
    expect(typeof keyPair.publicKey.vEnd.b).toBe('number')
    expect(typeof keyPair.publicKey.vEnd.c).toBe('number')
    expect(typeof keyPair.publicKey.vEnd.d).toBe('number')
  })

  test('generates walk of correct length for MOS-128', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)

    expect(keyPair.secretKey.walk.length).toBe(MOS_128.egrw.k)
  })

  test('generates walk of correct length for MOS-256', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_256.egrw, seed)

    expect(keyPair.secretKey.walk.length).toBe(MOS_256.egrw.k)
  })

  test('is deterministic for same seed', () => {
    const seed = secureRandomBytes(32)
    const keyPair1 = egrwKeyGen(MOS_128.egrw, seed)
    const keyPair2 = egrwKeyGen(MOS_128.egrw, seed)

    expect(keyPair1.publicKey.vStart.a).toBe(keyPair2.publicKey.vStart.a)
    expect(keyPair1.publicKey.vStart.b).toBe(keyPair2.publicKey.vStart.b)
    expect(keyPair1.publicKey.vEnd.a).toBe(keyPair2.publicKey.vEnd.a)
    expect(keyPair1.publicKey.vEnd.b).toBe(keyPair2.publicKey.vEnd.b)
    expect(keyPair1.secretKey.walk).toEqual(keyPair2.secretKey.walk)
  })

  test('produces different keys for different seeds', () => {
    const seed1 = secureRandomBytes(32)
    const seed2 = secureRandomBytes(32)
    const keyPair1 = egrwKeyGen(MOS_128.egrw, seed1)
    const keyPair2 = egrwKeyGen(MOS_128.egrw, seed2)

    // At least one component should differ
    const different =
      keyPair1.publicKey.vStart.a !== keyPair2.publicKey.vStart.a ||
      keyPair1.publicKey.vEnd.a !== keyPair2.publicKey.vEnd.a
    expect(different).toBe(true)
  })

  test('walk values are generator indices (0-3)', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)

    for (const step of keyPair.secretKey.walk) {
      expect(step).toBeGreaterThanOrEqual(0)
      expect(step).toBeLessThan(4)
    }
  })

  test('SL2 elements have determinant 1 (mod p)', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)
    const { p } = MOS_128.egrw

    const mod = (x: number, m: number) => ((x % m) + m) % m

    const detStart = mod(
      keyPair.publicKey.vStart.a * keyPair.publicKey.vStart.d -
        keyPair.publicKey.vStart.b * keyPair.publicKey.vStart.c,
      p,
    )
    expect(detStart).toBe(1)

    const detEnd = mod(
      keyPair.publicKey.vEnd.a * keyPair.publicKey.vEnd.d -
        keyPair.publicKey.vEnd.b * keyPair.publicKey.vEnd.c,
      p,
    )
    expect(detEnd).toBe(1)
  })
})

// =============================================================================
// Encryption/Decryption Tests
// =============================================================================

describe('egrwEncrypt/egrwDecrypt', () => {
  test('roundtrip recovers message', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)
    const message = secureRandomBytes(32)
    const randomness = secureRandomBytes(32)

    const ciphertext = egrwEncrypt(
      keyPair.publicKey,
      message,
      MOS_128.egrw,
      randomness,
    )
    const recovered = egrwDecrypt(
      ciphertext,
      keyPair.secretKey,
      keyPair.publicKey,
      MOS_128.egrw,
    )

    expect(constantTimeEqual(recovered, message)).toBe(true)
  })

  test('ciphertext has correct structure', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)
    const message = secureRandomBytes(32)
    const randomness = secureRandomBytes(32)

    const ciphertext = egrwEncrypt(
      keyPair.publicKey,
      message,
      MOS_128.egrw,
      randomness,
    )

    expect(ciphertext.vertex).toBeDefined()
    expect(ciphertext.commitment).toBeInstanceOf(Uint8Array)
  })

  test('is deterministic for same randomness', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)
    const message = secureRandomBytes(32)
    const randomness = secureRandomBytes(32)

    const ct1 = egrwEncrypt(
      keyPair.publicKey,
      message,
      MOS_128.egrw,
      randomness,
    )
    const ct2 = egrwEncrypt(
      keyPair.publicKey,
      message,
      MOS_128.egrw,
      randomness,
    )

    expect(ct1.vertex.a).toBe(ct2.vertex.a)
    expect(ct1.vertex.b).toBe(ct2.vertex.b)
    expect(constantTimeEqual(ct1.commitment, ct2.commitment)).toBe(true)
  })

  test('different randomness produces different ciphertext', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)
    const message = secureRandomBytes(32)
    const rand1 = secureRandomBytes(32)
    const rand2 = secureRandomBytes(32)

    const ct1 = egrwEncrypt(keyPair.publicKey, message, MOS_128.egrw, rand1)
    const ct2 = egrwEncrypt(keyPair.publicKey, message, MOS_128.egrw, rand2)

    expect(constantTimeEqual(ct1.commitment, ct2.commitment)).toBe(false)
  })

  test('works with MOS-256 parameters', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_256.egrw, seed)
    const message = secureRandomBytes(32)
    const randomness = secureRandomBytes(32)

    const ciphertext = egrwEncrypt(
      keyPair.publicKey,
      message,
      MOS_256.egrw,
      randomness,
    )
    const recovered = egrwDecrypt(
      ciphertext,
      keyPair.secretKey,
      keyPair.publicKey,
      MOS_256.egrw,
    )

    expect(constantTimeEqual(recovered, message)).toBe(true)
  })

  test('small messages work correctly', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)
    const message = new Uint8Array([1, 2, 3, 4, 5])
    const randomness = secureRandomBytes(32)

    const ciphertext = egrwEncrypt(
      keyPair.publicKey,
      message,
      MOS_128.egrw,
      randomness,
    )
    const recovered = egrwDecrypt(
      ciphertext,
      keyPair.secretKey,
      keyPair.publicKey,
      MOS_128.egrw,
    )

    // First 5 bytes should match
    expect(recovered[0]).toBe(1)
    expect(recovered[1]).toBe(2)
    expect(recovered[2]).toBe(3)
    expect(recovered[3]).toBe(4)
    expect(recovered[4]).toBe(5)
  })
})

// =============================================================================
// SL2 Element Serialization Tests
// =============================================================================

describe('sl2ToBytes/bytesToSl2', () => {
  test('roundtrip preserves SL2 element', () => {
    const element = { a: 100, b: 200, c: 300, d: 400 }
    const bytes = sl2ToBytes(element)
    const recovered = bytesToSl2(bytes)

    expect(recovered.a).toBe(element.a)
    expect(recovered.b).toBe(element.b)
    expect(recovered.c).toBe(element.c)
    expect(recovered.d).toBe(element.d)
  })

  test('produces 16 bytes', () => {
    const element = { a: 1, b: 2, c: 3, d: 4 }
    const bytes = sl2ToBytes(element)
    expect(bytes.length).toBe(16)
  })

  test('handles negative values', () => {
    const element = { a: -100, b: -200, c: 300, d: -400 }
    const bytes = sl2ToBytes(element)
    const recovered = bytesToSl2(bytes)

    expect(recovered.a).toBe(element.a)
    expect(recovered.b).toBe(element.b)
    expect(recovered.c).toBe(element.c)
    expect(recovered.d).toBe(element.d)
  })

  test('handles large values', () => {
    const element = { a: 1000000, b: 2000000, c: 3000000, d: 4000000 }
    const bytes = sl2ToBytes(element)
    const recovered = bytesToSl2(bytes)

    expect(recovered.a).toBe(element.a)
    expect(recovered.b).toBe(element.b)
    expect(recovered.c).toBe(element.c)
    expect(recovered.d).toBe(element.d)
  })
})

// =============================================================================
// Public Key Serialization Tests
// =============================================================================

describe('egrwSerializePublicKey/egrwDeserializePublicKey', () => {
  test('roundtrip preserves public key', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)

    const serialized = egrwSerializePublicKey(keyPair.publicKey)
    const deserialized = egrwDeserializePublicKey(serialized)

    expect(deserialized.vStart.a).toBe(keyPair.publicKey.vStart.a)
    expect(deserialized.vStart.b).toBe(keyPair.publicKey.vStart.b)
    expect(deserialized.vStart.c).toBe(keyPair.publicKey.vStart.c)
    expect(deserialized.vStart.d).toBe(keyPair.publicKey.vStart.d)

    expect(deserialized.vEnd.a).toBe(keyPair.publicKey.vEnd.a)
    expect(deserialized.vEnd.b).toBe(keyPair.publicKey.vEnd.b)
    expect(deserialized.vEnd.c).toBe(keyPair.publicKey.vEnd.c)
    expect(deserialized.vEnd.d).toBe(keyPair.publicKey.vEnd.d)
  })

  test('serialized form has correct size', () => {
    const seed = secureRandomBytes(32)
    const keyPair = egrwKeyGen(MOS_128.egrw, seed)

    const serialized = egrwSerializePublicKey(keyPair.publicKey)
    expect(serialized.length).toBe(32) // 16 bytes for vStart + 16 bytes for vEnd
  })

  test('different keys serialize differently', () => {
    const seed1 = secureRandomBytes(32)
    const seed2 = secureRandomBytes(32)
    const keyPair1 = egrwKeyGen(MOS_128.egrw, seed1)
    const keyPair2 = egrwKeyGen(MOS_128.egrw, seed2)

    const serialized1 = egrwSerializePublicKey(keyPair1.publicKey)
    const serialized2 = egrwSerializePublicKey(keyPair2.publicKey)

    expect(constantTimeEqual(serialized1, serialized2)).toBe(false)
  })
})
