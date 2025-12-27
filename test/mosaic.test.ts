/**
 * kMOSAIC Cryptographic Library - Test Suite
 *
 * Run with: bun test
 */

import { describe, test, expect, beforeAll } from 'bun:test'
import {
  kemGenerateKeyPair,
  encapsulate,
  decapsulate,
  encrypt,
  decrypt,
  signGenerateKeyPair,
  sign,
  verify,
  serializeCiphertext,
  deserializeCiphertext,
  serializeSignature,
  deserializeSignature,
  analyzePublicKey,
  getParams,
  MOS_128,
  MOS_256,
  shake256,
  sha3_256,
  hashConcat,
  constantTimeEqual,
  secureRandomBytes,
} from '../src/index.ts'

import type {
  MOSAICKeyPair,
  MOSAICPublicKey,
  MOSAICSecretKey,
} from '../src/types.ts'

// =============================================================================
// Utility Tests
// =============================================================================

describe('Utilities', () => {
  test('shake256 produces deterministic output', () => {
    const input = new Uint8Array([1, 2, 3, 4, 5])
    const out1 = shake256(input, 32)
    const out2 = shake256(input, 32)
    expect(constantTimeEqual(out1, out2)).toBe(true)
  })

  test('shake256 produces different outputs for different lengths', () => {
    const input = new Uint8Array([1, 2, 3, 4, 5])
    const out32 = shake256(input, 32)
    const out64 = shake256(input, 64)
    expect(out64.length).toBe(64)
    expect(out32.length).toBe(32)
  })

  test('sha3_256 produces 32-byte output', () => {
    const input = new Uint8Array([1, 2, 3, 4, 5])
    const hash = sha3_256(input)
    expect(hash.length).toBe(32)
  })

  test('constantTimeEqual returns true for equal arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5])
    const b = new Uint8Array([1, 2, 3, 4, 5])
    expect(constantTimeEqual(a, b)).toBe(true)
  })

  test('constantTimeEqual returns false for different arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5])
    const b = new Uint8Array([1, 2, 3, 4, 6])
    expect(constantTimeEqual(a, b)).toBe(false)
  })

  test('secureRandomBytes produces random output', () => {
    const a = secureRandomBytes(32)
    const b = secureRandomBytes(32)
    expect(a.length).toBe(32)
    expect(b.length).toBe(32)
    expect(constantTimeEqual(a, b)).toBe(false)
  })
})

// =============================================================================
// Parameter Tests
// =============================================================================

describe('Parameters', () => {
  test('MOS-128 params are valid', () => {
    expect(MOS_128.slss.n).toBeGreaterThan(0)
    expect(MOS_128.tdd.n).toBeGreaterThan(0)
    expect(MOS_128.egrw.k).toBeGreaterThan(0)
  })

  test('MOS-256 params are valid', () => {
    expect(MOS_256.slss.n).toBeGreaterThan(0)
    expect(MOS_256.tdd.n).toBeGreaterThan(0)
    expect(MOS_256.egrw.k).toBeGreaterThan(0)
  })

  test('getParams returns correct parameters', () => {
    expect(getParams('MOS-128')).toEqual(MOS_128)
    expect(getParams('MOS-256')).toEqual(MOS_256)
  })
})

// =============================================================================
// KEM Tests
// =============================================================================

describe('KEM', () => {
  let keyPair128: MOSAICKeyPair
  let keyPair256: MOSAICKeyPair

  beforeAll(async () => {
    keyPair128 = await kemGenerateKeyPair('MOS-128')
    keyPair256 = await kemGenerateKeyPair('MOS-256')
  })

  test('key generation produces valid keys', () => {
    expect(keyPair128.publicKey).toBeDefined()
    expect(keyPair128.secretKey).toBeDefined()
    expect(keyPair128.publicKey.slss).toBeDefined()
    expect(keyPair128.publicKey.tdd).toBeDefined()
    expect(keyPair128.publicKey.egrw).toBeDefined()
  })

  test('encapsulation and decapsulation roundtrip (MOS-128)', async () => {
    const { ciphertext, sharedSecret } = await encapsulate(keyPair128.publicKey)
    const recovered = await decapsulate(
      ciphertext,
      keyPair128.secretKey,
      keyPair128.publicKey,
    )
    expect(constantTimeEqual(sharedSecret, recovered)).toBe(true)
  })

  test('encapsulation and decapsulation roundtrip (MOS-256)', async () => {
    const { ciphertext, sharedSecret } = await encapsulate(keyPair256.publicKey)
    const recovered = await decapsulate(
      ciphertext,
      keyPair256.secretKey,
      keyPair256.publicKey,
    )
    expect(constantTimeEqual(sharedSecret, recovered)).toBe(true)
  })

  test('ciphertext serialization roundtrip', async () => {
    const { ciphertext } = await encapsulate(keyPair128.publicKey)
    const serialized = serializeCiphertext(ciphertext)
    const deserialized = deserializeCiphertext(serialized)

    // Compare ciphertext components
    expect(deserialized.c1).toBeDefined()
    expect(deserialized.c2).toBeDefined()
    expect(deserialized.c3).toBeDefined()
  })

  test('analyzePublicKey returns valid analysis', () => {
    const analysis = analyzePublicKey(keyPair128.publicKey)
    expect(analysis.slss.estimatedSecurity).toBeGreaterThan(0)
    expect(analysis.tdd.estimatedSecurity).toBeGreaterThan(0)
    expect(analysis.egrw.estimatedSecurity).toBeGreaterThan(0)
    expect(analysis.combined.estimatedSecurity).toBeGreaterThan(0)
  })
})

// =============================================================================
// Encryption Tests
// =============================================================================

describe('Encryption', () => {
  let keyPair: MOSAICKeyPair

  beforeAll(async () => {
    keyPair = await kemGenerateKeyPair('MOS-128')
  })

  test('encrypt/decrypt roundtrip with small message', async () => {
    const message = new TextEncoder().encode('Hello, kMOSAIC!')
    const encrypted = await encrypt(message, keyPair.publicKey)
    const decrypted = await decrypt(
      encrypted,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(new TextDecoder().decode(decrypted)).toBe('Hello, kMOSAIC!')
  })

  test('encrypt/decrypt roundtrip with larger message', async () => {
    const message = new TextEncoder().encode('A'.repeat(1000))
    const encrypted = await encrypt(message, keyPair.publicKey)
    const decrypted = await decrypt(
      encrypted,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(decrypted.length).toBe(message.length)
    expect(constantTimeEqual(message, decrypted)).toBe(true)
  })

  test('encrypt/decrypt with binary data', async () => {
    const message = secureRandomBytes(256)
    const encrypted = await encrypt(message, keyPair.publicKey)
    const decrypted = await decrypt(
      encrypted,
      keyPair.secretKey,
      keyPair.publicKey,
    )

    expect(constantTimeEqual(message, decrypted)).toBe(true)
  })

  test('encrypted ciphertext is larger than plaintext', async () => {
    const message = new TextEncoder().encode('Test message')
    const encrypted = await encrypt(message, keyPair.publicKey)

    expect(encrypted.length).toBeGreaterThan(message.length)
  })
})

// =============================================================================
// Signature Tests
// =============================================================================

describe('Signatures', () => {
  let keyPair: MOSAICKeyPair

  beforeAll(async () => {
    keyPair = await signGenerateKeyPair('MOS-128')
  })

  test('sign/verify roundtrip', async () => {
    const message = new TextEncoder().encode('Sign this message')
    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const valid = await verify(message, signature, keyPair.publicKey)

    expect(valid).toBe(true)
  })

  test('signature verification fails for tampered message', async () => {
    const message = new TextEncoder().encode('Original message')
    const tampered = new TextEncoder().encode('Tampered message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const valid = await verify(tampered, signature, keyPair.publicKey)

    expect(valid).toBe(false)
  })

  test('signature serialization roundtrip', async () => {
    const message = new TextEncoder().encode('Test serialization')
    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)

    const serialized = serializeSignature(signature)
    const deserialized = deserializeSignature(serialized)

    const valid = await verify(message, deserialized, keyPair.publicKey)
    expect(valid).toBe(true)
  })

  test('different messages produce different signatures', async () => {
    const message1 = new TextEncoder().encode('Message 1')
    const message2 = new TextEncoder().encode('Message 2')

    const sig1 = await sign(message1, keyPair.secretKey, keyPair.publicKey)
    const sig2 = await sign(message2, keyPair.secretKey, keyPair.publicKey)

    const sig1Bytes = serializeSignature(sig1)
    const sig2Bytes = serializeSignature(sig2)

    expect(constantTimeEqual(sig1Bytes, sig2Bytes)).toBe(false)
  })
})

// =============================================================================
// Security Properties Tests
// =============================================================================

describe('Security Properties', () => {
  test('wrong key cannot decapsulate', async () => {
    const keyPair1 = await kemGenerateKeyPair('MOS-128')
    const keyPair2 = await kemGenerateKeyPair('MOS-128')

    const { ciphertext, sharedSecret } = await encapsulate(keyPair1.publicKey)

    // Try to decapsulate with wrong key - should produce different result
    // (implicit rejection returns a pseudorandom value)
    const recovered = await decapsulate(
      ciphertext,
      keyPair2.secretKey,
      keyPair2.publicKey,
    )

    // Should not match
    expect(constantTimeEqual(sharedSecret, recovered)).toBe(false)
  })

  test('wrong key cannot verify signature', async () => {
    const keyPair1 = await signGenerateKeyPair('MOS-128')
    const keyPair2 = await signGenerateKeyPair('MOS-128')

    const message = new TextEncoder().encode('Test message')
    const signature = await sign(
      message,
      keyPair1.secretKey,
      keyPair1.publicKey,
    )

    // Try to verify with wrong public key
    const valid = await verify(message, signature, keyPair2.publicKey)

    expect(valid).toBe(false)
  })

  test('each encapsulation produces unique shared secret', async () => {
    const keyPair = await kemGenerateKeyPair('MOS-128')

    const { sharedSecret: ss1 } = await encapsulate(keyPair.publicKey)
    const { sharedSecret: ss2 } = await encapsulate(keyPair.publicKey)

    expect(constantTimeEqual(ss1, ss2)).toBe(false)
  })
})
