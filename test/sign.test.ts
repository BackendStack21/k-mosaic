/**
 * Unit tests for Digital Signatures
 */

import { describe, test, expect } from 'bun:test'
import {
  generateKeyPair,
  generateKeyPairFromSeed,
  sign,
  verify,
  serializeSignature,
  deserializeSignature,
} from '../src/sign/index.ts'
import { getParams, MOS_128, MOS_256 } from '../src/core/params.ts'
import { secureRandomBytes } from '../src/utils/random.ts'
import { constantTimeEqual } from '../src/utils/constant-time.ts'

// =============================================================================
// Key Generation Tests
// =============================================================================

describe('Signature generateKeyPair', () => {
  test('generates key pair with correct structure', async () => {
    const keyPair = await generateKeyPair('MOS-128')

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
    const kp1 = await generateKeyPair('MOS-128')
    const kp2 = await generateKeyPair('MOS-128')

    expect(
      constantTimeEqual(
        kp1.secretKey.publicKeyHash,
        kp2.secretKey.publicKeyHash,
      ),
    ).toBe(false)
  })

  test('works with MOS-256 security level', async () => {
    const keyPair = await generateKeyPair('MOS-256')

    expect(keyPair.publicKey.params.level).toBe('MOS-256')
    expect(keyPair.publicKey.slss.A.length).toBe(
      MOS_256.slss.m * MOS_256.slss.n,
    )
  })

  test('binding has correct length', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    expect(keyPair.publicKey.binding.length).toBe(32)
  })

  test('public key hash has correct length', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    expect(keyPair.secretKey.publicKeyHash.length).toBe(32)
  })
})

describe('Signature generateKeyPairFromSeed', () => {
  test('is deterministic for same seed', () => {
    const seed = secureRandomBytes(32)
    const kp1 = generateKeyPairFromSeed(MOS_128, seed)
    const kp2 = generateKeyPairFromSeed(MOS_128, seed)

    expect(
      constantTimeEqual(
        kp1.secretKey.publicKeyHash,
        kp2.secretKey.publicKeyHash,
      ),
    ).toBe(true)
    expect(
      constantTimeEqual(kp1.publicKey.binding, kp2.publicKey.binding),
    ).toBe(true)
  })

  test('produces different keys for different seeds', () => {
    const seed1 = secureRandomBytes(32)
    const seed2 = secureRandomBytes(32)
    const kp1 = generateKeyPairFromSeed(MOS_128, seed1)
    const kp2 = generateKeyPairFromSeed(MOS_128, seed2)

    expect(
      constantTimeEqual(
        kp1.secretKey.publicKeyHash,
        kp2.secretKey.publicKeyHash,
      ),
    ).toBe(false)
  })
})

// =============================================================================
// Sign/Verify Tests
// =============================================================================

describe('sign/verify', () => {
  test('sign/verify roundtrip', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const valid = await verify(message, signature, keyPair.publicKey)

    expect(valid).toBe(true)
  })

  test('signature has correct structure', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)

    expect(signature.commitment).toBeInstanceOf(Uint8Array)
    expect(signature.commitment.length).toBe(32)
    expect(signature.challenge).toBeInstanceOf(Uint8Array)
    expect(signature.challenge.length).toBe(32)
    expect(signature.response).toBeInstanceOf(Uint8Array)
    expect(signature.response.length).toBe(64)
  })

  test('verification fails for tampered message', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Original message')
    const tampered = new TextEncoder().encode('Tampered message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const valid = await verify(tampered, signature, keyPair.publicKey)

    expect(valid).toBe(false)
  })

  test('verification fails with wrong public key', async () => {
    const keyPair1 = await generateKeyPair('MOS-128')
    const keyPair2 = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')

    const signature = await sign(
      message,
      keyPair1.secretKey,
      keyPair1.publicKey,
    )
    const valid = await verify(message, signature, keyPair2.publicKey)

    expect(valid).toBe(false)
  })

  test('different messages produce different signatures', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message1 = new TextEncoder().encode('Message 1')
    const message2 = new TextEncoder().encode('Message 2')

    const sig1 = await sign(message1, keyPair.secretKey, keyPair.publicKey)
    const sig2 = await sign(message2, keyPair.secretKey, keyPair.publicKey)

    expect(constantTimeEqual(sig1.challenge, sig2.challenge)).toBe(false)
  })

  test('same message produces verifiable signatures', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Same message')

    const sig1 = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const sig2 = await sign(message, keyPair.secretKey, keyPair.publicKey)

    // Both signatures should verify (randomized signing)
    expect(await verify(message, sig1, keyPair.publicKey)).toBe(true)
    expect(await verify(message, sig2, keyPair.publicKey)).toBe(true)
  })

  test('works with MOS-256 parameters', async () => {
    const keyPair = await generateKeyPair('MOS-256')
    const message = new TextEncoder().encode('Test with MOS-256')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const valid = await verify(message, signature, keyPair.publicKey)

    expect(valid).toBe(true)
  })

  test('works with empty message', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new Uint8Array(0)

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const valid = await verify(message, signature, keyPair.publicKey)

    expect(valid).toBe(true)
  })

  test('works with binary data', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = secureRandomBytes(256)

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const valid = await verify(message, signature, keyPair.publicKey)

    expect(valid).toBe(true)
  })

  test('works with large message', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new Uint8Array(10000)
    for (let i = 0; i < message.length; i++) {
      message[i] = i % 256
    }

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const valid = await verify(message, signature, keyPair.publicKey)

    expect(valid).toBe(true)
  })
})

// =============================================================================
// Serialization Tests
// =============================================================================

describe('serializeSignature/deserializeSignature', () => {
  test('roundtrip preserves signature', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const serialized = serializeSignature(signature)
    const deserialized = deserializeSignature(serialized)

    expect(
      constantTimeEqual(deserialized.commitment, signature.commitment),
    ).toBe(true)
    expect(constantTimeEqual(deserialized.challenge, signature.challenge)).toBe(
      true,
    )
    expect(constantTimeEqual(deserialized.response, signature.response)).toBe(
      true,
    )
  })

  test('deserialized signature verifies correctly', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const serialized = serializeSignature(signature)
    const deserialized = deserializeSignature(serialized)

    const valid = await verify(message, deserialized, keyPair.publicKey)
    expect(valid).toBe(true)
  })

  test('serialized signature has reasonable size', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const serialized = serializeSignature(signature)

    // Should be larger than just the challenge
    expect(serialized.length).toBeGreaterThan(32)
  })

  test('different messages serialize differently', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message1 = new TextEncoder().encode('Test message 1')
    const message2 = new TextEncoder().encode('Test message 2')

    const sig1 = await sign(message1, keyPair.secretKey, keyPair.publicKey)
    const sig2 = await sign(message2, keyPair.secretKey, keyPair.publicKey)

    const serialized1 = serializeSignature(sig1)
    const serialized2 = serializeSignature(sig2)

    expect(constantTimeEqual(serialized1, serialized2)).toBe(false)
  })
})

// =============================================================================
// Security Tests
// =============================================================================

describe('Signature Security', () => {
  test('modifying challenge invalidates signature', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)

    // Modify the challenge
    const modifiedSig = {
      ...signature,
      challenge: secureRandomBytes(32),
    }

    const valid = await verify(message, modifiedSig, keyPair.publicKey)
    expect(valid).toBe(false)
  })

  test('modifying commitment invalidates signature', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')

    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)

    // Modify the commitment (which is used for challenge computation)
    const modifiedCommitment = new Uint8Array(signature.commitment)
    modifiedCommitment[0] = modifiedCommitment[0] ^ 0xff
    const modifiedSig = {
      ...signature,
      commitment: modifiedCommitment,
    }

    const valid = await verify(message, modifiedSig, keyPair.publicKey)
    expect(valid).toBe(false)
  })

  test('signature cannot be reused for different message', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message1 = new TextEncoder().encode('Message 1')
    const message2 = new TextEncoder().encode('Message 2')

    const signature = await sign(message1, keyPair.secretKey, keyPair.publicKey)

    // Try to use signature for different message
    const validForOriginal = await verify(
      message1,
      signature,
      keyPair.publicKey,
    )
    const validForOther = await verify(message2, signature, keyPair.publicKey)

    expect(validForOriginal).toBe(true)
    expect(validForOther).toBe(false)
  })
})
