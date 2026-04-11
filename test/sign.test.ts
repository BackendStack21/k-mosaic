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
    expect(signature.response.length).toBe(128) // 64B t' + 64B z
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

  test('deserializeSignature rejects trailing bytes', async () => {
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Test message')
    const signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
    const serialized = serializeSignature(signature)
    const withTrailing = new Uint8Array(serialized.length + 1)
    withTrailing.set(serialized)
    withTrailing[withTrailing.length - 1] = 0x01

    expect(() => deserializeSignature(withTrailing)).toThrow('trailing bytes')
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

// =============================================================================
// Forgery Resistance Tests
// =============================================================================

describe('Forgery Resistance', () => {
  test('existential forgery attack is rejected: arbitrary commitment + any response', async () => {
    // This test validates the fix for Finding 1 (Critical): Existential Forgery.
    //
    // PRE-FIX attack: An attacker could pick any arbitrary commitment*, compute
    // challenge* = H_domain(commitment* || msgHash || pkHash), then use ANY 64-byte
    // response* — verify() would return true because it never checked the response.
    //
    // POST-FIX: verify() checks the algebraic relation A'·z - c·t' = w_check and
    // that H(w_check_bytes || tBytes || msgHash || binding) == commitment. Without
    // knowing s' (s.t. A'·s' = t'), an attacker cannot construct valid (tBytes, zBytes)
    // that satisfy this check for an arbitrary commitment.
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Victim message')

    // Get the public key hash and message hash as the attacker would
    const msgHash = new Uint8Array(32).fill(0xab) // attacker's chosen msgHash
    const forgedCommitment = secureRandomBytes(32) // random commitment

    // Compute the "correct" challenge for this forged commitment
    // (exactly what the old broken code allowed)
    // Attacker picks arbitrary 128-byte response
    const forgedResponse = secureRandomBytes(128)

    // Re-derive challenge as verifier would
    // (attacker cannot control pkHash — it's derived from the public key)
    const forgedChallenge = secureRandomBytes(32) // attacker can't compute real one without pk

    const forgedSig = {
      commitment: forgedCommitment,
      challenge: forgedChallenge,
      response: forgedResponse,
    }

    const valid = await verify(message, forgedSig, keyPair.publicKey)
    expect(valid).toBe(false)
  })

  test('existential forgery: correct challenge, wrong response fails algebraic check', async () => {
    // Attacker computes a valid challenge (using public information) but uses
    // a random response. The algebraic check in verify() must reject this.
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Victim message')

    // Attacker can compute msgHash and pkHash from public information
    // They pick an arbitrary commitment and derive the correct challenge
    const { sha3_256: h } = await import('../src/utils/shake.ts')
    const { hashConcat: hc, hashWithDomain: hd } =
      await import('../src/utils/shake.ts')
    const { serializePublicKey } = await import('../src/sign/index.ts')

    const msgHash = h(hc(message, keyPair.publicKey.binding))
    const pkHash = h(serializePublicKey(keyPair.publicKey))
    const forgedCommitment = secureRandomBytes(32)

    // Compute VALID challenge (the old scheme allowed this to pass)
    const challenge = hd(
      'kmosaic-sign-chal-v2',
      hc(forgedCommitment, msgHash, pkHash),
    )

    // Attacker uses random 128-byte response — no knowledge of s'
    const forgedResponse = secureRandomBytes(128)

    const forgedSig = {
      commitment: forgedCommitment,
      challenge,
      response: forgedResponse,
    }

    const valid = await verify(message, forgedSig, keyPair.publicKey)
    // MUST be false: response doesn't satisfy A'·z - c·t' == w_check for any valid w_check
    expect(valid).toBe(false)
  })

  test('existential forgery: 1000 random forgery attempts all rejected', async () => {
    // Statistical test: 1000 attempts with random responses should all fail.
    // If any succeed, the scheme is broken.
    const keyPair = await generateKeyPair('MOS-128')
    const message = new TextEncoder().encode('Target message')

    const { sha3_256: h } = await import('../src/utils/shake.ts')
    const { hashConcat: hc, hashWithDomain: hd } =
      await import('../src/utils/shake.ts')
    const { serializePublicKey } = await import('../src/sign/index.ts')

    const msgHash = h(hc(message, keyPair.publicKey.binding))
    const pkHash = h(serializePublicKey(keyPair.publicKey))

    let accepted = 0
    const ATTEMPTS = 1000

    for (let i = 0; i < ATTEMPTS; i++) {
      const forgedCommitment = secureRandomBytes(32)
      const challenge = hd(
        'kmosaic-sign-chal-v2',
        hc(forgedCommitment, msgHash, pkHash),
      )
      const forgedResponse = secureRandomBytes(128)

      const valid = await verify(
        message,
        { commitment: forgedCommitment, challenge, response: forgedResponse },
        keyPair.publicKey,
      )
      if (valid) accepted++
    }

    // Zero forgeries should be accepted
    expect(accepted).toBe(0)
  })
})
