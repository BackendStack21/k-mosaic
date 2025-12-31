import { describe, it, expect } from 'bun:test'
import {
  generateKeyPair,
  sign,
  verify,
  generateKeyPairFromSeed,
} from '../src/sign/index'
import { SecurityLevel } from '../src/types'
import { MOS_128 } from '../src/core/params'

describe('Signature Verification Edge Cases', () => {
  it('verifies with invalid signature structure returns false', async () => {
    const kp = await generateKeyPair(SecurityLevel.MOS_128)
    const msg = new Uint8Array([1, 2, 3])

    // Create an invalid signature with wrong commitment length
    const invalidSig = {
      commitment: new Uint8Array(16), // Wrong length (should be 32)
      challenge: new Uint8Array(32),
      response: new Uint8Array(64),
    }

    const valid = await verify(msg, invalidSig, kp.publicKey)
    expect(valid).toBe(false)
  })

  it('verifies with modified challenge returns false', async () => {
    const kp = await generateKeyPair(SecurityLevel.MOS_128)
    const msg = new Uint8Array([1, 2, 3])
    const sig = await sign(msg, kp.secretKey, kp.publicKey)

    // Modify challenge
    const modifiedSig = {
      ...sig,
      challenge: new Uint8Array(sig.challenge.map((b) => b ^ 0xff)),
    }

    const valid = await verify(msg, modifiedSig, kp.publicKey)
    expect(valid).toBe(false)
  })
})

describe('Signature Edge Cases', () => {
  it('generateKeyPairFromSeed throws for short seed', () => {
    expect(() => generateKeyPairFromSeed(MOS_128, new Uint8Array(31))).toThrow(
      'Seed must be at least 32 bytes',
    )
  })
})
