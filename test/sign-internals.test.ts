import { describe, it, expect } from 'bun:test'
import {
  vecSub,
  checkNorm,
  combineWalks,
  generateKeyPair,
  sign,
  verify,
  generateKeyPairFromSeed,
} from '../src/sign/index'
import { SecurityLevel } from '../src/types'
import { MOS_128 } from '../src/core/params'

describe('Signature Internals', () => {
  it('vecSub subtracts vectors correctly', () => {
    const a = new Int32Array([5, 10, 15])
    const b = new Int32Array([2, 12, 5])
    const q = 20
    const result = vecSub(a, b, q)
    expect(result).toEqual(new Int32Array([3, 18, 10]))
  })

  it('checkNorm validates bounds correctly', () => {
    const q = 100
    const bound = 10

    // Within bounds
    expect(checkNorm(new Int32Array([0, 5, 10, -5, -10]), bound, q)).toBe(true)

    // Out of bounds (positive)
    expect(checkNorm(new Int32Array([11]), bound, q)).toBe(false)

    // Out of bounds (negative)
    expect(checkNorm(new Int32Array([-11]), bound, q)).toBe(false)

    // Modular wrapping
    // 90 is -10 mod 100, so it should be valid
    expect(checkNorm(new Int32Array([90]), bound, q)).toBe(true)

    // 89 is -11 mod 100, so it should be invalid
    expect(checkNorm(new Int32Array([89]), bound, q)).toBe(false)
  })

  it('combineWalks combines walks correctly', () => {
    const y = [0, 1, 2, 3]
    const secret = [1, 1, 1, 1]
    const challenge = 1
    const result = combineWalks(y, secret, challenge)
    // (0+1)%4=1, (1+1)%4=2, (2+1)%4=3, (3+1)%4=0
    expect(result).toEqual([1, 2, 3, 0])
  })

  it('combineWalks handles different lengths', () => {
    const y = [0, 1]
    const secret = [1, 1, 1, 1]
    const challenge = 1
    const result = combineWalks(y, secret, challenge)
    // y extended with 0s: [0, 1, 0, 0]
    // (0+1)%4=1, (1+1)%4=2, (0+1)%4=1, (0+1)%4=1
    expect(result).toEqual([1, 2, 1, 1])
  })
})

describe('Signature Verification Fallbacks', () => {
  it('verifies with missing commitments (fallback path)', async () => {
    const kp = await generateKeyPair(SecurityLevel.MOS_128)
    const msg = new Uint8Array([1, 2, 3])
    const sig = await sign(msg, kp.secretKey, kp.publicKey)

    // Remove commitments from signature
    const sigNoCommitments = {
      ...sig,
      z1: { ...sig.z1, commitment: new Uint8Array(0) },
      z2: { ...sig.z2, commitment: new Uint8Array(0) },
    }

    // Verification should fail because commitments are part of the challenge hash
    // and the fallback reconstruction won't match the original commitments used for signing
    // due to LWE error and hash-based commitment for TDD.
    // However, this exercises the fallback code paths.
    const valid = await verify(msg, sigNoCommitments, kp.publicKey)
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
