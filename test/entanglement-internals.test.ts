import { describe, it, expect } from 'bun:test'
import {
  verifyNIZKProof,
  deserializeNIZKProof,
} from '../src/entanglement/index'
import { sha3_256, hashConcat, hashWithDomain } from '../src/utils/shake'

const DOMAIN_NIZK = 'kmosaic-nizk-v1'

describe('verifyNIZKProof edge cases', () => {
  const validHashes = [
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
  ]
  const validMsgHash = new Uint8Array(32)
  const validCommitments = [
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
  ]

  // Compute valid challenge
  const challengeInput = hashConcat(
    hashWithDomain(`${DOMAIN_NIZK}-msg`, validMsgHash),
    ...validCommitments,
    ...validHashes,
  )
  const validChallenge = sha3_256(challengeInput)

  const validProof = {
    challenge: validChallenge,
    responses: [new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)],
    commitments: validCommitments,
  }

  it('rejects invalid commitment count', () => {
    const proof = { ...validProof, commitments: [new Uint8Array(32)] }
    expect(verifyNIZKProof(proof, validHashes, validMsgHash)).toBe(false)
  })

  it('rejects invalid response count', () => {
    const proof = { ...validProof, responses: [new Uint8Array(32)] }
    expect(verifyNIZKProof(proof, validHashes, validMsgHash)).toBe(false)
  })

  it('rejects invalid ciphertext hash count', () => {
    expect(
      verifyNIZKProof(validProof, [new Uint8Array(32)], validMsgHash),
    ).toBe(false)
  })

  it('rejects invalid challenge length', () => {
    const proof = { ...validProof, challenge: new Uint8Array(31) }
    expect(verifyNIZKProof(proof, validHashes, validMsgHash)).toBe(false)
  })

  it('rejects challenge mismatch', () => {
    const proof = { ...validProof, challenge: new Uint8Array(32).fill(1) }
    expect(verifyNIZKProof(proof, validHashes, validMsgHash)).toBe(false)
  })

  it('rejects short responses', () => {
    // Use valid challenge but short response
    const proof = {
      ...validProof,
      responses: [new Uint8Array(31), new Uint8Array(32), new Uint8Array(32)],
    }
    expect(verifyNIZKProof(proof, validHashes, validMsgHash)).toBe(false)
  })
})

describe('deserializeNIZKProof edge cases', () => {
  it('throws for short data', () => {
    expect(() => deserializeNIZKProof(new Uint8Array(7))).toThrow('too short')
  })

  it('throws for invalid part count', () => {
    const data = new Uint8Array(8)
    new DataView(data.buffer).setUint32(0, 6, true) // 6 parts
    expect(() => deserializeNIZKProof(data)).toThrow('expected 7 parts')
  })

  it('throws for truncated length read', () => {
    const data = new Uint8Array(8)
    new DataView(data.buffer).setUint32(0, 7, true) // 7 parts
    // But data ends immediately
    expect(() => deserializeNIZKProof(data)).toThrow('truncated')
  })

  it('throws for huge part length', () => {
    const data = new Uint8Array(12)
    const view = new DataView(data.buffer)
    view.setUint32(0, 7, true) // 7 parts
    view.setUint32(4, 2000000, true) // Huge length
    expect(() => deserializeNIZKProof(data)).toThrow('too large')
  })

  it('throws for truncated part data', () => {
    const data = new Uint8Array(12)
    const view = new DataView(data.buffer)
    view.setUint32(0, 7, true) // 7 parts
    view.setUint32(4, 100, true) // Length 100
    // But data ends
    expect(() => deserializeNIZKProof(data)).toThrow('truncated')
  })
})
