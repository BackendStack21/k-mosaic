/**
 * Unit tests for entanglement layer
 */

import { describe, test, expect } from 'bun:test'
import {
  secretShare,
  secretReconstruct,
  secretShareDeterministic,
  computeBinding,
  createCommitment,
  verifyCommitment,
  generateNIZKProof,
  verifyNIZKProof,
  serializeNIZKProof,
  deserializeNIZKProof,
} from '../src/entanglement/index.ts'
import { constantTimeEqual } from '../src/utils/constant-time.ts'
import { secureRandomBytes } from '../src/utils/random.ts'
import { sha3_256 } from '../src/utils/shake.ts'

// =============================================================================
// Secret Sharing Tests
// =============================================================================

describe('secretShare', () => {
  test('splits secret into n shares', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5])
    const shares = secretShare(secret, 3)
    expect(shares.length).toBe(3)
    for (const share of shares) {
      expect(share.length).toBe(secret.length)
    }
  })

  test('throws for n < 2', () => {
    const secret = new Uint8Array([1, 2, 3])
    expect(() => secretShare(secret, 1)).toThrow()
    expect(() => secretShare(secret, 0)).toThrow()
  })

  test('produces different shares each time', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5])
    const shares1 = secretShare(secret, 3)
    const shares2 = secretShare(secret, 3)
    // At least one share should be different (random)
    let allSame = true
    for (let i = 0; i < 3; i++) {
      if (!constantTimeEqual(shares1[i], shares2[i])) {
        allSame = false
        break
      }
    }
    expect(allSame).toBe(false)
  })

  test('XOR of all shares equals secret', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5])
    const shares = secretShare(secret, 3)
    const xored = new Uint8Array(secret.length)
    for (let i = 0; i < secret.length; i++) {
      xored[i] = shares[0][i] ^ shares[1][i] ^ shares[2][i]
    }
    expect(constantTimeEqual(xored, secret)).toBe(true)
  })
})

describe('secretReconstruct', () => {
  test('reconstructs secret from all shares', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    const shares = secretShare(secret, 3)
    const recovered = secretReconstruct(shares)
    expect(constantTimeEqual(recovered, secret)).toBe(true)
  })

  test('works with 2 shares', () => {
    const secret = new Uint8Array([10, 20, 30, 40])
    const shares = secretShare(secret, 2)
    const recovered = secretReconstruct(shares)
    expect(constantTimeEqual(recovered, secret)).toBe(true)
  })

  test('works with 5 shares', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5])
    const shares = secretShare(secret, 5)
    const recovered = secretReconstruct(shares)
    expect(constantTimeEqual(recovered, secret)).toBe(true)
  })

  test('throws for fewer than 2 shares', () => {
    const share = new Uint8Array([1, 2, 3])
    expect(() => secretReconstruct([share])).toThrow()
    expect(() => secretReconstruct([])).toThrow()
  })

  test('throws for mismatched share lengths', () => {
    const share1 = new Uint8Array([1, 2, 3])
    const share2 = new Uint8Array([1, 2, 3, 4])
    expect(() => secretReconstruct([share1, share2])).toThrow()
  })

  test('fails to reconstruct with missing shares', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5])
    const shares = secretShare(secret, 3)
    const recovered = secretReconstruct([shares[0], shares[1]]) // Missing one
    expect(constantTimeEqual(recovered, secret)).toBe(false)
  })
})

describe('secretShareDeterministic', () => {
  test('produces deterministic shares for same seed', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5])
    const seed = new Uint8Array([
      10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
    ])
    const shares1 = secretShareDeterministic(secret, 3, seed)
    const shares2 = secretShareDeterministic(secret, 3, seed)
    for (let i = 0; i < 3; i++) {
      expect(constantTimeEqual(shares1[i], shares2[i])).toBe(true)
    }
  })

  test('produces different shares for different seeds', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5])
    const seed1 = new Uint8Array([
      10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
    ])
    const seed2 = new Uint8Array([
      50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200,
    ])
    const shares1 = secretShareDeterministic(secret, 3, seed1)
    const shares2 = secretShareDeterministic(secret, 3, seed2)
    // At least one share should differ
    let allSame = true
    for (let i = 0; i < 3; i++) {
      if (!constantTimeEqual(shares1[i], shares2[i])) {
        allSame = false
        break
      }
    }
    expect(allSame).toBe(false)
  })

  test('reconstructs correctly', () => {
    const secret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
    const seed = new Uint8Array([
      10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
    ])
    const shares = secretShareDeterministic(secret, 3, seed)
    const recovered = secretReconstruct(shares)
    expect(constantTimeEqual(recovered, secret)).toBe(true)
  })
})

// =============================================================================
// Binding Commitment Tests
// =============================================================================

describe('createCommitment', () => {
  test('produces commitment and opening', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5])
    const { commitment, opening } = createCommitment(data)
    expect(commitment.length).toBe(32)
    expect(opening.length).toBe(32)
  })

  test('produces different commitments for same data', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5])
    const c1 = createCommitment(data)
    const c2 = createCommitment(data)
    // Different openings lead to different commitments
    expect(constantTimeEqual(c1.commitment, c2.commitment)).toBe(false)
  })
})

describe('verifyCommitment', () => {
  test('verifies valid commitment', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5])
    const { commitment, opening } = createCommitment(data)
    expect(verifyCommitment(data, commitment, opening)).toBe(true)
  })

  test('rejects commitment for wrong data', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5])
    const wrongData = new Uint8Array([1, 2, 3, 4, 6])
    const { commitment, opening } = createCommitment(data)
    expect(verifyCommitment(wrongData, commitment, opening)).toBe(false)
  })

  test('rejects commitment with wrong opening', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5])
    const { commitment } = createCommitment(data)
    const wrongOpening = secureRandomBytes(32)
    expect(verifyCommitment(data, commitment, wrongOpening)).toBe(false)
  })
})

describe('computeBinding', () => {
  test('produces 32-byte binding hash', () => {
    const slssData = new Uint8Array([1, 2, 3])
    const tddData = new Uint8Array([4, 5, 6])
    const egrwData = new Uint8Array([7, 8, 9])
    const binding = computeBinding(slssData, tddData, egrwData)
    expect(binding.length).toBe(32)
  })

  test('is deterministic', () => {
    const slssData = new Uint8Array([1, 2, 3])
    const tddData = new Uint8Array([4, 5, 6])
    const egrwData = new Uint8Array([7, 8, 9])
    const binding1 = computeBinding(slssData, tddData, egrwData)
    const binding2 = computeBinding(slssData, tddData, egrwData)
    expect(constantTimeEqual(binding1, binding2)).toBe(true)
  })

  test('produces different binding for different inputs', () => {
    const slssData = new Uint8Array([1, 2, 3])
    const tddData = new Uint8Array([4, 5, 6])
    const egrwData1 = new Uint8Array([7, 8, 9])
    const egrwData2 = new Uint8Array([7, 8, 10])
    const binding1 = computeBinding(slssData, tddData, egrwData1)
    const binding2 = computeBinding(slssData, tddData, egrwData2)
    expect(constantTimeEqual(binding1, binding2)).toBe(false)
  })

  test('order matters', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([4, 5, 6])
    const c = new Uint8Array([7, 8, 9])
    const binding1 = computeBinding(a, b, c)
    const binding2 = computeBinding(b, a, c)
    expect(constantTimeEqual(binding1, binding2)).toBe(false)
  })
})

// =============================================================================
// NIZK Proof Tests
// =============================================================================

describe('NIZK Proofs', () => {
  test('generateNIZKProof produces valid structure', () => {
    const message = new Uint8Array([1, 2, 3, 4, 5])
    const shares = [
      new Uint8Array([10, 20, 30]),
      new Uint8Array([40, 50, 60]),
      new Uint8Array([70, 80, 90]),
    ]
    const ciphertextHashes = [
      sha3_256(new Uint8Array([1])),
      sha3_256(new Uint8Array([2])),
      sha3_256(new Uint8Array([3])),
    ]
    const randomness = secureRandomBytes(32)

    const proof = generateNIZKProof(
      message,
      shares,
      ciphertextHashes,
      randomness,
    )

    expect(proof.challenge.length).toBe(32)
    expect(proof.commitments.length).toBe(3)
    expect(proof.responses.length).toBe(3)
  })

  test('verifyNIZKProof accepts valid proof', () => {
    const message = new Uint8Array([1, 2, 3, 4, 5])
    const shares = [
      new Uint8Array([10, 20, 30]),
      new Uint8Array([40, 50, 60]),
      new Uint8Array([70, 80, 90]),
    ]
    const ciphertextHashes = [
      sha3_256(new Uint8Array([1])),
      sha3_256(new Uint8Array([2])),
      sha3_256(new Uint8Array([3])),
    ]
    const randomness = secureRandomBytes(32)

    const proof = generateNIZKProof(
      message,
      shares,
      ciphertextHashes,
      randomness,
    )
    // Note: generateNIZKProof uses raw message bytes in challenge, so verify needs raw message too
    // The parameter is named messageHash but actually expects raw message for consistency
    const valid = verifyNIZKProof(proof, ciphertextHashes, message)
    expect(valid).toBe(true)
  })

  test('verifyNIZKProof rejects proof with wrong ciphertext hashes', () => {
    const message = new Uint8Array([1, 2, 3, 4, 5])
    const shares = [
      new Uint8Array([10, 20, 30]),
      new Uint8Array([40, 50, 60]),
      new Uint8Array([70, 80, 90]),
    ]
    const ciphertextHashes = [
      sha3_256(new Uint8Array([1])),
      sha3_256(new Uint8Array([2])),
      sha3_256(new Uint8Array([3])),
    ]
    const wrongHashes = [
      sha3_256(new Uint8Array([9])),
      sha3_256(new Uint8Array([8])),
      sha3_256(new Uint8Array([7])),
    ]
    const randomness = secureRandomBytes(32)

    const proof = generateNIZKProof(
      message,
      shares,
      ciphertextHashes,
      randomness,
    )
    const messageHash = sha3_256(message)

    const valid = verifyNIZKProof(proof, wrongHashes, messageHash)
    expect(valid).toBe(false)
  })

  test('verifyNIZKProof rejects proof with wrong message hash', () => {
    const message = new Uint8Array([1, 2, 3, 4, 5])
    const shares = [
      new Uint8Array([10, 20, 30]),
      new Uint8Array([40, 50, 60]),
      new Uint8Array([70, 80, 90]),
    ]
    const ciphertextHashes = [
      sha3_256(new Uint8Array([1])),
      sha3_256(new Uint8Array([2])),
      sha3_256(new Uint8Array([3])),
    ]
    const randomness = secureRandomBytes(32)

    const proof = generateNIZKProof(
      message,
      shares,
      ciphertextHashes,
      randomness,
    )
    const wrongMessageHash = sha3_256(new Uint8Array([9, 9, 9]))

    const valid = verifyNIZKProof(proof, ciphertextHashes, wrongMessageHash)
    expect(valid).toBe(false)
  })

  test('verifyNIZKProof rejects proof with wrong number of commitments', () => {
    const proof = {
      challenge: new Uint8Array(32),
      commitments: [new Uint8Array(32), new Uint8Array(32)], // Only 2
      responses: [new Uint8Array(64), new Uint8Array(64), new Uint8Array(64)],
    }
    const ciphertextHashes = [
      new Uint8Array(32),
      new Uint8Array(32),
      new Uint8Array(32),
    ]

    const valid = verifyNIZKProof(proof, ciphertextHashes, new Uint8Array(32))
    expect(valid).toBe(false)
  })
})

describe('NIZK Serialization', () => {
  test('serializeNIZKProof roundtrip', () => {
    const message = new Uint8Array([1, 2, 3, 4, 5])
    const shares = [
      new Uint8Array([10, 20, 30]),
      new Uint8Array([40, 50, 60]),
      new Uint8Array([70, 80, 90]),
    ]
    const ciphertextHashes = [
      sha3_256(new Uint8Array([1])),
      sha3_256(new Uint8Array([2])),
      sha3_256(new Uint8Array([3])),
    ]
    const randomness = secureRandomBytes(32)

    const proof = generateNIZKProof(
      message,
      shares,
      ciphertextHashes,
      randomness,
    )
    const serialized = serializeNIZKProof(proof)
    const deserialized = deserializeNIZKProof(serialized)

    expect(constantTimeEqual(deserialized.challenge, proof.challenge)).toBe(
      true,
    )
    expect(deserialized.commitments.length).toBe(3)
    expect(deserialized.responses.length).toBe(3)
    for (let i = 0; i < 3; i++) {
      expect(
        constantTimeEqual(deserialized.commitments[i], proof.commitments[i]),
      ).toBe(true)
      expect(
        constantTimeEqual(deserialized.responses[i], proof.responses[i]),
      ).toBe(true)
    }
  })

  test('deserialized proof still verifies', () => {
    const message = new Uint8Array([1, 2, 3, 4, 5])
    const shares = [
      new Uint8Array([10, 20, 30]),
      new Uint8Array([40, 50, 60]),
      new Uint8Array([70, 80, 90]),
    ]
    const ciphertextHashes = [
      sha3_256(new Uint8Array([1])),
      sha3_256(new Uint8Array([2])),
      sha3_256(new Uint8Array([3])),
    ]
    const randomness = secureRandomBytes(32)

    const proof = generateNIZKProof(
      message,
      shares,
      ciphertextHashes,
      randomness,
    )
    const serialized = serializeNIZKProof(proof)
    const deserialized = deserializeNIZKProof(serialized)

    // Note: generateNIZKProof uses raw message bytes in challenge, so verify needs raw message too
    const valid = verifyNIZKProof(deserialized, ciphertextHashes, message)
    expect(valid).toBe(true)
  })
})
