/**
 * Unit tests for utility functions
 */

import { describe, test, expect, beforeEach } from 'bun:test'
import {
  shake256,
  sha3_256,
  hashConcat,
  hashWithDomain,
} from '../src/utils/shake.ts'
import {
  constantTimeEqual,
  constantTimeSelect,
  constantTimeSelectInt32,
  constantTimeLessThan,
  constantTimeAbs,
  constantTimeMod,
  zeroize,
  SecureBuffer,
} from '../src/utils/constant-time.ts'
import {
  secureRandomBytes,
  randomInt,
  randomIntRange,
  randomZq,
  randomVectorZq,
  randomSparseVector,
  sampleGaussian,
  sampleGaussianVector,
  deterministicBytes,
  expandSeed,
  validateSeedEntropy,
} from '../src/utils/random.ts'

// =============================================================================
// SHAKE256 and SHA3 Tests
// =============================================================================

describe('shake256', () => {
  test('produces deterministic output for same input', () => {
    const input = new Uint8Array([1, 2, 3, 4, 5])
    const output1 = shake256(input, 32)
    const output2 = shake256(input, 32)
    expect(constantTimeEqual(output1, output2)).toBe(true)
  })

  test('produces different outputs for different inputs', () => {
    const input1 = new Uint8Array([1, 2, 3])
    const input2 = new Uint8Array([4, 5, 6])
    const output1 = shake256(input1, 32)
    const output2 = shake256(input2, 32)
    expect(constantTimeEqual(output1, output2)).toBe(false)
  })

  test('produces correct output length', () => {
    const input = new Uint8Array([1, 2, 3])
    expect(shake256(input, 16).length).toBe(16)
    expect(shake256(input, 32).length).toBe(32)
    expect(shake256(input, 64).length).toBe(64)
    expect(shake256(input, 128).length).toBe(128)
  })

  test('produces different outputs for different lengths', () => {
    const input = new Uint8Array([1, 2, 3])
    const short = shake256(input, 16)
    const long = shake256(input, 64)
    // First 16 bytes should match
    expect(constantTimeEqual(short, long.slice(0, 16))).toBe(true)
  })

  test('handles empty input', () => {
    const input = new Uint8Array(0)
    const output = shake256(input, 32)
    expect(output.length).toBe(32)
  })

  test('handles large input', () => {
    const input = new Uint8Array(10000).fill(42)
    const output = shake256(input, 32)
    expect(output.length).toBe(32)
  })
})

describe('sha3_256', () => {
  test('produces 32-byte output', () => {
    const input = new Uint8Array([1, 2, 3])
    const output = sha3_256(input)
    expect(output.length).toBe(32)
  })

  test('produces deterministic output', () => {
    const input = new Uint8Array([1, 2, 3, 4, 5])
    const output1 = sha3_256(input)
    const output2 = sha3_256(input)
    expect(constantTimeEqual(output1, output2)).toBe(true)
  })

  test('produces different outputs for different inputs', () => {
    const input1 = new Uint8Array([1, 2, 3])
    const input2 = new Uint8Array([1, 2, 4])
    const output1 = sha3_256(input1)
    const output2 = sha3_256(input2)
    expect(constantTimeEqual(output1, output2)).toBe(false)
  })

  test('handles empty input', () => {
    const input = new Uint8Array(0)
    const output = sha3_256(input)
    expect(output.length).toBe(32)
  })
})

describe('hashConcat', () => {
  test('hashes multiple inputs together', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([4, 5, 6])
    const result = hashConcat(a, b)
    expect(result.length).toBe(32)
  })

  test('order matters', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([4, 5, 6])
    const result1 = hashConcat(a, b)
    const result2 = hashConcat(b, a)
    expect(constantTimeEqual(result1, result2)).toBe(false)
  })

  test('handles multiple inputs', () => {
    const a = new Uint8Array([1])
    const b = new Uint8Array([2])
    const c = new Uint8Array([3])
    const result = hashConcat(a, b, c)
    expect(result.length).toBe(32)
  })

  test('handles empty inputs', () => {
    const a = new Uint8Array(0)
    const b = new Uint8Array([1, 2, 3])
    const result = hashConcat(a, b)
    expect(result.length).toBe(32)
  })
})

describe('hashWithDomain', () => {
  test('produces different output for different domains', () => {
    const input = new Uint8Array([1, 2, 3])
    const result1 = hashWithDomain('domain1', input)
    const result2 = hashWithDomain('domain2', input)
    expect(constantTimeEqual(result1, result2)).toBe(false)
  })

  test('produces deterministic output', () => {
    const input = new Uint8Array([1, 2, 3])
    const result1 = hashWithDomain('test-domain', input)
    const result2 = hashWithDomain('test-domain', input)
    expect(constantTimeEqual(result1, result2)).toBe(true)
  })

  test('handles empty domain', () => {
    const input = new Uint8Array([1, 2, 3])
    const result = hashWithDomain('', input)
    expect(result.length).toBe(32)
  })
})

// =============================================================================
// Constant-Time Operations Tests
// =============================================================================

describe('constantTimeEqual', () => {
  test('returns true for equal arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5])
    const b = new Uint8Array([1, 2, 3, 4, 5])
    expect(constantTimeEqual(a, b)).toBe(true)
  })

  test('returns false for different arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5])
    const b = new Uint8Array([1, 2, 3, 4, 6])
    expect(constantTimeEqual(a, b)).toBe(false)
  })

  test('returns false for different length arrays', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([1, 2, 3, 4])
    expect(constantTimeEqual(a, b)).toBe(false)
  })

  test('handles empty arrays', () => {
    const a = new Uint8Array(0)
    const b = new Uint8Array(0)
    expect(constantTimeEqual(a, b)).toBe(true)
  })
})

describe('constantTimeSelect', () => {
  test('returns a when condition is 1', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([4, 5, 6])
    const result = constantTimeSelect(1, a, b)
    expect(constantTimeEqual(result, a)).toBe(true)
  })

  test('returns b when condition is 0', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([4, 5, 6])
    const result = constantTimeSelect(0, a, b)
    expect(constantTimeEqual(result, b)).toBe(true)
  })

  test('throws for different length arrays', () => {
    const a = new Uint8Array([1, 2, 3])
    const b = new Uint8Array([4, 5, 6, 7])
    expect(() => constantTimeSelect(1, a, b)).toThrow()
  })
})

describe('constantTimeSelectInt32', () => {
  test('returns a when condition is 1', () => {
    const a = new Int32Array([100, 200, 300])
    const b = new Int32Array([400, 500, 600])
    const result = constantTimeSelectInt32(1, a, b)
    expect(result[0]).toBe(100)
    expect(result[1]).toBe(200)
    expect(result[2]).toBe(300)
  })

  test('returns b when condition is 0', () => {
    const a = new Int32Array([100, 200, 300])
    const b = new Int32Array([400, 500, 600])
    const result = constantTimeSelectInt32(0, a, b)
    expect(result[0]).toBe(400)
    expect(result[1]).toBe(500)
    expect(result[2]).toBe(600)
  })

  test('throws for different length arrays', () => {
    const a = new Int32Array([1, 2, 3])
    const b = new Int32Array([4, 5, 6, 7])
    expect(() => constantTimeSelectInt32(1, a, b)).toThrow()
  })
})

describe('constantTimeLessThan', () => {
  test('returns 1 when a < b', () => {
    expect(constantTimeLessThan(5, 10)).toBe(1)
    expect(constantTimeLessThan(0, 1)).toBe(1)
    expect(constantTimeLessThan(-5, 0)).toBe(1)
  })

  test('returns 0 when a >= b', () => {
    expect(constantTimeLessThan(10, 5)).toBe(0)
    expect(constantTimeLessThan(5, 5)).toBe(0)
    expect(constantTimeLessThan(0, -1)).toBe(0)
  })
})

describe('constantTimeAbs', () => {
  test('returns absolute value of positive number', () => {
    expect(constantTimeAbs(5)).toBe(5)
    expect(constantTimeAbs(100)).toBe(100)
  })

  test('returns absolute value of negative number', () => {
    expect(constantTimeAbs(-5)).toBe(5)
    expect(constantTimeAbs(-100)).toBe(100)
  })

  test('returns 0 for 0', () => {
    expect(constantTimeAbs(0)).toBe(0)
  })
})

describe('constantTimeMod', () => {
  test('works for positive numbers', () => {
    expect(constantTimeMod(10, 3)).toBe(1)
    expect(constantTimeMod(15, 5)).toBe(0)
    expect(constantTimeMod(7, 4)).toBe(3)
  })

  test('works for negative numbers', () => {
    expect(constantTimeMod(-1, 5)).toBe(4)
    expect(constantTimeMod(-10, 3)).toBe(2)
  })
})

describe('zeroize', () => {
  test('zeroes Uint8Array', () => {
    const buffer = new Uint8Array([1, 2, 3, 4, 5])
    zeroize(buffer)
    expect(buffer.every((x) => x === 0)).toBe(true)
  })

  test('zeroes Int8Array', () => {
    const buffer = new Int8Array([1, 2, 3, 4, 5])
    zeroize(buffer)
    expect(buffer.every((x) => x === 0)).toBe(true)
  })

  test('zeroes Int32Array', () => {
    const buffer = new Int32Array([100, 200, 300])
    zeroize(buffer)
    expect(buffer.every((x) => x === 0)).toBe(true)
  })
})

describe('SecureBuffer', () => {
  test('creates buffer of specified length', () => {
    const buffer = new SecureBuffer(32)
    expect(buffer.length).toBe(32)
    buffer.dispose()
  })

  test('creates buffer from existing data', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5])
    const buffer = new SecureBuffer(data)
    expect(buffer.length).toBe(5)
    expect(buffer.buffer[0]).toBe(1)
    buffer.dispose()
  })

  test('throws when accessing disposed buffer', () => {
    const buffer = new SecureBuffer(32)
    buffer.dispose()
    expect(() => buffer.buffer).toThrow()
  })

  test('zeroes data on dispose', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5])
    const buffer = new SecureBuffer(data)
    const ref = buffer.buffer // Get reference before dispose
    buffer.dispose()
    // The original reference should now be zeroed
    expect(ref.every((x) => x === 0)).toBe(true)
  })

  test('supports Symbol.dispose', () => {
    const buffer = new SecureBuffer(32)
    buffer[Symbol.dispose]()
    expect(() => buffer.buffer).toThrow()
  })

  test('clones buffer', () => {
    const data = new Uint8Array([1, 2, 3])
    const buffer = new SecureBuffer(data)
    const clone = buffer.clone()
    expect(clone.length).toBe(3)
    expect(clone.buffer).toEqual(data)
    expect(clone.buffer).not.toBe(buffer.buffer) // Different instances
    buffer.dispose()
    clone.dispose()
  })

  test('throws when cloning disposed buffer', () => {
    const buffer = new SecureBuffer(32)
    buffer.dispose()
    expect(() => buffer.clone()).toThrow()
  })

  test('randomizes buffer', () => {
    const buffer = new SecureBuffer(32)
    const original = new Uint8Array(buffer.buffer)
    buffer.randomize()
    expect(buffer.buffer).not.toEqual(original)
    buffer.dispose()
  })

  test('throws when randomizing disposed buffer', () => {
    const buffer = new SecureBuffer(32)
    buffer.dispose()
    expect(() => buffer.randomize()).toThrow()
  })
})

// =============================================================================
// Random Number Generation Tests
// =============================================================================

describe('secureRandomBytes', () => {
  test('produces correct length', () => {
    expect(secureRandomBytes(16).length).toBe(16)
    expect(secureRandomBytes(32).length).toBe(32)
    expect(secureRandomBytes(64).length).toBe(64)
  })

  test('produces different outputs each time', () => {
    const a = secureRandomBytes(32)
    const b = secureRandomBytes(32)
    expect(constantTimeEqual(a, b)).toBe(false)
  })

  test('produces non-zero output', () => {
    const bytes = secureRandomBytes(32)
    expect(bytes.some((x) => x !== 0)).toBe(true)
  })
})

describe('randomInt', () => {
  test('produces values in range [0, max)', () => {
    for (let i = 0; i < 100; i++) {
      const val = randomInt(10)
      expect(val).toBeGreaterThanOrEqual(0)
      expect(val).toBeLessThan(10)
    }
  })

  test('returns 0 when max is 1', () => {
    expect(randomInt(1)).toBe(0)
  })

  test('throws for non-positive max', () => {
    expect(() => randomInt(0)).toThrow()
    expect(() => randomInt(-1)).toThrow()
  })
})

describe('randomIntRange', () => {
  test('produces values in range [min, max]', () => {
    for (let i = 0; i < 100; i++) {
      const val = randomIntRange(5, 10)
      expect(val).toBeGreaterThanOrEqual(5)
      expect(val).toBeLessThanOrEqual(10)
    }
  })

  test('returns min when min equals max', () => {
    expect(randomIntRange(5, 5)).toBe(5)
  })
})

describe('randomZq', () => {
  test('produces values in range [0, q)', () => {
    const q = 7681
    for (let i = 0; i < 100; i++) {
      const val = randomZq(q)
      expect(val).toBeGreaterThanOrEqual(0)
      expect(val).toBeLessThan(q)
    }
  })
})

describe('randomVectorZq', () => {
  test('produces vector of correct length', () => {
    const v = randomVectorZq(10, 7681)
    expect(v.length).toBe(10)
  })

  test('all elements are in range [0, q)', () => {
    const q = 7681
    const v = randomVectorZq(100, q)
    for (let i = 0; i < v.length; i++) {
      expect(v[i]).toBeGreaterThanOrEqual(0)
      expect(v[i]).toBeLessThan(q)
    }
  })
})

describe('randomSparseVector', () => {
  test('produces vector of correct length', () => {
    const v = randomSparseVector(100, 10)
    expect(v.length).toBe(100)
  })

  test('has exactly w non-zero entries', () => {
    const v = randomSparseVector(100, 10)
    const nonZero = v.filter((x) => x !== 0).length
    expect(nonZero).toBe(10)
  })

  test('non-zero entries are -1 or 1', () => {
    const v = randomSparseVector(100, 20)
    for (let i = 0; i < v.length; i++) {
      expect(v[i]).toBeGreaterThanOrEqual(-1)
      expect(v[i]).toBeLessThanOrEqual(1)
    }
  })

  test('throws when w > n', () => {
    expect(() => randomSparseVector(5, 10)).toThrow()
  })
})

describe('sampleGaussian', () => {
  test('produces values around 0', () => {
    let sum = 0
    const n = 1000
    for (let i = 0; i < n; i++) {
      sum += sampleGaussian(3.0)
    }
    const mean = sum / n
    expect(Math.abs(mean)).toBeLessThan(1) // Should be close to 0
  })

  test('produces integer values', () => {
    for (let i = 0; i < 100; i++) {
      const val = sampleGaussian(3.0)
      expect(Number.isInteger(val)).toBe(true)
    }
  })
})

describe('sampleGaussianVector', () => {
  test('produces vector of correct length', () => {
    const v = sampleGaussianVector(50, 3.0)
    expect(v.length).toBe(50)
  })

  test('values are reasonable', () => {
    const v = sampleGaussianVector(100, 3.0)
    for (let i = 0; i < v.length; i++) {
      expect(Math.abs(v[i])).toBeLessThan(100) // 3-sigma is about 9
    }
  })
})

describe('deterministicBytes', () => {
  test('produces deterministic output', () => {
    const seed = new Uint8Array([1, 2, 3, 4, 5])
    const a = deterministicBytes(seed, 32)
    const b = deterministicBytes(seed, 32)
    expect(constantTimeEqual(a, b)).toBe(true)
  })

  test('produces different output for different seeds', () => {
    const seed1 = new Uint8Array([1, 2, 3])
    const seed2 = new Uint8Array([4, 5, 6])
    const a = deterministicBytes(seed1, 32)
    const b = deterministicBytes(seed2, 32)
    expect(constantTimeEqual(a, b)).toBe(false)
  })
})

describe('expandSeed', () => {
  test('produces correct number of seeds', () => {
    const seed = new Uint8Array([1, 2, 3, 4, 5])
    const expanded = expandSeed(seed, 5)
    expect(expanded.length).toBe(5)
  })

  test('each seed has correct length', () => {
    const seed = new Uint8Array([1, 2, 3, 4, 5])
    const expanded = expandSeed(seed, 3, 32)
    for (const s of expanded) {
      expect(s.length).toBe(32)
    }
  })

  test('produces different seeds', () => {
    const seed = new Uint8Array([1, 2, 3, 4, 5])
    const expanded = expandSeed(seed, 3)
    expect(constantTimeEqual(expanded[0], expanded[1])).toBe(false)
    expect(constantTimeEqual(expanded[1], expanded[2])).toBe(false)
  })

  test('is deterministic', () => {
    const seed = new Uint8Array([1, 2, 3, 4, 5])
    const expanded1 = expandSeed(seed, 3)
    const expanded2 = expandSeed(seed, 3)
    for (let i = 0; i < 3; i++) {
      expect(constantTimeEqual(expanded1[i], expanded2[i])).toBe(true)
    }
  })
})

describe('validateSeedEntropy', () => {
  test('accepts valid seed', () => {
    const seed = secureRandomBytes(32)
    expect(() => validateSeedEntropy(seed)).not.toThrow()
  })

  test('throws for short seed', () => {
    const seed = new Uint8Array(31)
    expect(() => validateSeedEntropy(seed)).toThrow(
      'Seed must be at least 32 bytes',
    )
  })

  test('throws for identical bytes', () => {
    const seed = new Uint8Array(32).fill(0)
    expect(() => validateSeedEntropy(seed)).toThrow('all bytes are identical')
  })

  test('throws for ascending sequence', () => {
    const seed = new Uint8Array(32)
    for (let i = 0; i < 32; i++) seed[i] = i
    expect(() => validateSeedEntropy(seed)).toThrow(
      'sequential pattern detected',
    )
  })

  test('throws for descending sequence', () => {
    const seed = new Uint8Array(32)
    for (let i = 0; i < 32; i++) seed[i] = 32 - i
    expect(() => validateSeedEntropy(seed)).toThrow(
      'sequential pattern detected',
    )
  })

  test('throws for repeating pattern', () => {
    const seed = new Uint8Array(32)
    for (let i = 0; i < 32; i++) seed[i] = i % 3
    expect(() => validateSeedEntropy(seed)).toThrow('repeating pattern')
  })

  test('throws for low diversity', () => {
    const seed = new Uint8Array(32)
    // Use only 4 unique values
    for (let i = 0; i < 32; i++) seed[i] = i % 4
    // This might trigger repeating pattern first, so let's make it non-repeating but low diversity
    // 0, 0, 1, 1, 2, 2, 3, 3, ...
    for (let i = 0; i < 32; i++) seed[i] = Math.floor(i / 8)
    expect(() => validateSeedEntropy(seed)).toThrow('unique byte values')
  })
})

describe('randomVectorZq optimized path', () => {
  test('works for q=256 (power of 2, 1 byte)', () => {
    const v = randomVectorZq(100, 256)
    expect(v.length).toBe(100)
    expect(v.every((x) => x >= 0 && x < 256)).toBe(true)
  })

  test('works for q=65536 (power of 2, 2 bytes)', () => {
    const v = randomVectorZq(100, 65536)
    expect(v.length).toBe(100)
    expect(v.every((x) => x >= 0 && x < 65536)).toBe(true)
  })
})

describe('SecureBuffer Getters', () => {
  test('returns correct length', () => {
    const buffer = new SecureBuffer(10)
    expect(buffer.length).toBe(10)
    buffer.dispose()
  })

  test('returns correct disposed state', () => {
    const buffer = new SecureBuffer(10)
    expect(buffer.isDisposed).toBe(false)
    buffer.dispose()
    expect(buffer.isDisposed).toBe(true)
  })
})
