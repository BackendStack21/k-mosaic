/**
 * Unit tests for core parameters
 */

import { describe, test, expect } from 'bun:test'
import {
  getParams,
  validateParams,
  MOS_128,
  MOS_256,
} from '../src/core/params.ts'
import { SecurityLevel } from '../src/types.ts'

// =============================================================================
// Parameter Sets Tests
// =============================================================================

describe('MOS_128', () => {
  test('has correct security level', () => {
    expect(MOS_128.level).toBe(SecurityLevel.MOS_128)
  })

  test('has valid SLSS parameters', () => {
    expect(MOS_128.slss.n).toBe(512)
    expect(MOS_128.slss.m).toBe(384)
    expect(MOS_128.slss.q).toBe(12289)
    expect(MOS_128.slss.w).toBe(64)
    expect(MOS_128.slss.sigma).toBe(3.19)
  })

  test('has valid TDD parameters', () => {
    expect(MOS_128.tdd.n).toBe(24)
    expect(MOS_128.tdd.r).toBe(6)
    expect(MOS_128.tdd.q).toBe(7681)
    expect(MOS_128.tdd.sigma).toBe(2.0)
  })

  test('has valid EGRW parameters', () => {
    expect(MOS_128.egrw.p).toBe(1021)
    expect(MOS_128.egrw.k).toBe(128)
  })

  test('passes validation', () => {
    expect(() => validateParams(MOS_128)).not.toThrow()
  })
})

describe('MOS_256', () => {
  test('has correct security level', () => {
    expect(MOS_256.level).toBe(SecurityLevel.MOS_256)
  })

  test('has valid SLSS parameters', () => {
    expect(MOS_256.slss.n).toBe(1024)
    expect(MOS_256.slss.m).toBe(768)
    expect(MOS_256.slss.q).toBe(12289)
    expect(MOS_256.slss.w).toBe(128)
    expect(MOS_256.slss.sigma).toBe(3.19)
  })

  test('has valid TDD parameters', () => {
    expect(MOS_256.tdd.n).toBe(36)
    expect(MOS_256.tdd.r).toBe(9)
    expect(MOS_256.tdd.q).toBe(7681)
    expect(MOS_256.tdd.sigma).toBe(2.0)
  })

  test('has valid EGRW parameters', () => {
    expect(MOS_256.egrw.p).toBe(2039)
    expect(MOS_256.egrw.k).toBe(256)
  })

  test('passes validation', () => {
    expect(() => validateParams(MOS_256)).not.toThrow()
  })
})

// =============================================================================
// getParams Tests
// =============================================================================

describe('getParams', () => {
  test('returns MOS_128 for MOS-128 level', () => {
    const params = getParams(SecurityLevel.MOS_128)
    expect(params).toBe(MOS_128)
  })

  test('returns MOS_256 for MOS-256 level', () => {
    const params = getParams(SecurityLevel.MOS_256)
    expect(params).toBe(MOS_256)
  })

  test('throws for unknown security level', () => {
    expect(() => getParams('MOS-512' as any)).toThrow()
  })
})

// =============================================================================
// validateParams Tests
// =============================================================================

describe('validateParams', () => {
  test('throws for zero SLSS dimension', () => {
    const params = {
      ...MOS_128,
      slss: { ...MOS_128.slss, n: 0 },
    }
    expect(() => validateParams(params)).toThrow(
      'SLSS dimensions must be positive',
    )
  })

  test('throws for negative SLSS dimension', () => {
    const params = {
      ...MOS_128,
      slss: { ...MOS_128.slss, m: -1 },
    }
    expect(() => validateParams(params)).toThrow(
      'SLSS dimensions must be positive',
    )
  })

  test('throws for SLSS sparsity exceeding dimension', () => {
    const params = {
      ...MOS_128,
      slss: { ...MOS_128.slss, w: 1000 },
    }
    expect(() => validateParams(params)).toThrow(
      'SLSS sparsity cannot exceed dimension',
    )
  })

  test('throws for non-prime SLSS modulus', () => {
    const params = {
      ...MOS_128,
      slss: { ...MOS_128.slss, q: 12288 }, // Not prime
    }
    expect(() => validateParams(params)).toThrow('SLSS modulus must be prime')
  })

  test('throws for zero TDD dimension', () => {
    const params = {
      ...MOS_128,
      tdd: { ...MOS_128.tdd, n: 0 },
    }
    expect(() => validateParams(params)).toThrow(
      'TDD dimensions must be positive',
    )
  })

  test('throws for TDD rank exceeding dimension', () => {
    const params = {
      ...MOS_128,
      tdd: { ...MOS_128.tdd, r: 100 },
    }
    expect(() => validateParams(params)).toThrow(
      'TDD rank cannot exceed dimension',
    )
  })

  test('throws for non-prime EGRW p', () => {
    const params = {
      ...MOS_128,
      egrw: { ...MOS_128.egrw, p: 1000 }, // Not prime
    }
    expect(() => validateParams(params)).toThrow('EGRW prime must be prime')
  })

  test('throws for zero EGRW walk length', () => {
    const params = {
      ...MOS_128,
      egrw: { ...MOS_128.egrw, k: 0 },
    }
    expect(() => validateParams(params)).toThrow(
      'EGRW walk length must be positive',
    )
  })

  test('throws for negative EGRW walk length', () => {
    const params = {
      ...MOS_128,
      egrw: { ...MOS_128.egrw, k: -1 },
    }
    expect(() => validateParams(params)).toThrow(
      'EGRW walk length must be positive',
    )
  })

  // Security validation tests
  test('throws when SLSS m is less than n/2', () => {
    const params = {
      ...MOS_128,
      slss: { ...MOS_128.slss, m: 100, n: 512 }, // m=100 < n/2=256
    }
    expect(() => validateParams(params)).toThrow(
      'SLSS m should be at least n/2 for security',
    )
  })

  test('throws when SLSS sigma is less than 3.0', () => {
    const params = {
      ...MOS_128,
      slss: { ...MOS_128.slss, sigma: 2.5 },
    }
    expect(() => validateParams(params)).toThrow(
      'SLSS sigma should be at least 3.0',
    )
  })

  test('throws when EGRW p is less than 1000', () => {
    const params = {
      ...MOS_128,
      egrw: { ...MOS_128.egrw, p: 503 }, // Small prime
    }
    expect(() => validateParams(params)).toThrow(
      'EGRW p should be at least 1000 for security',
    )
  })

  test('throws when EGRW k is less than 64', () => {
    const params = {
      ...MOS_128,
      egrw: { ...MOS_128.egrw, k: 32 },
    }
    expect(() => validateParams(params)).toThrow(
      'EGRW walk length should be at least 64',
    )
  })
})
