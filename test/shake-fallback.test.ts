import { describe, it, expect } from 'bun:test'
import { shake256Fallback, shake256 } from '../src/utils/shake'

describe('shake256Fallback', () => {
  it('produces correct output length', () => {
    const input = new Uint8Array([1, 2, 3])
    const output = shake256Fallback(input, 32)
    expect(output.length).toBe(32)
  })

  it('produces deterministic output', () => {
    const input = new Uint8Array([1, 2, 3])
    const output1 = shake256Fallback(input, 32)
    const output2 = shake256Fallback(input, 32)
    expect(output1).toEqual(output2)
  })

  it('produces different outputs for different inputs', () => {
    const input1 = new Uint8Array([1, 2, 3])
    const input2 = new Uint8Array([1, 2, 4])
    const output1 = shake256Fallback(input1, 32)
    const output2 = shake256Fallback(input2, 32)
    expect(output1).not.toEqual(output2)
  })

  it('produces different outputs for different lengths', () => {
    const input = new Uint8Array([1, 2, 3])
    const output1 = shake256Fallback(input, 32)
    const output2 = shake256Fallback(input, 64)
    expect(output1).not.toEqual(output2.slice(0, 32)) // SHAKE property: prefix property doesn't necessarily hold for this construction but good to check behavior
  })

  it('handles empty input', () => {
    const input = new Uint8Array([])
    const output = shake256Fallback(input, 32)
    expect(output.length).toBe(32)
  })

  it('handles large input', () => {
    const input = new Uint8Array(1000).fill(1)
    const output = shake256Fallback(input, 32)
    expect(output.length).toBe(32)
  })

  it('handles large output', () => {
    const input = new Uint8Array([1, 2, 3])
    const output = shake256Fallback(input, 1000)
    expect(output.length).toBe(1000)
  })
})

describe('shake256 edge cases', () => {
  it('throws for negative output length', () => {
    expect(() => shake256(new Uint8Array([]), -1)).toThrow()
  })

  it('returns empty array for 0 output length', () => {
    const output = shake256(new Uint8Array([]), 0)
    expect(output.length).toBe(0)
  })
})
