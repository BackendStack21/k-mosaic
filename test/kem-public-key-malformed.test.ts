import { describe, test, expect } from 'bun:test'
import {
  generateKeyPair,
  serializePublicKey,
  deserializePublicKey,
} from '../src/kem/index.ts'

describe('KEM public key deserialization hardening', () => {
  test('rejects trailing bytes in serialized public key', async () => {
    const { publicKey } = await generateKeyPair()
    const serialized = serializePublicKey(publicKey)
    const withTrailing = new Uint8Array(serialized.length + 1)
    withTrailing.set(serialized, 0)
    withTrailing[withTrailing.length - 1] = 0xaa

    expect(() => deserializePublicKey(withTrailing)).toThrow('trailing bytes')
  })

  test('rejects oversized component length headers', () => {
    // [level_len=7]["MOS-128"][slss_len=0xFFFFFFFF]...
    const data = new Uint8Array(4 + 7 + 4)
    const view = new DataView(data.buffer)
    view.setUint32(0, 7, true)
    data.set(new TextEncoder().encode('MOS-128'), 4)
    view.setUint32(11, 0xffffffff, true)

    expect(() => deserializePublicKey(data)).toThrow(
      'SLSS component out of bounds',
    )
  })
})
