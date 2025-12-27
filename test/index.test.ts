import { describe, it, expect } from 'bun:test'
import crypto, { SecurityLevel } from '../src/index'

describe('MOSAIC Top-Level API', () => {
  it('exports KEM operations', async () => {
    expect(crypto.kem).toBeDefined()
    expect(crypto.kem.generateKeyPair).toBeDefined()
    expect(crypto.kem.encapsulate).toBeDefined()
    expect(crypto.kem.decapsulate).toBeDefined()
    expect(crypto.kem.encrypt).toBeDefined()
    expect(crypto.kem.decrypt).toBeDefined()

    const kp = await crypto.kem.generateKeyPair()
    expect(kp).toBeDefined()

    const enc = await crypto.kem.encapsulate(kp.publicKey)
    expect(enc).toBeDefined()

    const ss = await crypto.kem.decapsulate(
      enc.ciphertext,
      kp.secretKey,
      kp.publicKey,
    )
    expect(ss).toBeDefined()
    expect(ss).toEqual(enc.sharedSecret)

    const msg = new Uint8Array([1, 2, 3])
    const ct = await crypto.kem.encrypt(msg, kp.publicKey)
    const decrypted = await crypto.kem.decrypt(ct, kp.secretKey, kp.publicKey)
    expect(decrypted).toEqual(msg)
  })

  it('exports Signature operations', async () => {
    expect(crypto.sign).toBeDefined()
    expect(crypto.sign.generateKeyPair).toBeDefined()
    expect(crypto.sign.sign).toBeDefined()
    expect(crypto.sign.verify).toBeDefined()

    const kp = await crypto.sign.generateKeyPair()
    const msg = new Uint8Array([1, 2, 3])
    const sig = await crypto.sign.sign(msg, kp.secretKey, kp.publicKey)
    const valid = await crypto.sign.verify(msg, sig, kp.publicKey)
    expect(valid).toBe(true)
  })

  it('exports Parameters', async () => {
    expect(crypto.params).toBeDefined()
    const params128 = await crypto.params[SecurityLevel.MOS_128]()
    expect(params128).toBeDefined()
    expect(params128.level).toBe(SecurityLevel.MOS_128)

    const params256 = await crypto.params[SecurityLevel.MOS_256]()
    expect(params256).toBeDefined()
    expect(params256.level).toBe(SecurityLevel.MOS_256)
  })
})
