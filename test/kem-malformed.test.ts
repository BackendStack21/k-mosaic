import { describe, test, expect } from 'bun:test'
import { encapsulate, decapsulate, encrypt, decrypt } from '../src/kem/index.ts'
import { kemGenerateKeyPair } from '../src/index.ts'

describe('KEM malformed/corrupted ciphertext handling', () => {
  test('decapsulate returns 32-byte implicit reject on proof tampering', async () => {
    const { publicKey, secretKey } = await kemGenerateKeyPair()
    const { ciphertext, sharedSecret } = await encapsulate(publicKey)

    // Tamper proof (set to zeros)
    const corrupted = {
      ...ciphertext,
      proof: new Uint8Array(ciphertext.proof.length),
    }

    const recovered = await decapsulate(corrupted as any, secretKey, publicKey)
    expect(recovered).toBeInstanceOf(Uint8Array)
    expect(recovered.length).toBe(32)
    // Should not equal original shared secret
    let equal = true
    if (recovered.length === sharedSecret.length) {
      for (let i = 0; i < 32; i++)
        if (recovered[i] !== sharedSecret[i]) {
          equal = false
          break
        }
    } else equal = false
    expect(equal).toBe(false)
  })

  test('decapsulate returns implicit reject on malformed fragment lengths', async () => {
    const { publicKey, secretKey } = await kemGenerateKeyPair()
    const { ciphertext, sharedSecret } = await encapsulate(publicKey)

    // Corrupt SLSS fragment by making u very short
    const bad = JSON.parse(JSON.stringify(ciphertext))
    bad.c1.u = new Int32Array([0])

    const recovered = await decapsulate(bad as any, secretKey, publicKey)
    expect(recovered).toBeInstanceOf(Uint8Array)
    expect(recovered.length).toBe(32)
    // Should not equal original shared secret
    let equal = true
    for (let i = 0; i < 32; i++)
      if (recovered[i] !== sharedSecret[i]) {
        equal = false
        break
      }
    expect(equal).toBe(false)
  })

  test('decrypt fails gracefully on truncated serialized ciphertext', async () => {
    const { publicKey, secretKey } = await kemGenerateKeyPair()

    const plaintext = new TextEncoder().encode('test message')
    const encrypted = await encrypt(plaintext, publicKey)

    // Truncate the data so KEM length header doesn't match available data
    const truncated = encrypted.slice(0, 8)

    await expect(decrypt(truncated, secretKey, publicKey)).rejects.toThrow()
  })

  test('decapsulate returns implicit reject when public key does not match secretKey', async () => {
    const { publicKey, secretKey } = await kemGenerateKeyPair()
    const { ciphertext, sharedSecret } = await encapsulate(publicKey)

    // Mutate public key binding to simulate mismatch
    const badPk = {
      ...publicKey,
      binding: new Uint8Array(publicKey.binding.length),
    }

    const recovered = await decapsulate(ciphertext, secretKey, badPk as any)
    expect(recovered).toBeInstanceOf(Uint8Array)
    expect(recovered.length).toBe(32)

    // Should not equal original shared secret
    let equal = true
    for (let i = 0; i < 32; i++)
      if (recovered[i] !== sharedSecret[i]) {
        equal = false
        break
      }
    expect(equal).toBe(false)
  })
})
