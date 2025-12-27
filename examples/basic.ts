/**
 * kMOSAIC Cryptographic Library - Basic Usage Examples
 *
 * This file demonstrates the key features of the kMOSAIC post-quantum
 * cryptographic library.
 *
 * ⚠️ SECURITY NOTICE:
 * This library is EXPERIMENTAL and NOT suitable for production use.
 * - No formal security proofs exist for the combined SLSS+TDD+EGRW construction
 * - Not reviewed by the academic cryptographic community
 * - JavaScript runtime cannot guarantee constant-time execution
 *
 * For production use, consider standardized algorithms like CRYSTALS-Kyber/Dilithium.
 */

import {
  // KEM operations
  kemGenerateKeyPair,
  encapsulate,
  decapsulate,
  encrypt,
  decrypt,

  // Signature operations
  signGenerateKeyPair,
  sign,
  verify,

  // Utilities
  analyzePublicKey,
  serializeCiphertext,
  deserializeCiphertext,
  serializeSignature,
  deserializeSignature,

  // Security levels
  SecurityLevel,
} from '../src/index.ts'

// =============================================================================
// Example 1: Key Encapsulation (KEM)
// =============================================================================

async function kemExample() {
  console.log('\n=== kMOSAIC KEM Example ===\n')

  // Generate key pair
  console.log('Generating kMOSAIC key pair (MOS-128)...')
  const startKeyGen = performance.now()
  const { publicKey, secretKey } = await kemGenerateKeyPair(
    SecurityLevel.MOS_128,
  )
  const keyGenTime = performance.now() - startKeyGen
  console.log(`Key generation took ${keyGenTime.toFixed(2)}ms`)

  // Analyze public key
  const analysis = analyzePublicKey(publicKey)
  console.log(`\nPublic key analysis:`)
  console.log(
    `  SLSS - dimension: ${analysis.slss.dimension}, security: ~${analysis.slss.estimatedSecurity} bits`,
  )
  console.log(
    `  TDD  - tensor dim: ${analysis.tdd.tensorDim}, security: ~${analysis.tdd.estimatedSecurity} bits`,
  )
  console.log(
    `  EGRW - graph size: ${analysis.egrw.graphSize}, security: ~${analysis.egrw.estimatedSecurity} bits`,
  )
  console.log(
    `  Combined security: ~${analysis.combined.estimatedSecurity} bits (${analysis.combined.quantumSecurity} post-quantum)`,
  )

  // Encapsulate shared secret
  console.log('\nEncapsulating shared secret...')
  const startEncap = performance.now()
  const { ciphertext, sharedSecret } = await encapsulate(publicKey)
  const encapTime = performance.now() - startEncap
  console.log(`Encapsulation took ${encapTime.toFixed(2)}ms`)
  console.log(
    `Shared secret (first 16 bytes): ${Buffer.from(sharedSecret.slice(0, 16)).toString('hex')}`,
  )

  // Decapsulate to recover shared secret
  console.log('\nDecapsulating...')
  const startDecap = performance.now()
  const recoveredSecret = await decapsulate(ciphertext, secretKey, publicKey)
  const decapTime = performance.now() - startDecap
  console.log(`Decapsulation took ${decapTime.toFixed(2)}ms`)
  console.log(
    `Recovered secret (first 16 bytes): ${Buffer.from(recoveredSecret.slice(0, 16)).toString('hex')}`,
  )

  // Verify secrets match
  const match = Buffer.from(sharedSecret).equals(Buffer.from(recoveredSecret))
  console.log(`\nSecrets match: ${match ? '✓ YES' : '✗ NO'}`)

  // Serialize and deserialize ciphertext
  const serialized = serializeCiphertext(ciphertext)
  console.log(`\nCiphertext size: ${serialized.length} bytes`)
  const deserialized = deserializeCiphertext(serialized)

  return match
}

// =============================================================================
// Example 2: Hybrid Encryption (KEM + AES-256-GCM)
// =============================================================================

async function encryptionExample() {
  console.log('\n=== kMOSAIC Hybrid Encryption Example ===\n')

  // Generate key pair
  const { publicKey, secretKey } = await kemGenerateKeyPair(
    SecurityLevel.MOS_128,
  )

  // Encrypt a message
  const message = new TextEncoder().encode('Hello, post-quantum world! 🔐')
  console.log(`Original message: "${new TextDecoder().decode(message)}"`)
  console.log(`Message size: ${message.length} bytes`)

  const startEncrypt = performance.now()
  const encrypted = await encrypt(message, publicKey)
  const encryptTime = performance.now() - startEncrypt
  console.log(`\nEncryption took ${encryptTime.toFixed(2)}ms`)
  console.log(`Ciphertext size: ${encrypted.length} bytes`)
  console.log(
    `Expansion factor: ${(encrypted.length / message.length).toFixed(1)}x`,
  )

  // Decrypt the message
  const startDecrypt = performance.now()
  const decrypted = await decrypt(encrypted, secretKey, publicKey)
  const decryptTime = performance.now() - startDecrypt
  console.log(`\nDecryption took ${decryptTime.toFixed(2)}ms`)
  console.log(`Decrypted message: "${new TextDecoder().decode(decrypted)}"`)

  // Verify
  const match =
    new TextDecoder().decode(decrypted) === new TextDecoder().decode(message)
  console.log(`\nDecryption successful: ${match ? '✓ YES' : '✗ NO'}`)

  return match
}

// =============================================================================
// Example 3: Digital Signatures
// =============================================================================

async function signatureExample() {
  console.log('\n=== kMOSAIC Digital Signature Example ===\n')

  // Generate signing key pair
  console.log('Generating signature key pair...')
  const startKeyGen = performance.now()
  const { publicKey, secretKey } = await signGenerateKeyPair(
    SecurityLevel.MOS_128,
  )
  const keyGenTime = performance.now() - startKeyGen
  console.log(`Key generation took ${keyGenTime.toFixed(2)}ms`)

  // Message to sign
  const message = new TextEncoder().encode(
    'This is a signed message from kMOSAIC!',
  )
  console.log(`\nMessage: "${new TextDecoder().decode(message)}"`)

  // Sign the message
  console.log('\nSigning message...')
  const startSign = performance.now()
  const signature = await sign(message, secretKey, publicKey)
  const signTime = performance.now() - startSign
  console.log(`Signing took ${signTime.toFixed(2)}ms`)

  // Serialize signature
  const serializedSig = serializeSignature(signature)
  console.log(`Signature size: ${serializedSig.length} bytes`)

  // Verify the signature
  console.log('\nVerifying signature...')
  const startVerify = performance.now()
  const valid = await verify(message, signature, publicKey)
  const verifyTime = performance.now() - startVerify
  console.log(`Verification took ${verifyTime.toFixed(2)}ms`)
  console.log(`Signature valid: ${valid ? '✓ YES' : '✗ NO'}`)

  // Test with tampered message
  const tamperedMessage = new TextEncoder().encode(
    'This is a TAMPERED message!',
  )
  const tamperedValid = await verify(tamperedMessage, signature, publicKey)
  console.log(
    `\nTampered message verification: ${tamperedValid ? '✗ PASSED (bad!)' : '✓ FAILED (good!)'}`,
  )

  // Deserialize and re-verify
  const deserializedSig = deserializeSignature(serializedSig)
  const reVerified = await verify(message, deserializedSig, publicKey)
  console.log(
    `Re-verification after serialization: ${reVerified ? '✓ YES' : '✗ NO'}`,
  )

  return valid && !tamperedValid
}

// =============================================================================
// Example 4: Security Levels
// =============================================================================

async function securityLevelsExample() {
  console.log('\n=== kMOSAIC Security Levels Comparison ===\n')

  // MOS-128
  console.log('Testing MOS-128 (128-bit post-quantum security)...')
  const mos128 = await kemGenerateKeyPair(SecurityLevel.MOS_128)
  const analysis128 = analyzePublicKey(mos128.publicKey)
  console.log(
    `  Combined security: ~${analysis128.combined.estimatedSecurity} bits`,
  )
  console.log(
    `  Post-quantum security: ~${analysis128.combined.quantumSecurity} bits`,
  )

  // MOS-256
  console.log('\nTesting MOS-256 (256-bit post-quantum security)...')
  const mos256 = await kemGenerateKeyPair(SecurityLevel.MOS_256)
  const analysis256 = analyzePublicKey(mos256.publicKey)
  console.log(
    `  Combined security: ~${analysis256.combined.estimatedSecurity} bits`,
  )
  console.log(
    `  Post-quantum security: ~${analysis256.combined.quantumSecurity} bits`,
  )

  console.log('\nComparison:')
  console.log(
    `  MOS-128: ~${analysis128.combined.quantumSecurity} bits post-quantum security`,
  )
  console.log(
    `  MOS-256: ~${analysis256.combined.quantumSecurity} bits post-quantum security`,
  )

  return true
}

// =============================================================================
// Run all examples
// =============================================================================

async function main() {
  console.log(
    '╔══════════════════════════════════════════════════════════════╗',
  )
  console.log(
    '║           kMOSAIC Post-Quantum Cryptography Demo              ║',
  )
  console.log(
    '║  Multi-Oracle Structured Algebraic Intractability Composition║',
  )
  console.log(
    '╚══════════════════════════════════════════════════════════════╝',
  )

  console.log('\n⚠️  SECURITY NOTICE: This library is EXPERIMENTAL.')
  console.log('    Not suitable for production security applications.\n')

  const results: boolean[] = []

  try {
    results.push(await kemExample())
    results.push(await encryptionExample())
    results.push(await signatureExample())
    results.push(await securityLevelsExample())

    console.log(
      '\n═══════════════════════════════════════════════════════════════',
    )
    console.log(
      `\nAll tests passed: ${results.every((r) => r) ? '✓ YES' : '✗ NO'}`,
    )

    if (results.every((r) => r)) {
      console.log('\n🎉 kMOSAIC is working correctly!')
      console.log('\nKey Features:')
      console.log('  • Three independent hard problems (SLSS, TDD, EGRW)')
      console.log(
        '  • XOR 3-of-3 secret sharing with cryptographic entanglement',
      )
      console.log('  • IND-CCA2 secure KEM (Fujisaki-Okamoto transform)')
      console.log(
        '  • Multi-witness Fiat-Shamir signatures with timing padding',
      )
      console.log(
        '  • Native Node.js crypto for core operations (timingSafeEqual, SHAKE256)',
      )
      console.log('  • Enhanced entropy validation for seed inputs')
      console.log('\nSecurity Mitigations Applied:')
      console.log('  ✓ Constant-time equality via crypto.timingSafeEqual()')
      console.log('  ✓ Native SHAKE256/SHA3-256 via crypto.createHash()')
      console.log('  ✓ Signature timing padding (min 25-50ms execution)')
      console.log('  ✓ Comprehensive seed entropy validation')
      console.log('  ✓ Implicit rejection for KEM decapsulation failures')
    }
  } catch (error) {
    console.error('\n❌ Error running examples:', error)
    process.exit(1)
  }
}

main().catch(console.error)
