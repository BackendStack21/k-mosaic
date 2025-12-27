/**
 * kMOSAIC Benchmark vs Node.js Crypto (X25519/Ed25519)
 *
 * Compares kMOSAIC post-quantum cryptography against the fastest
 * classical implementations in Node.js.
 *
 * ⚠️ SECURITY NOTICE:
 * kMOSAIC is EXPERIMENTAL and NOT suitable for production use.
 * - No formal security proofs exist for the combined SLSS+TDD+EGRW construction
 * - Not reviewed by the academic cryptographic community
 * - JavaScript runtime cannot guarantee constant-time execution
 *
 * This benchmark compares an experimental research library (kMOSAIC)
 * against production-ready, battle-tested implementations (X25519/Ed25519).
 */

import * as crypto from 'crypto'
import {
  kemGenerateKeyPair,
  encapsulate,
  decapsulate,
  signGenerateKeyPair,
  sign,
  verify,
  SecurityLevel,
} from '../src/index.ts'

// =============================================================================
// Benchmark Configuration
// =============================================================================

const ITERATIONS = {
  keyGen: 10,
  kemOps: 50,
  signOps: 50,
}

interface BenchmarkResult {
  operation: string
  implementation: string
  iterations: number
  totalMs: number
  avgMs: number
  opsPerSec: number
}

// =============================================================================
// Utility Functions
// =============================================================================

async function benchmark(
  name: string,
  impl: string,
  iterations: number,
  fn: () => Promise<void> | void,
): Promise<BenchmarkResult> {
  // Warmup
  for (let i = 0; i < Math.min(3, iterations); i++) {
    await fn()
  }

  // Actual benchmark
  const start = performance.now()
  for (let i = 0; i < iterations; i++) {
    await fn()
  }
  const totalMs = performance.now() - start

  return {
    operation: name,
    implementation: impl,
    iterations,
    totalMs,
    avgMs: totalMs / iterations,
    opsPerSec: (iterations / totalMs) * 1000,
  }
}

function formatResult(result: BenchmarkResult): string {
  return `${result.avgMs.toFixed(3).padStart(10)} ms/op | ${result.opsPerSec.toFixed(1).padStart(8)} ops/sec`
}

function printComparison(mosaic: BenchmarkResult, node: BenchmarkResult) {
  const ratio = mosaic.avgMs / node.avgMs
  const faster = ratio < 1 ? 'kMOSAIC' : 'Node.js'
  const factor = ratio < 1 ? (1 / ratio).toFixed(1) : ratio.toFixed(1)
  console.log(`  Comparison: ${faster} is ${factor}x faster`)
}

// =============================================================================
// Node.js X25519 KEM Implementation
// =============================================================================

interface X25519KeyPair {
  publicKey: Buffer
  privateKey: crypto.KeyObject
}

interface X25519Ciphertext {
  ephemeralPublic: Buffer
  sharedSecret: Buffer
}

function x25519KeyGen(): X25519KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519')
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }),
    privateKey,
  }
}

function x25519Encapsulate(recipientPublicKey: Buffer): X25519Ciphertext {
  // Generate ephemeral key pair
  const { publicKey: ephemeralPublic, privateKey: ephemeralPrivate } =
    crypto.generateKeyPairSync('x25519')

  // Import recipient's public key
  const recipientKey = crypto.createPublicKey({
    key: recipientPublicKey,
    format: 'der',
    type: 'spki',
  })

  // Derive shared secret
  const sharedSecret = crypto.diffieHellman({
    privateKey: ephemeralPrivate,
    publicKey: recipientKey,
  })

  // Hash the shared secret (like a proper KEM)
  const finalSecret = crypto.createHash('sha256').update(sharedSecret).digest()

  return {
    ephemeralPublic: ephemeralPublic.export({ type: 'spki', format: 'der' }),
    sharedSecret: finalSecret,
  }
}

function x25519Decapsulate(
  ciphertext: X25519Ciphertext,
  privateKey: crypto.KeyObject,
): Buffer {
  const ephemeralKey = crypto.createPublicKey({
    key: ciphertext.ephemeralPublic,
    format: 'der',
    type: 'spki',
  })

  const sharedSecret = crypto.diffieHellman({
    privateKey,
    publicKey: ephemeralKey,
  })

  return crypto.createHash('sha256').update(sharedSecret).digest()
}

// =============================================================================
// Node.js Ed25519 Signature Implementation
// =============================================================================

interface Ed25519KeyPair {
  publicKey: Buffer
  privateKey: crypto.KeyObject
}

function ed25519KeyGen(): Ed25519KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }),
    privateKey,
  }
}

function ed25519Sign(
  message: Uint8Array,
  privateKey: crypto.KeyObject,
): Buffer {
  return crypto.sign(null, message, privateKey)
}

function ed25519Verify(
  message: Uint8Array,
  signature: Buffer,
  publicKey: Buffer,
): boolean {
  const key = crypto.createPublicKey({
    key: publicKey,
    format: 'der',
    type: 'spki',
  })
  return crypto.verify(null, message, key, signature)
}

// =============================================================================
// Benchmark Suite
// =============================================================================

async function runBenchmarks() {
  console.log(
    '╔══════════════════════════════════════════════════════════════════════════╗',
  )
  console.log(
    '║              kMOSAIC vs Node.js Crypto Benchmark                          ║',
  )
  console.log(
    '║  Post-Quantum (kMOSAIC) vs Classical (X25519/Ed25519)                     ║',
  )
  console.log(
    '╚══════════════════════════════════════════════════════════════════════════╝\n',
  )

  console.log(
    '⚠️  SECURITY NOTICE: kMOSAIC is EXPERIMENTAL - not for production use!',
  )
  console.log(
    '   Comparing research library vs battle-tested implementations.\n',
  )

  const results: BenchmarkResult[] = []

  // -------------------------------------------------------------------------
  // KEM Key Generation
  // -------------------------------------------------------------------------
  console.log('📊 KEM Key Generation')
  console.log('─'.repeat(60))

  const mosaicKeyGenResult = await benchmark(
    'KEM KeyGen',
    'kMOSAIC',
    ITERATIONS.keyGen,
    async () => {
      await kemGenerateKeyPair(SecurityLevel.MOS_128)
    },
  )
  results.push(mosaicKeyGenResult)
  console.log(`  kMOSAIC:  ${formatResult(mosaicKeyGenResult)}`)

  const nodeKeyGenResult = await benchmark(
    'KEM KeyGen',
    'X25519',
    ITERATIONS.keyGen,
    () => {
      x25519KeyGen()
    },
  )
  results.push(nodeKeyGenResult)
  console.log(`  X25519:  ${formatResult(nodeKeyGenResult)}`)
  printComparison(mosaicKeyGenResult, nodeKeyGenResult)
  console.log()

  // -------------------------------------------------------------------------
  // KEM Encapsulation
  // -------------------------------------------------------------------------
  console.log('📊 KEM Encapsulation')
  console.log('─'.repeat(60))

  // Pre-generate keys for encapsulation tests
  const mosaicKemKeys = await kemGenerateKeyPair(SecurityLevel.MOS_128)
  const nodeKemKeys = x25519KeyGen()

  const mosaicEncapResult = await benchmark(
    'KEM Encap',
    'kMOSAIC',
    ITERATIONS.kemOps,
    async () => {
      await encapsulate(mosaicKemKeys.publicKey)
    },
  )
  results.push(mosaicEncapResult)
  console.log(`  kMOSAIC:  ${formatResult(mosaicEncapResult)}`)

  const nodeEncapResult = await benchmark(
    'KEM Encap',
    'X25519',
    ITERATIONS.kemOps,
    () => {
      x25519Encapsulate(nodeKemKeys.publicKey)
    },
  )
  results.push(nodeEncapResult)
  console.log(`  X25519:  ${formatResult(nodeEncapResult)}`)
  printComparison(mosaicEncapResult, nodeEncapResult)
  console.log()

  // -------------------------------------------------------------------------
  // KEM Decapsulation
  // -------------------------------------------------------------------------
  console.log('📊 KEM Decapsulation')
  console.log('─'.repeat(60))

  // Pre-generate ciphertexts
  const mosaicCiphertext = await encapsulate(mosaicKemKeys.publicKey)
  const nodeCiphertext = x25519Encapsulate(nodeKemKeys.publicKey)

  const mosaicDecapResult = await benchmark(
    'KEM Decap',
    'kMOSAIC',
    ITERATIONS.kemOps,
    async () => {
      await decapsulate(
        mosaicCiphertext.ciphertext,
        mosaicKemKeys.secretKey,
        mosaicKemKeys.publicKey,
      )
    },
  )
  results.push(mosaicDecapResult)
  console.log(`  kMOSAIC:  ${formatResult(mosaicDecapResult)}`)

  const nodeDecapResult = await benchmark(
    'KEM Decap',
    'X25519',
    ITERATIONS.kemOps,
    () => {
      x25519Decapsulate(nodeCiphertext, nodeKemKeys.privateKey)
    },
  )
  results.push(nodeDecapResult)
  console.log(`  X25519:  ${formatResult(nodeDecapResult)}`)
  printComparison(mosaicDecapResult, nodeDecapResult)
  console.log()

  // -------------------------------------------------------------------------
  // Signature Key Generation
  // -------------------------------------------------------------------------
  console.log('📊 Signature Key Generation')
  console.log('─'.repeat(60))

  const mosaicSignKeyGenResult = await benchmark(
    'Sign KeyGen',
    'kMOSAIC',
    ITERATIONS.keyGen,
    async () => {
      await signGenerateKeyPair(SecurityLevel.MOS_128)
    },
  )
  results.push(mosaicSignKeyGenResult)
  console.log(`  kMOSAIC:   ${formatResult(mosaicSignKeyGenResult)}`)

  const nodeSignKeyGenResult = await benchmark(
    'Sign KeyGen',
    'Ed25519',
    ITERATIONS.keyGen,
    () => {
      ed25519KeyGen()
    },
  )
  results.push(nodeSignKeyGenResult)
  console.log(`  Ed25519:  ${formatResult(nodeSignKeyGenResult)}`)
  printComparison(mosaicSignKeyGenResult, nodeSignKeyGenResult)
  console.log()

  // -------------------------------------------------------------------------
  // Signing
  // -------------------------------------------------------------------------
  console.log('📊 Signing')
  console.log('─'.repeat(60))

  const message = new TextEncoder().encode(
    'Benchmark message for signature testing - kMOSAIC vs Ed25519',
  )
  const mosaicSignKeys = await signGenerateKeyPair(SecurityLevel.MOS_128)
  const nodeSignKeys = ed25519KeyGen()

  const mosaicSignResult = await benchmark(
    'Sign',
    'kMOSAIC',
    ITERATIONS.signOps,
    async () => {
      await sign(message, mosaicSignKeys.secretKey, mosaicSignKeys.publicKey)
    },
  )
  results.push(mosaicSignResult)
  console.log(`  kMOSAIC:   ${formatResult(mosaicSignResult)}`)

  const nodeSignResult = await benchmark(
    'Sign',
    'Ed25519',
    ITERATIONS.signOps,
    () => {
      ed25519Sign(message, nodeSignKeys.privateKey)
    },
  )
  results.push(nodeSignResult)
  console.log(`  Ed25519:  ${formatResult(nodeSignResult)}`)
  printComparison(mosaicSignResult, nodeSignResult)
  console.log()

  // -------------------------------------------------------------------------
  // Verification
  // -------------------------------------------------------------------------
  console.log('📊 Verification')
  console.log('─'.repeat(60))

  const mosaicSig = await sign(
    message,
    mosaicSignKeys.secretKey,
    mosaicSignKeys.publicKey,
  )
  const nodeSig = ed25519Sign(message, nodeSignKeys.privateKey)

  const mosaicVerifyResult = await benchmark(
    'Verify',
    'kMOSAIC',
    ITERATIONS.signOps,
    async () => {
      await verify(message, mosaicSig, mosaicSignKeys.publicKey)
    },
  )
  results.push(mosaicVerifyResult)
  console.log(`  kMOSAIC:   ${formatResult(mosaicVerifyResult)}`)

  const nodeVerifyResult = await benchmark(
    'Verify',
    'Ed25519',
    ITERATIONS.signOps,
    () => {
      ed25519Verify(message, nodeSig, nodeSignKeys.publicKey)
    },
  )
  results.push(nodeVerifyResult)
  console.log(`  Ed25519:  ${formatResult(nodeVerifyResult)}`)
  printComparison(mosaicVerifyResult, nodeVerifyResult)
  console.log()

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  console.log('═'.repeat(76))
  console.log('\n📋 SUMMARY\n')

  console.log(
    '┌─────────────────────┬─────────────┬─────────────┬──────────────┐',
  )
  console.log(
    '│ Operation           │ kMOSAIC (ms) │ Node.js (ms)│ Ratio        │',
  )
  console.log(
    '├─────────────────────┼─────────────┼─────────────┼──────────────┤',
  )

  const pairs = [
    ['KEM KeyGen', mosaicKeyGenResult, nodeKeyGenResult],
    ['KEM Encapsulate', mosaicEncapResult, nodeEncapResult],
    ['KEM Decapsulate', mosaicDecapResult, nodeDecapResult],
    ['Sign KeyGen', mosaicSignKeyGenResult, nodeSignKeyGenResult],
    ['Sign', mosaicSignResult, nodeSignResult],
    ['Verify', mosaicVerifyResult, nodeVerifyResult],
  ] as const

  for (const [name, mosaic, node] of pairs) {
    const ratio = mosaic.avgMs / node.avgMs
    const ratioStr =
      ratio > 1
        ? `${ratio.toFixed(1)}x slower`
        : `${(1 / ratio).toFixed(1)}x faster`
    console.log(
      `│ ${name.padEnd(19)} │ ${mosaic.avgMs.toFixed(3).padStart(11)} │ ${node.avgMs
        .toFixed(3)
        .padStart(11)} │ ${ratioStr.padStart(12)} │`,
    )
  }

  console.log(
    '└─────────────────────┴─────────────┴─────────────┴──────────────┘',
  )

  // -------------------------------------------------------------------------
  // Key Size Comparison
  // -------------------------------------------------------------------------
  console.log('\n📦 KEY & SIGNATURE SIZES\n')

  console.log('┌─────────────────────┬─────────────┬─────────────┐')
  console.log('│ Component           │ kMOSAIC      │ Classical   │')
  console.log('├─────────────────────┼─────────────┼─────────────┤')
  console.log(
    `│ KEM Public Key      │ ~${(7500).toString().padStart(6)} B │ ${(44).toString().padStart(8)} B │`,
  )
  console.log(
    `│ KEM Ciphertext      │ ~${(7800).toString().padStart(6)} B │ ${(76).toString().padStart(8)} B │`,
  )
  console.log(
    `│ Signature           │ ~${(7400).toString().padStart(6)} B │ ${(64).toString().padStart(8)} B │`,
  )
  console.log('└─────────────────────┴─────────────┴─────────────┘')

  console.log('\n💡 NOTES:')
  console.log(
    '  • kMOSAIC provides post-quantum security (resistant to quantum attacks)',
  )
  console.log(
    '  • X25519/Ed25519 are classical algorithms (vulnerable to quantum computers)',
  )
  console.log(
    '  • kMOSAIC combines 3 independent hard problems for defense-in-depth',
  )
  console.log(
    '  • Size/speed tradeoff is typical for post-quantum cryptography',
  )
  console.log('')
  console.log('🛡️  SECURITY MITIGATIONS (kMOSAIC):')
  console.log('  • Native timingSafeEqual for constant-time comparisons')
  console.log('  • Native SHAKE256/SHA3-256 via Node.js crypto')
  console.log('  • Timing attack padding (25-50ms minimum for signatures)')
  console.log('  • Entropy validation for seed generation')
  console.log('  • Implicit rejection in KEM decapsulation\n')
}

// Run benchmarks
runBenchmarks().catch(console.error)
