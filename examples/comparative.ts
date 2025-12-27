/**
 * Comparative Benchmark Script
 *
 * Validates the performance statistics documented in DEVELOPER_GUIDE.md
 * Uses Node.js compatible APIs (works with Bun)
 *
 * Run with:
 *   bun run examples/comparative.ts
 *   node --experimental-strip-types examples/comparative.ts
 */

import {
  kemGenerateKeyPair,
  encapsulate,
  decapsulate,
  signGenerateKeyPair,
  sign,
  verify,
  serializePublicKey,
  serializeCiphertext,
  serializeSignature,
  MOS_128,
  MOS_256,
  SecurityLevel,
} from '../src/index.ts'

// Benchmark configuration
const WARMUP_ITERATIONS = 5
const BENCHMARK_ITERATIONS = 20

// Helper to format bytes
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

// Helper to format time
function formatTime(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(2)} μs`
  if (ms < 1000) return `${ms.toFixed(2)} ms`
  return `${(ms / 1000).toFixed(2)} s`
}

// Benchmark runner
async function benchmark(
  name: string,
  fn: () => Promise<void>,
): Promise<number> {
  // Warmup
  for (let i = 0; i < WARMUP_ITERATIONS; i++) {
    await fn()
  }

  // Actual benchmark
  const times: number[] = []
  for (let i = 0; i < BENCHMARK_ITERATIONS; i++) {
    const start = performance.now()
    await fn()
    const end = performance.now()
    times.push(end - start)
  }

  // Calculate statistics
  const avg = times.reduce((a, b) => a + b, 0) / times.length
  return avg
}

// Size measurement helper
function measureSize(name: string, data: Uint8Array | object): number {
  let size: number
  if (data instanceof Uint8Array) {
    size = data.length
  } else {
    // For objects, serialize to JSON and measure
    const json = JSON.stringify(data)
    size = new TextEncoder().encode(json).length
  }
  return size
}

// KEM Benchmarks
async function benchmarkKEM(securityLevel: SecurityLevel, level: string) {
  console.log(`\n${'='.repeat(60)}`)
  console.log(`KEM Benchmarks - ${level}`)
  console.log('='.repeat(60))

  // Key Generation
  let keyPair: Awaited<ReturnType<typeof kemGenerateKeyPair>>
  const keygenTime = await benchmark('KEM KeyGen', async () => {
    keyPair = await kemGenerateKeyPair(securityLevel)
  })
  console.log(`✓ Key Generation:     ${formatTime(keygenTime)}`)

  // Measure key sizes
  keyPair = await kemGenerateKeyPair(securityLevel)
  const pkSize = measureSize(
    'Public Key',
    serializePublicKey(keyPair.publicKey),
  )
  const skSize = measureSize('Secret Key', keyPair.secretKey)
  console.log(`  Public Key Size:    ${formatBytes(pkSize)}`)
  console.log(`  Secret Key Size:    ${formatBytes(skSize)}`)

  // Encapsulation
  let ciphertext: Awaited<ReturnType<typeof encapsulate>>
  const encapTime = await benchmark('Encapsulate', async () => {
    ciphertext = await encapsulate(keyPair.publicKey)
  })
  console.log(`✓ Encapsulation:      ${formatTime(encapTime)}`)

  // Measure ciphertext size
  ciphertext = await encapsulate(keyPair.publicKey)
  const ctSize = measureSize(
    'Ciphertext',
    serializeCiphertext(ciphertext.ciphertext),
  )
  console.log(`  Ciphertext Size:    ${formatBytes(ctSize)}`)

  // Decapsulation
  const decapTime = await benchmark('Decapsulate', async () => {
    await decapsulate(
      ciphertext.ciphertext,
      keyPair.secretKey,
      keyPair.publicKey,
    )
  })
  console.log(`✓ Decapsulation:      ${formatTime(decapTime)}`)

  // Throughput calculations
  const encapThroughput = 1000 / encapTime
  const decapThroughput = 1000 / decapTime
  console.log(`\nThroughput:`)
  console.log(`  Encapsulations/sec: ${encapThroughput.toFixed(0)}`)
  console.log(`  Decapsulations/sec: ${decapThroughput.toFixed(0)}`)

  return {
    keygenTime,
    encapTime,
    decapTime,
    pkSize,
    skSize,
    ctSize,
  }
}

// Signature Benchmarks
async function benchmarkSign(securityLevel: SecurityLevel, level: string) {
  console.log(`\n${'='.repeat(60)}`)
  console.log(`Signature Benchmarks - ${level}`)
  console.log('='.repeat(60))

  // Key Generation
  let keyPair: Awaited<ReturnType<typeof signGenerateKeyPair>>
  const keygenTime = await benchmark('Sign KeyGen', async () => {
    keyPair = await signGenerateKeyPair(securityLevel)
  })
  console.log(`✓ Key Generation:     ${formatTime(keygenTime)}`)

  // Measure key sizes
  keyPair = await signGenerateKeyPair(securityLevel)
  const pkSize = measureSize('Public Key', keyPair.publicKey)
  const skSize = measureSize('Secret Key', keyPair.secretKey)
  console.log(`  Public Key Size:    ${formatBytes(pkSize)}`)
  console.log(`  Secret Key Size:    ${formatBytes(skSize)}`)

  // Test message
  const message = new TextEncoder().encode('Test message for benchmarking')

  // Signing
  let signature: Awaited<ReturnType<typeof sign>>
  const signTime = await benchmark('Sign', async () => {
    signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
  })
  console.log(`✓ Signing:            ${formatTime(signTime)}`)

  // Measure signature size
  signature = await sign(message, keyPair.secretKey, keyPair.publicKey)
  const sigSize = measureSize('Signature', serializeSignature(signature))
  console.log(`  Signature Size:     ${formatBytes(sigSize)}`)

  // Verification
  const verifyTime = await benchmark('Verify', async () => {
    await verify(message, signature, keyPair.publicKey)
  })
  console.log(`✓ Verification:       ${formatTime(verifyTime)}`)

  // Throughput calculations
  const signThroughput = 1000 / signTime
  const verifyThroughput = 1000 / verifyTime
  console.log(`\nThroughput:`)
  console.log(`  Signatures/sec:     ${signThroughput.toFixed(0)}`)
  console.log(`  Verifications/sec:  ${verifyThroughput.toFixed(0)}`)

  return {
    keygenTime,
    signTime,
    verifyTime,
    pkSize,
    skSize,
    sigSize,
  }
}

// Summary table
function printSummaryTable(
  mos128Kem: any,
  mos256Kem: any,
  mos128Sign: any,
  mos256Sign: any,
) {
  console.log(`\n${'='.repeat(80)}`)
  console.log('SUMMARY TABLE - Performance')
  console.log('='.repeat(80))

  console.log('\n┌─────────────────────┬──────────────┬──────────────┐')
  console.log('│ Operation           │ MOS_128      │ MOS_256      │')
  console.log('├─────────────────────┼──────────────┼──────────────┤')
  console.log(
    `│ KEM KeyGen          │ ${formatTime(mos128Kem.keygenTime).padEnd(12)} │ ${formatTime(
      mos256Kem.keygenTime,
    ).padEnd(12)} │`,
  )
  console.log(
    `│ KEM Encapsulate     │ ${formatTime(mos128Kem.encapTime).padEnd(12)} │ ${formatTime(
      mos256Kem.encapTime,
    ).padEnd(12)} │`,
  )
  console.log(
    `│ KEM Decapsulate     │ ${formatTime(mos128Kem.decapTime).padEnd(12)} │ ${formatTime(
      mos256Kem.decapTime,
    ).padEnd(12)} │`,
  )
  console.log('├─────────────────────┼──────────────┼──────────────┤')
  console.log(
    `│ Sign KeyGen         │ ${formatTime(mos128Sign.keygenTime).padEnd(12)} │ ${formatTime(
      mos256Sign.keygenTime,
    ).padEnd(12)} │`,
  )
  console.log(
    `│ Sign                │ ${formatTime(mos128Sign.signTime).padEnd(12)} │ ${formatTime(
      mos256Sign.signTime,
    ).padEnd(12)} │`,
  )
  console.log(
    `│ Verify              │ ${formatTime(mos128Sign.verifyTime).padEnd(12)} │ ${formatTime(
      mos256Sign.verifyTime,
    ).padEnd(12)} │`,
  )
  console.log('└─────────────────────┴──────────────┴──────────────┘')

  console.log(`\n${'='.repeat(80)}`)
  console.log('SUMMARY TABLE - Sizes')
  console.log('='.repeat(80))

  console.log('\n┌─────────────────────┬──────────────┬──────────────┐')
  console.log('│ Component           │ MOS_128      │ MOS_256      │')
  console.log('├─────────────────────┼──────────────┼──────────────┤')
  console.log(
    `│ Public Key (KEM)    │ ${formatBytes(mos128Kem.pkSize).padEnd(12)} │ ${formatBytes(
      mos256Kem.pkSize,
    ).padEnd(12)} │`,
  )
  console.log(
    `│ Public Key (Sign)   │ ${formatBytes(mos128Sign.pkSize).padEnd(12)} │ ${formatBytes(
      mos256Sign.pkSize,
    ).padEnd(12)} │`,
  )
  console.log(
    `│ Secret Key          │ ${formatBytes(mos128Kem.skSize).padEnd(12)} │ ${formatBytes(
      mos256Kem.skSize,
    ).padEnd(12)} │`,
  )
  console.log(
    `│ Ciphertext          │ ${formatBytes(mos128Kem.ctSize).padEnd(12)} │ ${formatBytes(
      mos256Kem.ctSize,
    ).padEnd(12)} │`,
  )
  console.log(
    `│ Signature           │ ${formatBytes(mos128Sign.sigSize).padEnd(12)} │ ${formatBytes(
      mos256Sign.sigSize,
    ).padEnd(12)} │`,
  )
  console.log('└─────────────────────┴──────────────┴──────────────┘')
}

// Main benchmark runner
async function main() {
  console.log('╔═══════════════════════════════════════════════════════════╗')
  console.log('║         kMOSAIC Comparative Performance Benchmark         ║')
  console.log('╚═══════════════════════════════════════════════════════════╝')

  console.log(`\nRuntime: ${typeof Bun !== 'undefined' ? 'Bun' : 'Node.js'}`)
  console.log(`Warmup iterations: ${WARMUP_ITERATIONS}`)
  console.log(`Benchmark iterations: ${BENCHMARK_ITERATIONS}`)
  console.log(`\nStarting benchmarks...`)

  try {
    // Benchmark MOS_128
    const mos128Kem = await benchmarkKEM(MOS_128.level, 'MOS_128')
    const mos128Sign = await benchmarkSign(MOS_128.level, 'MOS_128')

    // Benchmark MOS_256
    const mos256Kem = await benchmarkKEM(MOS_256.level, 'MOS_256')
    const mos256Sign = await benchmarkSign(MOS_256.level, 'MOS_256')

    // Print summary
    printSummaryTable(mos128Kem, mos256Kem, mos128Sign, mos256Sign)

    console.log(`\n${'='.repeat(80)}`)
    console.log('✓ Benchmark completed successfully!')
    console.log('='.repeat(80))
    console.log(
      '\nNote: Performance may vary based on hardware, runtime, and system load.',
    )
  } catch (error) {
    console.error('\n❌ Benchmark failed:', error)
    process.exit(1)
  }
}

// Run benchmarks
main().catch((error) => {
  console.error('Fatal error:', error)
  process.exit(1)
})
