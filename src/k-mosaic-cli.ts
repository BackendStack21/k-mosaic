#!/usr/bin/env bun

import { Command } from 'commander'
import * as fs from 'fs/promises'
import {
  kemGenerateKeyPair,
  encapsulate,
  decapsulate,
  encrypt,
  decrypt,
  signGenerateKeyPair,
  sign,
  verify,
  serializeSignature,
  deserializeSignature,
  SecurityLevel,
  CLI_VERSION,
  MOSAICPublicKey,
  MOSAICSecretKey,
  MOSAICSignature,
  getParams,
  slssSerializePublicKey,
  tddSerializePublicKey,
  egrwSerializePublicKey,
  slssDeserializePublicKey,
  tddDeserializePublicKey,
  egrwDeserializePublicKey,
  type EncapsulationResult,
} from './index.js'
import { Buffer } from 'buffer'

const program = new Command()

program
  .name('k-mosaic-cli')
  .description('CLI for kMOSAIC post-quantum cryptographic library')
  .version(CLI_VERSION)

// Version command
program
  .command('version')
  .description('Show version information')
  .action(() => {
    console.log(`kMOSAIC CLI version ${CLI_VERSION}`)
  })

// #region Helpers
// Helper to write output
async function writeOutput(
  data: string | Uint8Array,
  outputPath?: string,
): Promise<void> {
  if (outputPath) {
    await fs.writeFile(outputPath, data)
    console.log(`Output written to ${outputPath}`)
  } else {
    process.stdout.write(data)
  }
}

// Helper to read input
async function readInput(
  inputPath?: string,
  message?: string,
): Promise<Buffer> {
  if (message) {
    return Buffer.from(message)
  }
  if (inputPath) {
    return fs.readFile(inputPath)
  }
  // read from stdin
  const chunks: Buffer[] = []
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks)
}

function toSerializable(obj: any): any {
  if (
    obj instanceof Uint8Array ||
    obj instanceof Int8Array ||
    obj instanceof Int32Array
  ) {
    return Array.from(obj)
  }
  if (Array.isArray(obj)) {
    return obj.map(toSerializable)
  }
  if (typeof obj === 'object' && obj !== null) {
    const newObj: any = {}
    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        newObj[key] = toSerializable(obj[key])
      }
    }
    return newObj
  }
  return obj
}

function customDeserializePublicKey(data: Uint8Array): MOSAICPublicKey {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  let offset = 0

  const levelLen = view.getUint32(offset, true)
  offset += 4
  const levelStr = new TextDecoder().decode(
    data.subarray(offset, offset + levelLen),
  )
  offset += levelLen

  const params = getParams(levelStr as SecurityLevel)

  const slssLen = view.getUint32(offset, true)
  offset += 4
  // Create a proper copy to ensure alignment for Int32Array views
  const slssData = new Uint8Array(slssLen)
  slssData.set(data.subarray(offset, offset + slssLen))
  const slss = slssDeserializePublicKey(slssData)
  offset += slssLen

  const tddLen = view.getUint32(offset, true)
  offset += 4
  const tddData = new Uint8Array(tddLen)
  tddData.set(data.subarray(offset, offset + tddLen))
  const tdd = tddDeserializePublicKey(tddData)
  offset += tddLen

  const egrwLen = view.getUint32(offset, true)
  offset += 4
  const egrwData = new Uint8Array(egrwLen)
  egrwData.set(data.subarray(offset, offset + egrwLen))
  const egrw = egrwDeserializePublicKey(egrwData)
  offset += egrwLen

  const binding = new Uint8Array(32)
  binding.set(data.subarray(offset, offset + 32))
  offset += 32

  return { slss, tdd, egrw, binding, params }
}

function secretKeyFromObject(obj: any): MOSAICSecretKey {
  // Go stores seed and publicKeyHash as base64 strings
  const seed =
    typeof obj.seed === 'string'
      ? new Uint8Array(Buffer.from(obj.seed, 'base64'))
      : new Uint8Array(obj.seed)
  const publicKeyHash =
    typeof obj.publicKeyHash === 'string'
      ? new Uint8Array(Buffer.from(obj.publicKeyHash, 'base64'))
      : new Uint8Array(obj.publicKeyHash)

  return {
    slss: { s: new Int8Array(obj.slss.s) },
    tdd: {
      factors: {
        a: obj.tdd.factors.a.map((arr: number[]) => new Int32Array(arr)),
        b: obj.tdd.factors.b.map((arr: number[]) => new Int32Array(arr)),
        c: obj.tdd.factors.c.map((arr: number[]) => new Int32Array(arr)),
      },
    },
    egrw: { walk: obj.egrw.walk },
    seed,
    publicKeyHash,
  }
}
// #endregion

// #region KEM Commands
const kem = program.command('kem').description('KEM operations')

kem
  .command('keygen')
  .description('Generate a new KEM key pair')
  .option('-l, --level <level>', 'Security level: 128 or 256', '128')
  .option('-o, --output <path>', 'Output file path (default: stdout)')
  .action(async (options: { level: string; output?: string }) => {
    const level =
      options.level === '256' ? SecurityLevel.MOS_256 : SecurityLevel.MOS_128
    console.log(`Generating KEM key pair for level ${level}...`)

    const { publicKey, secretKey } = await kemGenerateKeyPair(level)

    const serializableSecretKey = toSerializable(secretKey)

    // This is a custom serializePublicKey that follows what the Go CLI expects
    const slssBytes = slssSerializePublicKey(publicKey.slss)
    const tddBytes = tddSerializePublicKey(publicKey.tdd)
    const egrwBytes = egrwSerializePublicKey(publicKey.egrw)
    const levelStr = publicKey.params.level
    const levelBytes = new TextEncoder().encode(levelStr)
    const totalLen =
      4 +
      levelBytes.length +
      4 +
      slssBytes.length +
      4 +
      tddBytes.length +
      4 +
      egrwBytes.length +
      publicKey.binding.length
    const result = new Uint8Array(totalLen)
    const view = new DataView(result.buffer)
    let offset = 0
    view.setUint32(offset, levelBytes.length, true)
    offset += 4
    result.set(levelBytes, offset)
    offset += levelBytes.length
    view.setUint32(offset, slssBytes.length, true)
    offset += 4
    result.set(slssBytes, offset)
    offset += slssBytes.length
    view.setUint32(offset, tddBytes.length, true)
    offset += 4
    result.set(tddBytes, offset)
    offset += tddBytes.length
    view.setUint32(offset, egrwBytes.length, true)
    offset += 4
    result.set(egrwBytes, offset)
    offset += egrwBytes.length
    result.set(publicKey.binding, offset)

    const keyFile = {
      security_level: level,
      public_key: Buffer.from(result).toString('base64'),
      secret_key: Buffer.from(JSON.stringify(serializableSecretKey)).toString(
        'base64',
      ),
      created_at: new Date().toISOString(),
    }

    await writeOutput(JSON.stringify(keyFile, null, 2), options.output)
  })

kem
  .command('encrypt')
  .description('Encrypt a message using KEM')
  .requiredOption('-p, --public-key <path>', 'Path to public key file')
  .option('-m, --message <text>', 'Text message to encrypt')
  .option('-i, --input <path>', 'File to encrypt')
  .option('-o, --output <path>', 'Output file path')
  .action(
    async (options: {
      publicKey: string
      message?: string
      input?: string
      output?: string
    }) => {
      const pkFileData = await fs.readFile(options.publicKey, 'utf-8')
      const pkFile = JSON.parse(pkFileData)
      const publicKeyBytes = Buffer.from(pkFile.public_key, 'base64')
      const publicKey = customDeserializePublicKey(publicKeyBytes)

      const plaintext = await readInput(options.input, options.message)

      const ciphertext = await encrypt(plaintext, publicKey)

      const output = {
        ciphertext: Buffer.from(ciphertext).toString('base64'),
      }

      await writeOutput(JSON.stringify(output, null, 2), options.output)
    },
  )

kem
  .command('decrypt')
  .description('Decrypt a message using KEM')
  .requiredOption('-s, --secret-key <path>', 'Path to secret key file')
  .requiredOption('-p, --public-key <path>', 'Path to public key file')
  .requiredOption('-c, --ciphertext <path>', 'Path to ciphertext file')
  .option('-o, --output <path>', 'Output file path')
  .action(
    async (options: {
      secretKey: string
      publicKey: string
      ciphertext: string
      output?: string
    }) => {
      const pkFileData = await fs.readFile(options.publicKey, 'utf-8')
      const pkFile = JSON.parse(pkFileData)
      const publicKeyBytes = Buffer.from(pkFile.public_key, 'base64')
      const publicKey = customDeserializePublicKey(publicKeyBytes)

      const skFileData = await fs.readFile(options.secretKey, 'utf-8')
      const skFile = JSON.parse(skFileData)
      const secretKeyJson = Buffer.from(skFile.secret_key, 'base64').toString(
        'utf-8',
      )
      const secretKeyObj = JSON.parse(secretKeyJson)
      const secretKey = secretKeyFromObject(secretKeyObj)

      const ctFileData = await fs.readFile(options.ciphertext, 'utf-8')
      const ctFile = JSON.parse(ctFileData)
      const ciphertextBuffer = Buffer.from(ctFile.ciphertext, 'base64')
      // Create a properly aligned copy
      const ciphertextBytes = new Uint8Array(ciphertextBuffer.length)
      ciphertextBytes.set(ciphertextBuffer)

      const plaintext = await decrypt(ciphertextBytes, secretKey, publicKey)

      await writeOutput(plaintext, options.output)
    },
  )

const signCmd = program.command('sign').description('Signature operations')

signCmd
  .command('keygen')
  .description('Generate a new signing key pair')
  .option('-l, --level <level>', 'Security level: 128 or 256', '128')
  .option('-o, --output <path>', 'Output file path (default: stdout)')
  .action(async (options: { level: string; output?: string }) => {
    const level =
      options.level === '256' ? SecurityLevel.MOS_256 : SecurityLevel.MOS_128
    console.log(`Generating signing key pair for level ${level}...`)

    const { publicKey, secretKey } = await signGenerateKeyPair(level)

    const serializableSecretKey = toSerializable(secretKey)

    // This is a custom serializePublicKey that follows what the Go CLI expects
    const slssBytes = slssSerializePublicKey(publicKey.slss)
    const tddBytes = tddSerializePublicKey(publicKey.tdd)
    const egrwBytes = egrwSerializePublicKey(publicKey.egrw)
    const levelStr = publicKey.params.level
    const levelBytes = new TextEncoder().encode(levelStr)
    const totalLen =
      4 +
      levelBytes.length +
      4 +
      slssBytes.length +
      4 +
      tddBytes.length +
      4 +
      egrwBytes.length +
      publicKey.binding.length
    const result = new Uint8Array(totalLen)
    const view = new DataView(result.buffer)
    let offset = 0
    view.setUint32(offset, levelBytes.length, true)
    offset += 4
    result.set(levelBytes, offset)
    offset += levelBytes.length
    view.setUint32(offset, slssBytes.length, true)
    offset += 4
    result.set(slssBytes, offset)
    offset += slssBytes.length
    view.setUint32(offset, tddBytes.length, true)
    offset += 4
    result.set(tddBytes, offset)
    offset += tddBytes.length
    view.setUint32(offset, egrwBytes.length, true)
    offset += 4
    result.set(egrwBytes, offset)
    offset += egrwBytes.length
    result.set(publicKey.binding, offset)

    const keyFile = {
      security_level: level,
      public_key: Buffer.from(result).toString('base64'),
      secret_key: Buffer.from(JSON.stringify(serializableSecretKey)).toString(
        'base64',
      ),
      created_at: new Date().toISOString(),
    }

    await writeOutput(JSON.stringify(keyFile, null, 2), options.output)
  })

signCmd
  .command('sign')
  .description('Sign a message or file')
  .requiredOption('-s, --secret-key <path>', 'Path to secret key file')
  .requiredOption('-p, --public-key <path>', 'Path to public key file')
  .option('-m, --message <text>', 'Text message to sign')
  .option('-i, --input <path>', 'File to sign')
  .option('-o, --output <path>', 'Output file path')
  .action(
    async (options: {
      secretKey: string
      publicKey: string
      message?: string
      input?: string
      output?: string
    }) => {
      const pkFileData = await fs.readFile(options.publicKey, 'utf-8')
      const pkFile = JSON.parse(pkFileData)
      const publicKeyBytes = Buffer.from(pkFile.public_key, 'base64')
      const publicKey = customDeserializePublicKey(publicKeyBytes)

      const skFileData = await fs.readFile(options.secretKey, 'utf-8')
      const skFile = JSON.parse(skFileData)
      const secretKeyJson = Buffer.from(skFile.secret_key, 'base64').toString(
        'utf-8',
      )
      const secretKeyObj = JSON.parse(secretKeyJson)
      const secretKey = secretKeyFromObject(secretKeyObj)

      const message = await readInput(options.input, options.message)

      const signature = await sign(message, secretKey, publicKey)

      const output = {
        message: message.toString('base64'),
        signature: Buffer.from(serializeSignature(signature)).toString(
          'base64',
        ),
      }

      await writeOutput(JSON.stringify(output, null, 2), options.output)
    },
  )

signCmd
  .command('verify')
  .description('Verify a signature')
  .requiredOption('-p, --public-key <path>', 'Path to public key file')
  .requiredOption('-g, --signature <path>', 'Path to signature file')
  .option('-m, --message <text>', 'Original message')
  .option('-i, --input <file>', 'Original file')
  .action(
    async (options: {
      publicKey: string
      signature: string
      message?: string
      input?: string
    }) => {
      const pkFileData = await fs.readFile(options.publicKey, 'utf-8')
      const pkFile = JSON.parse(pkFileData)
      const publicKeyBytes = Buffer.from(pkFile.public_key, 'base64')
      const publicKey = customDeserializePublicKey(publicKeyBytes)

      const sigFileData = await fs.readFile(options.signature, 'utf-8')
      const sigFile = JSON.parse(sigFileData)

      let message: Buffer
      if (options.message || options.input) {
        message = await readInput(options.input, options.message)
      } else {
        message = Buffer.from(sigFile.message, 'base64')
      }

      const signatureBuffer = Buffer.from(sigFile.signature, 'base64')
      // Create a properly aligned copy for Int32Array views
      const signatureBytes = new Uint8Array(signatureBuffer.length)
      signatureBytes.set(signatureBuffer)
      const signature = deserializeSignature(signatureBytes)

      const isValid = await verify(message, signature, publicKey)

      if (isValid) {
        console.log('Signature is valid ✓')
        process.exit(0)
      } else {
        console.log('Signature is invalid ✗')
        process.exit(1)
      }
    },
  )

// #endregion

// #region Benchmark Command
program
  .command('benchmark')
  .description('Run performance benchmarks')
  .option('-n, --iterations <number>', 'Number of iterations', '10')
  .option('-l, --level <level>', 'Security level: 128 or 256', '128')
  .action(async (options: { level: string; iterations: string }) => {
    const level =
      options.level === '256' ? SecurityLevel.MOS_256 : SecurityLevel.MOS_128
    const iterations = parseInt(options.iterations, 10)
    console.log(`kMOSAIC Benchmark Results`)
    console.log(`=========================`)
    console.log(`Security Level: ${level}`)
    console.log(`Iterations: ${iterations}`)
    console.log(``)

    let total: number = 0,
      start: number = 0

    // KEM
    console.log(`Key Encapsulation Mechanism (KEM)`)
    console.log(`---------------------------------`)
    total = 0
    for (let i = 0; i < iterations; i++) {
      start = performance.now()
      await kemGenerateKeyPair(level)
      total += performance.now() - start
    }
    console.log(`  KeyGen:      ${(total / iterations).toFixed(2)}ms (avg)`)

    const { publicKey, secretKey } = await kemGenerateKeyPair(level)
    total = 0
    let ct: EncapsulationResult | undefined
    for (let i = 0; i < iterations; i++) {
      start = performance.now()
      ct = await encapsulate(publicKey)
      total += performance.now() - start
    }
    console.log(`  Encapsulate: ${(total / iterations).toFixed(2)}ms (avg)`)

    total = 0
    for (let i = 0; i < iterations; i++) {
      start = performance.now()
      await decapsulate(ct!.ciphertext, secretKey, publicKey)
      total += performance.now() - start
    }
    console.log(`  Decapsulate: ${(total / iterations).toFixed(2)}ms (avg)`)

    // Sign
    console.log(``)
    console.log(`Digital Signatures`)
    console.log(`------------------`)
    total = 0
    for (let i = 0; i < iterations; i++) {
      start = performance.now()
      await signGenerateKeyPair(level)
      total += performance.now() - start
    }
    console.log(`  KeyGen:      ${(total / iterations).toFixed(2)}ms (avg)`)

    const { publicKey: signPk, secretKey: signSk } =
      await signGenerateKeyPair(level)
    const message = Buffer.from('test message')
    let signature: MOSAICSignature | undefined
    total = 0
    for (let i = 0; i < iterations; i++) {
      start = performance.now()
      signature = await sign(message, signSk, signPk)
      total += performance.now() - start
    }
    console.log(`  Sign:        ${(total / iterations).toFixed(2)}ms (avg)`)

    total = 0
    for (let i = 0; i < iterations; i++) {
      start = performance.now()
      await verify(message, signature!, signPk)
      total += performance.now() - start
    }
    console.log(`  Verify:      ${(total / iterations).toFixed(2)}ms (avg)`)
  })
// #endregion

program.parse(process.argv)
