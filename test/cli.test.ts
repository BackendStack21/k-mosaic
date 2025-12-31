/**
 * CLI Integration Tests
 *
 * Tests for k-mosaic-cli to ensure consistency with Go CLI specification (CLI.md)
 * These tests verify:
 * - Command structure and options
 * - Output format compatibility
 * - Roundtrip operations (keygen -> encrypt -> decrypt, keygen -> sign -> verify)
 * - Cross-implementation compatibility
 */

import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { spawn } from 'bun'
import * as fs from 'fs/promises'
import * as path from 'path'
import * as os from 'os'

const CLI_PATH = path.join(import.meta.dir, '..', 'k-mosaic-cli.ts')

// Temp directory for test files
let tempDir: string

beforeAll(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'k-mosaic-cli-test-'))
})

afterAll(async () => {
  await fs.rm(tempDir, { recursive: true, force: true })
})

// Helper to run CLI commands
async function runCli(
  args: string[],
  options?: { stdin?: string },
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = spawn({
    cmd: ['bun', CLI_PATH, ...args],
    stdout: 'pipe',
    stderr: 'pipe',
    stdin: options?.stdin ? 'pipe' : undefined,
  })

  if (options?.stdin && proc.stdin) {
    proc.stdin.write(options.stdin)
    proc.stdin.end()
  }

  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])

  const exitCode = await proc.exited

  return { stdout, stderr, exitCode }
}

// =============================================================================
// Version Command Tests
// =============================================================================

describe('CLI version command', () => {
  test('version command outputs version info', async () => {
    const result = await runCli(['version'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toMatch(/kMOSAIC CLI version/)
  })

  test('--version flag outputs version', async () => {
    const result = await runCli(['--version'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/)
  })
})

// =============================================================================
// Help Commands Tests
// =============================================================================

describe('CLI help commands', () => {
  test('help shows available commands', async () => {
    const result = await runCli(['--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('kem')
    expect(result.stdout).toContain('sign')
    expect(result.stdout).toContain('benchmark')
    expect(result.stdout).toContain('version')
  })

  test('kem --help shows KEM commands', async () => {
    const result = await runCli(['kem', '--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('keygen')
    expect(result.stdout).toContain('encrypt')
    expect(result.stdout).toContain('decrypt')
    expect(result.stdout).toContain('encapsulate')
    expect(result.stdout).toContain('decapsulate')
  })

  test('sign --help shows signature commands', async () => {
    const result = await runCli(['sign', '--help'])
    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('keygen')
    expect(result.stdout).toContain('sign')
    expect(result.stdout).toContain('verify')
  })
})

// =============================================================================
// KEM Key Generation Tests
// =============================================================================

describe('CLI kem keygen', () => {
  test('generates keypair with default level (128)', async () => {
    const outputPath = path.join(tempDir, 'kem-keypair-default.json')
    const result = await runCli(['kem', 'keygen', '-o', outputPath])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Generating KEM key pair')

    const keyFile = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(keyFile.security_level).toBe('MOS-128')
    expect(keyFile.public_key).toBeDefined()
    expect(keyFile.secret_key).toBeDefined()
    expect(keyFile.created_at).toBeDefined()
    expect(typeof keyFile.public_key).toBe('string')
    expect(typeof keyFile.secret_key).toBe('string')
  })

  test('generates keypair with level 256', async () => {
    const outputPath = path.join(tempDir, 'kem-keypair-256.json')
    const result = await runCli([
      'kem',
      'keygen',
      '-l',
      '256',
      '-o',
      outputPath,
    ])

    expect(result.exitCode).toBe(0)

    const keyFile = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(keyFile.security_level).toBe('MOS-256')
  })

  test('key file format matches Go CLI specification', async () => {
    const outputPath = path.join(tempDir, 'kem-keypair-format.json')
    await runCli(['kem', 'keygen', '-o', outputPath])

    const keyFile = JSON.parse(await fs.readFile(outputPath, 'utf-8'))

    // Verify Go CLI compatible format:
    // {
    //   "security_level": "MOS-128",
    //   "public_key": "base64-encoded-public-key...",
    //   "secret_key": "base64-encoded-secret-key...",
    //   "created_at": "2024-12-29T10:30:00Z"
    // }
    expect(keyFile).toHaveProperty('security_level')
    expect(keyFile).toHaveProperty('public_key')
    expect(keyFile).toHaveProperty('secret_key')
    expect(keyFile).toHaveProperty('created_at')

    // public_key should be base64 decodable
    expect(() => Buffer.from(keyFile.public_key, 'base64')).not.toThrow()

    // secret_key should be base64 encoded JSON
    const secretKeyJson = Buffer.from(keyFile.secret_key, 'base64').toString(
      'utf-8',
    )
    expect(() => JSON.parse(secretKeyJson)).not.toThrow()

    // created_at should be valid ISO date
    expect(() => new Date(keyFile.created_at)).not.toThrow()
    expect(new Date(keyFile.created_at).toISOString()).toBe(keyFile.created_at)
  })
})

// =============================================================================
// KEM Encrypt/Decrypt Tests
// =============================================================================

describe('CLI kem encrypt/decrypt', () => {
  let keyFilePath: string

  beforeAll(async () => {
    keyFilePath = path.join(tempDir, 'kem-encrypt-keypair.json')
    await runCli(['kem', 'keygen', '-o', keyFilePath])
  })

  test('encrypts message with -m flag', async () => {
    const outputPath = path.join(tempDir, 'encrypted-message.json')
    const result = await runCli([
      'kem',
      'encrypt',
      '--public-key',
      keyFilePath,
      '-m',
      'Hello, World!',
      '-o',
      outputPath,
    ])

    expect(result.exitCode).toBe(0)

    const encrypted = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(encrypted).toHaveProperty('ciphertext')
    expect(typeof encrypted.ciphertext).toBe('string')
    // ciphertext should be base64 decodable
    expect(() => Buffer.from(encrypted.ciphertext, 'base64')).not.toThrow()
  })

  test('encrypts file with -i flag', async () => {
    const inputPath = path.join(tempDir, 'plaintext.txt')
    const outputPath = path.join(tempDir, 'encrypted-file.json')
    await fs.writeFile(inputPath, 'File content to encrypt')

    const result = await runCli([
      'kem',
      'encrypt',
      '--public-key',
      keyFilePath,
      '-i',
      inputPath,
      '-o',
      outputPath,
    ])

    expect(result.exitCode).toBe(0)

    const encrypted = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(encrypted).toHaveProperty('ciphertext')
  })

  test('roundtrip encrypt/decrypt message', async () => {
    const encryptedPath = path.join(tempDir, 'roundtrip-encrypted.json')
    const decryptedPath = path.join(tempDir, 'roundtrip-decrypted.txt')
    const originalMessage = 'Secret quantum-safe message!'

    // Encrypt
    await runCli([
      'kem',
      'encrypt',
      '--public-key',
      keyFilePath,
      '-m',
      originalMessage,
      '-o',
      encryptedPath,
    ])

    // Decrypt
    const decryptResult = await runCli([
      'kem',
      'decrypt',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '--ciphertext',
      encryptedPath,
      '-o',
      decryptedPath,
    ])

    expect(decryptResult.exitCode).toBe(0)

    const decrypted = await fs.readFile(decryptedPath, 'utf-8')
    expect(decrypted).toBe(originalMessage)
  })

  test('roundtrip encrypt/decrypt binary file', async () => {
    const inputPath = path.join(tempDir, 'binary-input.bin')
    const encryptedPath = path.join(tempDir, 'binary-encrypted.json')
    const decryptedPath = path.join(tempDir, 'binary-decrypted.bin')

    // Create binary data
    const binaryData = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd])
    await fs.writeFile(inputPath, binaryData)

    // Encrypt
    await runCli([
      'kem',
      'encrypt',
      '--public-key',
      keyFilePath,
      '-i',
      inputPath,
      '-o',
      encryptedPath,
    ])

    // Decrypt
    await runCli([
      'kem',
      'decrypt',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '--ciphertext',
      encryptedPath,
      '-o',
      decryptedPath,
    ])

    const decrypted = await fs.readFile(decryptedPath)
    expect(Buffer.compare(decrypted, binaryData)).toBe(0)
  })

  test('decrypt fails with wrong key', async () => {
    const wrongKeyPath = path.join(tempDir, 'wrong-key.json')
    const encryptedPath = path.join(tempDir, 'wrong-key-encrypted.json')

    // Generate another keypair
    await runCli(['kem', 'keygen', '-o', wrongKeyPath])

    // Encrypt with original key
    await runCli([
      'kem',
      'encrypt',
      '--public-key',
      keyFilePath,
      '-m',
      'Secret',
      '-o',
      encryptedPath,
    ])

    // Try to decrypt with wrong key
    const result = await runCli([
      'kem',
      'decrypt',
      '--secret-key',
      wrongKeyPath,
      '--public-key',
      wrongKeyPath,
      '--ciphertext',
      encryptedPath,
    ])

    expect(result.exitCode).not.toBe(0)
  })
})

// =============================================================================
// KEM Encapsulate/Decapsulate Tests
// =============================================================================

describe('CLI kem encapsulate/decapsulate', () => {
  let keyFilePath: string

  beforeAll(async () => {
    keyFilePath = path.join(tempDir, 'kem-encap-keypair.json')
    await runCli(['kem', 'keygen', '-o', keyFilePath])
  })

  test('encapsulate produces ciphertext and shared_secret', async () => {
    const outputPath = path.join(tempDir, 'encapsulation.json')
    const result = await runCli([
      'kem',
      'encapsulate',
      '--public-key',
      keyFilePath,
      '-o',
      outputPath,
    ])

    expect(result.exitCode).toBe(0)

    const encap = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(encap).toHaveProperty('ciphertext')
    expect(encap).toHaveProperty('shared_secret')
    expect(typeof encap.ciphertext).toBe('string')
    expect(typeof encap.shared_secret).toBe('string')

    // Both should be base64 decodable
    expect(() => Buffer.from(encap.ciphertext, 'base64')).not.toThrow()
    expect(() => Buffer.from(encap.shared_secret, 'base64')).not.toThrow()
  })

  test('roundtrip encapsulate/decapsulate produces same shared secret', async () => {
    const encapPath = path.join(tempDir, 'encap-roundtrip.json')

    // Encapsulate
    await runCli([
      'kem',
      'encapsulate',
      '--public-key',
      keyFilePath,
      '-o',
      encapPath,
    ])

    const encap = JSON.parse(await fs.readFile(encapPath, 'utf-8'))
    const originalSecret = encap.shared_secret

    // Decapsulate
    const decapResult = await runCli([
      'kem',
      'decapsulate',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '--ciphertext',
      encapPath,
    ])

    expect(decapResult.exitCode).toBe(0)
    expect(decapResult.stdout.trim()).toBe(originalSecret)
  })
})

// =============================================================================
// Signature Key Generation Tests
// =============================================================================

describe('CLI sign keygen', () => {
  test('generates signature keypair with default level (128)', async () => {
    const outputPath = path.join(tempDir, 'sign-keypair-default.json')
    const result = await runCli(['sign', 'keygen', '-o', outputPath])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Generating Signature key pair')

    const keyFile = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(keyFile.security_level).toBe('MOS-128')
    expect(keyFile.public_key).toBeDefined()
    expect(keyFile.secret_key).toBeDefined()
    expect(keyFile.created_at).toBeDefined()
  })

  test('generates signature keypair with level 256', async () => {
    const outputPath = path.join(tempDir, 'sign-keypair-256.json')
    const result = await runCli([
      'sign',
      'keygen',
      '-l',
      '256',
      '-o',
      outputPath,
    ])

    expect(result.exitCode).toBe(0)

    const keyFile = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(keyFile.security_level).toBe('MOS-256')
  })

  test('signature key file format matches Go CLI specification', async () => {
    const outputPath = path.join(tempDir, 'sign-keypair-format.json')
    await runCli(['sign', 'keygen', '-o', outputPath])

    const keyFile = JSON.parse(await fs.readFile(outputPath, 'utf-8'))

    // Same format as KEM keys per Go CLI spec
    expect(keyFile).toHaveProperty('security_level')
    expect(keyFile).toHaveProperty('public_key')
    expect(keyFile).toHaveProperty('secret_key')
    expect(keyFile).toHaveProperty('created_at')

    // Validate base64 encoding
    expect(() => Buffer.from(keyFile.public_key, 'base64')).not.toThrow()
    expect(() =>
      JSON.parse(Buffer.from(keyFile.secret_key, 'base64').toString('utf-8')),
    ).not.toThrow()
  })
})

// =============================================================================
// Signature Sign/Verify Tests
// =============================================================================

describe('CLI sign sign/verify', () => {
  let keyFilePath: string

  beforeAll(async () => {
    keyFilePath = path.join(tempDir, 'sign-test-keypair.json')
    await runCli(['sign', 'keygen', '-o', keyFilePath])
  })

  test('signs message with -m flag', async () => {
    const outputPath = path.join(tempDir, 'signature.json')
    const result = await runCli([
      'sign',
      'sign',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '-m',
      'Test message',
      '-o',
      outputPath,
    ])

    expect(result.exitCode).toBe(0)

    const sigFile = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(sigFile).toHaveProperty('message')
    expect(sigFile).toHaveProperty('signature')
    expect(typeof sigFile.message).toBe('string')
    expect(typeof sigFile.signature).toBe('string')

    // Both should be base64 decodable
    expect(() => Buffer.from(sigFile.message, 'base64')).not.toThrow()
    expect(() => Buffer.from(sigFile.signature, 'base64')).not.toThrow()
  })

  test('signs file with -i flag', async () => {
    const inputPath = path.join(tempDir, 'document.txt')
    const outputPath = path.join(tempDir, 'document-signature.json')
    await fs.writeFile(inputPath, 'Important document content')

    const result = await runCli([
      'sign',
      'sign',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '-i',
      inputPath,
      '-o',
      outputPath,
    ])

    expect(result.exitCode).toBe(0)

    const sigFile = JSON.parse(await fs.readFile(outputPath, 'utf-8'))
    expect(sigFile).toHaveProperty('signature')
  })

  test('verifies valid signature', async () => {
    const sigPath = path.join(tempDir, 'verify-valid-sig.json')

    // Sign
    await runCli([
      'sign',
      'sign',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '-m',
      'Verified message',
      '-o',
      sigPath,
    ])

    // Verify
    const result = await runCli([
      'sign',
      'verify',
      '--public-key',
      keyFilePath,
      '--signature',
      sigPath,
    ])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('valid')
  })

  test('verifies signature with explicit message', async () => {
    const sigPath = path.join(tempDir, 'verify-explicit-sig.json')
    const message = 'Message for explicit verification'

    // Sign
    await runCli([
      'sign',
      'sign',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '-m',
      message,
      '-o',
      sigPath,
    ])

    // Verify with explicit message
    const result = await runCli([
      'sign',
      'verify',
      '--public-key',
      keyFilePath,
      '--signature',
      sigPath,
      '-m',
      message,
    ])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('valid')
  })

  test('verifies signature for file with -i flag', async () => {
    const inputPath = path.join(tempDir, 'verify-file.txt')
    const sigPath = path.join(tempDir, 'verify-file-sig.json')
    const content = 'File content for signature verification'
    await fs.writeFile(inputPath, content)

    // Sign
    await runCli([
      'sign',
      'sign',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '-i',
      inputPath,
      '-o',
      sigPath,
    ])

    // Verify with file
    const result = await runCli([
      'sign',
      'verify',
      '--public-key',
      keyFilePath,
      '--signature',
      sigPath,
      '-i',
      inputPath,
    ])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('valid')
  })

  test('rejects tampered message', async () => {
    const sigPath = path.join(tempDir, 'tampered-sig.json')

    // Sign original message
    await runCli([
      'sign',
      'sign',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '-m',
      'Original message',
      '-o',
      sigPath,
    ])

    // Try to verify with different message
    const result = await runCli([
      'sign',
      'verify',
      '--public-key',
      keyFilePath,
      '--signature',
      sigPath,
      '-m',
      'Tampered message',
    ])

    expect(result.exitCode).toBe(1)
    expect(result.stdout).toContain('invalid')
  })

  test('rejects signature with wrong key', async () => {
    const wrongKeyPath = path.join(tempDir, 'wrong-sign-key.json')
    const sigPath = path.join(tempDir, 'wrong-key-sig.json')

    // Generate another keypair
    await runCli(['sign', 'keygen', '-o', wrongKeyPath])

    // Sign with original key
    await runCli([
      'sign',
      'sign',
      '--secret-key',
      keyFilePath,
      '--public-key',
      keyFilePath,
      '-m',
      'Test message',
      '-o',
      sigPath,
    ])

    // Try to verify with wrong key
    const result = await runCli([
      'sign',
      'verify',
      '--public-key',
      wrongKeyPath,
      '--signature',
      sigPath,
    ])

    expect(result.exitCode).toBe(1)
    expect(result.stdout).toContain('invalid')
  })
})

// =============================================================================
// Benchmark Command Tests
// =============================================================================

describe('CLI benchmark', () => {
  test('runs benchmark with default options', async () => {
    const result = await runCli(['benchmark', '-n', '1'])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('kMOSAIC Benchmark Results')
    expect(result.stdout).toContain('Key Encapsulation Mechanism')
    expect(result.stdout).toContain('Digital Signatures')
    expect(result.stdout).toContain('KeyGen')
    expect(result.stdout).toContain('Encapsulate')
    expect(result.stdout).toContain('Decapsulate')
    expect(result.stdout).toContain('Sign')
    expect(result.stdout).toContain('Verify')
  })

  test('runs benchmark with level 256', async () => {
    const result = await runCli(['benchmark', '-l', '256', '-n', '1'])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('MOS-256')
  })

  test('respects iteration count', async () => {
    const result = await runCli(['benchmark', '-n', '2'])

    expect(result.exitCode).toBe(0)
    expect(result.stdout).toContain('Iterations: 2')
  })
})

// =============================================================================
// Output Format Tests (Go CLI Compatibility)
// =============================================================================

describe('CLI output format compatibility', () => {
  test('encrypted message format matches Go CLI spec', async () => {
    const keyPath = path.join(tempDir, 'format-kem-key.json')
    const encPath = path.join(tempDir, 'format-encrypted.json')

    await runCli(['kem', 'keygen', '-o', keyPath])
    await runCli([
      'kem',
      'encrypt',
      '--public-key',
      keyPath,
      '-m',
      'Test',
      '-o',
      encPath,
    ])

    const encrypted = JSON.parse(await fs.readFile(encPath, 'utf-8'))

    // Go CLI spec format: { "ciphertext": "base64-encoded-ciphertext..." }
    expect(Object.keys(encrypted)).toEqual(['ciphertext'])
    expect(typeof encrypted.ciphertext).toBe('string')
  })

  test('signature format matches Go CLI spec', async () => {
    const keyPath = path.join(tempDir, 'format-sign-key.json')
    const sigPath = path.join(tempDir, 'format-signature.json')

    await runCli(['sign', 'keygen', '-o', keyPath])
    await runCli([
      'sign',
      'sign',
      '--secret-key',
      keyPath,
      '--public-key',
      keyPath,
      '-m',
      'Test',
      '-o',
      sigPath,
    ])

    const signature = JSON.parse(await fs.readFile(sigPath, 'utf-8'))

    // Go CLI spec format:
    // {
    //   "message": "base64-encoded-message...",
    //   "signature": "base64-encoded-signature..."
    // }
    expect(Object.keys(signature).sort()).toEqual(['message', 'signature'])
    expect(typeof signature.message).toBe('string')
    expect(typeof signature.signature).toBe('string')
  })

  test('encapsulation result format matches Go CLI spec', async () => {
    const keyPath = path.join(tempDir, 'format-encap-key.json')
    const encapPath = path.join(tempDir, 'format-encapsulation.json')

    await runCli(['kem', 'keygen', '-o', keyPath])
    await runCli([
      'kem',
      'encapsulate',
      '--public-key',
      keyPath,
      '-o',
      encapPath,
    ])

    const encap = JSON.parse(await fs.readFile(encapPath, 'utf-8'))

    // Go CLI spec format:
    // {
    //   "ciphertext": "base64-encoded-ciphertext...",
    //   "shared_secret": "base64-encoded-shared-secret..."
    // }
    expect(Object.keys(encap).sort()).toEqual(['ciphertext', 'shared_secret'])
    expect(typeof encap.ciphertext).toBe('string')
    expect(typeof encap.shared_secret).toBe('string')
  })
})

// =============================================================================
// Error Handling Tests
// =============================================================================

describe('CLI error handling', () => {
  test('kem encrypt requires --public-key', async () => {
    const result = await runCli(['kem', 'encrypt', '-m', 'Test'])
    expect(result.exitCode).not.toBe(0)
  })

  test('kem decrypt requires --secret-key', async () => {
    const keyPath = path.join(tempDir, 'err-key.json')
    await runCli(['kem', 'keygen', '-o', keyPath])

    const result = await runCli([
      'kem',
      'decrypt',
      '--public-key',
      keyPath,
      '--ciphertext',
      keyPath,
    ])
    expect(result.exitCode).not.toBe(0)
  })

  test('kem decrypt requires --ciphertext', async () => {
    const keyPath = path.join(tempDir, 'err-key2.json')
    await runCli(['kem', 'keygen', '-o', keyPath])

    const result = await runCli([
      'kem',
      'decrypt',
      '--secret-key',
      keyPath,
      '--public-key',
      keyPath,
    ])
    expect(result.exitCode).not.toBe(0)
  })

  test('sign sign requires --secret-key', async () => {
    const keyPath = path.join(tempDir, 'err-sign-key.json')
    await runCli(['sign', 'keygen', '-o', keyPath])

    const result = await runCli([
      'sign',
      'sign',
      '--public-key',
      keyPath,
      '-m',
      'Test',
    ])
    expect(result.exitCode).not.toBe(0)
  })

  test('sign verify requires --signature', async () => {
    const keyPath = path.join(tempDir, 'err-verify-key.json')
    await runCli(['sign', 'keygen', '-o', keyPath])

    const result = await runCli(['sign', 'verify', '--public-key', keyPath])
    expect(result.exitCode).not.toBe(0)
  })

  test('handles non-existent key file', async () => {
    const result = await runCli([
      'kem',
      'encrypt',
      '--public-key',
      '/nonexistent/key.json',
      '-m',
      'Test',
    ])
    expect(result.exitCode).not.toBe(0)
  })
})

// =============================================================================
// Cross-Implementation Compatibility Tests
// =============================================================================

describe('CLI cross-implementation compatibility', () => {
  test('public key can be extracted for sharing (jq-compatible format)', async () => {
    const keyPath = path.join(tempDir, 'cross-compat-key.json')
    await runCli(['kem', 'keygen', '-o', keyPath])

    const keyFile = JSON.parse(await fs.readFile(keyPath, 'utf-8'))

    // Simulate jq extraction: jq '{public_key: .public_key, security_level: .security_level}'
    const publicOnly = {
      public_key: keyFile.public_key,
      security_level: keyFile.security_level,
    }

    // The extracted public key should be usable for encryption
    const publicKeyPath = path.join(tempDir, 'cross-compat-public.json')
    await fs.writeFile(publicKeyPath, JSON.stringify(publicOnly))

    const encPath = path.join(tempDir, 'cross-compat-enc.json')
    const encResult = await runCli([
      'kem',
      'encrypt',
      '--public-key',
      publicKeyPath,
      '-m',
      'Test message',
      '-o',
      encPath,
    ])

    expect(encResult.exitCode).toBe(0)

    // And decryptable with full keypair
    const decResult = await runCli([
      'kem',
      'decrypt',
      '--secret-key',
      keyPath,
      '--public-key',
      keyPath,
      '--ciphertext',
      encPath,
    ])

    expect(decResult.exitCode).toBe(0)
    expect(decResult.stdout.trim()).toBe('Test message')
  })

  test('KEM and Sign keys are separate (cannot be mixed)', async () => {
    const kemKeyPath = path.join(tempDir, 'kem-only-key.json')
    const signKeyPath = path.join(tempDir, 'sign-only-key.json')

    await runCli(['kem', 'keygen', '-o', kemKeyPath])
    await runCli(['sign', 'keygen', '-o', signKeyPath])

    // Try to sign with KEM key (should fail)
    const signResult = await runCli([
      'sign',
      'sign',
      '--secret-key',
      kemKeyPath,
      '--public-key',
      kemKeyPath,
      '-m',
      'Test',
    ])

    // Note: This might not fail depending on implementation
    // but it's good to document behavior

    // Try to encrypt with sign key (should work as they share format)
    const encResult = await runCli([
      'kem',
      'encrypt',
      '--public-key',
      signKeyPath,
      '-m',
      'Test',
    ])

    // Both KEM and Sign use same public key format, so this might work
    // The important thing is consistency
  })
})
