# kMOSAIC - Post-Quantum Cryptographic Library

**Multi-Oracle Structured Algebraic Intractability Composition**

A novel post-quantum cryptographic library that combines three heterogeneous hard problems with cryptographic entanglement for defense-in-depth security.

> A faster Go-based implementation is available at [https://github.com/BackendStack21/k-mosaic-go](https://github.com/BackendStack21/k-mosaic-go)

## 🔐 Overview

kMOSAIC is an experimental post-quantum cryptography scheme designed with a unique approach: rather than relying on a single mathematical hard problem, it cryptographically entangles **three independent hard problems** from different mathematical domains:

1. **SLSS** (Sparse Lattice Subset Sum) - Combines the NP-hardness of subset sum with lattice-based cryptography
2. **TDD** (Tensor Decomposition Distinguishing) - Based on the computational hardness of tensor rank decomposition
3. **EGRW** (Expander Graph Random Walk) - Number-theoretic problem in Cayley graphs of SL(2, ℤ_p)

## 🛡️ Why kMOSAIC?

### The Problem: Lattice Monoculture

Current NIST post-quantum standards (ML-KEM/Kyber, ML-DSA/Dilithium) rely heavily on a single mathematical family: **Lattices**. If a breakthrough in lattice reduction algorithms occurs, the majority of the world's quantum-safe infrastructure could be compromised simultaneously.

### The Solution: Heterogeneous Hardness

kMOSAIC mitigates this risk through **Heterogeneous Hardness**. By combining three mathematically distinct problems (Lattices, Tensors, Graphs), kMOSAIC ensures that:

- Breaking one problem reveals **zero information** about the secret.
- Breaking two problems still reveals **zero information**.
- An attacker must solve **all three** problems to compromise the system.

This approach provides a robust hedge against unexpected cryptanalytic breakthroughs, similar to how the **SIKE** algorithm was broken in 2022.

## ✨ Key Features

- **Triple-redundant security**: An attacker must break ALL THREE problems simultaneously
- **IND-CCA2 secure KEM**: Fujisaki-Okamoto transform with implicit rejection
- **Multi-witness signatures**: Fiat-Shamir scheme proving knowledge of three entangled witnesses
- **Defense-in-depth**: Even if one problem is broken, the system remains secure
- **Bun/Node.js compatible**: Works with both Bun runtime and Node.js

## 📦 Installation

```bash
# Using Bun
bun add k-mosaic

# Using npm
npm install k-mosaic
```

## 🚀 Quick Start

### Key Encapsulation (KEM)

```typescript
import { kemGenerateKeyPair, encapsulate, decapsulate, MOS_128 } from 'k-mosaic'

// Generate key pair (MOS-128 or MOS-256)
const { publicKey, secretKey } = await kemGenerateKeyPair(MOS_128)

// Encapsulate a shared secret
const { ciphertext, sharedSecret } = await encapsulate(publicKey)

// Decapsulate to recover the shared secret
const recovered = await decapsulate(ciphertext, secretKey, publicKey)
// sharedSecret === recovered
```

### Hybrid Encryption

```typescript
import { kemGenerateKeyPair, encrypt, decrypt, MOS_128 } from 'k-mosaic'

const { publicKey, secretKey } = await kemGenerateKeyPair(MOS_128)

// Encrypt a message
const message = new TextEncoder().encode('Hello, post-quantum world!')
const encrypted = await encrypt(message, publicKey)

// Decrypt
const decrypted = await decrypt(encrypted, secretKey, publicKey)
console.log(new TextDecoder().decode(decrypted))
// "Hello, post-quantum world!"
```

### Digital Signatures

```typescript
import { signGenerateKeyPair, sign, verify, MOS_128 } from 'k-mosaic'

// Generate signing key pair
const { publicKey, secretKey } = await signGenerateKeyPair(MOS_128)

// Sign a message
const message = new TextEncoder().encode('Important document')
const signature = await sign(message, secretKey, publicKey)

// Verify signature
const isValid = await verify(message, signature, publicKey)
console.log(isValid) // true
```

## 💻 Command Line Interface

kMOSAIC includes a command-line interface for terminal-based cryptographic operations:

```bash
# Install globally
bun install -g k-mosaic

# Or use via npx
npx k-mosaic-cli --help
```

### CLI Examples

```bash
# KEM: Generate keys, encrypt, and decrypt
k-mosaic-cli kem keygen -l 128 -o keys.json
k-mosaic-cli kem encrypt -p keys.json -m "Secret message" -o enc.json
k-mosaic-cli kem decrypt -s keys.json -p keys.json -c enc.json

# Signatures: Generate keys, sign, and verify
k-mosaic-cli sign keygen -l 128 -o sign.json
k-mosaic-cli sign sign -s sign.json -p sign.json -m "Document" -o sig.json
k-mosaic-cli sign verify -p sign.json -g sig.json
```

The CLI supports:

- Key generation for both KEM and signatures
- File-based encryption/decryption
- Message signing and verification
- JSON output for easy integration with other tools

For complete CLI documentation, see [CLI.md](CLI.md).

## 🔒 Security Levels

| Level   | Post-Quantum Security | Use Case          |
| ------- | --------------------- | ----------------- |
| MOS-128 | ~128 bits             | Standard security |
| MOS-256 | ~256 bits             | High security     |

## 📚 Algorithm Details

### Cryptographic Entanglement

kMOSAIC uses XOR 3-of-3 secret sharing combined with hash-based binding commitments:

```
K = K₁ ⊕ K₂ ⊕ K₃
binding = H(SLSS_pk || TDD_pk || EGRW_pk)
```

All three shares are required to recover the secret, and the binding ensures the three problem instances are cryptographically linked.

> ⚠️ Implementation note: the library prefers native SHAKE256 (XOF) support. If the runtime lacks native SHAKE256, kMOSAIC falls back to a counter-mode SHA3-256 based construction which may not provide the same security margins as a native XOF. For production deployments, ensure your runtime supports SHAKE256 or use an environment that provides it.

### Hard Problems

#### SLSS (Sparse Lattice Subset Sum)

- Public: Matrix A ∈ ℤ_q^(m×n), target t = As
- Secret: Sparse vector s with Hamming weight w
- Security: Combines subset sum NP-hardness with LWE-style lattice hardness

#### TDD (Tensor Decomposition Distinguishing)

- Public: 3-tensor T ∈ ℤ_q^(n×n×n)
- Secret: Low-rank decomposition T = Σᵢ aᵢ ⊗ bᵢ ⊗ cᵢ
- Security: Tensor rank computation is NP-hard over finite fields

#### EGRW (Expander Graph Random Walk)

- Graph: Cayley graph of SL(2, ℤ_p) with 4 generators
- Public: Start vertex v_start, end vertex v_end
- Secret: Random walk path of length k
- Security: Related to discrete log in matrix groups

## 🛠️ API Reference

### Core Types & Parameters

```typescript
// Security levels
enum SecurityLevel {
  MOS_128 = 'MOS-128'  // 128-bit post-quantum security
  MOS_256 = 'MOS-256'  // 256-bit post-quantum security
}

// Parameter sets
getParams(level: SecurityLevel): MOSAICParams
validateParams(params: MOSAICParams): void

const MOS_128: MOSAICParams  // MOS-128 parameter set
const MOS_256: MOSAICParams  // MOS-256 parameter set
```

#### Parameter and Key Structures

```typescript
interface MOSAICParams {
  level: SecurityLevel
  slss: SLSSParams
  tdd: TDDParams
  egrw: EGRWParams
}

interface MOSAICPublicKey {
  slss: SLSSPublicKey
  tdd: TDDPublicKey
  egrw: EGRWPublicKey
  binding: Uint8Array // 32-byte cryptographic binding hash
  params: MOSAICParams
}

interface MOSAICSecretKey {
  slss: SLSSSecretKey
  tdd: TDDSecretKey
  egrw: EGRWSecretKey
  seed: Uint8Array // Original seed for implicit rejection
  publicKeyHash: Uint8Array
}

interface MOSAICKeyPair {
  publicKey: MOSAICPublicKey
  secretKey: MOSAICSecretKey
}

interface MOSAICCiphertext {
  c1: SLSSCiphertext
  c2: TDDCiphertext
  c3: EGRWCiphertext
  proof: Uint8Array
}

interface MOSAICSignature {
  commitment: Uint8Array // 32 bytes
  challenge: Uint8Array // 32 bytes
  response: Uint8Array // 64 bytes
}

interface EncapsulationResult {
  sharedSecret: Uint8Array
  ciphertext: MOSAICCiphertext
}

interface SecurityAnalysis {
  slss: { dimension: number; sparsity: number; estimatedSecurity: number }
  tdd: { tensorDim: number; rank: number; estimatedSecurity: number }
  egrw: { graphSize: number; walkLength: number; estimatedSecurity: number }
  combined: { estimatedSecurity: number; quantumSecurity: number }
}
```

### KEM Functions

```typescript
// Key generation
generateKeyPair(level?: SecurityLevel): Promise<MOSAICKeyPair>
generateKeyPairFromSeed(params: MOSAICParams, seed: Uint8Array): MOSAICKeyPair

// Encapsulation/Decapsulation
encapsulate(publicKey: MOSAICPublicKey): Promise<EncapsulationResult>
encapsulateDeterministic(
  publicKey: MOSAICPublicKey,
  ephemeralSecret: Uint8Array
): EncapsulationResult

decapsulate(
  ciphertext: MOSAICCiphertext,
  secretKey: MOSAICSecretKey,
  publicKey: MOSAICPublicKey
): Promise<Uint8Array>

// Hybrid encryption (message encryption with AES-256-GCM)
encrypt(plaintext: Uint8Array, publicKey: MOSAICPublicKey): Promise<Uint8Array>
decrypt(
  ciphertext: Uint8Array,
  secretKey: MOSAICSecretKey,
  publicKey: MOSAICPublicKey
): Promise<Uint8Array>

// Serialization
serializePublicKey(pk: MOSAICPublicKey): Uint8Array
deserializePublicKey(data: Uint8Array): MOSAICPublicKey
serializeCiphertext(ct: MOSAICCiphertext): Uint8Array
deserializeCiphertext(data: Uint8Array): MOSAICCiphertext

// Analysis
analyzePublicKey(publicKey: MOSAICPublicKey): SecurityAnalysis
```

### Signature Functions

```typescript
// Key generation
generateKeyPair(level?: SecurityLevel): Promise<MOSAICKeyPair>
generateKeyPairFromSeed(params: MOSAICParams, seed: Uint8Array): MOSAICKeyPair

// Signing and verification
sign(
  message: Uint8Array,
  secretKey: MOSAICSecretKey,
  publicKey: MOSAICPublicKey
): Promise<MOSAICSignature>

verify(
  message: Uint8Array,
  signature: MOSAICSignature,
  publicKey: MOSAICPublicKey
): Promise<boolean>

// Serialization
serializeSignature(sig: MOSAICSignature): Uint8Array
deserializeSignature(data: Uint8Array): MOSAICSignature
serializePublicKey(pk: MOSAICPublicKey): Uint8Array
```

### Cryptographic Utilities

#### Random Number Generation

```typescript
secureRandomBytes(length: number): Uint8Array
randomInt(max: number): number
randomIntRange(min: number, max: number): number
randomZq(q: number): number
randomVectorZq(n: number, q: number): Int32Array
randomSparseVector(n: number, w: number): Int8Array
sampleGaussian(sigma: number): number
sampleGaussianVector(n: number, sigma: number): Int32Array
deterministicBytes(seed: Uint8Array, length: number, context?: Uint8Array): Uint8Array
expandSeed(seed: Uint8Array, count: number, seedLength?: number): Uint8Array[]
validateSeedEntropy(seed: Uint8Array): void
```

#### Hashing Functions

```typescript
shake256(input: Uint8Array, outputLength: number): Uint8Array
shake256Fallback(input: Uint8Array, outputLength: number): Uint8Array
sha3_256(input: Uint8Array): Uint8Array
hashConcat(...inputs: Uint8Array[]): Uint8Array
hashWithDomain(domain: string, input: Uint8Array): Uint8Array
isNativeShake256Available(): boolean
```

#### Constant-Time Operations

```typescript
constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean
constantTimeSelect(condition: number, a: Uint8Array, b: Uint8Array): Uint8Array
constantTimeSelectInt32(condition: number, a: Int32Array, b: Int32Array): Int32Array
constantTimeLessThan(a: number, b: number): number
constantTimeAbs(x: number): number
constantTimeMod(x: number, q: number): number
zeroize(buffer: Uint8Array | Int8Array | Int32Array): void
```

#### Secure Buffer

```typescript
class SecureBuffer {
  constructor(lengthOrData: number | Uint8Array)
  get buffer(): Uint8Array
  get length(): number
  get isDisposed(): boolean
  dispose(): void
  clone(): SecureBuffer
  randomize(): void
  [Symbol.dispose](): void
}
```

### Entanglement & Cryptographic Binding

```typescript
// Secret sharing
secretShare(secret: Uint8Array, n: number): Uint8Array[]
secretReconstruct(shares: Uint8Array[]): Uint8Array
secretShareDeterministic(
  secret: Uint8Array,
  n: number,
  seed: Uint8Array
): Uint8Array[]

// Commitments and binding
interface BindingCommitment {
  commitment: Uint8Array
  opening: Uint8Array
}

createCommitment(data: Uint8Array): BindingCommitment
verifyCommitment(
  data: Uint8Array,
  commitment: Uint8Array,
  opening: Uint8Array
): boolean

computeBinding(
  slssData: Uint8Array,
  tddData: Uint8Array,
  egrwData: Uint8Array
): Uint8Array

// NIZK proofs
interface NIZKProof {
  challenge: Uint8Array
  responses: Uint8Array[]
  commitments: Uint8Array[]
}

generateNIZKProof(
  message: Uint8Array,
  shares: Uint8Array[],
  ciphertextHashes: Uint8Array[],
  randomness: Uint8Array
): NIZKProof

verifyNIZKProof(
  proof: NIZKProof,
  ciphertextHashes: Uint8Array[],
  message: Uint8Array
): boolean

serializeNIZKProof(proof: NIZKProof): Uint8Array
deserializeNIZKProof(data: Uint8Array): NIZKProof
```

### Low-Level Problem APIs (Advanced)

For direct access to individual hard problems:

#### SLSS (Sparse Lattice Subset Sum)

```typescript
interface SLSSPublicKey {
  A: Int32Array  // m x n matrix (flattened)
  t: Int32Array  // m-vector
}

interface SLSSSecretKey {
  s: Int8Array   // Sparse n-vector in {-1, 0, 1}
}

interface SLSSCiphertext {
  u: Int32Array
  v: Int32Array
}

interface SLSSKeyPair {
  publicKey: SLSSPublicKey
  secretKey: SLSSSecretKey
}

slssKeyGen(params: SLSSParams, seed: Uint8Array): SLSSKeyPair
slssEncrypt(
  publicKey: SLSSPublicKey,
  message: Uint8Array,
  params: SLSSParams,
  randomness: Uint8Array
): SLSSCiphertext

slssDecrypt(
  ciphertext: SLSSCiphertext,
  secretKey: SLSSSecretKey,
  params: SLSSParams
): Uint8Array

slssSerializePublicKey(pk: SLSSPublicKey): Uint8Array
slssDeserializePublicKey(data: Uint8Array): SLSSPublicKey
```

#### TDD (Tensor Decomposition Distinguishing)

```typescript
interface TDDPublicKey {
  T: Int32Array  // n x n x n tensor (flattened)
}

interface TDDSecretKey {
  factors: {
    a: Int32Array[]
    b: Int32Array[]
    c: Int32Array[]
  }
}

interface TDDCiphertext {
  data: Int32Array
}

interface TDDKeyPair {
  publicKey: TDDPublicKey
  secretKey: TDDSecretKey
}

tddKeyGen(params: TDDParams, seed: Uint8Array): TDDKeyPair
tddEncrypt(
  publicKey: TDDPublicKey,
  message: Uint8Array,
  params: TDDParams,
  randomness: Uint8Array
): TDDCiphertext

tddDecrypt(
  ciphertext: TDDCiphertext,
  secretKey: TDDSecretKey,
  params: TDDParams
): Uint8Array

tddSerializePublicKey(pk: TDDPublicKey): Uint8Array
tddDeserializePublicKey(data: Uint8Array): TDDPublicKey
```

#### EGRW (Expander Graph Random Walk)

```typescript
interface SL2Element {
  a: number; b: number; c: number; d: number
}

interface EGRWPublicKey {
  vStart: SL2Element
  vEnd: SL2Element
}

interface EGRWSecretKey {
  walk: number[]  // Sequence of generator indices
}

interface EGRWCiphertext {
  vertex: SL2Element
  commitment: Uint8Array
}

interface EGRWKeyPair {
  publicKey: EGRWPublicKey
  secretKey: EGRWSecretKey
}

egrwKeyGen(params: EGRWParams, seed: Uint8Array): EGRWKeyPair
egrwEncrypt(
  publicKey: EGRWPublicKey,
  message: Uint8Array,
  params: EGRWParams,
  randomness: Uint8Array
): EGRWCiphertext

egrwDecrypt(
  ciphertext: EGRWCiphertext,
  secretKey: EGRWSecretKey,
  publicKey: EGRWPublicKey,
  params: EGRWParams
): Uint8Array

egrwSerializePublicKey(pk: EGRWPublicKey): Uint8Array
egrwDeserializePublicKey(data: Uint8Array): EGRWPublicKey

// SL(2, Z_p) utilities
getGenerators(p: number): SL2Element[]
modInverse(a: number, p: number): number
sl2ToBytes(element: SL2Element): Uint8Array
bytesToSl2(data: Uint8Array): SL2Element
evictOldestCacheEntries(): void
```

### Convenience API

```typescript
// The library also provides a convenience object for async operations:
import crypto from 'k-mosaic'

const keyPair = await crypto.kem.generateKeyPair()
const { ciphertext, sharedSecret } = await crypto.kem.encapsulate(
  keyPair.publicKey,
)

const signature = await crypto.sign.sign(
  message,
  keyPair.secretKey,
  keyPair.publicKey,
)
const isValid = await crypto.sign.verify(message, signature, keyPair.publicKey)
```

### Version Information

```typescript
const ALGORITHM_NAME = 'kMOSAIC' // Algorithm name
const ALGORITHM_VERSION = '1.0' // Algorithm version
const CLI_VERSION = '1.0.0' // CLI version

interface AlgorithmInfo {
  name: string
  fullName: string
  version: string
  securityLevels: SecurityLevel[]
  hardProblems: Array<{
    name: string
    fullName: string
    description: string
    complexity: string
  }>
  entanglement: {
    description: string
    benefit: string
  }
  features: {
    kem: string
    signatures: string
    hybridReady: string
  }
}

const ALGORITHM_INFO: AlgorithmInfo
```

## ⚠️ Disclaimer

**kMOSAIC is an experimental cryptographic scheme.** It has NOT been:

- Formally verified or peer-reviewed
- Analyzed by professional cryptographers
- Standardized by any organization (NIST, IETF, etc.)

**DO NOT use in production** without proper security audit. This implementation is for research and educational purposes only.

## 🔐 Security

### Security Audit (December 2025)

An internal security review identified and fixed critical vulnerabilities:

| Issue                    | Severity    | Status   |
| ------------------------ | ----------- | -------- |
| TDD plaintext storage    | 🔴 Critical | ✅ Fixed |
| EGRW randomness exposure | 🔴 Critical | ✅ Fixed |
| TDD modular bias         | 🟠 High     | ✅ Fixed |

All 304 tests pass. See [SECURITY_REPORT.md](SECURITY_REPORT.md) for full details.

**Known Limitations:**

- JavaScript cannot guarantee constant-time execution (JIT/GC effects)
- Memory zeroization is best-effort due to GC behavior
- These are documented in the code and security report

## 🧪 Testing

```bash
# Run tests
bun test

# Run examples
bun run examples/basic.ts
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## � Documentation & Research

### 📘 The kMOSAIC Book

For a complete guide to post-quantum cryptography and kMOSAIC implementation details, read [**The kMOSAIC Book (Developer Guide)**](DEVELOPER_GUIDE.md).

### 📄 White Paper

For a deep dive into the theoretical foundations, security analysis, and performance benchmarks, please read the [**kMOSAIC White Paper**](kMOSAIC_WHITE_PAPER.md).

### 🔐 Security Report

For details on the security audit, identified vulnerabilities, and applied fixes, see the [**Security Report**](SECURITY_REPORT.md).

### Research Foundations

kMOSAIC draws inspiration from:

- Lattice-based cryptography (NTRU, Kyber)
- Multilinear maps and tensor cryptography
- Cayley graph hash functions
- Secret sharing and threshold cryptography

The novel contribution is the **cryptographic entanglement** of three independent hard problems, providing defense-in-depth against future cryptanalytic advances.

---

**Note**: This is a proof-of-concept implementation. For production post-quantum cryptography, consider NIST-standardized algorithms like ML-KEM (Kyber) and ML-DSA (Dilithium).
