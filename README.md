# kMOSAIC - Post-Quantum Cryptographic Library

**Multi-Oracle Structured Algebraic Intractability Composition**

A novel post-quantum cryptographic library that combines three heterogeneous hard problems with cryptographic entanglement for defense-in-depth security.

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
SecurityLevel.MOS_128  // 128-bit post-quantum security
SecurityLevel.MOS_256  // 256-bit post-quantum security

// Parameter sets
MOS_128: MOSAICParams  // MOS-128 parameters
MOS_256: MOSAICParams  // MOS-256 parameters
getParams(level: SecurityLevel): MOSAICParams
validateParams(params: MOSAICParams): void
```

### KEM Functions

```typescript
// Key generation
kemGenerateKeyPair(level?: SecurityLevel): Promise<MOSAICKeyPair>
kemGenerateKeyPairFromSeed(seed: Uint8Array, level?: SecurityLevel): Promise<MOSAICKeyPair>

// Encapsulation/Decapsulation
encapsulate(publicKey: MOSAICPublicKey): Promise<{ ciphertext: MOSAICCiphertext, sharedSecret: Uint8Array }>
encapsulateDeterministic(publicKey: MOSAICPublicKey, ephemeralSecret: Uint8Array): Promise<{ ciphertext: MOSAICCiphertext, sharedSecret: Uint8Array }>
decapsulate(ciphertext: MOSAICCiphertext, secretKey: MOSAICSecretKey, publicKey: MOSAICPublicKey): Promise<Uint8Array>

// Hybrid encryption
encrypt(message: Uint8Array, publicKey: MOSAICPublicKey): Promise<Uint8Array>
decrypt(ciphertext: Uint8Array, secretKey: MOSAICSecretKey, publicKey: MOSAICPublicKey): Promise<Uint8Array>

// Serialization
serializePublicKey(pk: MOSAICPublicKey): Uint8Array
serializeCiphertext(ct: MOSAICCiphertext): Uint8Array
deserializeCiphertext(data: Uint8Array): MOSAICCiphertext

// Analysis
analyzePublicKey(pk: MOSAICPublicKey): SecurityAnalysis
```

### Signature Functions

```typescript
// Key generation
signGenerateKeyPair(level?: SecurityLevel): Promise<MOSAICKeyPair>
signGenerateKeyPairFromSeed(seed: Uint8Array, level?: SecurityLevel): Promise<MOSAICKeyPair>

// Signing and verification
sign(message: Uint8Array, secretKey: MOSAICSecretKey, publicKey: MOSAICPublicKey): Promise<MOSAICSignature>
verify(message: Uint8Array, signature: MOSAICSignature, publicKey: MOSAICPublicKey): Promise<boolean>

// Serialization
serializeSignature(sig: MOSAICSignature): Uint8Array
deserializeSignature(data: Uint8Array): MOSAICSignature
```

### Cryptographic Utilities

```typescript
// Random number generation
secureRandomBytes(length: number): Uint8Array
randomVectorZq(n: number, q: number): Int32Array
randomSparseVector(n: number, w: number): Int32Array
sampleGaussianVector(n: number, sigma: number): Int32Array

// Hashing functions
shake256(input: Uint8Array, length: number): Uint8Array
sha3_256(input: Uint8Array): Uint8Array
hashConcat(...inputs: Uint8Array[]): Uint8Array
hashWithDomain(domain: string, data: Uint8Array): Uint8Array

// Constant-time operations
constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean
constantTimeSelect(condition: number, a: Uint8Array, b: Uint8Array): Uint8Array
zeroize(arr: Int8Array | Uint8Array | Int32Array): void
SecureBuffer(length: number): SecureBuffer
```

### Entanglement & Proofs

```typescript
// Secret sharing
secretShare(secret: Uint8Array, n: number): Uint8Array[]
secretReconstruct(shares: Uint8Array[]): Uint8Array

// Commitments
computeBinding(...parts: Uint8Array[]): Uint8Array
createCommitment(data: Uint8Array): { commitment: Uint8Array, opening: Uint8Array }
verifyCommitment(commitment: Uint8Array, data: Uint8Array, opening: Uint8Array): boolean

// Zero-knowledge proofs
generateNIZKProof(...): NIZKProof
verifyNIZKProof(proof: NIZKProof, ...): boolean
```

### Low-Level Problem APIs (Advanced)

For direct access to individual hard problems:

```typescript
// SLSS (Sparse Lattice Subset Sum)
slssKeyGen(seed: Uint8Array, params: SLSSParams): { publicKey: SLSSPublicKey, secretKey: SLSSSecretKey }
slssEncrypt(message: Uint8Array, publicKey: SLSSPublicKey, randomness: Uint8Array): SLSSCiphertext
slssDecrypt(ciphertext: SLSSCiphertext, secretKey: SLSSSecretKey): Uint8Array

// TDD (Tensor Decomposition Distinguishing)
tddKeyGen(seed: Uint8Array, params: TDDParams): { publicKey: TDDPublicKey, secretKey: TDDSecretKey }
tddEncrypt(message: Uint8Array, publicKey: TDDPublicKey, randomness: Uint8Array): TDDCiphertext
tddDecrypt(ciphertext: TDDCiphertext, secretKey: TDDSecretKey): Uint8Array

// EGRW (Expander Graph Random Walk)
egrwKeyGen(seed: Uint8Array, params: EGRWParams): { publicKey: EGRWPublicKey, secretKey: EGRWSecretKey }
egrwEncrypt(message: Uint8Array, publicKey: EGRWPublicKey, randomness: Uint8Array): EGRWCiphertext
egrwDecrypt(ciphertext: EGRWCiphertext, secretKey: EGRWSecretKey): Uint8Array
```

### Version Information

```typescript
VERSION: string           // Library version
ALGORITHM_NAME: string    // "kMOSAIC"
ALGORITHM_VERSION: string // Algorithm version
ALGORITHM_INFO: {         // Complete algorithm metadata
  name: string
  fullName: string
  version: string
  securityLevels: SecurityLevel[]
  hardProblems: Array<{ name, fullName, description, complexity }>
  entanglement: { description, benefit }
  features: { kem, signatures, hybridReady }
}
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
