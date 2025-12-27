# kMOSAIC: A Novel Post-Quantum Cryptographic Algorithm

## Multi-Oracle Structured Algebraic Intractability Composition

**Version:** 1.0  
**Date:** December, 2025  
**Authors:** Rolando Santamaria Maso <kyberneees@gmail.com>

---

## ⚠️ Important Disclaimer

**This white paper presents an experimental cryptographic construction that has NOT been:**

- Formally verified by academic peer review
- Analyzed by the broader cryptographic research community
- Submitted to any standards organization ([NIST](https://www.nist.gov/), [IETF](https://www.ietf.org/), [ISO](https://www.iso.org/))
- Tested against real-world adversarial conditions

**DO NOT use this algorithm in production systems protecting sensitive data** until it has undergone rigorous cryptanalysis. For production applications, use established, standardized post-quantum algorithms such as [ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final) and [ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final).

This document describes a novel theoretical approach that we believe warrants further academic investigation.

---

## Table of Contents

0. [Primer for Non-Experts](#0-primer-for-non-experts)
1. [Executive Summary](#1-executive-summary)
2. [The Problem: Single Points of Failure in Cryptography](#2-the-problem-single-points-of-failure-in-cryptography)
3. [The kMOSAIC Innovation: Cryptographic Entanglement](#3-the-kmosaic-innovation-cryptographic-entanglement)
4. [The Three Hard Problems](#4-the-three-hard-problems)
5. [How It Works: A Visual Guide](#5-how-it-works-a-visual-guide)
6. [Key Encapsulation Mechanism (KEM)](#6-key-encapsulation-mechanism-kem)
7. [Digital Signatures](#7-digital-signatures)
8. [Security Analysis](#8-security-analysis)
9. [Performance Characteristics](#9-performance-characteristics)
10. [Code Examples](#10-code-examples)
11. [Comparison with Existing Schemes](#11-comparison-with-existing-schemes)
12. [Future Work and Research Directions](#12-future-work-and-research-directions)
13. [Conclusion](#13-conclusion)
14. [References](#14-references)

---

## 0. Primer for Non-Experts

Before diving into the technical details, we introduce key concepts used in this paper.

### What is Post-Quantum Cryptography (PQC)?

Modern encryption (like [RSA](<https://en.wikipedia.org/wiki/RSA_(cryptosystem)>)) relies on math problems that are hard for traditional computers but easy for large quantum computers. **Post-Quantum Cryptography** involves designing new encryption methods that are hard for _both_ classical and quantum computers to break.

### What is a "Hard Problem"?

In cryptography, a "hard problem" is a mathematical puzzle that is easy to create but extremely difficult to solve without a specific "key." For example, multiplying two large prime numbers is easy, but finding those original numbers given only the result (factoring) is very hard.

### What is "Defense-in-Depth"?

Instead of relying on a single lock to protect a secret, **Defense-in-Depth** uses multiple, different types of locks. If a thief picks one lock, the door remains shut. In kMOSAIC, we use three different mathematical "locks" simultaneously.

### What is "Cryptographic Entanglement"?

This is a technique where we bind multiple mathematical problems together so they cannot be separated. An attacker cannot attack the problems one by one; they must solve all of them at the same time to recover the secret.

---

## 1. Executive Summary

### What is kMOSAIC?

kMOSAIC (**Multi-Oracle Structured Algebraic Intractability Composition**) is a novel post-quantum cryptographic construction that achieves **defense-in-depth** security by cryptographically entangling three independent mathematical hard problems from different domains.

### The Core Innovation

Unlike traditional cryptographic schemes that rely on a **single mathematical assumption**, kMOSAIC fragments secrets across three fundamentally different computational problems:

| Component | Mathematical Domain  | Problem Type                        |
| --------- | -------------------- | ----------------------------------- |
| **SLSS**  | Lattice Cryptography | Sparse Lattice Subset Sum           |
| **TDD**   | Multilinear Algebra  | Tensor Decomposition Distinguishing |
| **EGRW**  | Graph Theory         | Expander Graph Random Walk          |

### Why This Matters

To break kMOSAIC, an attacker must simultaneously solve **all three** problems. Breaking any one (or even two) reveals **zero information** about the secret due to the information-theoretic properties of the secret sharing scheme.

```
Security = SLSS × TDD × EGRW
(not SLSS + TDD + EGRW)
```

### Key Benefits

1. **Quantum Resistance Diversity**: Different quantum algorithms would be needed for each component
2. **Graceful Degradation**: If one problem is broken, the others still protect the secret
3. **Future-Proof Design**: Hedges against unexpected cryptanalytic breakthroughs
4. **Defense-in-Depth**: Multiple independent layers of security

---

## 2. The Problem: Single Points of Failure in Cryptography

### 2.1 The Current State of Post-Quantum Cryptography

All widely-deployed post-quantum cryptographic schemes rely on **a single hardness assumption**:

| Scheme                                                          | Single Point of Failure                                                            |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| ML-KEM (Kyber)                                                  | [Module-LWE](https://en.wikipedia.org/wiki/Learning_with_errors) is hard           |
| ML-DSA (Dilithium)                                              | [Module-SIS](https://en.wikipedia.org/wiki/Short_integer_solution_problem) is hard |
| [McEliece](https://en.wikipedia.org/wiki/McEliece_cryptosystem) | Syndrome decoding is hard                                                          |
| [SPHINCS+](https://sphincs.org/)                                | Hash functions are one-way                                                         |

### 2.2 The Historical Problem

History has shown that "impossible" problems can suddenly become tractable:

- **RSA** was considered secure → [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm) (1994) breaks it on quantum computers
- **[SIKE/SIDH](https://en.wikipedia.org/wiki/Supersingular_isogeny_key_exchange)** was a NIST PQC finalist → Broken in 2022 using classical computers (e.g., SIKEp434 key recovery in ~1 hour on a single-core computer).
- **[MD5](https://en.wikipedia.org/wiki/MD5)** was the standard hash → Collision attacks made it obsolete

When a single assumption fails, the **entire cryptographic scheme collapses instantly**.

### 2.3 The Lattice Monoculture Risk

The current post-quantum standardization landscape is heavily skewed towards a single mathematical family: **lattices** (especially for KEMs).

- **[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM/Kyber)**: Module-Lattice based
- **[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA/Dilithium)**: Module-Lattice based
- **[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (SLH-DSA / SPHINCS+)**: Hash-based digital signatures
- **Falcon**: Selected by NIST for standardization (FIPS publication forthcoming) ([Selected Algorithms](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022))

This creates a systemic risk concentration: a major breakthrough affecting lattice-based assumptions could have outsized impact on widely deployed lattice-based schemes.

### 2.4 The Traditional "Fix": Hybrid Cryptography

Current hybrid approaches simply concatenate two schemes:

```
Ciphertext = Encrypt_Kyber(message) || Encrypt_ClassicDH(message)
```

**Problem**: This reveals the same message through different channels. If either is broken, the message is exposed.

### 2.5 What We Need: True Defense-in-Depth

The ideal solution would be a **Robust Combiner** that:

1. Split the secret so that **each fragment reveals nothing**
2. Require **all components** to reconstruct the secret
3. Use **mathematically unrelated** problems
4. Make the components **inseparable** (cryptographically bound)

This is exactly what kMOSAIC provides.

---

## 3. The kMOSAIC Innovation: Cryptographic Entanglement

### 3.1 The Core Concept

kMOSAIC introduces **cryptographic entanglement**—a construction where three hard problems become **inseparable**, and the secret is distributed across all three in a way that:

1. Any single problem reveals **zero bits** of information
2. Any two problems reveal **zero bits** of information
3. Only solving **all three** recovers the secret

### 3.2 Visual Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                    TRADITIONAL HYBRID                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│    ┌─────────┐        ┌─────────┐                              │
│    │ Kyber   │        │ Classic │                              │
│    │ Encrypt │        │ Encrypt │                              │
│    └────┬────┘        └────┬────┘                              │
│         │                  │                                    │
│         ▼                  ▼                                    │
│    [C1: message]      [C2: message]     ← Same message!        │
│         │                  │                                    │
│         └────────┬─────────┘                                    │
│                  │                                              │
│            [C1 || C2]                                           │
│                                                                 │
│    ⚠️ Break ONE = Get message                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    kMOSAIC ENTANGLEMENT                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                     Secret: K                                   │
│                        │                                        │
│             ┌──────────┼──────────┐                            │
│             ▼          ▼          ▼                            │
│    K = [Fragment₁] ⊕ [Fragment₂] ⊕ [Fragment₃]                │
│             │          │          │                            │
│             ▼          ▼          ▼                            │
│    ┌────────────┐ ┌────────────┐ ┌────────────┐               │
│    │    SLSS    │ │    TDD     │ │    EGRW    │               │
│    │  (Lattice) │ │  (Tensor)  │ │  (Graph)   │               │
│    └─────┬──────┘ └─────┬──────┘ └─────┬──────┘               │
│          │              │              │                       │
│          └──────────────┼──────────────┘                       │
│                         │                                       │
│              ╔══════════╧══════════╗                           │
│              ║  BINDING COMMITMENT ║  ← Cryptographically      │
│              ║   H(SLSS||TDD||EGRW)║    binds all three        │
│              ╚═════════════════════╝                           │
│                                                                 │
│    ✓ Break ONE = Zero information                              │
│    ✓ Break TWO = Zero information                              │
│    ✓ Break ALL THREE = Recover secret                          │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Information-Theoretic Secret Sharing

kMOSAIC uses XOR-based 3-of-3 secret sharing:

```
Secret K = 256 random bits

Fragment₁ = random 256 bits
Fragment₂ = random 256 bits
Fragment₃ = K ⊕ Fragment₁ ⊕ Fragment₂
```

**Mathematical Property**: Any two fragments are statistically independent of K. This is **information-theoretic security**—not computational. Even with infinite computing power, two fragments reveal nothing.

### 3.4 The Binding Commitment

To prevent an attacker from substituting components, kMOSAIC binds all three using a hash commitment:

```
Binding = SHA3-256(SLSS_PublicKey || TDD_PublicKey || EGRW_PublicKey)
```

This binding value is incorporated into the parameters of all three problems, creating a **circular dependency** that makes them inseparable.

---

## 4. The Three Hard Problems

kMOSAIC strategically combines three problems from **different mathematical domains**:

### 4.1 SLSS: Sparse Lattice Subset Sum

**Domain**: Lattice-based cryptography with sparsity constraints

**The Problem**:

```
Given:
  - Matrix A ∈ ℤq^{m×n}  (public)
  - Target vector t ∈ ℤq^m (public)

Find:
  - Sparse vector s ∈ {-1, 0, 1}^n
  - With exactly w non-zero entries
  - Such that: A·s ≡ t (mod q)
```

**Why It's Hard**:

- Combines the **NP-hardness of subset sum** with **lattice structure**
- Quantum algorithms for lattices don't exploit sparsity
- Algorithms for subset sum don't exploit lattice structure
- Related to Learning With Errors (LWE) with sparse secrets

**Visual Intuition**:

```
         A (public matrix)              s (secret)        t (target)
    ┌─────────────────────┐          ┌─────┐           ┌─────┐
    │  3  7  2  9  1  5  │          │  0  │           │     │
    │  8  4  6  2  7  3  │    ×     │  1  │     =     │  ?  │
    │  1  9  5  8  4  6  │          │  0  │           │     │
    │  5  2  8  1  6  9  │          │ -1  │           │     │
    └─────────────────────┘          │  0  │           └─────┘
                                     │  1  │
                                     └─────┘
                              (sparse: only 3 non-zeros)
```

Finding which columns of A sum to t (with signs) is computationally infeasible.

### 4.2 TDD: Tensor Decomposition Distinguishing

**Domain**: Multilinear algebra / Tensor computation

**The Problem**:

```
Given:
  - A 3-dimensional tensor T ∈ ℤq^{n×n×n}

Distinguish:
  - Is T a low-rank tensor? T = Σᵢ aᵢ ⊗ bᵢ ⊗ cᵢ (rank r)
  - Or is T random noise?
```

**Why It's Hard**:

- Tensor rank computation is **NP-hard** over finite fields
- **No known quantum speedup** for tensor decomposition
- Mathematically unrelated to lattice problems
- Requires finding the hidden low-rank structure

**Visual Intuition**:

```
A 3D tensor (imagine a Rubik's cube of numbers):

           ┌─────────────────┐
          /│                /│
         / │    n          / │
        /  │              /  │
       ┌───┼─────────────┐   │
       │   │             │   │
     n │   │             │   │
       │   └─────────────┼───┘
       │  /        n     │  /
       │ /               │ /
       │/                │/
       └─────────────────┘

Secret: This tensor = a₁⊗b₁⊗c₁ + a₂⊗b₂⊗c₂ + ... + aᵣ⊗bᵣ⊗cᵣ
(Finding the vectors a, b, c is the hard problem)
```

### 4.3 EGRW: Expander Graph Random Walk

**Domain**: Graph theory / Group theory

**The Problem**:

```
Given:
  - Cayley graph G of SL(2, ℤp) with 4 generators
  - Starting vertex v_start (2×2 matrix)
  - Ending vertex v_end (2×2 matrix)
  - Walk length k

Find:
  - The sequence of k generator moves from v_start to v_end
```

**Why It's Hard**:

- The graph has approximately p³ vertices (enormous)
- There are 4^k possible paths of length k
- Related to discrete logarithm in matrix groups
- **No efficient quantum algorithm known**
- Graph structure provides optimal expansion (Ramanujan property)

**Visual Intuition**:

```
The Cayley Graph (massively simplified):

         [Start]
            │
       ┌────┼────┬────┐
       │    │    │    │
       ▼    ▼    ▼    ▼
      ( )  ( )  ( )  ( )   ← 4 possible first moves
       │    │    │    │
    ┌──┴─┐ ... ... ...     ← 16 possible after 2 moves
    │    │
   ...  ...                 ← 4^k possible paths!
    │
    ▼
  [End]

Secret: Which sequence of moves (S, S⁻¹, T, T⁻¹) was taken?
```

### 4.4 Why These Three Specifically?

| Property               | SLSS               | TDD                    | EGRW        |
| ---------------------- | ------------------ | ---------------------- | ----------- |
| Mathematical Domain    | Lattices           | Tensors                | Graphs      |
| NP-Hard                | ✓ (subset sum)     | ✓ (rank decomposition) | Related     |
| Quantum Speedup        | Partial            | None known             | None known  |
| Structure Exploited    | Sparsity + Lattice | Multilinearity         | Expansion   |
| Relationship to Others | Independent        | Independent            | Independent |

The key insight: **No known algorithm** solves all three efficiently, and there's **no theoretical reason** to believe such an algorithm exists.

---

## 5. How It Works: A Visual Guide

### 5.1 The Big Picture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        KEY GENERATION                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Seed (256 bits)                                                   │
│        │                                                            │
│        ├──────────────┬──────────────┬──────────────┐              │
│        ▼              ▼              ▼              ▼              │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐        │
│   │ Expand  │    │  SLSS   │    │   TDD   │    │  EGRW   │        │
│   │ Seeds   │───▶│ KeyGen  │───▶│ KeyGen  │───▶│ KeyGen  │        │
│   └─────────┘    └────┬────┘    └────┬────┘    └────┬────┘        │
│                       │              │              │              │
│                       ▼              ▼              ▼              │
│                  [SLSS Keys]    [TDD Keys]     [EGRW Keys]        │
│                       │              │              │              │
│                       └──────────────┼──────────────┘              │
│                                      ▼                              │
│                              ┌──────────────┐                       │
│                              │   BINDING    │                       │
│                              │  COMMITMENT  │                       │
│                              └──────────────┘                       │
│                                      │                              │
│                          ┌───────────┴───────────┐                 │
│                          ▼                       ▼                 │
│                    PUBLIC KEY              SECRET KEY              │
│                    (~0.8-3.2 MB)           (~9-18 KB)              │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Encapsulation (Creating a Shared Secret)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENCAPSULATION                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Generate random ephemeral secret: m                               │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────────────────────────────────────────────┐              │
│   │           SECRET SHARING (XOR-based)            │              │
│   │    m = m₁ ⊕ m₂ ⊕ m₃                            │              │
│   │    (Each fragment reveals NOTHING about m)      │              │
│   └───────────────────┬─────────────────────────────┘              │
│                       │                                             │
│        ┌──────────────┼──────────────┐                             │
│        ▼              ▼              ▼                             │
│   ┌─────────┐    ┌─────────┐    ┌─────────┐                       │
│   │  SLSS   │    │   TDD   │    │  EGRW   │                       │
│   │ Encrypt │    │ Encrypt │    │ Encrypt │                       │
│   │   m₁    │    │   m₂    │    │   m₃    │                       │
│   └────┬────┘    └────┬────┘    └────┬────┘                       │
│        │              │              │                             │
│        ▼              ▼              ▼                             │
│      [c₁]          [c₂]           [c₃]                            │
│        │              │              │                             │
│        └──────────────┼──────────────┘                             │
│                       ▼                                             │
│              ┌──────────────────────┐                              │
│              │    NIZK PROOF        │                              │
│              │  (proves correct     │                              │
│              │   construction)      │                              │
│              └──────────────────────┘                              │
│                       │                                             │
│        ┌──────────────┴──────────────┐                             │
│        ▼                             ▼                             │
│   CIPHERTEXT                   SHARED SECRET                       │
│   (c₁, c₂, c₃, proof)         = SHAKE256(m || ...)                │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 Decapsulation (Recovering the Shared Secret)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DECAPSULATION                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   CIPHERTEXT (c₁, c₂, c₃, proof)                                   │
│        │                                                            │
│        ▼                                                            │
│   ┌─────────────────────┐                                          │
│   │   VERIFY NIZK       │  ← Ensures ciphertext is well-formed     │
│   │      PROOF          │                                          │
│   └──────────┬──────────┘                                          │
│              │                                                      │
│        ┌─────┴─────┬─────────────┐                                 │
│        ▼           ▼             ▼                                 │
│   ┌─────────┐ ┌─────────┐  ┌─────────┐                            │
│   │  SLSS   │ │   TDD   │  │  EGRW   │                            │
│   │ Decrypt │ │ Decrypt │  │ Decrypt │   ← Requires SECRET KEY    │
│   │   c₁    │ │   c₂    │  │   c₃    │                            │
│   └────┬────┘ └────┬────┘  └────┬────┘                            │
│        │           │            │                                  │
│        ▼           ▼            ▼                                  │
│      [m₁']       [m₂']        [m₃']                               │
│        │           │            │                                  │
│        └───────────┼────────────┘                                  │
│                    ▼                                                │
│   ┌─────────────────────────────────────────────────┐              │
│   │    RECONSTRUCT: m' = m₁' ⊕ m₂' ⊕ m₃'           │              │
│   └─────────────────────────────────────────────────┘              │
│                    │                                                │
│                    ▼                                                │
│   ┌─────────────────────────────────────────────────┐              │
│   │   RE-ENCAPSULATE & VERIFY                       │              │
│   │   (Fujisaki-Okamoto transform for IND-CCA2)     │              │
│   └─────────────────────────────────────────────────┘              │
│                    │                                                │
│                    ▼                                                │
│              SHARED SECRET                                          │
│              = SHAKE256(m' || ...)                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 6. Key Encapsulation Mechanism (KEM)

### 6.1 What is a KEM?

A Key Encapsulation Mechanism (KEM) is a cryptographic primitive that establishes a shared secret between two parties:

1. **Alice** generates a key pair (public key, secret key)
2. **Alice** shares her public key with Bob
3. **Bob** uses Alice's public key to create a ciphertext and shared secret
4. **Alice** uses her secret key to recover the same shared secret

The shared secret is then used with symmetric encryption (e.g., [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)) for actual message encryption.

### 6.2 kMOSAIC-KEM Overview

```typescript
// Key Generation
const { publicKey, secretKey } = await kemGenerateKeyPair(SecurityLevel.MOS_128)

// Encapsulation (Bob's side)
const { ciphertext, sharedSecret } = await encapsulate(publicKey)

// Decapsulation (Alice's side)
const recovered = await decapsulate(ciphertext, secretKey, publicKey)

// sharedSecret === recovered (32 bytes of shared entropy)
```

### 6.3 Security Properties

| Property                                                                      | Description                              | How kMOSAIC Achieves It                                        |
| ----------------------------------------------------------------------------- | ---------------------------------------- | -------------------------------------------------------------- |
| **[IND-CPA](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability)**  | Ciphertexts are indistinguishable        | Three independent encryption schemes                           |
| **[IND-CCA2](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability)** | Secure against chosen-ciphertext attacks | Fujisaki-Okamoto transform with implicit rejection             |
| **Key Indistinguishability**                                                  | Shared secrets look random               | [SHAKE256](https://en.wikipedia.org/wiki/SHA-3) key derivation |

### 6.4 Parameter Sets

| Parameter           | MOS-128  | MOS-256  | Description                     |
| ------------------- | -------- | -------- | ------------------------------- |
| **Security Target** | 128-bit  | 256-bit  | Post-quantum security level     |
| **SLSS n**          | 512      | 1024     | Lattice dimension               |
| **SLSS m**          | 384      | 768      | Number of equations             |
| **SLSS w**          | 64       | 128      | Sparsity weight                 |
| **TDD n**           | 24       | 36       | Tensor dimension                |
| **TDD r**           | 6        | 9        | Tensor rank                     |
| **EGRW p**          | 1021     | 2039     | Prime (graph size ≈ p³)         |
| **EGRW k**          | 128      | 256      | Walk length                     |
| **Public Key**      | ~824 KB  | ~3.2 MB  | Dominated by TDD tensor ($n^3$) |
| **Secret Key**      | ~9 KB    | ~18 KB   | -                               |
| **Ciphertext**      | ~5.9 KB  | ~10.7 KB | -                               |
| **Shared Secret**   | 32 bytes | 32 bytes | -                               |

---

## 7. Digital Signatures

### 7.1 The Multi-Witness Paradigm

Traditional digital signatures prove knowledge of **one witness** (the secret key). kMOSAIC-SIGN proves knowledge of **three entangled witnesses** simultaneously.

```
Traditional Fiat-Shamir:          kMOSAIC Multi-Witness:

Commit(witness) → c               Commit(w₁) → c₁
                                  Commit(w₂) → c₂
                                  Commit(w₃) → c₃

Challenge = H(c || msg)           Challenge = H(c₁||c₂||c₃||msg)
                                    ↑
                                    └── Binds ALL THREE together

Response(witness, ch)             Response(w₁, ch) → z₁
                                  Response(w₂, ch) → z₂
                                  Response(w₃, ch) → z₃
```

### 7.2 Why This Matters

An attacker forging a signature must:

1. **Know the SLSS secret** (sparse lattice vector)
2. **Know the TDD secret** (tensor decomposition factors)
3. **Know the EGRW secret** (random walk path)

All three responses must be consistent with the **same unified challenge**.

### 7.3 Signature Size Tradeoffs

| Property    | MOS-128 | MOS-256 | Notes                   |
| ----------- | ------- | ------- | ----------------------- |
| Public Key  | ~2.7 MB | ~11 MB  | Three component keys    |
| Secret Key  | ~9 KB   | ~18 KB  | Three witnesses         |
| Signature   | ~6 KB   | ~12 KB  | Three responses + hints |
| Sign Time   | ~26 ms  | ~51 ms  | Parallelizable          |
| Verify Time | ~4 ms   | ~14 ms  | Parallelizable          |

---

## 8. Security Analysis

### 8.1 The Attack Surface

To recover a kMOSAIC-protected secret, an attacker must break **all three problems**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK SCENARIOS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scenario 1: Break SLSS only                                    │
│  ─────────────────────────────                                  │
│  Recovers: m₁ (first fragment)                                  │
│  Information about secret K: ZERO (information-theoretic)       │
│  Result: Attack fails ✗                                         │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scenario 2: Break TDD only                                     │
│  ─────────────────────────────                                  │
│  Recovers: m₂ (second fragment)                                 │
│  Information about secret K: ZERO                               │
│  Result: Attack fails ✗                                         │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scenario 3: Break EGRW only                                    │
│  ─────────────────────────────                                  │
│  Recovers: m₃ (third fragment)                                  │
│  Information about secret K: ZERO                               │
│  Result: Attack fails ✗                                         │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scenario 4: Break any TWO problems                             │
│  ─────────────────────────────────                              │
│  Recovers: Two fragments (e.g., m₁ and m₂)                      │
│  Information about K: Still ZERO!                               │
│  Why: XOR sharing requires ALL shares                           │
│  Result: Attack fails ✗                                         │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Scenario 5: Break ALL THREE problems                           │
│  ────────────────────────────────────                           │
│  Recovers: m₁, m₂, m₃                                           │
│  Can compute: K = m₁ ⊕ m₂ ⊕ m₃                                  │
│  Result: Attack succeeds ✓                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Quantum Attack Analysis

| Attack Type                   | Affects                 | Impact on kMOSAIC                                                 |
| ----------------------------- | ----------------------- | ----------------------------------------------------------------- |
| **Shor's Algorithm**          | Factoring, Discrete Log | ✗ Not applicable                                                  |
| **Grover's Algorithm**        | Brute force search      | Quadratic speedup on each component (accounted for in parameters) |
| **BKZ/LLL for Lattices**      | SLSS only               | Breaks only 1/3 of the construction                               |
| **Tensor Quantum Algorithms** | TDD                     | None known                                                        |
| **Graph Quantum Algorithms**  | EGRW                    | None efficient known                                              |

**Key Insight**: There's no known quantum algorithm that simultaneously attacks all three problem types.

### 8.3 Security Theorem (Informal)

**Claim**: kMOSAIC-KEM is IND-CCA2 secure under the following assumptions:

1. The SLSS problem is hard (related to LWE + subset sum)
2. The TDD problem is hard (tensor decomposition is NP-hard)
3. The EGRW problem is hard (navigation in Cayley graphs)
4. SHAKE256 behaves as a random oracle
5. The [NIZK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) proof system is sound and zero-knowledge

The probability of breaking kMOSAIC is:

```
P(break kMOSAIC) ≈ P(break SLSS) × P(break TDD) × P(break EGRW)
```

The security of the combined construction relies on all three problems remaining hard. The heterogeneous nature provides defense-in-depth: breaking any single problem family does not compromise the system.

### 8.4 Known Limitations and Honest Assessment

| Limitation               | Severity       | Notes                                     |
| ------------------------ | -------------- | ----------------------------------------- |
| No formal security proof | High           | Requires academic cryptanalysis           |
| Novel construction       | High           | May have unforeseen weaknesses            |
| Larger key sizes         | Medium         | Trade-off for defense-in-depth            |
| JavaScript timing        | Implementation | Use native implementations for production |

### 8.5 Implementation Security (December 2025)

An internal security audit identified and addressed the following issues:

| Issue                    | Severity    | Status   | Resolution                                  |
| ------------------------ | ----------- | -------- | ------------------------------------------- |
| TDD plaintext storage    | 🔴 Critical | ✅ Fixed | XOR encryption with masked-matrix keystream |
| EGRW randomness exposure | 🔴 Critical | ✅ Fixed | Ephemeral walk vertex derivation            |
| TDD modular bias         | 🟠 High     | ✅ Fixed | Rejection sampling for uniform distribution |

**JavaScript Runtime Limitations (Acknowledged):**

- Constant-time operations cannot be guaranteed due to JIT optimization and garbage collection
- Memory zeroization is best-effort due to GC behavior
- These are fundamental to the JavaScript runtime; native implementations are recommended for high-security deployments

For complete audit details, see [SECURITY_REPORT.md](SECURITY_REPORT.md).

---

## 9. Performance Characteristics

### 9.1 Benchmarks (Reference Implementation)

Tested on Apple M2 Pro Mac, Bun runtime v1.3.5, single-threaded (MOS-128):

| Operation           | Time (ms) | Ops/Sec | Comparison vs Classical    |
| ------------------- | --------- | ------- | -------------------------- |
| **KEM KeyGen**      | ~19.4 ms  | ~52     | ~1360x slower than X25519  |
| **KEM Encapsulate** | ~0.51 ms  | ~1947   | ~12x slower than X25519    |
| **KEM Decapsulate** | ~0.53 ms  | ~1885   | ~17x slower than X25519    |
| **Sign KeyGen**     | ~24.7 ms  | ~40     | ~2250x slower than Ed25519 |
| **Sign**            | ~25.6 ms  | ~39     | ~577x slower than Ed25519  |
| **Verify**          | ~3.4 ms   | ~291    | ~101x slower than Ed25519  |

_Note: The encapsulation/decapsulation speed is surprisingly fast due to optimized matrix operations and delayed modular reductions. The key generation and signing operations are dominated by the TDD (Tensor) component which involves O(n³) operations._

### 9.2 Size Comparison with Other PQ Schemes

| Scheme              | Public Key | Ciphertext | Security                |
| ------------------- | ---------- | ---------- | ----------------------- |
| kMOSAIC MOS-128     | ~824 KB    | ~5.9 KB    | Target ~128-bit         |
| kMOSAIC MOS-256     | ~3.2 MB    | ~10.7 KB   | Target ~256-bit         |
| ML-KEM-768 (Kyber)  | 1.2 KB     | 1.1 KB     | NIST level 3 (~AES-192) |
| ML-KEM-1024 (Kyber) | 1.6 KB     | 1.6 KB     | NIST level 5 (~AES-256) |
| Classic McEliece    | 261 KB     | 128 B      | Varies by parameter set |

**Trade-off**: kMOSAIC has significantly larger public keys than Kyber (due to the $O(n^3)$ tensor component) but provides defense-in-depth through heterogeneous hardness. Its ciphertext size remains relatively small compared to the key sizes.

### 9.3 When to Use kMOSAIC

**Good fit for**:

- High-security applications where defense-in-depth is valuable
- Long-term secrets (decades) where future cryptanalysis is a concern
- Systems that can tolerate larger key sizes
- Hybrid approaches combined with established algorithms

**Not ideal for**:

- Constrained embedded devices
- High-throughput scenarios
- Applications requiring minimal bandwidth

---

## 10. Code Examples

### 10.1 Basic Key Encapsulation

```typescript
import { kemGenerateKeyPair, encapsulate, decapsulate, MOS_128 } from 'k-mosaic'

async function basicKEM() {
  // Step 1: Alice generates a key pair
  console.log('Generating kMOSAIC key pair...')
  const { publicKey, secretKey } = await kemGenerateKeyPair(MOS_128)

  // Step 2: Alice shares publicKey with Bob (over any channel)

  // Step 3: Bob encapsulates a shared secret
  const { ciphertext, sharedSecret } = await encapsulate(publicKey)
  console.log(
    "Bob's shared secret:",
    Buffer.from(sharedSecret).toString('hex').slice(0, 32) + '...',
  )

  // Step 4: Bob sends ciphertext to Alice

  // Step 5: Alice decapsulates to get the same shared secret
  const aliceSecret = await decapsulate(ciphertext, secretKey, publicKey)
  console.log(
    "Alice's shared secret:",
    Buffer.from(aliceSecret).toString('hex').slice(0, 32) + '...',
  )

  // Step 6: Verify they match
  const match = Buffer.from(sharedSecret).equals(Buffer.from(aliceSecret))
  console.log('Secrets match:', match) // true

  // Now both parties can use the 32-byte shared secret for symmetric encryption
}
```

### 10.2 Hybrid Encryption (Full Message)

```typescript
import { kemGenerateKeyPair, encrypt, decrypt, MOS_128 } from 'k-mosaic'

async function hybridEncryption() {
  // Generate key pair
  const { publicKey, secretKey } = await kemGenerateKeyPair(MOS_128)

  // Encrypt a message (uses KEM + AES-256-GCM internally)
  const message = new TextEncoder().encode('Hello, post-quantum world!')
  const encrypted = await encrypt(message, publicKey)

  console.log('Encrypted size:', encrypted.length, 'bytes')

  // Decrypt
  const decrypted = await decrypt(encrypted, secretKey, publicKey)
  const plaintext = new TextDecoder().decode(decrypted)

  console.log('Decrypted:', plaintext)
  // "Hello, post-quantum world!"
}
```

### 10.3 Digital Signatures

```typescript
import { signGenerateKeyPair, sign, verify, MOS_128 } from 'k-mosaic'

async function digitalSignature() {
  // Generate signing key pair
  const { publicKey, secretKey } = await signGenerateKeyPair(MOS_128)

  // Sign a document
  const document = new TextEncoder().encode('Important contract terms...')
  const signature = await sign(document, secretKey, publicKey)

  console.log('Signature size:', signature.length, 'bytes')

  // Anyone can verify with the public key
  const isValid = await verify(document, signature, publicKey)
  console.log('Signature valid:', isValid) // true

  // Tampering detection
  const tamperedDoc = new TextEncoder().encode('MODIFIED contract terms...')
  const isValidTampered = await verify(tamperedDoc, signature, publicKey)
  console.log('Tampered signature valid:', isValidTampered) // false
}
```

### 10.4 Security Analysis

```typescript
import { kemGenerateKeyPair, analyzePublicKey, MOS_128 } from 'k-mosaic'

async function securityAnalysis() {
  const { publicKey } = await kemGenerateKeyPair(MOS_128)

  // Analyze the security of each component
  const analysis = analyzePublicKey(publicKey)

  console.log('Security Analysis:')
  console.log('─'.repeat(50))
  console.log(`SLSS Component:`)
  console.log(`  Lattice dimension: ${analysis.slss.dimension}`)
  console.log(`  Sparsity weight: ${analysis.slss.sparsity}`)
  console.log(`  Estimated security: ~${analysis.slss.estimatedSecurity} bits`)
  console.log()
  console.log(`TDD Component:`)
  console.log(
    `  Tensor dimension: ${analysis.tdd.tensorDim}×${analysis.tdd.tensorDim}×${analysis.tdd.tensorDim}`,
  )
  console.log(`  Tensor rank: ${analysis.tdd.rank}`)
  console.log(`  Estimated security: ~${analysis.tdd.estimatedSecurity} bits`)
  console.log()
  console.log(`EGRW Component:`)
  console.log(`  Graph size: ~${analysis.egrw.graphSize} vertices`)
  console.log(`  Walk length: ${analysis.egrw.walkLength}`)
  console.log(`  Estimated security: ~${analysis.egrw.estimatedSecurity} bits`)
  console.log()
  console.log(`Combined Security:`)
  console.log(`  Classical: ~${analysis.combined.estimatedSecurity} bits`)
  console.log(`  Post-Quantum: ~${analysis.combined.quantumSecurity} bits`)
}
```

---

## 11. Comparison with Existing Schemes

### 11.1 Feature Comparison

| Feature                  | ML-KEM (Kyber)            | kMOSAIC                 | McEliece                  |
| ------------------------ | ------------------------- | ----------------------- | ------------------------- |
| **Hardness Assumptions** | 1 (M-LWE)                 | **3 (SLSS+TDD+EGRW)**   | 1 (Syndrome decoding)     |
| **Defense-in-Depth**     | ✗ Single Point of Failure | **✓ Triple Redundancy** | ✗ Single Point of Failure |
| **Public Key Size**      | 1.2 KB (Kyber-768)        | ~824 KB (MOS-128)       | 261 KB (mceliece348864)   |
| **Ciphertext Size**      | 1.1 KB (Kyber-768)        | ~5.9 KB (MOS-128)       | 128 B (mceliece348864)    |
| **Standardized**         | NIST (2024)               | ✗ Experimental          | NIST (2024)               |
| **Security Proof**       | Formal (ROM)              | Informal (Heuristic)    | Formal                    |
| **Quantum Maturity**     | High                      | Low                     | High                      |

### 11.2 When to Choose Each

**Choose ML-KEM (Kyber) when**:

- You need a standardized, proven algorithm
- Bandwidth and key size are critical
- You trust the M-LWE assumption

**Choose kMOSAIC when**:

- Defense-in-depth is a priority
- You want to hedge against future cryptanalysis
- Key size is not a constraint
- Experimental/research context

**Choose McEliece when**:

- You prioritize code-based security
- Small ciphertext is important
- Large public keys are acceptable

### 11.3 The Case for Heterogeneous Hardness

The history of cryptography shows that assumptions can fail unexpectedly:

| Year | Event                      | Impact                                                                 |
| ---- | -------------------------- | ---------------------------------------------------------------------- |
| 1994 | Shor's algorithm published | RSA, DH, ECC become quantum-vulnerable                                 |
| 2004 | MD5 collisions announced   | MD5 no longer suitable for collision resistance                        |
| 2022 | SIKE broken                | NIST PQC finalist eliminated (e.g., ~1 hour for SIKEp434 key recovery) |

kMOSAIC's heterogeneous approach means that even if one problem class is broken, the secret remains protected by the other two. This is particularly critical given the concentration of deployment around lattice-based KEMs and signatures. A major breakthrough in lattice cryptanalysis could undermine lattice-based schemes (e.g., ML-KEM/ML-DSA, and other lattice-based proposals), while kMOSAIC's TDD and EGRW components are designed to be unrelated to lattice assumptions.

---

## 12. Future Work and Research Directions

### 12.1 Theoretical Work Needed

1. **Formal Security Proofs**: Develop rigorous security reductions for the combined construction
2. **Cryptanalysis Invitation**: Submit to academic review and cryptographic competitions
3. **Parameter Optimization**: Fine-tune parameters based on latest attack complexity estimates

### 12.2 Implementation Improvements

1. **Native Implementations**: Develop Rust/Go implementations with proper constant-time guarantees
2. **Hardware Acceleration**: Explore SIMD optimizations for matrix/tensor operations
3. **Threshold Variants**: Extend to threshold signatures and distributed key generation

### 12.3 Standardization Path

1. Submit to academic conferences (CRYPTO, EUROCRYPT, ASIACRYPT)
2. Invite public cryptanalysis
3. If validated, propose to IETF/NIST for consideration

### 12.4 Reference Implementation Roadmap

The current Node.js/TypeScript implementation is for **validation and research purposes**.

**Codebase Statistics:**

- **Language**: TypeScript (Strict Mode)
- **Size**: ~4,500 lines of code
- **Test Coverage**: Comprehensive unit tests for all three components
- **Dependencies**: Minimal (only Node.js built-ins)

A production-quality implementation should be:

- Written in a memory-safe systems language (Rust, Go)
- Formally verified for constant-time execution
- Reviewed by professional cryptographers
- Tested against known attack vectors

---

## 13. Conclusion

### 13.1 Summary

kMOSAIC introduces a novel approach to post-quantum cryptography through **cryptographic entanglement** of three heterogeneous hard problems:

- **SLSS**: Sparse Lattice Subset Sum (lattice-based)
- **TDD**: Tensor Decomposition Distinguishing (tensor-based)
- **EGRW**: Expander Graph Random Walk (graph-based)

The key innovation is that an attacker must break **all three** independent problems to compromise the system, while breaking any subset reveals **zero information** about the secret.

### 13.2 Key Takeaways

1. **Defense-in-Depth**: Multiple independent security layers
2. **Quantum Diversity**: No single quantum algorithm threatens all components
3. **Information-Theoretic Sharing**: Secret fragmentation with perfect security
4. **Binding Commitment**: Components are cryptographically inseparable

### 13.3 Call to Action

We invite the cryptographic community to:

1. **Analyze** the security of this construction
2. **Attack** the reference implementation
3. **Improve** the parameter selection
4. **Collaborate** on formal security proofs

This is an experimental proposal intended to spark discussion about defense-in-depth approaches in post-quantum cryptography.

---

## 14. References

### Academic Foundations

1. Regev, O. (2005). "On Lattices, Learning with Errors, Random Linear Codes, and Cryptography". [J. ACM 56, 6, Article 34](https://dl.acm.org/doi/10.1145/1638593.1638599)
2. Kiltz, E., et al. (2018). "A Modular Analysis of the Fujisaki-Okamoto Transformation". [TCC 2017](https://eprint.iacr.org/2017/604)
3. Håstad, J. (1990). "Tensor Rank is NP-Complete". [J. Algorithms 11(4): 644-654](<https://doi.org/10.1016/0196-6774(90)90014-6>)
4. Lubotzky, A., et al. (1988). "Ramanujan Graphs". [Combinatorica 8, 261–277](https://doi.org/10.1007/BF02126799)
5. Shamir, A. (1979). "How to Share a Secret". [CACM 22(11): 612-613](https://doi.org/10.1145/359168.359176)
6. Fiat, A., Shamir, A. (1986). "How to Prove Yourself: Practical Solutions to Identification and Signature Problems". [CRYPTO 1986](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)

### Related Cryptographic Schemes

7. NIST Post-Quantum Cryptography Standardization (2024). [NIST IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.pdf)
8. Bernstein, D.J., Lange, T. (2017). "Post-Quantum Cryptography". [Nature 549, 188–194](https://www.nature.com/articles/nature23461)
9. Ajtai, M. (1996). "Generating Hard Instances of Lattice Problems". [STOC '96](https://dl.acm.org/doi/10.1145/237814.237838)

### Reference Implementation

10. kMOSAIC TypeScript Implementation: [https://github.com/BackendStack21/k-mosaic](https://github.com/BackendStack21/k-mosaic)

---

## Appendix A: Algorithm Pseudocode

### A.1 Key Generation

```
function kemGenerateKeyPair(level):
    seed ← random(256 bits)

    // Generate component keys
    (slss_pk, slss_sk) ← SLSS.KeyGen(seed, level.slss_params)
    (tdd_pk, tdd_sk)   ← TDD.KeyGen(seed, level.tdd_params)
    (egrw_pk, egrw_sk) ← EGRW.KeyGen(seed, level.egrw_params)

    // Create binding commitment
    binding ← SHA3-256(slss_pk || tdd_pk || egrw_pk)

    publicKey ← {slss_pk, tdd_pk, egrw_pk, binding, level}
    secretKey ← {slss_sk, tdd_sk, egrw_sk, seed}

    return (publicKey, secretKey)
```

### A.2 Encapsulation

```
function encapsulate(publicKey):
    m ← random(256 bits)  // Ephemeral secret

    // Split secret into three shares
    (m₁, m₂, m₃) ← SecretShare(m, 3)

    // Encrypt each share with different problem
    c₁ ← SLSS.Encrypt(m₁, publicKey.slss)
    c₂ ← TDD.Encrypt(m₂, publicKey.tdd)
    c₃ ← EGRW.Encrypt(m₃, publicKey.egrw)

    // Generate NIZK proof of correct construction
    proof ← NIZK.Prove(m, m₁, m₂, m₃, c₁, c₂, c₃)

    ciphertext ← {c₁, c₂, c₃, proof}
    sharedSecret ← SHAKE256(m || Hash(ciphertext), 32)

    return (ciphertext, sharedSecret)
```

### A.3 Decapsulation

```
function decapsulate(ciphertext, secretKey, publicKey):
    // Verify NIZK proof
    if not NIZK.Verify(ciphertext.proof, ciphertext):
        return ⊥

    // Decrypt each component
    m₁' ← SLSS.Decrypt(ciphertext.c₁, secretKey.slss)
    m₂' ← TDD.Decrypt(ciphertext.c₂, secretKey.tdd)
    m₃' ← EGRW.Decrypt(ciphertext.c₃, secretKey.egrw)

    // Reconstruct secret
    m' ← m₁' ⊕ m₂' ⊕ m₃'

    // Re-encapsulate to verify (Fujisaki-Okamoto)
    (ciphertext', _) ← encapsulate_deterministic(publicKey, m')

    if ciphertext' ≠ ciphertext:
        // Implicit rejection
        return SHAKE256(secretKey.seed || Hash(ciphertext), 32)
    else:
        return SHAKE256(m' || Hash(ciphertext), 32)
```

---

## Appendix B: Security Level Justification

### B.1 SLSS Security Estimate

For SLSS with parameters (n, m, q, w):

- Lattice dimension: n
- Sparsity: w non-zero entries in {-1, 0, 1}
- Security ≈ 2^(0.292 × n) for lattice attacks
- Additional hardness from sparsity constraint

### B.2 TDD Security Estimate

For TDD with parameters (n, r, q):

- Tensor dimension: n × n × n
- Rank: r
- Best known attacks: O(n^(r/2)) operations
- Security ≈ r × log₂(n) bits

### B.3 EGRW Security Estimate

For EGRW with parameters (p, k):

- Graph size: |SL(2, ℤp)| ≈ p³
- Walk length: k
- Possible paths: 4^k
- Security ≈ min(k × log₂(4), 3 × log₂(p))

---

**Document Version**: 1.0  
**Last Updated**: December 26, 2025  
**Status**: Experimental - Not for Production Use
