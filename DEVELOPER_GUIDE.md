# The kMOSAIC Book

## A Complete Guide to Post-Quantum Cryptography with Defense-in-Depth

**Version 1.0** | **December 2025**

---

# Preface

> ⚠️ **IMPORTANT DISCLAIMER**: kMOSAIC is an **experimental** cryptographic construction. It has **NOT** undergone formal peer review or security auditing. **DO NOT** use it for production systems protecting sensitive data. For production, use NIST-standardized algorithms like ML-KEM (Kyber) and ML-DSA (Dilithium).

Welcome to The kMOSAIC Book. This guide is designed to take you from zero knowledge of cryptography to a complete understanding of how kMOSAIC works, why it exists, and how to use it in your applications.

**Who This Book Is For:**

- Software developers who want to understand cryptography
- Security engineers evaluating post-quantum solutions
- Students learning about modern cryptography
- Anyone curious about how we protect data from quantum computers

**How to Read This Book:**

- **Part I** (Chapters 1-3): Foundational concepts. Start here if you're new to cryptography.
- **Part II** (Chapters 4-7): The mathematics behind kMOSAIC. Essential for understanding the security.
- **Part III** (Chapters 8-11): Implementation details. For developers building with kMOSAIC.
- **Part IV** (Chapters 12-15): Advanced topics. Security engineering, comparisons, and the future.
- **Appendices**: Quick reference, glossary, and resources.

Let's begin.

---

# Table of Contents

## Part I: Foundations

1. [What is Cryptography?](#chapter-1-what-is-cryptography)
   - [The Basic Problem](#the-basic-problem)
   - [Symmetric vs Asymmetric Cryptography](#symmetric-vs-asymmetric-cryptography)
   - [What Does "Secure" Mean?](#what-does-secure-mean)
   - [The Role of Mathematics](#the-role-of-mathematics)

2. [The Quantum Threat](#chapter-2-the-quantum-threat)
   - [Classical Computers vs Quantum Computers](#classical-computers-vs-quantum-computers)
   - [How Quantum Computers Break Current Cryptography](#how-quantum-computers-break-current-cryptography)
   - [Shor's Algorithm Explained Simply](#shors-algorithm-explained-simply)
   - [Grover's Algorithm and Symmetric Crypto](#grovers-algorithm-and-symmetric-crypto)
   - [When Will Quantum Computers Be a Threat?](#when-will-quantum-computers-be-a-threat)

3. [Introduction to kMOSAIC](#chapter-3-introduction-to-kmosaic)
   - [The Defense-in-Depth Philosophy](#the-defense-in-depth-philosophy)
   - [Why Three Problems Instead of One?](#why-three-problems-instead-of-one)
   - [The kMOSAIC Architecture Overview](#the-kmosaic-architecture-overview)
   - [What kMOSAIC Provides](#what-kmosaic-provides)

## Part II: The Mathematics

4. [Mathematical Preliminaries](#chapter-4-mathematical-preliminaries)
   - [Numbers and Modular Arithmetic](#numbers-and-modular-arithmetic)
   - [Vectors and Matrices](#vectors-and-matrices)
   - [Groups and Algebraic Structures](#groups-and-algebraic-structures)
   - [Probability and Randomness](#probability-and-randomness)
   - [Hash Functions](#hash-functions)

5. [Lattice Cryptography (SLSS)](#chapter-5-lattice-cryptography-slss)
   - [What is a Lattice?](#what-is-a-lattice)
   - [Hard Problems on Lattices](#hard-problems-on-lattices)
   - [The Short Integer Solution (SIS) Problem](#the-short-integer-solution-sis-problem)
   - [Learning With Errors (LWE)](#learning-with-errors-lwe)
   - [How kMOSAIC Uses Lattices](#how-kmosaic-uses-lattices)

6. [Tensor Cryptography (TDD)](#chapter-6-tensor-cryptography-tdd)
   - [What is a Tensor?](#what-is-a-tensor)
   - [Tensor Decomposition](#tensor-decomposition)
   - [Why Tensors are Hard to Decompose](#why-tensors-are-hard-to-decompose)
   - [The TDD Construction](#the-tdd-construction)
   - [How kMOSAIC Uses Tensors](#how-kmosaic-uses-tensors)

7. [Graph Cryptography (EGRW)](#chapter-7-graph-cryptography-egrw)
   - [What is a Graph?](#what-is-a-graph)
   - [Expander Graphs](#expander-graphs)
   - [Random Walks on Graphs](#random-walks-on-graphs)
   - [The EGRW Construction](#the-egrw-construction)
   - [How kMOSAIC Uses Graphs](#how-kmosaic-uses-graphs)

## Part III: Implementation

8. [Key Encapsulation Mechanism (KEM)](#chapter-8-key-encapsulation-mechanism-kem)
   - [What is a KEM?](#what-is-a-kem)
   - [KEM vs Key Exchange vs Encryption](#kem-vs-key-exchange-vs-encryption)
   - [The kMOSAIC KEM Protocol](#the-kmosaic-kem-protocol)
   - [Code Examples](#kem-code-examples)
   - [Security Properties](#kem-security-properties)

9. [Digital Signatures](#chapter-9-digital-signatures)
   - [What is a Digital Signature?](#what-is-a-digital-signature)
   - [The Fiat-Shamir Transform](#the-fiat-shamir-transform)
   - [The kMOSAIC Signature Protocol](#the-kmosaic-signature-protocol)
   - [Code Examples](#signature-code-examples)
   - [Rejection Sampling Explained](#rejection-sampling-explained-in-depth)

10. [Cryptographic Entanglement](#chapter-10-cryptographic-entanglement)
    - [The Problem with Simple Combination](#the-problem-with-simple-combination)
    - [Secret Sharing Fundamentals](#secret-sharing-fundamentals)
    - [How kMOSAIC Binds Components](#how-kmosaic-binds-components)
    - [The Security Proof Intuition](#the-security-proof-intuition)

11. [Using kMOSAIC in Your Application](#chapter-11-using-kmosaic-in-your-application)
    - [Installation and Setup](#installation-and-setup)
    - [Encrypting Data](#encrypting-data)
    - [Signing Messages](#signing-messages)
    - [Key Management Best Practices](#key-management-best-practices)
    - [Error Handling](#error-handling)

## Part IV: Advanced Topics

12. [Security Engineering](#chapter-12-security-engineering)
    - [Side-Channel Attacks](#side-channel-attacks)
    - [Constant-Time Programming](#constant-time-programming)
    - [Memory Safety](#memory-safety)
    - [Secure Randomness](#secure-randomness)

13. [Parameters and Performance](#chapter-13-parameters-and-performance)
    - [Security Levels Explained](#security-levels-explained)
    - [Parameter Selection](#parameter-selection)
    - [Performance Benchmarks](#performance-benchmarks)
    - [Optimization Strategies](#optimization-strategies)

14. [Comparison with Other Schemes](#chapter-14-comparison-with-other-schemes)
    - [NIST Standardized Algorithms](#nist-standardized-algorithms)
    - [When to Use kMOSAIC](#when-to-use-kmosaic)
    - [Migration Strategies](#migration-strategies)

15. [The Future of Post-Quantum Cryptography](#chapter-15-the-future-of-post-quantum-cryptography)
    - [Ongoing Research](#ongoing-research)
    - [Potential Attacks](#potential-attacks)
    - [The Road Ahead](#the-road-ahead)

## Appendices

- [Appendix A: Glossary](#appendix-a-glossary)
- [Appendix B: Further Reading](#appendix-b-further-reading)
- [Appendix C: API Reference](#appendix-c-api-reference)
- [Appendix D: FAQ](#appendix-d-faq)

---

# Part I: Foundations

---

# Chapter 1: What is Cryptography?

Before we dive into kMOSAIC, we need to understand what cryptography is and why it matters. This chapter builds your foundation from the ground up.

## The Basic Problem

Imagine you want to send a message to your friend across the room, but there's someone in the middle who can hear everything you say. How do you communicate secretly?

This is the fundamental problem of cryptography: **how do we communicate securely when others might be listening?**

Let's make this concrete with an example:

**Alice** wants to send a message to **Bob**. **Eve** (the eavesdropper) is watching the communication channel.

```
Alice ----[Message]----> Bob
              ^
              |
            Eve (watching)
```

Without cryptography, Eve sees everything Alice sends. With cryptography, Alice can transform her message into something that looks like nonsense to Eve, but Bob can transform it back into the original message.

### A Simple Example: The Caesar Cipher

One of the oldest cryptographic techniques is the Caesar Cipher, used by Julius Caesar over 2000 years ago.

**The Idea**: Shift each letter in your message by a fixed number.

**Example with shift of 3**:

```
Original:  H E L L O
Shifted:   K H O O R
```

- A → D
- B → E
- C → F
- ... and so on

To decrypt, Bob shifts back by 3:

```
Received:  K H O O R
Shifted:   H E L L O
```

**The Key**: The number 3 (the shift amount) is the "key". Alice and Bob must both know this key.

**The Problem**: The Caesar cipher is extremely weak. There are only 26 possible shifts, so Eve can try all of them in seconds. Modern cryptography needs to be much, much harder to break.

### What Modern Cryptography Needs

A good cryptographic system must have these properties:

1. **Correctness**: If Alice encrypts a message and Bob decrypts it with the right key, he gets the original message back.

2. **Security**: Even if Eve sees the encrypted message (ciphertext), she cannot figure out the original message (plaintext) without the key.

3. **Efficiency**: Encryption and decryption should be fast enough for practical use.

4. **Key Space**: There should be so many possible keys that Eve cannot try them all.

## Symmetric vs Asymmetric Cryptography

There are two fundamental types of cryptography. Understanding the difference is crucial.

### Symmetric Cryptography (Secret-Key)

In symmetric cryptography, Alice and Bob share the **same secret key**.

```
Alice                                  Bob
  |                                     |
  |  Secret Key: "MyPassword123"        |  Secret Key: "MyPassword123"
  |                                     |
  |  Encrypt("Hello") → "Xk9#mP"        |
  |  --------------------------→        |
  |                                     |  Decrypt("Xk9#mP") → "Hello"
```

**Examples**: AES, ChaCha20, 3DES

**Advantages**:

- Very fast (hardware acceleration available)
- Small keys (128-256 bits)
- Well-understood security

**The Big Problem**: How do Alice and Bob share the secret key in the first place?

If they meet in person, they can exchange keys. But what if they're on opposite sides of the world and have never met? They can't send the key over the internet because Eve is watching!

This is called the **Key Distribution Problem**.

### Asymmetric Cryptography (Public-Key)

Asymmetric cryptography, invented in the 1970s[^diffie1976], solved the key distribution problem with a brilliant insight: **use two different keys**.

- **Public Key**: Can be shared with everyone (even Eve)
- **Private Key**: Kept secret by the owner

```
Alice                                  Bob
  |                                     |
  | Has: Bob's Public Key               | Has: Bob's Private Key
  |      (everyone has this)            |      (only Bob has this)
  |                                     |
  |  Encrypt("Hello", BobPublicKey)     |
  |  → "Xk9#mP"                         |
  |  --------------------------→        |
  |                                     |  Decrypt("Xk9#mP", BobPrivateKey)
  |                                     |  → "Hello"
```

**The Magic**: A message encrypted with the public key can ONLY be decrypted with the corresponding private key. Even if Eve has the public key (she does!), she cannot decrypt.

**Examples**: RSA, Elliptic Curve Cryptography (ECC), Diffie-Hellman

**How is This Possible?**

This relies on **trapdoor functions** — mathematical operations that are:

- Easy to compute in one direction
- Very hard to reverse WITHOUT extra information (the "trapdoor")
- Easy to reverse WITH the trapdoor

**Example: RSA**

RSA is based on the difficulty of factoring large numbers.

- It's easy to multiply: 61 × 53 = 3233
- It's hard to factor: 3233 = ? × ?

For small numbers like 3233, you can try all possibilities. But RSA uses numbers with 2048+ bits (617+ digits). No computer can factor such numbers in a reasonable time.

The private key contains the factors. The public key contains the product. Without the factors (private key), you can't efficiently reverse the encryption.

## What Does "Secure" Mean?

When we say a cryptographic system is "secure," what exactly do we mean?

### Perfect Security (Information-Theoretic)

A system has **perfect security** if, even with unlimited computing power, an attacker learns nothing about the plaintext from the ciphertext.

**The One-Time Pad** achieves this:

1. Generate a random key as long as your message
2. XOR the message with the key
3. Never reuse the key

```
Message:  01001000 01100101 01101100 01101100 01101111  ("Hello")
Key:      10110101 11001010 00110011 10101010 01010101  (random)
XOR:      11111101 10101111 01011111 11000110 00111010  (ciphertext)
```

This is mathematically unbreakable. Every possible plaintext is equally likely given the ciphertext.

**Problem**: The key must be as long as the message and can never be reused. This is impractical for most applications.

### Computational Security

Since perfect security is impractical, we settle for **computational security**:

A system is computationally secure if breaking it would require more computing resources than any attacker could realistically have.

**What counts as "secure enough"?**

We measure security in "bits of security":

| Security Level | Operations to Break | Real-World Equivalent                   |
| :------------- | :------------------ | :-------------------------------------- |
| 80 bits        | 2^80 ≈ 10^24        | Not secure today                        |
| 128 bits       | 2^128 ≈ 10^38       | Secure against all known attacks        |
| 256 bits       | 2^256 ≈ 10^77       | More atoms than in the visible universe |

**128 bits of security** is the current standard. Breaking it would require:

- More energy than the sun produces in its lifetime
- Running every computer on Earth for billions of years

### Attack Models

Security also depends on what the attacker can do:

1. **Ciphertext-Only Attack (COA)**: Eve only sees encrypted messages.

2. **Known-Plaintext Attack (KPA)**: Eve knows some plaintext-ciphertext pairs.

3. **Chosen-Plaintext Attack (CPA)**: Eve can encrypt messages of her choice.

4. **Chosen-Ciphertext Attack (CCA)**: Eve can also decrypt messages of her choice (except the target).

Modern cryptography aims for security against CCA (the strongest attack model).

## The Role of Mathematics

Cryptography is applied mathematics. Every cryptographic system is built on mathematical problems that are believed to be hard to solve.

### One-Way Functions

A **one-way function** is easy to compute but hard to invert.

**Example: Modular exponentiation**

Given: g = 5, x = 347, p = 541

Compute: y = g^x mod p = 5^347 mod 541 = 237

Easy! A computer does this in microseconds.

But given only (g=5, y=237, p=541), finding x is hard. This is the **Discrete Logarithm Problem**.

### Trapdoor Functions

A **trapdoor function** is a one-way function that becomes easy to invert if you know a secret (the trapdoor).

**Example: RSA**

- Public: (n, e) where n = p × q (product of two primes)
- Private: (p, q, d) where d is derived from p and q

Encryption: c = m^e mod n (easy with public key)
Decryption: m = c^d mod n (easy with private key, hard without)

The trapdoor is knowing the factors p and q.

### The Foundation of Trust

Here's the crucial insight: **cryptography's security rests on mathematical assumptions**.

For RSA, we assume:

> "Factoring large numbers is computationally infeasible."

For Elliptic Curves, we assume:

> "The discrete logarithm problem on elliptic curves is hard."

If these assumptions are wrong (if someone finds fast algorithms to solve these problems), the cryptography breaks.

**This is exactly what quantum computers threaten.**

---

# Chapter 2: The Quantum Threat

This chapter explains why we need post-quantum cryptography. We'll cover quantum computing basics and exactly how it threatens current cryptography.

## Classical Computers vs Quantum Computers

### How Classical Computers Work

Classical computers (your laptop, phone, servers) use **bits** — tiny switches that are either 0 or 1.

Everything a classical computer does is manipulating these bits:

- Adding numbers
- Searching lists
- Running your browser

A classical computer with n bits can be in ONE of 2^n possible states at any time.

**Example with 2 bits**: Can be in state 00, 01, 10, or 11 — but only ONE of these at a time.

### How Quantum Computers Work

Quantum computers use **qubits** (quantum bits). A qubit can be in a **superposition** of 0 AND 1 simultaneously.

This isn't science fiction — it's quantum mechanics, experimentally verified for over 100 years.

**Key quantum phenomena**:

1. **Superposition**: A qubit can be 0, 1, or BOTH at the same time (with different probabilities).

2. **Entanglement**: Multiple qubits can be correlated in ways that classical physics cannot explain.

3. **Interference**: Quantum states can add up (constructive) or cancel out (destructive).

**The Power**: A quantum computer with n qubits can represent 2^n states simultaneously.

- 50 qubits → 2^50 = 1,125,899,906,842,624 states
- 100 qubits → 2^100 ≈ 10^30 states

**The Catch**: When you measure a qubit, the superposition "collapses" to either 0 or 1. You can't directly read out all 2^n states.

The art of quantum algorithms is setting up interference so that wrong answers cancel out and right answers amplify.

### What Quantum Computers Can and Cannot Do

❌ **Quantum computers are NOT**:

- Infinitely fast classical computers
- Magic boxes that solve everything instantly
- Able to try all possibilities at once (not that simple)

✅ **Quantum computers ARE**:

- A different model of computation
- Faster at SOME problems (not all)
- Particularly good at problems with special mathematical structure

**Problems quantum computers excel at**:

- Factoring large numbers
- Discrete logarithms
- Searching unstructured databases (modest speedup)
- Simulating quantum systems (chemistry, physics)

**Problems quantum computers DON'T help much with**:

- Most everyday computing tasks
- General NP-complete problems (traveling salesman, etc.)
- Hash function collision-finding (only modest speedup)

## How Quantum Computers Break Current Cryptography

### Shor's Algorithm: The Cryptographic Nightmare

In 1994, mathematician Peter Shor discovered a quantum algorithm that can[^shor1994]:

1. **Factor large numbers** in polynomial time
2. **Solve discrete logarithms** in polynomial time

This is catastrophic for cryptography because:

| Algorithm          | Security Based On  | Broken by Shor's Algorithm? |
| :----------------- | :----------------- | :-------------------------- |
| RSA                | Integer Factoring  | ✅ Yes                      |
| DSA                | Discrete Logarithm | ✅ Yes                      |
| ECDSA              | Elliptic Curve DLP | ✅ Yes                      |
| Diffie-Hellman     | Discrete Logarithm | ✅ Yes                      |
| Bitcoin signatures | ECDSA              | ✅ Yes                      |

Almost ALL widely-used public-key cryptography is broken.

## Shor's Algorithm Explained Simply

Let's understand Shor's algorithm without complex mathematics.

### The Goal

We want to factor N = 15 (in real life, N has 2048+ bits).

### The Classical Approach

Try dividing by 2, 3, 4, 5... until you find a factor.
Time: O(√N) — still extremely slow for 2048-bit numbers.

### The Quantum Insight

Shor's algorithm doesn't directly search for factors. Instead:

1. **Convert factoring to period-finding**

   Pick a random number a (say, a = 7).

   Consider the sequence: 7^1 mod 15, 7^2 mod 15, 7^3 mod 15, ...

   This gives: 7, 4, 13, 1, 7, 4, 13, 1, ...

   The sequence repeats with period r = 4!

2. **Find the period using quantum mechanics**

   A quantum computer can find this period r efficiently using the Quantum Fourier Transform.

   This is where quantum superposition provides the speedup.

3. **Extract factors from the period**

   Once we know r = 4:
   - Compute 7^(4/2) mod 15 = 7^2 mod 15 = 49 mod 15 = 4
   - Compute gcd(4-1, 15) = gcd(3, 15) = 3 ← Factor found!
   - Compute gcd(4+1, 15) = gcd(5, 15) = 5 ← Other factor!

   15 = 3 × 5 ✓

### Why This is Fast

Classical period-finding: Exponential time
Quantum period-finding: Polynomial time

The quantum speedup comes from the ability to evaluate f(x) = a^x mod N for many values of x simultaneously in superposition, then use interference to extract the period.

### The Bottom Line

**With a large enough quantum computer, RSA is broken.**

A 2048-bit RSA key could be factored in hours or days instead of billions of years.

## Grover's Algorithm and Symmetric Crypto

Shor's algorithm is specific to factoring and discrete logs. What about symmetric cryptography (AES)?

### Grover's Algorithm

In 1996, Lov Grover discovered a quantum algorithm for searching[^grover1996]:

**Classical search**: To find an item in N possibilities → N tries (on average N/2)
**Quantum search**: To find an item in N possibilities → √N tries

### Impact on AES

AES-128 has 2^128 possible keys.

| Attack Type | Classical        | Quantum (Grover) |
| :---------- | :--------------- | :--------------- |
| Brute Force | 2^128 operations | 2^64 operations  |

This cuts the security level in half!

**The Solution**: Double the key size.

- AES-128 → AES-256 (128 bits of post-quantum security)

### Impact on Hash Functions

Hash functions (SHA-256, SHA-3) are also affected:

| Attack    | Classical | Quantum                |
| :-------- | :-------- | :--------------------- |
| Preimage  | 2^256     | 2^128                  |
| Collision | 2^128     | 2^85 (slightly better) |

**Solution**: Use SHA-384 or SHA-512 for post-quantum security.

### Summary: What's Broken?

| Cryptography Type     | Example  | Quantum Threat           | Solution             |
| :-------------------- | :------- | :----------------------- | :------------------- |
| Public-Key Encryption | RSA      | Completely broken (Shor) | New algorithms (PQC) |
| Digital Signatures    | ECDSA    | Completely broken (Shor) | New algorithms (PQC) |
| Key Exchange          | DH, ECDH | Completely broken (Shor) | New algorithms (PQC) |
| Symmetric Encryption  | AES      | Security halved (Grover) | Double key size      |
| Hash Functions        | SHA-256  | Security halved (Grover) | Use larger hash      |

## When Will Quantum Computers Be a Threat?

### Current State (2025)

As of 2025:

- Largest quantum computers: ~1000 qubits
- Most are "noisy" (errors accumulate quickly)
- Nobody has broken real cryptography with a quantum computer

**To break RSA-2048, experts estimate we need**:

- ~4000+ logical qubits (error-corrected)
- Millions of physical qubits (due to error correction overhead)
- Hours to days of coherent operation

### Timeline Estimates

Different experts give different estimates:

| Source         | Estimate for "Cryptographically Relevant" QC |
| :------------- | :------------------------------------------- |
| NSA            | "Not if, but when" — planning for 2030s      |
| NIST           | Started PQC standardization in 2016          |
| Tech Companies | Most estimate 2030-2040                      |
| Optimists      | Could be sooner with breakthroughs           |

### The "Harvest Now, Decrypt Later" Attack

Here's why we need to act NOW, not later:

1. Adversaries can record encrypted communications TODAY
2. They store this data
3. When quantum computers arrive, they decrypt everything

This means:

- Sensitive data with long lifetimes (medical records, state secrets, financial data) is already at risk
- Anything encrypted today with RSA/ECC could be readable in 10-20 years

**The NSA and other agencies are believed to be doing exactly this.**

### The Bottom Line

We don't know exactly when quantum computers will break cryptography, but:

1. It WILL happen eventually
2. The transition takes years (updating infrastructure is slow)
3. Some data needs protection for decades

Therefore: **We need to start deploying post-quantum cryptography NOW.**

---

# Chapter 3: Introduction to kMOSAIC

Now that you understand the threat, let's introduce kMOSAIC — a unique approach to post-quantum cryptography.

## The Defense-in-Depth Philosophy

### What is Defense-in-Depth?

Defense-in-depth is a security strategy that uses multiple layers of protection. If one layer fails, others still protect you.

**Physical Security Example**:

```
Layer 1: Security fence around building
Layer 2: Locked doors
Layer 3: Security guards
Layer 4: Safe for valuables
Layer 5: Alarm system
```

A burglar must defeat ALL layers, not just one.

### Applying Defense-in-Depth to Cryptography

Most post-quantum schemes use a single mathematical assumption:

```
┌─────────────────────────────────────┐
│         Your Encrypted Data          │
│                                       │
│  Protected by: Lattice Assumption     │
│                                       │
│  If lattices are broken → GAME OVER   │
└─────────────────────────────────────┘
```

kMOSAIC uses three independent assumptions:

```
┌─────────────────────────────────────────────────────┐
│              Your Encrypted Data                     │
├─────────────────────────────────────────────────────┤
│ Layer 1: Lattice Assumption (must break this)        │
├─────────────────────────────────────────────────────┤
│ Layer 2: Tensor Assumption (AND this)                │
├─────────────────────────────────────────────────────┤
│ Layer 3: Graph Assumption (AND this)                 │
├─────────────────────────────────────────────────────┤
│  Attacker must break ALL THREE to decrypt            │
└─────────────────────────────────────────────────────┘
```

### Why This Matters

History shows cryptographic assumptions can fail:

| Year    | What Happened                                                   |
| :------ | :-------------------------------------------------------------- |
| 2017    | NIST's SHA-1 declared broken (collisions found)[^sha1collision] |
| 2022    | SIKE (isogeny-based) completely broken[^castryck2022]           |
| 2022    | Rainbow (multivariate) broken[^beullens2022]                    |
| Ongoing | Lattice attacks improving (LLL, BKZ algorithms)                 |

If you're using a single-assumption scheme and that assumption fails, you have zero security.

With kMOSAIC, if one assumption fails, you still have two others protecting you.

## Why Three Problems Instead of One?

### The Heterogeneity Principle

kMOSAIC doesn't just use three problems — it uses three **fundamentally different** problems:

| Component | Mathematical Field      | Problem Type                      |
| :-------- | :---------------------- | :-------------------------------- |
| SLSS      | Number Theory / Algebra | Finding short vectors in lattices |
| TDD       | Multilinear Algebra     | Decomposing tensors               |
| EGRW      | Graph Theory            | Finding paths in expander graphs  |

**Why does this matter?**

Cryptographic breakthroughs are usually specific to one mathematical area:

- Lattice attacks (LLL, BKZ) don't help with tensors
- Tensor decomposition algorithms don't help with graphs
- Graph algorithms don't help with lattices

An attacker who breaks lattices is still stuck on tensors and graphs.

### Comparison with Other Hybrid Approaches

Some systems combine RSA + Lattice or ECC + Lattice. This is called "hybrid" cryptography.

**The Problem**: Both RSA/ECC and Lattice are from algebraic number theory. A fundamental breakthrough in algebraic structures could impact both.

**kMOSAIC's Approach**: Use problems from truly different mathematical universes.

## The kMOSAIC Architecture Overview

kMOSAIC has three main components:

### 1. SLSS (Structured Lattice Short Signature)

**Based on**: The [Short Integer Solution (SIS)](https://en.wikipedia.org/wiki/Short_integer_solution_problem) problem

**Intuition**:

- Public: A matrix A and a target vector t
- Secret: A short vector s such that A × s = t
- Hard Problem: Finding short vectors in high-dimensional spaces

**Analogy**: Imagine a maze in 1000 dimensions. You're given a destination point. You must find the shortest path using only tiny steps. Classical computers can't explore 1000-dimensional mazes efficiently.

### 2. TDD (Tensor Decomposition Distinguishing)

**Based on**: The hardness of [tensor decomposition](https://en.wikipedia.org/wiki/Tensor_decomposition)

**Intuition**:

- A tensor is a 3D (or higher) array of numbers
- Public: A tensor T (the "mixed" version)
- Secret: The simple components that created T
- Hard Problem: Unmixing the tensor into its components

**Analogy**: Imagine mixing red, blue, and yellow paint. You get a new color. Now, given ONLY the final color, figure out exactly how much of each original color went in. For 2D (matrices), this is easy. For 3D+ (tensors), it's NP-hard.

### 3. EGRW (Expander Graph Random Walk)

**Based on**: Finding specific paths in [expander graphs](https://en.wikipedia.org/wiki/Expander_graph)

**Intuition**:

- Public: Starting point A and ending point B on a huge, highly-connected graph
- Secret: The specific path from A to B
- Hard Problem: Finding the path when the graph is astronomically large

**Analogy**: Imagine a maze with 10^100 rooms, where each room has 4 doors, and every room looks identical. You're told someone started at room A and ended at room B. Find their exact path. Without the original path (secret key), this is infeasible.

### How They Work Together

The three components don't just run in parallel — they're cryptographically entangled:

```
Secret Message S
      │
      ▼
┌─────┴─────┐
│  Split S  │  (Secret Sharing)
└─────┬─────┘
      │
  ┌───┼───┐
  ▼   ▼   ▼
 s₁  s₂  s₃   (Three shares)
  │   │   │
  ▼   ▼   ▼
┌───┐┌───┐┌───┐
│SLSS││TDD││EGRW│  (Three encryptions)
└─┬─┘└─┬─┘└─┬─┘
  │   │   │
  ▼   ▼   ▼
 C₁  C₂  C₃   (Three ciphertexts)
```

**Key Point**: To recover S, you need ALL THREE shares. Breaking two out of three gets you nothing (information-theoretically secure).

## What kMOSAIC Provides

### Key Encapsulation Mechanism (KEM)

**Purpose**: Allow two parties to agree on a shared secret key over an insecure channel.

**Typical Use Case**:

1. Alice generates a kMOSAIC key pair (public + private)
2. Bob uses Alice's public key to encapsulate a random secret
3. Alice uses her private key to decapsulate and recover the same secret
4. Both now share a secret key for symmetric encryption (AES, etc.)

### Digital Signatures

**Purpose**: Prove that a message came from you and hasn't been modified.

**Typical Use Case**:

1. Alice generates a signing key pair
2. Alice signs a message with her private key
3. Anyone can verify the signature with Alice's public key
4. If the message was altered, verification fails

### Security Properties

kMOSAIC aims to provide:

| Property         | Meaning                                                                               |
| :--------------- | :------------------------------------------------------------------------------------ |
| IND-CCA2         | Indistinguishability under Chosen Ciphertext Attack (gold standard for encryption)    |
| EUF-CMA          | Existential Unforgeability under Chosen Message Attack (gold standard for signatures) |
| Post-Quantum     | Secure against known quantum attacks                                                  |
| Defense-in-Depth | Secure even if one of three assumptions fails                                         |

### What kMOSAIC Does NOT Do

- ❌ Symmetric encryption (use AES with kMOSAIC KEM)
- ❌ Password hashing (use Argon2, bcrypt)
- ❌ Key derivation (use HKDF with kMOSAIC output)
- ❌ Random number generation (uses system CSPRNG)

kMOSAIC focuses on the hard problem: post-quantum key encapsulation and signatures with defense-in-depth.

---

# Part II: The Mathematics

This part covers the mathematical foundations you need to understand kMOSAIC. Don't worry — we'll build up from basic concepts.

---

# Chapter 4: Mathematical Preliminaries

Before diving into the specific cryptographic constructions, we need to establish a common mathematical vocabulary. This chapter covers the building blocks that appear throughout cryptography.

## Numbers and Modular Arithmetic

### The Integers

You're familiar with integers: ..., -3, -2, -1, 0, 1, 2, 3, ...

In cryptography, we often work with **positive integers** and perform operations on them.

### Division and Remainders

When you divide 17 by 5:

- 17 ÷ 5 = 3 remainder 2
- We write: 17 = 5 × 3 + 2

The **remainder** (2 in this case) is the key concept for modular arithmetic.

### Modular Arithmetic: Clock Math

**Modular arithmetic** is like a clock. On a 12-hour clock:

- 10 o'clock + 5 hours = 3 o'clock (not 15 o'clock)
- We "wrap around" when we exceed 12

In mathematical notation:

```
10 + 5 ≡ 3 (mod 12)
```

This reads as "10 plus 5 is congruent to 3, modulo 12."

### The Modulo Operation

For any integers a and n (n > 0):

```
a mod n = remainder when a is divided by n
```

**Examples**:

```
17 mod 5 = 2      (17 = 5×3 + 2)
23 mod 7 = 2      (23 = 7×3 + 2)
100 mod 10 = 0    (100 = 10×10 + 0)
-3 mod 5 = 2      (-3 = 5×(-1) + 2)
```

### Why Modular Arithmetic Matters in Cryptography

1. **Bounded Numbers**: Without mod, numbers grow infinitely. With mod, they stay in a fixed range [0, n-1].

2. **One-Way Properties**: Some operations are easy to compute but hard to reverse in modular arithmetic.

3. **Efficient Computation**: Computers can handle fixed-size numbers efficiently.

### Modular Addition and Multiplication

All normal arithmetic rules apply, but we always reduce the result:

```
(7 + 8) mod 10 = 15 mod 10 = 5
(7 × 8) mod 10 = 56 mod 10 = 6
```

**Associativity**: (a + b) + c ≡ a + (b + c) (mod n)
**Commutativity**: a + b ≡ b + a (mod n)
**Distributivity**: a × (b + c) ≡ a×b + a×c (mod n)

### Modular Exponentiation

Raising a number to a power, then taking mod:

```
3^4 mod 7 = 81 mod 7 = 4
```

**The trick for large exponents**: We don't compute 3^1000000 then reduce. Instead, we reduce at each step:

```
3^1 mod 7 = 3
3^2 mod 7 = 9 mod 7 = 2
3^4 mod 7 = (3^2)^2 mod 7 = 2^2 mod 7 = 4
3^8 mod 7 = (3^4)^2 mod 7 = 4^2 mod 7 = 16 mod 7 = 2
```

This is called **square-and-multiply** and makes large exponents tractable.

### The Discrete Logarithm Problem

Given: g = 5, p = 23, and y = 8
Find: x such that 5^x ≡ 8 (mod 23)

This is **hard** for large numbers! You essentially have to try values of x one by one.

Answer: x = 18 (you can verify: 5^18 mod 23 = 8)

This one-way property (easy to compute, hard to reverse) is the basis of classical cryptography.

## Vectors and Matrices

### Vectors: Lists of Numbers

A **vector** is an ordered list of numbers:

```
v = [3, 7, 2, 5]
```

This is a 4-dimensional vector. Each number is called a **component** or **element**.

We can visualize 2D and 3D vectors as arrows:

- [3, 4] is an arrow pointing 3 units right and 4 units up
- [1, 2, 3] is an arrow in 3D space

For cryptography, we work with vectors in 100s or 1000s of dimensions. You can't visualize them, but the math still works!

### Vector Operations

**Addition** (component-wise):

```
[1, 2, 3] + [4, 5, 6] = [5, 7, 9]
```

**Scalar Multiplication**:

```
3 × [1, 2, 3] = [3, 6, 9]
```

**Dot Product** (multiply corresponding elements, then sum):

```
[1, 2, 3] · [4, 5, 6] = 1×4 + 2×5 + 3×6 = 4 + 10 + 18 = 32
```

### Vector Length (Norm)

The **Euclidean norm** (length) of a vector:

```
||[3, 4]|| = √(3² + 4²) = √(9 + 16) = √25 = 5
```

In cryptography, we care about "short" vectors — vectors with small norms.

### Matrices: Tables of Numbers

A **matrix** is a 2D grid of numbers:

```
A = | 1  2  3 |
    | 4  5  6 |
```

This is a 2×3 matrix (2 rows, 3 columns).

### Matrix-Vector Multiplication

Multiplying a matrix by a vector:

```
| 1  2 |   | 3 |   | 1×3 + 2×4 |   | 11 |
| 3  4 | × | 4 | = | 3×3 + 4×4 | = | 25 |
```

Each row of the matrix is "dotted" with the vector.

### Why Matrices Matter in Cryptography

In lattice cryptography:

- The **public key** is often a matrix A
- The **secret key** is often a short vector s
- The relationship is: t = A × s (mod q)

Given A and t, finding s is the hard problem!

## Groups and Algebraic Structures

### What is a Group?

A **group** is a set of elements with an operation (like addition or multiplication) that satisfies certain rules.

**Formal Definition**: A group (G, ∘) has:

1. **Closure**: If a, b are in G, then a ∘ b is in G
2. **Associativity**: (a ∘ b) ∘ c = a ∘ (b ∘ c)
3. **Identity**: There's an element e where a ∘ e = e ∘ a = a
4. **Inverses**: For each a, there's a⁻¹ where a ∘ a⁻¹ = e

### Examples of Groups

**Integers under addition (ℤ, +)**:

- Closure: integer + integer = integer ✓
- Associativity: (1+2)+3 = 1+(2+3) ✓
- Identity: 0 (a + 0 = a) ✓
- Inverses: -a (a + (-a) = 0) ✓

**Integers mod n under addition (ℤn, +)**:

- {0, 1, 2, ..., n-1} with addition mod n
- Identity: 0
- Inverse of a: n - a

### Why Groups Matter in Cryptography

Groups give us:

1. **Structure**: Well-understood mathematical properties
2. **Hard Problems**: Like discrete logarithm
3. **Homomorphic Properties**: Operations on encrypted data

### The Special Linear Group SL(2, ℤp)

This is the group used in kMOSAIC's graph component (EGRW).

**Definition**: 2×2 matrices with integer entries (mod p) and determinant = 1

```
| a  b |
| c  d |  where ad - bc ≡ 1 (mod p)
```

**Example in SL(2, ℤ5)**:

```
| 2  1 |
| 3  2 |  Check: 2×2 - 1×3 = 4 - 3 = 1 ✓
```

**Group operation**: Matrix multiplication (mod p)

This group is:

- **Non-abelian**: A × B ≠ B × A in general
- **Large**: Has p³ - p elements for prime p
- **Connected**: Forms an expander graph (good for EGRW)

## Probability and Randomness

### Why Randomness Matters

Cryptography is fundamentally probabilistic:

- Keys must be randomly generated
- Encryption often uses random values
- Security is measured probabilistically

### Basic Probability

The **probability** of an event is a number between 0 and 1:

- 0 = impossible
- 1 = certain
- 0.5 = 50% chance

**Example**: Fair coin flip

- P(heads) = 0.5
- P(tails) = 0.5

### Random Variables and Distributions

A **random variable** X takes values according to some probability distribution.

**Uniform Distribution**: All values equally likely

- Roll a die: P(1) = P(2) = ... = P(6) = 1/6

**Gaussian (Normal) Distribution**: Bell curve

- Most values near the mean
- Values far from mean are rare

### Cryptographic Randomness

Not all randomness is equal!

**Bad** (predictable):

```javascript
Math.random() // Uses predictable PRNG
```

**Good** (cryptographically secure):

```javascript
crypto.getRandomValues(new Uint8Array(32)) // Uses system entropy
```

A **CSPRNG** (Cryptographically Secure Pseudo-Random Number Generator) is:

- Statistically indistinguishable from true randomness
- Unpredictable even if you know previous outputs

### Negligible Probability

In cryptography, we say a probability is **negligible** if it's smaller than 1/n^c for any constant c, as n grows.

**Example**:

- 1/2^128 is negligible (effectively zero)
- 1/n is NOT negligible (still significant)

When we say "this scheme is secure," we mean an attacker succeeds with only negligible probability.

## Hash Functions

### What is a Hash Function?

A **hash function** takes any input and produces a fixed-size output:

```
H("Hello") → a591a6d40bf420404a011733cfb7b190
H("Hello!") → 9ae5c00e1e9d80f3e9c4a7e5f7a8c3d1
```

Notice:

- Different inputs → completely different outputs
- Same length output regardless of input length

### Properties of Cryptographic Hash Functions

1. **Deterministic**: Same input always gives same output

2. **Fast**: Computing the hash is quick

3. **Pre-image Resistance**: Given H(x), finding x is infeasible
   - You can't "reverse" a hash

4. **Second Pre-image Resistance**: Given x₁, finding x₂ where H(x₁) = H(x₂) is infeasible
   - You can't find another input with the same hash

5. **Collision Resistance**: Finding ANY two x₁ ≠ x₂ where H(x₁) = H(x₂) is infeasible
   - Due to birthday paradox, this is harder than pre-image resistance

### The Avalanche Effect

A tiny change in input completely changes the output:

```
SHA-256("Hello")  → 185f8db32271fe25f561a6fc938b2e26...
SHA-256("Hellp")  → 5e96e7a36cb6c462d01b75e5ab6c0d76...
```

One letter changed, but the hash is completely different!

### Common Hash Functions

| Hash Function | Output Size  | Security Status |
| :------------ | :----------- | :-------------- |
| MD5           | 128 bits     | ❌ Broken       |
| SHA-1         | 160 bits     | ❌ Broken       |
| SHA-256       | 256 bits     | ✅ Secure       |
| SHA-3         | 256/512 bits | ✅ Secure       |
| SHAKE256      | Variable     | ✅ Secure (XOF) |

### How kMOSAIC Uses Hashes

1. **Key Derivation**: Deriving the final shared key from components
2. **Challenges**: In signatures, creating the challenge c = H(message, commitments)
3. **Commitments**: Binding values without revealing them
4. **Random Oracle**: Modeling ideal hash behavior in security proofs

---

# Chapter 5: Lattice Cryptography (SLSS)

This chapter explains the first pillar of kMOSAIC: lattice-based cryptography. We'll build intuition from the ground up.

## What is a Lattice?

### The 2D Intuition

Imagine an infinite grid of points on graph paper:

```
    •   •   •   •   •   •   •
    •   •   •   •   •   •   •
    •   •   •   •   •   •   •
    •   •   •   •   •   •   •
    •   •   •   •   •   •   •
```

This is a 2-dimensional lattice! Every point is a combination of two "basis vectors":

- Moving right: (1, 0)
- Moving up: (0, 1)

Any point can be reached by: a×(1,0) + b×(0,1) = (a, b) for integers a, b.

### Formal Definition

A **lattice** L is the set of all integer combinations of n linearly independent vectors:

```
L = { a₁v₁ + a₂v₂ + ... + aₙvₙ : aᵢ ∈ ℤ }
```

Where v₁, v₂, ..., vₙ are the **basis vectors**.

### Different Bases, Same Lattice

Here's the key insight: the same lattice can have many different bases!

**Example in 2D**:

Basis 1: v₁ = (1, 0), v₂ = (0, 1)
Basis 2: v₁ = (1, 0), v₂ = (1, 1)

Both generate the same points, but one basis has shorter vectors.

```
Basis 1:          Basis 2:
    ↑                 ↗
    |               ↗
    •---→          •---→
```

### High-Dimensional Lattices

In cryptography, we use lattices in 500+ dimensions.

You can't visualize 500D space, but the math still works:

- A 500-dimensional lattice is defined by 500 basis vectors
- Each vector has 500 components
- Points are integer combinations of these vectors

The security comes from the difficulty of navigating high-dimensional spaces.

## Hard Problems on Lattices

### The Shortest Vector Problem (SVP)

**Problem**: Given a lattice basis, find the shortest non-zero vector in the lattice.

**Easy in 2D**:

```
    •   •   •   •   •
    •   •   •   •   •
    •   •   O   •   •   ← Origin
    •   •   •   •   •

The shortest vectors are clearly (1,0), (0,1), etc.
```

**Hard in 500D**: The lattice has ~2^500 "directions" to check. Finding the shortest is computationally infeasible.

### The Closest Vector Problem (CVP)

**Problem**: Given a lattice and a target point (not on the lattice), find the lattice point closest to the target.

```
    •       •       •

    •   ×   •       •   ← × is the target, which • is closest?

    •       •       •
```

In 2D, you can see the answer. In 500D, this is as hard as SVP.

### Why These Problems Are Hard

1. **Exponential Search Space**: A lattice in n dimensions has points spreading in 2^n directions.

2. **No Efficient Algorithms**: The best known algorithms (LLL, BKZ) give approximate solutions but not exact ones for large dimensions.

3. **Quantum Resistance**: Unlike factoring, there's no known quantum algorithm that solves lattice problems efficiently.

## The Short Integer Solution (SIS) Problem

### Definition

Given:

- A random matrix A ∈ ℤq^(m×n)
- A bound β

Find:

- A non-zero vector s with ||s|| ≤ β such that A × s ≡ 0 (mod q)

In other words: find a short vector s that maps to zero when multiplied by A.

### Visual Intuition

Think of A as defining a "code":

```
A × s = 0 (mod q)
```

You want to find a "codeword" s that:

1. Is short (small coefficients)
2. Gets mapped to zero by A

It's like finding a password that passes a test, but the password must be simple (short).

### Why SIS is Hard

- Random A gives no structure to exploit
- Short vectors are sparse in high-dimensional space
- Checking all short vectors takes exponential time

### The Inhomogeneous Variant (ISIS)

Given:

- Matrix A
- Target vector t

Find:

- Short vector s such that A × s ≡ t (mod q)

This is what kMOSAIC's SLSS actually uses:

- **Public Key**: (A, t) where t = A × s (mod q)
- **Secret Key**: The short vector s

## Learning With Errors (LWE)

### The Problem

Given:

- A random matrix A ∈ ℤq^(m×n)
- A vector b = A × s + e (mod q)

Where s is secret and e is a small "error" vector.

Find: s

### The Key Insight: Errors Make It Hard

Without errors:

- b = A × s is just a system of linear equations
- We can solve it with Gaussian elimination in polynomial time!

With errors:

- The errors scramble the system
- We can't use standard linear algebra techniques
- The problem becomes as hard as lattice problems

### Why Errors Help Security

**No errors**:

```
b = A × s
```

To solve: Just invert A (or use Gaussian elimination).

**With errors**:

```
b = A × s + e
```

The error e "hides" the true relationship. Even if you approximately solve A × s ≈ b, the error prevents you from finding the exact s.

### LWE in Practice

LWE is the basis of[^regev2005]:

- **ML-KEM (Kyber)**: NIST's chosen key encapsulation
- **ML-DSA (Dilithium)**: NIST's chosen digital signature
- Many other post-quantum schemes

## How kMOSAIC Uses Lattices

### The SLSS Construction

kMOSAIC's lattice component (SLSS) uses a variant of the SIS problem for signatures:

**Key Generation**:

1. Generate random matrix A ∈ ℤq^(m×n)
2. Generate short secret vector s ∈ {-1, 0, 1}^n
3. Compute t = A × s (mod q)
4. Public Key: (A, t)
5. Secret Key: s

**Signing** (simplified):

1. Generate random "mask" vector y
2. Compute commitment w = A × y (mod q)
3. Hash to get challenge c = H(message, w)
4. Compute response z = y + c × s
5. If z is too large, restart (rejection sampling)
6. Output signature (c, z)

**Verification**:

1. Recompute w' = A × z - c × t (mod q)
2. Recompute c' = H(message, w')
3. Accept if c' = c and z is small

### Security of SLSS

The security reduces to:

- **SIS Assumption**: Finding short s given (A, t = A×s) is hard
- **Rejection Sampling**: Ensures z looks random (doesn't leak s)

If you can forge a signature, you can solve SIS. Since SIS is believed to be hard (even for quantum computers), the signature scheme is secure.

### Concrete Parameters

For MOS-128 (actual implementation):

- n = 512 (lattice dimension)
- m = 384 (equations, ratio m/n = 0.75)
- q = 12289 (prime modulus, NTT-friendly)
- w = 64 (sparsity weight)

For MOS-256:

- n = 1024, m = 768, q = 12289, w = 128

---

# Chapter 6: Tensor Cryptography (TDD)

This chapter explains the second pillar: tensor-based cryptography. Tensors are less well-known than lattices, but equally powerful.

## What is a Tensor?

### Building Up: Scalars, Vectors, Matrices, Tensors

Let's build intuition step by step:

**Scalar** (0D): A single number

```
42
```

**Vector** (1D): A list of numbers

```
[3, 7, 2]
```

**Matrix** (2D): A table of numbers

```
| 1  2  3 |
| 4  5  6 |
```

**Tensor** (3D+): A "cube" (or hypercube) of numbers

```
       Layer 0          Layer 1
    | 1  2  3 |      | 10 11 12 |
    | 4  5  6 |      | 13 14 15 |
```

This 2×3×2 tensor has 12 elements arranged in a 3D grid.

### Another Way to Think About It

- A scalar is accessed with 0 indices: x
- A vector is accessed with 1 index: v[i]
- A matrix is accessed with 2 indices: M[i][j]
- A tensor is accessed with 3+ indices: T[i][j][k]

### Real-World Tensor Examples

1. **Color Images**: Height × Width × 3 (RGB channels) = 3D tensor

2. **Video**: Height × Width × Channels × Time = 4D tensor

3. **Scientific Data**: Often multi-dimensional measurements

### Tensor Notation

We write a 3D tensor as:

```
T ∈ ℤ^(n₁ × n₂ × n₃)
```

An element at position (i, j, k) is written as:

```
T[i, j, k]  or  T_{ijk}
```

## Tensor Decomposition

### The Matrix Case (Review)

Matrices have nice decompositions. The **Singular Value Decomposition (SVD)**:

```
M = U × Σ × V^T
```

Where:

- U and V are orthogonal matrices
- Σ is diagonal (singular values)

This lets us:

- Compress data (keep only large singular values)
- Find low-rank structure
- Solve linear systems efficiently

### Rank-1 Tensors

A **rank-1 tensor** is the simplest possible tensor:

```
T = a ⊗ b ⊗ c
```

Where ⊗ is the "outer product":

```
T[i, j, k] = a[i] × b[j] × c[k]
```

**Example**:

```
a = [1, 2]
b = [3, 4]
c = [5, 6]

T[0,0,0] = 1 × 3 × 5 = 15
T[0,0,1] = 1 × 3 × 6 = 18
T[1,1,0] = 2 × 4 × 5 = 40
...
```

A rank-1 tensor is completely determined by its three factor vectors!

### Tensor Rank

The **rank** of a tensor T is the minimum number of rank-1 tensors needed to sum to T:

```
T = Σᵢ aᵢ ⊗ bᵢ ⊗ cᵢ
```

**Example**:

- Rank-1: T = a ⊗ b ⊗ c
- Rank-2: T = (a₁ ⊗ b₁ ⊗ c₁) + (a₂ ⊗ b₂ ⊗ c₂)
- ...

### The CP Decomposition

The **Canonical Polyadic (CP) decomposition** expresses T as a sum of rank-1 tensors:

```
T = Σᵣ λᵣ (aᵣ ⊗ bᵣ ⊗ cᵣ)
```

Finding this decomposition is the fundamental problem.

## Why Tensors are Hard to Decompose

### Matrix Decomposition: Easy

For matrices, SVD gives the unique optimal decomposition in polynomial time. It's a solved problem!

### Tensor Decomposition: Hard

For tensors (3D and higher):

1. **No Unique Decomposition**: The same tensor can have different decompositions

2. **NP-Hard**: Computing the rank of a tensor is NP-complete

3. **No Efficient Algorithm**: Unlike SVD, there's no polynomial-time algorithm for tensors

### The Computational Hardness

**Theorem**: Determining whether a 3D tensor has rank ≤ r is NP-complete[^hillar2013].

This means:

- No polynomial-time algorithm exists (unless P = NP)
- The best algorithms are exponential in the tensor dimensions

### Why This is Good for Cryptography

If we design a cryptosystem where:

- The secret is the decomposition factors
- The public key is the composed tensor

Then breaking it requires tensor decomposition — an NP-hard problem!

## The TDD Construction

### Key Idea: Distinguishing Problem

Instead of exactly decomposing a tensor, kMOSAIC uses a **distinguishing problem**:

Given a tensor T, determine if:

- T was constructed from a secret low-rank decomposition, OR
- T is a completely random tensor

If you can't tell the difference, you can't break the scheme!

### Key Generation

**Step 1**: Generate random factor vectors

```
E = {(a₁, b₁, c₁), (a₂, b₂, c₂), ..., (aᵣ, bᵣ, cᵣ)}
```

**Step 2**: Construct the tensor

```
T = Σᵢ aᵢ ⊗ bᵢ ⊗ cᵢ + noise
```

**Step 3**:

- Public Key: T (the tensor)
- Secret Key: E (the factors)

### Encryption (Simplified)

To encrypt a bit b:

1. If b = 0: Publish T (unchanged)
2. If b = 1: Add structured perturbation based on message

Decryption requires knowing the factors E.

### Why This Works

- **With E**: You can "undo" the tensor construction and read the message
- **Without E**: T looks like random noise — you can't tell if there's a message

## How kMOSAIC Uses Tensors

### The TDD Component

kMOSAIC's tensor component provides:

1. **Key Generation**: Create tensor T from secret factors E
2. **Encapsulation**: Encode a secret share into tensor structure
3. **Decapsulation**: Recover the share using E

### Security Properties

- **NP-Hardness**: Based on tensor decomposition complexity
- **Quantum Resistance**: No known quantum speedup for tensor problems
- **Different Math**: Truly independent from lattice problems

### Concrete Parameters

For MOS-128 (actual implementation):

- n = 24 (tensor dimension per mode)
- Tensor size: 24 × 24 × 24 = 13,824 elements
- Rank: r = 6

For MOS-256:

- n = 36, tensor size: 36³ = 46,656 elements, rank r = 9

---

# Chapter 7: Graph Cryptography (EGRW)

This chapter explains the third pillar: graph-based cryptography using expander graphs and random walks.

## What is a Graph?

### Basic Definitions

A **graph** G = (V, E) consists of:

- **Vertices** (V): Points or "nodes"
- **Edges** (E): Connections between vertices

```
    A ---- B
    |      |
    |      |
    C ---- D
```

Here:

- V = {A, B, C, D}
- E = {(A,B), (A,C), (B,D), (C,D)}

### Directed vs Undirected

**Undirected**: Edges go both ways (A—B means you can go A→B or B→A)

**Directed**: Edges have direction (A→B doesn't imply B→A)

kMOSAIC uses directed graphs (or equivalently, group actions).

### Graph Properties

**Degree**: Number of edges connected to a vertex

- In our example, every vertex has degree 2

**Regular Graph**: Every vertex has the same degree

- Our example is 2-regular

**Path**: A sequence of vertices connected by edges

- A → B → D is a path

**Connected**: You can reach any vertex from any other vertex

## Expander Graphs

### What Makes a Graph an "Expander"?

An **expander graph** is a sparse but highly connected graph. Key properties:

1. **Sparse**: Each vertex has few edges (low degree)
2. **Highly Connected**: Despite being sparse, the graph is extremely well-connected
3. **Rapid Mixing**: Random walks quickly reach any part of the graph

### The Expansion Property

For any subset S of vertices, the number of edges leaving S is proportional to |S|.

```
Poorly connected:        Well-connected (expander):
    A—B   C—D               A—B—C
      |   |                 |×  ×|
    E—F   G—H               D—E—F

(Two separate clusters)    (Every subset reaches outside)
```

### Why Expanders are Useful

1. **Randomness Amplification**: Short random walks produce nearly-uniform distribution

2. **Error Reduction**: Can reduce error probabilities efficiently

3. **Cryptography**: Navigation is easy locally, hard globally

### The Spectral Gap

The quality of an expander is measured by its **spectral gap** λ:

- Larger gap = better expander
- Related to eigenvalues of the graph's adjacency matrix

**Ramanujan Graphs** achieve the optimal spectral gap — they're the best possible expanders.

## Random Walks on Graphs

### What is a Random Walk?

A **random walk** starts at a vertex and repeatedly moves to a random neighbor.

```
Start: A
Step 1: Randomly choose neighbor → B
Step 2: Randomly choose neighbor → D
Step 3: Randomly choose neighbor → B
...
```

### Mixing Time

The **mixing time** is how many steps until the walk's distribution is nearly uniform.

**On expander graphs**: Mixing is very fast — O(log n) steps for n vertices.

**On poorly connected graphs**: Can take much longer.

### Why Random Walks Matter for Cryptography

After a random walk on an expander:

- **Easy** (with the path): Knowing the steps, you can replicate the walk
- **Hard** (without the path): Given only start and end, finding the path is infeasible

This is the basis of EGRW!

## The EGRW Construction

### The Graph: Cayley Graph of SL(2, ℤp)

kMOSAIC uses a specific graph:

**Vertices**: Elements of the group SL(2, ℤp)

- 2×2 matrices with determinant 1 (mod p)
- About p³ vertices for prime p

**Edges**: Defined by fixed "generators" S = {g₁, g₂, g₃, g₄}

- There's an edge from M to M × gᵢ for each generator

**Properties**:

- 4-regular (each vertex has exactly 4 outgoing edges)
- Highly connected (proven Ramanujan expander for certain generators)
- Manageable (p = 1021 gives ≈10⁹ vertices for MOS-128)

### Why SL(2, ℤp)?

1. **Large Group**: Exponentially many elements
2. **Efficient Computation**: Matrix multiplication is fast
3. **Provable Expansion**: Known to be a Ramanujan graph
4. **Non-Abelian**: M × N ≠ N × M, making the math richer

### Key Generation

**Step 1**: Start with identity matrix I (or random matrix M₀)

**Step 2**: Perform a random walk of length ℓ

```
M₁ = M₀ × g_{w₁}
M₂ = M₁ × g_{w₂}
...
Mₗ = M_{ℓ-1} × g_{wₗ}
```

Where w = (w₁, w₂, ..., wₗ) is a random sequence from {1, 2, 3, 4}

**Step 3**:

- Public Key: (M₀, Mₗ) — start and end matrices
- Secret Key: w — the path (sequence of generator indices)

### Encryption (Simplified)

To encrypt a message for someone with public key (M₀, Mₗ):

1. Choose random mask path w'
2. Compute M' = M₀ × (walk along w')
3. Encode message into relationship between M', Mₗ, and secret data

Decryption requires knowing the original path w.

### Why It's Secure

**Given**: M₀ and Mₗ

**Find**: Path w such that M₀ × (walk along w) = Mₗ

This is the **navigation problem** on expander graphs:

- The graph has ~2^384 vertices
- Each vertex looks identical (no distinguishing features)
- Random walks mix in O(log n) ≈ 400 steps
- After mixing, the endpoint reveals almost nothing about the path

There's no known efficient algorithm (classical or quantum) to solve this!

## How kMOSAIC Uses Graphs

### The EGRW Component

In kMOSAIC, the graph component provides:

1. **Key Pair**: (start, end) matrices and the path between them
2. **Encapsulation**: Encode a secret share using path-dependent operations
3. **Decapsulation**: Recover the share by "walking backward" with the secret path

### Security Properties

- **Combinatorial Hardness**: Based on graph navigation, not algebraic structure
- **Quantum Resistance**: No quantum speedup for graph search
- **Different Math**: Completely independent from lattices and tensors

### Why Three Different Problems?

| Component | Mathematical Basis  | Attack Type Needed   |
| :-------- | :------------------ | :------------------- |
| SLSS      | Lattice geometry    | Lattice reduction    |
| TDD       | Multilinear algebra | Tensor decomposition |
| EGRW      | Graph theory        | Path finding         |

A breakthrough in one area doesn't help with the others!

### Concrete Parameters

For MOS-128 (actual implementation):

- p = 1021 (prime for SL(2, ℤ_p), group order ≈ p³ ≈ 10⁹)
- Walk length k = 128 (provides 256 bits entropy via 4 generators)
- Path size: 128 × 2 bits = 32 bytes

For MOS-256:

- p = 2039, walk length k = 256 (provides 512 bits entropy)

---

# Part III: Implementation

Now we move from theory to practice. This part shows how kMOSAIC actually works and how to use it.

---

# Chapter 8: Key Encapsulation Mechanism (KEM)

The KEM is the primary way to establish shared secrets for encryption. This chapter explains what a KEM is and how kMOSAIC implements it.

## What is a KEM?

### The Problem: Secure Key Exchange

Alice and Bob want to communicate securely, but:

- They've never met in person
- Eve is watching their entire communication
- They need a shared secret key for symmetric encryption (like AES)

How do they agree on a key without Eve learning it?

### Historical Solution: Diffie-Hellman

In 1976, Whitfield Diffie and Martin Hellman invented the first public key exchange[^diffie1976]:

```
Alice:                              Bob:
1. Pick secret a                    1. Pick secret b
2. Compute A = g^a mod p            2. Compute B = g^b mod p
3. Send A →                         3. Send B →
4. Receive B                        4. Receive A
5. Compute K = B^a mod p            5. Compute K = A^b mod p

Both get: K = g^(ab) mod p
```

Eve sees (g, p, A, B) but can't compute K without solving discrete log!

**Problem**: Diffie-Hellman is broken by quantum computers (Shor's algorithm).

### Modern Solution: Key Encapsulation Mechanism

A **KEM** is a cleaner abstraction that separates concerns:

1. **KeyGen()**: Generate (public_key, secret_key)
2. **Encapsulate(public_key)**: Generate (ciphertext, shared_secret)
3. **Decapsulate(ciphertext, secret_key)**: Recover shared_secret

The beauty: The sender doesn't choose the shared secret — the algorithm does!

### Why KEM Instead of Encryption?

Traditional public-key encryption encrypts a message of your choice. But:

- You might choose a weak message
- There are subtle security issues with "encrypt then sign"

With KEM:

- The shared secret is always cryptographically random
- You use this random key with symmetric encryption
- Cleaner security proofs

## KEM vs Key Exchange vs Encryption

### Key Exchange (Interactive)

```
Alice           Bob
  |    ----→     |   (Message 1)
  |    ←----     |   (Message 2)
  |    ----→     |   (Message 3)
```

Both parties send messages. Examples: Diffie-Hellman, ECDH.

**Downside**: Requires both parties to be online simultaneously.

### Key Encapsulation (Non-Interactive)

```
Alice                           Bob
  |                               |
  | ←---- Bob's Public Key ----   |  (Previously published)
  |                               |
  | ---- Ciphertext ----→         |  (Single message)
  |                               |
Both have shared secret
```

Alice can send to Bob even if Bob is offline.

**Use case**: Email, messaging when recipient is offline.

### Public-Key Encryption

```
Alice                           Bob
  |                               |
  | ←---- Bob's Public Key ----   |
  |                               |
  | ---- Encrypted Message --→    |
  |                               |
```

Encrypts an actual message directly.

**Downside**: Size limits, less efficient than symmetric encryption.

### The Hybrid Approach (Best Practice)

1. Use **KEM** to establish a shared secret
2. Use the shared secret with **AES-GCM** to encrypt the actual message

```
KEM:    Establishes 32-byte shared key K
AES:    Encrypts gigabytes of data using K
```

This is what kMOSAIC encourages!

## The kMOSAIC KEM Protocol

### Overview

kMOSAIC's KEM combines all three components:

```
┌──────────────────────────────────────────────────────────────┐
│                    kMOSAIC KEM                               │
├──────────────────────────────────────────────────────────────┤
│  1. Generate ephemeral secret σ                              │
│  2. Split σ into shares: σ = σ₁ ⊕ σ₂ ⊕ σ₃                    │
│  3. Encrypt σ₁ with SLSS (Lattice)                           │
│  4. Encrypt σ₂ with TDD (Tensor)                             │
│  5. Encrypt σ₃ with EGRW (Graph)                             │
│  6. Derive final key: K = H(σ, C₁, C₂, C₃)                   │
└──────────────────────────────────────────────────────────────┘
```

### Protocol Flow

```
Alice                               Bob
  │                                   │
  │ 1. KeyGen()                       │
  │ ───────────────────────────────►  │
  │   Sends Public Key (PK)           │
  │                                   │
  │                                   │ 2. Encapsulate(PK)
  │                                   │    • Generate secret σ
  │                                   │    • Split σ → σ₁, σ₂, σ₃
  │                                   │    • Encrypt shares → C₁, C₂, C₃
  │                                   │    • Derive K = Hash(...)
  │                                   │
  │   Sends Ciphertext (C₁, C₂, C₃)   │
  │ ◄───────────────────────────────  │
  │                                   │
  │ 3. Decapsulate(C, SK)             │
  │    • Decrypt C₁ → σ₁              │
  │    • Decrypt C₂ → σ₂              │
  │    • Decrypt C₃ → σ₃              │
  │    • Reconstruct σ                │
  │    • Derive K                     │
  │                                   │
  ▼                                   ▼
Both share Secret Key K
```

### Step-by-Step: Key Generation

```typescript
// What happens inside kemGenerateKeyPair()

// 1. Generate a random seed
const seed = secureRandomBytes(32)

// 2. Derive component seeds with domain separation
const slssSeed = hash('SLSS' + seed)
const tddSeed = hash('TDD' + seed)
const egrwSeed = hash('EGRW' + seed)

// 3. Generate key pairs for each component
const slssKeys = slssKeyGen(slssSeed) // Lattice keys
const tddKeys = tddKeyGen(tddSeed) // Tensor keys
const egrwKeys = egrwKeyGen(egrwSeed) // Graph keys

// 4. Combine into unified key pair
const hBind = hash(slssKeys.public, tddKeys.public, egrwKeys.public)

const publicKey = {
  slss: slssKeys.public, // Matrix A and target t
  tdd: tddKeys.public, // Tensor T
  egrw: egrwKeys.public, // Start and end matrices
  hBind: hBind, // Binding commitment
}

const secretKey = {
  slss: slssKeys.secret, // Short vector s
  tdd: tddKeys.secret, // Tensor factors E
  egrw: egrwKeys.secret, // Path w
}

return { publicKey, secretKey }
```

### Step-by-Step: Encapsulation

```typescript
// What happens inside encapsulate(publicKey)

// 1. Generate ephemeral secret
const sigma = secureRandomBytes(32)

// 2. Split into three shares using XOR secret sharing
const sigma1 = secureRandomBytes(32)
const sigma2 = secureRandomBytes(32)
const sigma3 = xor(sigma, xor(sigma1, sigma2)) // σ₃ = σ ⊕ σ₁ ⊕ σ₂

// Verify: sigma1 ⊕ sigma2 ⊕ sigma3 = sigma ✓

// 3. Encrypt each share with its component
const c1 = slssEncrypt(sigma1, publicKey.slss)
const c2 = tddEncrypt(sigma2, publicKey.tdd)
const c3 = egrwEncrypt(sigma3, publicKey.egrw)

// 4. Generate NIZK proof of correct construction
const proof = nizkProve(sigma, sigma1, sigma2, sigma3, c1, c2, c3)

// 5. Package ciphertext
const ciphertext = { c1, c2, c3, proof }

// 6. Derive the final shared secret
const sharedSecret = hash(sigma, ciphertext)

return { sharedSecret, ciphertext }
```

### Step-by-Step: Decapsulation

```typescript
// What happens inside decapsulate(ciphertext, secretKey, publicKey)

const { c1, c2, c3, proof } = ciphertext

// 1. Verify NIZK proof
if (!nizkVerify(proof, ciphertext)) {
  return hash(secretKey.rejectionSeed, ciphertext)
}

// 2. Decrypt each component
const sigma1Prime = slssDecrypt(c1, secretKey.slss)
const sigma2Prime = tddDecrypt(c2, secretKey.tdd)
const sigma3Prime = egrwDecrypt(c3, secretKey.egrw)

// 2. Reconstruct the ephemeral secret
const sigmaPrime = xor(sigma1Prime, xor(sigma2Prime, sigma3Prime))

// 3. Fujisaki-Okamoto validation (re-encrypt and compare)
const { ciphertext: cPrime } = encapsulateWithSeed(sigmaPrime, publicKey)

// 4. Check if re-encryption matches
const isValid = constantTimeEqual(ciphertext, cPrime)

// 5. Compute shared secret (or rejection key if invalid)
if (isValid) {
  return hash(sigmaPrime, c1, c2, c3)
} else {
  // Implicit rejection: return deterministic but useless key
  return hash(secretKey.rejectionSeed, ciphertext)
}
```

## KEM Code Examples

### Basic Usage

```typescript
import { kemGenerateKeyPair, encapsulate, decapsulate } from 'k-mosaic'

async function secureKeyExchange() {
  // === ALICE (Receiver) ===
  // Generate key pair (do this once, store securely)
  const aliceKeys = await kemGenerateKeyPair()

  // Share public key with the world
  publishPublicKey(aliceKeys.publicKey)

  // Keep secret key PRIVATE
  secureStore(aliceKeys.secretKey)

  // === BOB (Sender) ===
  // Get Alice's public key (from website, key server, etc.)
  const alicePublicKey = fetchPublicKey('alice')

  // Encapsulate: creates shared secret and ciphertext
  const { sharedSecret, ciphertext } = await encapsulate(alicePublicKey)

  // Use sharedSecret for symmetric encryption
  const encrypted = await aesEncrypt(message, sharedSecret)

  // Send ciphertext + encrypted message to Alice
  send({ ciphertext, encrypted })

  // === ALICE (Receiver) ===
  // Receive from Bob
  const received = receive()

  // Decapsulate: recover the same shared secret
  const recoveredSecret = await decapsulate(
    received.ciphertext,
    aliceKeys.secretKey,
    aliceKeys.publicKey,
  )

  // Decrypt the message
  const decrypted = await aesDecrypt(received.encrypted, recoveredSecret)

  // Bob's message is now readable!
  console.log(decrypted)
}
```

### With Different Security Levels

```typescript
import { kemGenerateKeyPair, MOS_128, MOS_256 } from 'k-mosaic'

// Standard security (128-bit post-quantum)
// Good for: web applications, mobile apps, general use
const standardKeys = await kemGenerateKeyPair(MOS_128)

// High security (256-bit post-quantum)
// Good for: government, long-term secrets, high-value data
const highSecurityKeys = await kemGenerateKeyPair(MOS_256)
```

### Error Handling

```typescript
import {
  kemGenerateKeyPair,
  encapsulate,
  decapsulate,
  KemError,
} from 'k-mosaic'

async function safeKeyExchange() {
  try {
    const keys = await kemGenerateKeyPair()
    const { sharedSecret, ciphertext } = await encapsulate(keys.publicKey)

    // Tamper with ciphertext (simulating attack)
    ciphertext[0] ^= 0xff

    // Decapsulation will succeed but return rejection key
    const recovered = await decapsulate(
      ciphertext,
      keys.secretKey,
      keys.publicKey,
    )

    // recovered !== sharedSecret (implicit rejection)
    // Attacker can't tell the difference!
  } catch (error) {
    if (error instanceof KemError) {
      console.error('KEM operation failed:', error.message)
    }
    throw error
  }
}
```

## KEM Security Properties

### IND-CCA2 Security

kMOSAIC's KEM achieves **IND-CCA2** (Indistinguishability under Adaptive Chosen Ciphertext Attack).

**What this means**:

1. An attacker who sees many ciphertexts...
2. And can get decryptions of any ciphertext EXCEPT the target...
3. Still cannot distinguish the shared secret from random!

This is the gold standard for encryption.

### Defense-in-Depth Security

Even stronger: kMOSAIC maintains security if ANY TWO of the three components are broken.

| Broken Components | Security      |
| :---------------- | :------------ |
| None              | Full security |
| SLSS only         | Full security |
| TDD only          | Full security |
| EGRW only         | Full security |
| SLSS + TDD        | Full security |
| SLSS + EGRW       | Full security |
| TDD + EGRW        | Full security |
| All three         | Broken        |

This is achieved through XOR secret sharing — each share individually reveals nothing.

### The Fujisaki-Okamoto Transform

Why do we re-encrypt during decapsulation?[^fo1999]

**Without FO Transform**: An attacker could submit slightly modified ciphertexts and learn from the responses.

**With FO Transform**:

- We detect ANY modification
- We return a useless but consistent rejection key
- The attacker learns nothing from their probes

This transforms a "passively secure" scheme into an "actively secure" one.

### Implicit Rejection

Why not just return an error on invalid ciphertext?

**Problem**: Timing differences could leak information

- Valid ciphertext: 10ms to respond
- Invalid ciphertext: 5ms to respond (error returned early)

**Solution**: Always do the same work, always return a key

- Valid: Return correct shared secret
- Invalid: Return hash(rejection_seed, ciphertext)

The attacker can't tell which happened!

---

# Chapter 9: Digital Signatures

Digital signatures prove authenticity and integrity. This chapter explains kMOSAIC's signature scheme in depth.

## What is a Digital Signature?

### The Problem: Authentication

You receive an email claiming to be from your bank. How do you know it's really from them?

**Physical World**: Handwritten signatures, official seals, ID verification
**Digital World**: We need mathematical proof of identity

### Properties of Digital Signatures

A good signature scheme provides:

1. **Authenticity**: Only the owner of the private key could have signed
2. **Integrity**: Any modification to the message invalidates the signature
3. **Non-Repudiation**: The signer cannot deny having signed

### How It Works (Conceptually)

```
Alice (Signer):
1. Has secret key SK
2. Computes Signature = Sign(message, SK)
3. Publishes (message, Signature)

Anyone (Verifier):
1. Has Alice's public key PK
2. Computes result = Verify(message, Signature, PK)
3. If result = true, the signature is valid
```

### Real-World Uses

- **Code Signing**: Verify software hasn't been tampered with
- **Email**: S/MIME, PGP signatures
- **Certificates**: TLS certificates (HTTPS)
- **Blockchain**: Bitcoin and cryptocurrency transactions
- **Documents**: Digital contracts, legal documents

## The Fiat-Shamir Transform

### Interactive Proofs of Knowledge

The signature scheme is based on "proving you know a secret" — without revealing it!

**Interactive Version (Imagine a conversation)**:

```
Verifier: "Prove you know the secret key"

Prover: "OK, here's a commitment" (random value)
Verifier: "Here's my random challenge"
Prover: "Here's my response" (uses secret + challenge)

Verifier: "Let me check... Yes, only someone with the secret could respond like that!"
```

This requires back-and-forth communication.

### Making It Non-Interactive

The **Fiat-Shamir Transform** replaces the verifier's random challenge with a hash:

```
Prover (alone):
1. Generate commitment
2. Challenge = Hash(message, commitment)  ← This is the key insight!
3. Compute response using secret + challenge
4. Signature = (commitment, response)
```

The hash function acts as an "honest verifier" — the prover can't cheat because they can't predict the hash output.

### Why This Works

1. **Commitment binds first**: The prover commits before knowing the challenge
2. **Challenge is unpredictable**: Hash output is essentially random
3. **Response requires secret**: Only the secret holder can compute valid response
4. **Anyone can verify**: The math checks out publicly

## The kMOSAIC Signature Protocol

### Overview

kMOSAIC's signature proves knowledge of secrets for ALL THREE components simultaneously:

```
┌──────────────────────────────────────────────────────────────┐
│                  kMOSAIC Signature                           │
├──────────────────────────────────────────────────────────────┤
│  For each component (SLSS, TDD, EGRW):                       │
│    1. Generate random mask                                   │
│    2. Compute commitment from mask                           │
│  3. Challenge = Hash(message, all commitments)               │
│  For each component:                                         │
│    4. Response = mask + challenge × secret                   │
│    5. Rejection sample if response is too large              │
│  6. Signature = (challenge, response₁, response₂, response₃) │
└──────────────────────────────────────────────────────────────┘
```

### Protocol Flow

```
Signer (Prover)                       Verifier
  │                                      │
  │ 1. Commitment (w)                    │
  │    • Generate random masks y₁, y₂, y₃│
  │    • w₁ = Commit(y₁), w₂=..., w₃=... │
  │                                      │
  │ 2. Challenge (c)                     │
  │    • c = Hash(Message || w₁||w₂||w₃) │
  │                                      │
  │ 3. Response (z)                      │
  │    • z₁ = y₁ + c * s₁                │
  │    • z₂ = y₂ + c * s₂                │
  │    • z₃ = y₃ + c * s₃                │
  │    • Check if z is safe (Rejection)  │
  │                                      │
  │ Signature = (c, z₁, z₂, z₃)          │
  │ ───────────────────────────────►     │
  │                                      │
  │                                      │ 4. Verify
  │                                      │    • Reconstruct w' from z, c
  │                                      │    • c' = Hash(Message || w')
  │                                      │    • Check c == c'
  │                                      │    • Check z is small
  ▼                                      ▼
```

### Step-by-Step: Key Generation

```typescript
// What happens inside signGenerateKeyPair()

// Similar to KEM key generation
const seed = secureRandomBytes(32)

// Generate signing keys for each component
const slssKeys = slssSignKeyGen(hash('SLSS-SIGN' + seed))
const tddKeys = tddSignKeyGen(hash('TDD-SIGN' + seed))
const egrwKeys = egrwSignKeyGen(hash('EGRW-SIGN' + seed))

// Public key: verification data for all three
const publicKey = {
  slss: slssKeys.public, // A, t
  tdd: tddKeys.public, // T
  egrw: egrwKeys.public, // Start, End matrices
}

// Secret key: secrets for all three
const secretKey = {
  slss: slssKeys.secret, // s
  tdd: tddKeys.secret, // E
  egrw: egrwKeys.secret, // path w
}

return { publicKey, secretKey }
```

### Step-by-Step: Signing

```typescript
// What happens inside sign(message, secretKey, publicKey)

let attempts = 0
const MAX_ATTEMPTS = 1000

while (attempts < MAX_ATTEMPTS) {
  attempts++

  // 1. COMMITMENT PHASE
  // Generate random masks for each component
  const y1 = sampleRandomMask(SLSS_PARAMS) // Lattice mask
  const y2 = sampleRandomMask(TDD_PARAMS) // Tensor mask
  const y3 = sampleRandomMask(EGRW_PARAMS) // Graph mask

  // Compute commitments (public projections of masks)
  const w1 = slssCommit(y1, publicKey.slss) // A × y1
  const w2 = tddCommit(y2, publicKey.tdd) // Tensor product
  const w3 = egrwCommit(y3, publicKey.egrw) // Matrix walk

  // 2. CHALLENGE PHASE
  // Hash message with all commitments
  const c = hash(message, w1, w2, w3)

  // 3. RESPONSE PHASE
  // Compute responses: z = y + c × s (for each component)
  const z1 = slssRespond(y1, c, secretKey.slss)
  const z2 = tddRespond(y2, c, secretKey.tdd)
  const z3 = egrwRespond(y3, c, secretKey.egrw)

  // 4. REJECTION SAMPLING
  // Check if responses are "safe" (don't leak secret key info)
  if (isSafe(z1) && isSafe(z2) && isSafe(z3)) {
    // Success! Return signature
    return { c, z1, z2, z3 }
  }

  // Response was too large, try again with fresh masks
}

throw new Error('Signing failed after max attempts')
```

### Step-by-Step: Verification

```typescript
// What happens inside verify(message, signature, publicKey)

const { c, z1, z2, z3 } = signature

// 1. Check response sizes (must be within bounds)
if (!isValidSize(z1) || !isValidSize(z2) || !isValidSize(z3)) {
  return false
}

// 2. Recompute commitments from responses and challenge
// w' = A × z - c × t  (for lattice)
const w1Prime = slssRecomputeCommitment(z1, c, publicKey.slss)
const w2Prime = tddRecomputeCommitment(z2, c, publicKey.tdd)
const w3Prime = egrwRecomputeCommitment(z3, c, publicKey.egrw)

// 3. Recompute challenge
const cPrime = hash(message, w1Prime, w2Prime, w3Prime)

// 4. Check if challenges match
return constantTimeEqual(c, cPrime)
```

### Why Verification Works

The key equation for the lattice component:

**During signing**:

- Commitment: w = A × y
- Response: z = y + c × s

**During verification**:

- Recompute: w' = A × z - c × t
- Substitute: w' = A × (y + c × s) - c × t
- Expand: w' = A × y + c × (A × s) - c × t
- Since t = A × s: w' = A × y + c × t - c × t
- Simplify: w' = A × y = w ✓

The math works out — we recover the original commitment!

## Signature Code Examples

### Basic Usage

```typescript
import { signGenerateKeyPair, sign, verify } from 'k-mosaic'

async function digitalSignatureExample() {
  // === ALICE (Signer) ===

  // Generate signing key pair
  const aliceKeys = await signGenerateKeyPair()

  // The message to sign
  const message = new TextEncoder().encode('I, Alice, agree to pay Bob $100')

  // Sign the message
  const signature = await sign(
    message,
    aliceKeys.secretKey,
    aliceKeys.publicKey,
  )

  // Share: message + signature + public key

  // === BOB (Verifier) ===

  // Verify the signature
  const isValid = await verify(message, signature, aliceKeys.publicKey)

  if (isValid) {
    console.log('✅ Signature valid! This is really from Alice.')
  } else {
    console.log('❌ Signature INVALID! This is a forgery.')
  }
}
```

### Detecting Tampering

```typescript
async function detectTampering() {
  const keys = await signGenerateKeyPair()

  const originalMessage = new TextEncoder().encode('Pay Bob $100')
  const signature = await sign(originalMessage, keys.secretKey, keys.publicKey)

  // Attacker tries to modify the message
  const tamperedMessage = new TextEncoder().encode('Pay Bob $999')

  // Verification fails on tampered message
  const isValid = await verify(tamperedMessage, signature, keys.publicKey)

  console.log(isValid) // false — tampering detected!
}
```

### Signing Different Data Types

```typescript
async function signVariousData() {
  const keys = await signGenerateKeyPair()

  // Sign a text message
  const textSig = await sign(
    new TextEncoder().encode('Hello, World!'),
    keys.secretKey,
    keys.publicKey,
  )

  // Sign a JSON object
  const jsonData = JSON.stringify({ action: 'transfer', amount: 100 })
  const jsonSig = await sign(
    new TextEncoder().encode(jsonData),
    keys.secretKey,
    keys.publicKey,
  )

  // Sign a file hash (for large files)
  const fileHash = await hashFile('large-document.pdf')
  const fileSig = await sign(fileHash, keys.secretKey, keys.publicKey)

  // All signatures are the same size regardless of input!
}
```

## Rejection Sampling Explained In Depth

### The Leakage Problem

Consider the simplest signature scheme:

```
Secret: s = 5
Sign: z = challenge × s = challenge × 5
```

**Problem**: After seeing a few signatures, you can compute s = z / challenge!

### Adding Randomness

Let's add a random mask:

```
Secret: s = 5
Mask: y (random, say 0-100)
Response: z = y + challenge × s
```

Now z = y + 5 × challenge

Can we still learn s? Maybe — if z is large, we know y was probably large, which tells us something about s.

### The Rejection Sampling Solution

We only output z if it "looks random" — specifically, if z falls within a range that's equally likely regardless of s.

```
Accept z only if: ||z|| < B (some bound)

If ||z|| ≥ B: throw away and try again with new y
```

### Visual Intuition

Imagine two distributions:

```
Distribution of z (given s=0):    Distribution of z (given s=5):
        ____                              ____
       /    \                            /    \
      /      \                          /      \
     /        \                        /        \
____/          \____              ____/          \____
   -100  0   100                    -95   5   105

If we only output z in range [-80, 80]:
        ____                              ____
       |    |                            |    |
      / |  | \                          / |  | \
     /  |  |  \                        /  |  |  \
____/   |__|   \____              ____/   |__|   \____
   -100 -80 80  100                 -95  -80 80  105

Both truncated distributions look the same!
```

By rejecting values outside the safe range, both distributions become indistinguishable.

### The Cost of Rejection Sampling

Each rejection means we try again. The acceptance probability depends on parameters.

For kMOSAIC:

- Typical acceptance rate: ~30-60%
- Average attempts per signature: 2-4
- This is a constant overhead, not a security issue

### Mathematical Guarantee

**Lemma**: With proper rejection sampling, the distribution of z is statistically close to a "mask-only" distribution, independent of the secret key s.

This gives us **zero-knowledge**: the signature reveals nothing about s beyond what the verifier could compute themselves!

---

# Chapter 10: Cryptographic Entanglement

This chapter explains how kMOSAIC binds its three components together to achieve defense-in-depth.

## The Problem with Simple Combination

### Approach 1: Independent Schemes

Run three separate cryptosystems in parallel:

```
Key = (Key_SLSS, Key_TDD, Key_EGRW)
Ciphertext = (C_SLSS, C_TDD, C_EGRW)
```

**Problem**: If ONE scheme is broken, its portion of the data is exposed.

Example: If 1/3 of a password is leaked, the remaining search space is much smaller.

### Approach 2: Key Concatenation

Combine derived keys:

```
SharedSecret = H(K_SLSS || K_TDD || K_EGRW)
```

**Better**: Even if one component leaks K_SLSS, the hash hides it.

**But**: If an attacker can compute K_SLSS, they've learned 1/3 of the hash input. This might help in some attack scenarios.

### Approach 3: Secret Sharing (kMOSAIC's Choice)

The secret is split such that ANY SUBSET reveals NOTHING.

```
Original secret: σ (32 bytes)
Split: σ₁, σ₂, σ₃ where σ = σ₁ ⊕ σ₂ ⊕ σ₃
```

**Information-Theoretic Security**:

- Given only σ₁: All values of σ are equally likely
- Given σ₁ and σ₂: Still all values equally likely!
- Need ALL THREE to recover σ

## Secret Sharing Fundamentals

### XOR Secret Sharing (2-of-2)

The simplest secret sharing:

```
Secret: S = 10110011 (binary)
Share1: R = 01101010 (random)
Share2: S ⊕ R = 11011001

To recover: Share1 ⊕ Share2 = 01101010 ⊕ 11011001 = 10110011 = S ✓
```

**Key property**: Given ONLY Share1 (or ONLY Share2), you learn NOTHING about S.

Why? For any guess of S, there exists a value of R that makes it work.

### Extending to 3-of-3

For kMOSAIC:

```
Secret: σ
Share1: σ₁ (random)
Share2: σ₂ (random)
Share3: σ₃ = σ ⊕ σ₁ ⊕ σ₂

Verify: σ₁ ⊕ σ₂ ⊕ σ₃ = σ₁ ⊕ σ₂ ⊕ (σ ⊕ σ₁ ⊕ σ₂) = σ ✓
```

**Security**: Need all 3 shares. Any 2 reveal nothing!

### Shamir's Secret Sharing (Threshold)

For more flexibility, Shamir's scheme allows k-of-n sharing:

```
3-of-5 sharing: Any 3 shareholders can reconstruct
               2 or fewer learn nothing
```

Based on polynomial interpolation. kMOSAIC uses the simpler XOR version since we always need all 3.

## How kMOSAIC Binds Components

### In the KEM

```
1. Generate ephemeral secret σ

2. Split into shares:
   σ₁ = random
   σ₂ = random
   σ₃ = σ ⊕ σ₁ ⊕ σ₂

3. Encrypt each share with different component:
   C₁ = SLSS.Encrypt(σ₁)
   C₂ = TDD.Encrypt(σ₂)
   C₃ = EGRW.Encrypt(σ₃)

4. Derive final key:
   K = H(σ || C₁ || C₂ || C₃)
```

The hash binding in step 4 adds additional protection:

- Includes ALL ciphertexts in the derivation
- Any tampering with ANY component changes K
- Provides "key confirmation" — both parties get same K only if everything matches

### In Signatures

For signatures, we use a different binding: **joint challenge**.

```
1. Generate commitments for all three:
   w₁ = SLSS.Commit(y₁)
   w₂ = TDD.Commit(y₂)
   w₃ = EGRW.Commit(y₃)

2. Single challenge for ALL:
   c = H(message || w₁ || w₂ || w₃)

3. All responses use SAME challenge:
   z₁ = SLSS.Respond(y₁, c, s₁)
   z₂ = TDD.Respond(y₂, c, s₂)
   z₃ = EGRW.Respond(y₃, c, s₃)
```

**Why this binds**: The challenge depends on ALL commitments. To forge, you must:

1. Commit to all three before knowing challenge
2. Respond correctly to the challenge for ALL THREE

If you can't solve one problem, you can't create a valid forgery.

## The Security Proof Intuition

### Breaking the KEM

**Theorem**: Breaking kMOSAIC KEM requires breaking ALL THREE underlying schemes.

**Proof Intuition**:

1. Suppose attacker breaks SLSS and TDD but not EGRW
2. Attacker recovers σ₁ and σ₂
3. But σ₃ is still encrypted under EGRW
4. σ₃ was random when generated
5. Without σ₃, attacker knows nothing about σ = σ₁ ⊕ σ₂ ⊕ σ₃
6. This is information-theoretic — no computation helps!

### Breaking Signatures

**Theorem**: Forging a kMOSAIC signature requires forging ALL THREE component signatures.

**Proof Intuition**:

1. The challenge c is a hash including all commitments
2. To produce valid (c, z₁, z₂, z₃), need valid responses for all three
3. If you can't solve one problem, you can't produce its valid response
4. Invalid response → wrong commitment → different challenge → verification fails

### The Power of Heterogeneity

Even if two components use the SAME mathematical assumption, breaking one doesn't help break the other when they're properly entangled.

But kMOSAIC goes further: the three problems are from DIFFERENT mathematical domains:

- Lattice geometry
- Multilinear algebra
- Graph combinatorics

A breakthrough in lattice algorithms doesn't help with tensors or graphs!

---

# Chapter 11: Using kMOSAIC in Your Application

This chapter provides practical guidance for integrating kMOSAIC into real applications, with a focus on the public API.

## Installation and Setup

### Package Installation

```bash
# Using Bun (recommended for best performance)
bun add k-mosaic

# Using npm
npm install k-mosaic

# Using yarn
yarn add k-mosaic

# Using pnpm
pnpm add k-mosaic
```

### Runtime Requirements

kMOSAIC works in:

- **Node.js** 18+
- **Bun** 1.0+
- **Deno** 1.30+
- **Modern Browsers** (Chrome 90+, Firefox 90+, Safari 15+)

Required features:

- `crypto.getRandomValues()` or `crypto.randomBytes()`
- `TextEncoder` / `TextDecoder`
- BigInt support

## Importing kMOSAIC

kMOSAIC offers two ways to import functionality:

1.  **Named Exports** (Recommended): Import specific functions directly. This allows for tree-shaking and smaller bundle sizes.
2.  **Default Export** (Convenience): Import the `crypto` object which groups functionality and supports lazy loading.

### Option 1: Named Exports

```typescript
import {
  kemGenerateKeyPair,
  encapsulate,
  decapsulate,
  signGenerateKeyPair,
  sign,
  verify,
  SecurityLevel,
  MOS_128,
  MOS_256,
} from 'k-mosaic'

// Import types (TypeScript only)
import type {
  MOSAICPublicKey,
  MOSAICSecretKey,
  MOSAICKeyPair,
  MOSAICCiphertext,
  MOSAICSignature,
} from 'k-mosaic'
```

### Option 2: The crypto Object

The default export `crypto` provides a structured API where modules are loaded dynamically (lazy loaded) when accessed. This is useful for keeping initial bundle sizes low if you only use parts of the library conditionally.

```typescript
import crypto from 'k-mosaic'

// Functions are async and load implementation on demand
const keys = await crypto.kem.generateKeyPair()
```

## Key Encapsulation & Encryption (KEM)

The KEM module handles key establishment and encryption.

### Key Generation

```typescript
import { kemGenerateKeyPair, MOS_128, MOS_256 } from 'k-mosaic'

// Standard security (128-bit post-quantum)
const standardKeys = await kemGenerateKeyPair(MOS_128)

// High security (256-bit post-quantum)
const highSecurityKeys = await kemGenerateKeyPair(MOS_256)
```

Using the `crypto` object:

```typescript
import crypto, { SecurityLevel } from 'k-mosaic'

// Parameters are loaded asynchronously
const params = await crypto.params[SecurityLevel.MOS_128]()
const keys = await crypto.kem.generateKeyPair(params)
```

### Encapsulation (Key Exchange)

Use this to establish a shared secret between two parties.

```typescript
import { encapsulate, decapsulate } from 'k-mosaic'

// Sender: Encapsulate against recipient's public key
const { sharedSecret, ciphertext } = await encapsulate(recipientPublicKey)

// Receiver: Decapsulate using own secret key
const recoveredSecret = await decapsulate(ciphertext, mySecretKey, myPublicKey)
```

### Direct Encryption

kMOSAIC provides convenience functions for encrypting messages directly. These wrappers handle the KEM + Symmetric Encryption (hybrid) flow for you.

```typescript
import { encrypt, decrypt } from 'k-mosaic'
import type { MOSAICPublicKey, MOSAICSecretKey } from 'k-mosaic'

// Encrypt a message (Uint8Array)
const message = new TextEncoder().encode('Top Secret')
const encryptedData = await encrypt(message, recipientPublicKey)

// Decrypt
const decryptedData = await decrypt(
  encryptedData,
  recipientSecretKey,
  recipientPublicKey,
)
```

Using the `crypto` object:

```typescript
import crypto from 'k-mosaic'

await crypto.kem.encrypt(message, pk)
await crypto.kem.decrypt(ciphertext, sk, pk)
```

## Digital Signatures

### Key Generation

```typescript
import { signGenerateKeyPair } from 'k-mosaic'

const signKeys = await signGenerateKeyPair()
```

### Signing and Verifying

```typescript
import { sign, verify } from 'k-mosaic'

const data = new TextEncoder().encode('Signed Document')

// Sign
const signature = await sign(data, signKeys.secretKey, signKeys.publicKey)

// Verify
const isValid = await verify(data, signature, signKeys.publicKey)
```

Using the `crypto` object:

```typescript
import crypto from 'k-mosaic'

const sig = await crypto.sign.sign(data, sk, pk)
const valid = await crypto.sign.verify(data, sig, pk)
```

## Key Management Best Practices

### Generating Keys

```typescript
import {
  kemGenerateKeyPair,
  kemGenerateKeyPairFromSeed,
  secureRandomBytes,
} from 'k-mosaic'

// ✅ Good: Generate fresh random keys
const keys = await kemGenerateKeyPair()

// ✅ Good: Generate from high-entropy seed (for determinism)
const seed = secureRandomBytes(32)
const deterministicKeys = await kemGenerateKeyPairFromSeed(seed)

// ❌ Bad: Deriving from password (too low entropy)
// Passwords don't have enough entropy for cryptographic keys
const weakSeed = someHashFunction('mypassword123') // Don't do this!
```

### Storing Private Keys

```typescript
import { secureRandomBytes } from 'k-mosaic'
import type { MOSAICSecretKey } from 'k-mosaic'

// ✅ Good: Encrypted storage (example - requires external crypto library)
async function storePrivateKey(key: MOSAICSecretKey, password: string) {
  // Derive encryption key from password (use PBKDF2, Argon2, etc.)
  const salt = secureRandomBytes(16)
  const derivedKey = await pbkdf2(password, salt, 100000)

  // Encrypt the private key (use AES-GCM or similar)
  const serialized = JSON.stringify(key)
  const encrypted = await aesGcmEncrypt(serialized, derivedKey)

  // Store salt + encrypted key
  return { salt, encrypted }
}

// ✅ Good: Hardware security module (HSM)
// For high-value keys, consider hardware storage

// ❌ Bad: Plaintext storage
localStorage.setItem('privateKey', JSON.stringify(key)) // Never!
```

### Key Rotation

```typescript
import { kemGenerateKeyPair, zeroize } from 'k-mosaic'
import type { MOSAICKeyPair, MOSAICPublicKey, MOSAICSecretKey } from 'k-mosaic'

async function rotateKeys(
  oldKeys: MOSAICKeyPair,
  updateCallback: (newPublicKey: MOSAICPublicKey) => Promise<void>,
) {
  // 1. Generate new keys
  const newKeys = await kemGenerateKeyPair()

  // 2. Update public key in all necessary places
  await updateCallback(newKeys.publicKey)

  // 3. Keep old keys for a transition period
  // (to decrypt messages sent with old key)

  // 4. After transition, securely delete old keys
  // Note: zeroize works on TypedArrays within the secret key structure
  if (oldKeys.secretKey.slss?.s) zeroize(oldKeys.secretKey.slss.s)
  if (oldKeys.secretKey.tdd?.E1) zeroize(oldKeys.secretKey.tdd.E1)
  // ... zeroize other secret components

  return newKeys
}
```

## Error Handling

### Error Types

kMOSAIC functions throw standard JavaScript `Error` objects with descriptive messages. You can catch and handle them based on the error message or use try-catch for general error handling.

```typescript
import { encapsulate } from 'k-mosaic'
import type { MOSAICPublicKey } from 'k-mosaic'

async function robustEncryption(data: Uint8Array, publicKey: MOSAICPublicKey) {
  try {
    const result = await encapsulate(publicKey)
    return result
  } catch (error) {
    if (error instanceof Error) {
      console.error('KEM operation failed:', error.message)
      // Check error message for specific issues
      if (
        error.message.includes('Invalid') ||
        error.message.includes('validation')
      ) {
        // Handle validation errors
      }
    } else {
      console.error('Unexpected error:', error)
    }
    throw error
  }
}
```

### Graceful Degradation

```typescript
import { verify } from 'k-mosaic'
import type { MOSAICPublicKey, MOSAICSignature } from 'k-mosaic'

async function tryVerify(
  message: Uint8Array,
  signature: MOSAICSignature,
  publicKey: MOSAICPublicKey,
): Promise<{ valid: boolean; error?: string }> {
  try {
    const valid = await verify(message, signature, publicKey)
    return { valid }
  } catch (error) {
    if (error instanceof Error) {
      // Handle specific error cases based on message
      if (error.message.includes('signature')) {
        return { valid: false, error: 'Malformed signature' }
      }
      if (error.message.includes('key') || error.message.includes('public')) {
        return { valid: false, error: 'Invalid public key' }
      }
      return { valid: false, error: error.message }
    }
    return { valid: false, error: 'Verification failed' }
  }
}
```

### Logging and Monitoring

```typescript
import { sign } from 'k-mosaic'
import type {
  MOSAICSecretKey,
  MOSAICPublicKey,
  MOSAICSignature,
} from 'k-mosaic'

async function monitoredSign(
  message: Uint8Array,
  secretKey: MOSAICSecretKey,
  publicKey: MOSAICPublicKey,
): Promise<MOSAICSignature> {
  const startTime = performance.now()

  try {
    const signature = await sign(message, secretKey, publicKey)

    const duration = performance.now() - startTime
    // Use your preferred metrics library
    metrics.record('signature_time_ms', duration)
    metrics.increment('signatures_success')

    return signature
  } catch (error) {
    metrics.increment('signatures_failed')
    throw error
  }
}
```

---

# Part IV: Advanced Topics

This part covers security engineering, performance, and the broader landscape of post-quantum cryptography.

---

# Chapter 12: Security Engineering

Cryptographic algorithms can be mathematically perfect but still have vulnerable implementations. This chapter covers the engineering practices that make kMOSAIC secure in practice.

## Side-Channel Attacks

### What are Side Channels?

A **side channel** is any information leaked by a computation other than its intended output:

- **Timing**: How long operations take
- **Power**: How much electricity is consumed
- **Electromagnetic**: Radio waves emitted by circuits
- **Cache**: Memory access patterns
- **Acoustic**: Sound made by hardware

### Timing Attacks

The most common side channel in software is timing.

**Vulnerable Code**:

```typescript
function compareSecrets(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false // Returns early on first mismatch!
    }
  }
  return true
}
```

**The Attack**:

```
Guess: [1, 0, 0, 0, ...]
Time: 0.001ms (instant failure - first byte wrong)

Guess: [correct_first_byte, 0, 0, 0, ...]
Time: 0.002ms (slightly longer - first byte right, second wrong)

Guess: [correct_first, correct_second, 0, 0, ...]
Time: 0.003ms (even longer)
```

By measuring timing, the attacker learns the secret one byte at a time!

### Power Analysis

Every CPU instruction consumes slightly different amounts of power.

```
Instruction: XOR with 0x00 → Low power
Instruction: XOR with 0xFF → Higher power
```

By monitoring power consumption (with an oscilloscope on the power line), attackers can deduce what values are being processed.

This is a real threat for:

- Smart cards
- Hardware security modules
- IoT devices

### Cache Timing

Modern CPUs cache memory for speed. Cached vs uncached access has different timing:

```
Cached memory access: ~4 cycles
Uncached memory access: ~100 cycles
```

If secret data determines which memory addresses are accessed, an attacker sharing the same CPU can detect this through cache timing.

### Electromagnetic Emissions

CPUs emit radio waves that vary with computation. With sensitive equipment, attackers can "listen" to computations from a distance.

TEMPEST attacks can read screens and keyboards through walls!

## Constant-Time Programming

### The Principle

**Rule**: The sequence of operations and memory accesses must be independent of secret data.

- No secret-dependent branches
- No secret-dependent memory lookups
- No secret-dependent loop bounds

### Constant-Time Comparison

```typescript
// kMOSAIC implementation
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }

  let result = 0

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i] // Accumulate differences
  }

  // Always processes all bytes, regardless of content
  return result === 0
}
```

**Why this works**:

- Always loops through ALL bytes
- XOR and OR take constant time
- No early return

### Constant-Time Selection

Choose between two values without branching:

```typescript
// Select a if condition is 1, b if condition is 0
// condition must be 0 or 1
function constantTimeSelect(condition: number, a: number, b: number): number {
  // Create mask: all 1s if condition=1, all 0s if condition=0
  const mask = -condition // -1 = 0xFFFFFFFF, -0 = 0x00000000

  return (a & mask) | (b & ~mask)
}

// Usage: no branch!
const result = constantTimeSelect(isValid, secretKey, randomKey)
```

### Avoiding Lookup Tables

Many cryptographic algorithms use lookup tables (S-boxes in AES, for example).

**Problem**: Table index depends on secret → cache timing leak

**Solutions**:

1. **Bitsliced implementation**: Compute table lookups with bitwise operations
2. **Constant-time table access**: Read ALL entries, select the right one with masking
3. **Hardware instructions**: Use AES-NI which is designed to be constant-time

### The Challenges in TypeScript/JavaScript

JavaScript engines are complex and can optimize in unpredictable ways:

- JIT compilation may reintroduce branches
- BigInt operations may have variable timing
- Memory allocation patterns vary

**kMOSAIC mitigations**:

1. Use typed arrays (Uint8Array, Uint32Array) for predictable behavior
2. Avoid BigInt in timing-critical paths where possible
3. Use WebAssembly for critical operations (more predictable)
4. Extensive testing with timing analysis tools

## Memory Safety

### The Garbage Collection Problem

JavaScript has automatic garbage collection. This means:

1. You can't reliably zero memory
2. Sensitive data may persist in memory
3. Data may be copied by the GC

### Mitigation Strategies

**Explicit Zeroing**:

```typescript
function zeroize(buffer: Uint8Array): void {
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = 0
  }
  // Note: Optimizer might remove this if buffer isn't used after
}

// More robust version
function secureZeroize(buffer: Uint8Array): void {
  crypto.getRandomValues(buffer) // Overwrite with random first
  buffer.fill(0) // Then zero
  // The random overwrite prevents optimization away
}
```

**SecureBuffer Class**:

```typescript
class SecureBuffer {
  private buffer: Uint8Array
  private disposed = false

  constructor(size: number) {
    this.buffer = new Uint8Array(size)
  }

  get data(): Uint8Array {
    if (this.disposed) throw new Error('Buffer disposed')
    return this.buffer
  }

  dispose(): void {
    if (!this.disposed) {
      secureZeroize(this.buffer)
      this.disposed = true
    }
  }

  [Symbol.dispose](): void {
    this.dispose()
  }
}

// Usage with TypeScript 5.2+ using statement
async function signMessage(msg: Uint8Array): Promise<Uint8Array> {
  using tempKey = new SecureBuffer(32)
  // ... use tempKey.data ...
  // Automatically zeroed when scope exits
}
```

### Memory Access Patterns

Even without reading memory content, access patterns can leak:

```typescript
// Bad: Access pattern reveals index
const value = table[secretIndex]

// Better: Access all, select with mask
let result = 0
for (let i = 0; i < table.length; i++) {
  const isTarget = constantTimeEqual(i, secretIndex)
  result = constantTimeSelect(isTarget, table[i], result)
}
```

## Secure Randomness

### Sources of Randomness

**Bad Sources**:

```typescript
Math.random() // Predictable PRNG
Date.now() // Low entropy
process.pid // Easily guessable
```

**Good Sources**:

```typescript
crypto.getRandomValues(buffer) // Browser/Node
crypto.randomBytes(size) / // Node.js
  dev /
  urandom // Unix systems
```

### How Operating Systems Generate Randomness

1. **Entropy Collection**: Mouse movements, keyboard timing, disk I/O timing, interrupt timing
2. **Entropy Pool**: Collected randomness stored and mixed
3. **CSPRNG**: Cryptographic algorithm expands the pool into unlimited random bytes

### Seeding and Determinism

Sometimes you need reproducible randomness (testing):

```typescript
// Deterministic key generation (for testing only!)
async function kemGenerateKeyPairFromSeed(seed: Uint8Array) {
  // Validate seed has sufficient entropy
  if (seed.length < 32) {
    throw new Error('Seed must be at least 32 bytes')
  }

  // Use SHAKE256 as a deterministic RNG
  const rng = createDeterministicRng(seed)

  // Generate keys using this RNG
  return generateKeyPairWithRng(rng)
}
```

**Warning**: Never use deterministic generation with low-entropy seeds!

### Entropy Estimation

How much randomness do you need?

| Use Case       | Minimum Entropy |
| :------------- | :-------------- |
| 128-bit key    | 128 bits        |
| 256-bit key    | 256 bits        |
| Nonce (unique) | 128 bits        |
| Random padding | 64+ bits        |

**Rule of thumb**: Use at least as many random bits as your security level.

## Security Audit Notes

An internal security audit (December 2025) reviewed the kMOSAIC implementation and identified several issues that have been addressed:

**Fixed Issues:**

- **TDD encryption**: Now uses XOR encryption with keystream derived from masked tensor matrix
- **EGRW encryption**: Randomness no longer exposed; uses ephemeral walk vertex derivation
- **Modular bias**: TDD sampling now uses rejection sampling for uniform distribution

**Known Limitations (Documented):**

- JavaScript cannot guarantee constant-time execution due to JIT/GC
- Memory zeroization is best-effort due to garbage collection
- These are fundamental to the JavaScript runtime, not implementation bugs

For complete details, see [SECURITY_REPORT.md](SECURITY_REPORT.md).

---

# Chapter 13: Parameters and Performance

This chapter explains kMOSAIC's parameter choices and performance characteristics.

## Security Levels Explained

### What is a "Security Level"?

Security level is measured in bits. An n-bit security level means:

- The best known attack requires 2^n operations
- For n=128, that's about 10^38 operations

### NIST Security Categories

NIST defines security levels relative to breaking symmetric algorithms:

| Level | Equivalent To     | Operations |
| :---- | :---------------- | :--------- |
| 1     | AES-128           | 2^128      |
| 2     | SHA-256 collision | 2^128      |
| 3     | AES-192           | 2^192      |
| 4     | SHA-384 collision | 2^192      |
| 5     | AES-256           | 2^256      |

### kMOSAIC Security Levels

| Parameter Set | NIST Level  | Best Known Attack |
| :------------ | :---------- | :---------------- |
| MOS_128       | 1 (128-bit) | ~2^128 operations |
| MOS_256       | 5 (256-bit) | ~2^256 operations |

### Quantum Security vs Classical Security

Classical security (bits) = 2 × Quantum security (bits)

Why? Grover's algorithm gives a quadratic speedup for search:

- Classical brute force: 2^n
- Quantum brute force: 2^(n/2)

So 256-bit classical ≈ 128-bit quantum security.

## Parameter Selection

### Lattice Parameters (SLSS)

| Parameter | MOS_128 | MOS_256 | Purpose             |
| :-------- | :------ | :------ | :------------------ |
| n         | 512     | 1024    | Lattice dimension   |
| m         | 384     | 768     | Number of equations |
| w         | 64      | 128     | Sparsity weight     |

**Trade-offs**:

- Larger n → More security, larger keys, slower
- Larger m → More constraints, larger public keys
- Larger w → More combinations, harder to guess

### Tensor Parameters (TDD)

| Parameter | MOS_128 | MOS_256 | Purpose          |
| :-------- | :------ | :------ | :--------------- |
| n         | 24      | 36      | Tensor dimension |
| r         | 6       | 9       | Rank             |

**Trade-offs**:

- Tensor size is O(n³) — grows fast!
- Lower rank → Smaller keys, potentially weaker
- Higher dimension → More security, much larger tensors

### Graph Parameters (EGRW)

| Parameter | MOS_128 | MOS_256 | Purpose                 |
| :-------- | :------ | :------ | :---------------------- |
| p         | 1021    | 2039    | Prime (graph size ≈ p³) |
| k         | 128     | 256     | Walk length             |

**Trade-offs**:

- Larger p → Larger group, more security, larger keys
- Longer walks → Better mixing, larger signatures
- More generators → Faster mixing, more complex

## Performance Benchmarks

### Key Generation

| Operation   | Time (ms) | Ops/sec |
| :---------- | :-------- | :------ |
| KEM KeyGen  | 19.289    | 51.8    |
| Sign KeyGen | 19.204    | 52.1    |

Key generation is done once and keys are reused.

### KEM Operations

| Operation   | Time (ms) | Ops/sec |
| :---------- | :-------- | :------ |
| Encapsulate | 0.538     | 1,860.0 |
| Decapsulate | 4.220     | 237.0   |

### Signature Operations

| Operation | Time (ms) | Ops/sec |
| :-------- | :-------- | :------ |
| Sign      | 0.040     | 25,049.6 |
| Verify    | 1.417     | 705.9   |

_Benchmarks on Apple M2 Pro, Bun runtime. Tested: December 31, 2025._

### Key and Signature Sizes

#### MOS-128 (128-bit Security)

| Component         | Size    | Notes |
| :---------------- | :------ | :---- |
| KEM Public Key    | ~824 KB | Contains SLSS matrix A (384 × 512 × 4 bytes), TDD tensor, EGRW keys |
| KEM Ciphertext    | ~5.7 KB | Contains SLSS vectors (c1), TDD ciphertext (c2), EGRW vertex path (c3), NIZK proof |
| Signature         | 140 B   | commitment (32B) + challenge (32B) + response (64B) + overhead (12B) |

#### MOS-256 (256-bit Security)

| Component         | Size    | Notes |
| :---------------- | :------ | :---- |
| KEM Public Key    | ~3.3 MB | Contains SLSS matrix A (768 × 1024 × 4 bytes), larger TDD tensor, EGRW keys |
| KEM Ciphertext    | ~10.5 KB| Larger ciphertexts due to bigger parameter sets |
| Signature         | 140 B   | Same as MOS-128 - signature size is independent of security level |

#### Classical Cryptography (for Reference)

| Component         | Size    | Status |
| :---------------- | :------ | :----- |
| X25519 Public Key | 32 B    | ✓ |
| X25519 Ciphertext | 32 B    | (44-76B with serialization metadata) |
| Ed25519 Signature | 64 B    | ✓ |

**Important Notes:**
- kMOSAIC provides post-quantum security at the cost of **much larger** keys compared to classical algorithms (~100x larger)
- Signatures are compact (140 bytes) despite the heterogeneous design
- Public key size dominates the communication footprint due to lattice-based matrix storage
- See [test/validate-sizes.test.ts](test/validate-sizes.test.ts) for runtime validation of these sizes

### Performance Considerations

kMOSAIC is slower and has larger keys — that's the cost of defense-in-depth.

## Optimization Strategies

### Parallelization

The three components are independent — parallelize them:

```typescript
async function parallelEncapsulate(publicKey: PublicKey) {
  const sigma = secureRandomBytes(32)
  const [sigma1, sigma2, sigma3] = splitSecret(sigma)

  // Run all three encryptions in parallel
  const [c1, c2, c3] = await Promise.all([
    slssEncrypt(sigma1, publicKey.slss),
    tddEncrypt(sigma2, publicKey.tdd),
    egrwEncrypt(sigma3, publicKey.egrw),
  ])

  return { sharedSecret: hash(sigma, c1, c2, c3), ciphertext: { c1, c2, c3 } }
}
```

### WebAssembly

Critical inner loops can be compiled to WebAssembly for better performance:

- Matrix multiplication (SLSS)
- Tensor operations (TDD)
- Modular arithmetic (all)

### Precomputation

Some values can be precomputed:

```typescript
// Precompute powers for EGRW
const generatorPowers = precomputeGeneratorPowers(generators, maxWalkLength)

// Precompute NTT tables for SLSS
const nttTables = precomputeNTT(n, q)
```

### Hardware Acceleration

Where available:

- AES-NI for hash functions (if using AES-based)
- SIMD for vector operations
- GPU for tensor operations (future)

---

# Chapter 14: Comparison with Other Schemes

This chapter puts kMOSAIC in context with other post-quantum cryptography options.

## NIST Standardized Algorithms

### ML-KEM (Kyber)

**Status**: FIPS 203 (August 2024)[^fips203]

**Based on**: Module-LWE (Learning With Errors)

| Feature    | ML-KEM-768   |
| :--------- | :----------- |
| Public Key | 1,184 bytes  |
| Ciphertext | 1,088 bytes  |
| Security   | NIST Level 3 |

**Pros**:

- Fast
- Small keys
- NIST standardized
- Hardware implementations coming

**Cons**:

- Single mathematical assumption
- If LWE is broken, completely insecure

### ML-DSA (Dilithium)

**Status**: FIPS 204 (August 2024)[^fips204]

**Based on**: Module-LWE + Fiat-Shamir

| Feature    | ML-DSA-65    |
| :--------- | :----------- |
| Public Key | 1,952 bytes  |
| Signature  | 3,293 bytes  |
| Security   | NIST Level 3 |

**Pros**:

- Relatively fast
- NIST standardized
- Good balance of sizes

**Cons**:

- Same LWE assumption as ML-KEM
- Larger signatures than classical

### SLH-DSA (SPHINCS+)

**Status**: FIPS 205 (August 2024)[^fips205]

**Based on**: Hash functions only

| Feature    | SLH-DSA-128s |
| :--------- | :----------- |
| Public Key | 32 bytes     |
| Signature  | 7,856 bytes  |
| Security   | NIST Level 1 |

**Pros**:

- Based on hash functions (very well understood)
- Tiny public keys
- Conservative assumption

**Cons**:

- Very large signatures
- Slow signing

## When to Use kMOSAIC

### kMOSAIC is Best When:

1. **Maximum Assurance Required**
   - Military/government applications
   - Critical infrastructure
   - Secrets that must stay secret for 50+ years

2. **Assumption Diversity is Critical**
   - You don't want to bet everything on lattices
   - Regulatory requirements for multiple algorithms

3. **Performance is Acceptable**
   - Not real-time or high-frequency
   - Can tolerate ~30ms per operation
   - Bandwidth for larger keys/signatures

### NIST Standards are Best When:

1. **Compliance Required**
   - FIPS compliance
   - FedRAMP certification
   - Industry regulations

2. **Performance Critical**
   - High-frequency trading
   - Real-time systems
   - Resource-constrained devices

3. **Interoperability Needed**
   - Communicating with government systems
   - Using standardized protocols (TLS 1.3 + PQC)

## Migration Strategies

### Hybrid Approach

Run kMOSAIC alongside classical or NIST algorithms:

```typescript
// Hybrid KEM: Classical + kMOSAIC
async function hybridEncapsulate(classicalPK, mosaicPK) {
  const [classicalResult, mosaicResult] = await Promise.all([
    x25519Encapsulate(classicalPK),
    mosaicEncapsulate(mosaicPK),
  ])

  // Combine shared secrets
  const combinedSecret = hash(
    classicalResult.sharedSecret,
    mosaicResult.sharedSecret,
  )

  return {
    sharedSecret: combinedSecret,
    ciphertext: {
      classical: classicalResult.ciphertext,
      mosaic: mosaicResult.ciphertext,
    },
  }
}
```

**Benefits**:

- Secure if EITHER scheme is secure
- Backward compatible
- Gradual migration

### Phased Rollout

1. **Phase 1**: Add kMOSAIC signatures alongside existing (dual signing)
2. **Phase 2**: Require kMOSAIC signature verification
3. **Phase 3**: Migrate to kMOSAIC-only
4. **Phase 4**: Remove legacy support

---

# Chapter 15: The Future of Post-Quantum Cryptography

This final chapter looks at what's ahead for PQC and kMOSAIC.

## Ongoing Research

### Lattice Cryptanalysis

Researchers continuously improve lattice attacks:

- **LLL Algorithm** (1982): First practical lattice reduction[^lll1982]
- **BKZ Algorithm** (1987): Better reduction, exponential time
- **BKZ 2.0** (2011): Improved practical performance
- **Sieving** (ongoing): Memory-intensive but faster

The security margin is being slowly eroded. Parameters may need increasing.

### Tensor Cryptanalysis

Tensor decomposition is less studied cryptographically:

- Most research in machine learning/statistics
- Fewer specialized attacks
- NP-hardness provides strong foundation

### Quantum Attacks on Graphs

Graph problems don't have known quantum speedups:

- Grover can search, but not structured search
- No analog of Shor's algorithm
- Quantum walk algorithms exist but don't break EGRW

## Potential Attacks

### What Could Break kMOSAIC?

| Attack                            | Would Break | Likelihood |
| :-------------------------------- | :---------- | :--------- |
| Better lattice reduction          | SLSS only   | Medium     |
| Tensor decomposition breakthrough | TDD only    | Low        |
| Graph navigation algorithm        | EGRW only   | Low        |
| All three simultaneously          | Full system | Very Low   |

### Quantum Computer Progress

| Year   | Qubits      | Threat Level |
| :----- | :---------- | :----------- |
| 2020   | ~60         | None         |
| 2025   | ~1000       | None         |
| 2030?  | ~10,000?    | Low          |
| 2035?  | ~100,000?   | Medium       |
| 2040+? | ~1,000,000? | High         |

These are estimates. Breakthroughs could accelerate or delays could occur.

### Side Channel Attacks

Implementation attacks remain the biggest near-term threat:

- Timing attacks on software
- Power analysis on hardware
- Fault injection

This is why security engineering (Chapter 12) is crucial!

## The Road Ahead

### For kMOSAIC

1. **Formal Security Proofs**: Complete reduction proofs for combined scheme
2. **Third-Party Audit**: Independent security assessment
3. **Hardware Optimization**: FPGA/ASIC implementations
4. **Standardization**: Potential submission to future NIST rounds
5. **Additional Bindings**: Python, Rust, Go, C implementations

### For Post-Quantum Cryptography

1. **Deployment**: Government and industry adoption of NIST standards
2. **TLS Integration**: Post-quantum key exchange in HTTPS
3. **Hybrid Modes**: Transition period with classical + PQC
4. **Code Signing**: Post-quantum signatures for software
5. **Quantum Networks**: Integration with quantum key distribution

### For You

1. **Start Now**: Begin planning PQC migration
2. **Inventory**: Identify systems using vulnerable cryptography
3. **Experiment**: Test PQC libraries in non-critical systems
4. **Monitor**: Watch for quantum computing developments
5. **Prepare**: Have migration plans ready

---

# Appendices

---

# Appendix A: Glossary

| Term                                | Definition                                                         |
| :---------------------------------- | :----------------------------------------------------------------- |
| **Asymmetric Cryptography**         | Cryptography using key pairs (public/private)                      |
| **CCA**                             | Chosen Ciphertext Attack — attacker can decrypt chosen ciphertexts |
| **CPA**                             | Chosen Plaintext Attack — attacker can encrypt chosen plaintexts   |
| **CSPRNG**                          | Cryptographically Secure Pseudo-Random Number Generator            |
| **CVP**                             | Closest Vector Problem — find nearest lattice point to a target    |
| **Defense-in-Depth**                | Security through multiple independent layers                       |
| **Entanglement (Cryptographic)**    | Binding multiple schemes so breaking one isn't enough              |
| **EUF-CMA**                         | Existential Unforgeability under Chosen Message Attack             |
| **Expander Graph**                  | Sparse but highly connected graph with rapid mixing                |
| **Fiat-Shamir Transform**           | Converting interactive proof to non-interactive signature          |
| **Fujisaki-Okamoto Transform**      | Converting CPA-secure to CCA-secure encryption                     |
| **Hash Function**                   | One-way function producing fixed-size output                       |
| **IND-CCA2**                        | Indistinguishability under Adaptive Chosen Ciphertext Attack       |
| **KEM**                             | Key Encapsulation Mechanism — secure key establishment             |
| **Lattice**                         | Regular grid of points in n-dimensional space                      |
| **LWE**                             | Learning With Errors — hard lattice problem                        |
| **Modular Arithmetic**              | Arithmetic with wraparound at a modulus                            |
| **NIST**                            | National Institute of Standards and Technology (US)                |
| **NP-Hard**                         | At least as hard as the hardest problems in NP                     |
| **Post-Quantum Cryptography (PQC)** | Cryptography resistant to quantum attacks                          |
| **Qubit**                           | Quantum bit — can be in superposition of 0 and 1                   |
| **Rejection Sampling**              | Discarding outputs that leak information                           |
| **Secret Sharing**                  | Splitting a secret so k-of-n shares reconstruct it                 |
| **Side Channel**                    | Information leakage beyond intended output                         |
| **SIS**                             | Short Integer Solution — find short vector in lattice              |
| **SLSS**                            | Structured Lattice Short Signature (kMOSAIC component)             |
| **SVP**                             | Shortest Vector Problem — find shortest non-zero lattice vector    |
| **Symmetric Cryptography**          | Cryptography using shared secret key                               |
| **TDD**                             | Tensor Decomposition Distinguishing (kMOSAIC component)            |
| **Tensor**                          | Multi-dimensional array generalizing matrices                      |
| **XOF**                             | Extendable Output Function — hash with arbitrary output length     |
| **Zeroize**                         | Securely overwrite sensitive data in memory                        |

---

# Appendix B: Further Reading

## Books

### Introductory

- **The Code Book** by Simon Singh — Popular history of cryptography
- **Crypto 101** (online) — Free introduction to cryptography

### Intermediate

- **An Introduction to Mathematical Cryptography** by Hoffstein, Pipher, Silverman
- **Serious Cryptography** by Jean-Philippe Aumasson

### Advanced

- **A Graduate Course in Applied Cryptography** by Boneh & Shoup (free online)
- **Post-Quantum Cryptography** edited by Bernstein, Buchmann, Dahmen
- **Quantum Computation and Quantum Information** by Nielsen & Chuang[^nielsen2010]

## Papers

### Foundational

- Shor (1994): "Algorithms for Quantum Computation" — The paper that started PQC
- Regev (2005): "On Lattices, Learning with Errors..." — Foundation of lattice crypto
- Lyubashevsky (2012): "Lattice Signatures Without Trapdoors" — Fiat-Shamir with aborts

### Surveys

- Peikert (2016): "A Decade of Lattice Cryptography" — Comprehensive lattice survey
- Kolda & Bader (2009): "Tensor Decompositions and Applications" — Tensor methods
- Hoory, Linial, Wigderson: "Expander Graphs and their Applications"

## Online Resources

- **NIST PQC Project**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **IACR ePrint**: https://eprint.iacr.org — Cryptography preprints
- **Crypto Stack Exchange**: https://crypto.stackexchange.com
- **PQCrypto Conference**: https://pqcrypto.org

---

# Appendix C: API Reference

## KEM Functions

### `kemGenerateKeyPair(params?)`

Generate a KEM key pair.

```typescript
async function kemGenerateKeyPair(
  params?: MosaicParams,
): Promise<{ publicKey: PublicKey; secretKey: SecretKey }>
```

**Parameters**:

- `params` (optional): `MOS_128` (default) or `MOS_256`

**Returns**: Object with `publicKey` and `secretKey`

---

### `encapsulate(publicKey)`

Encapsulate a random shared secret.

```typescript
async function encapsulate(
  publicKey: PublicKey,
): Promise<{ sharedSecret: Uint8Array; ciphertext: Ciphertext }>
```

**Parameters**:

- `publicKey`: Recipient's public key

**Returns**: Object with 32-byte `sharedSecret` and `ciphertext`

---

### `decapsulate(ciphertext, secretKey, publicKey)`

Recover the shared secret.

```typescript
async function decapsulate(
  ciphertext: Ciphertext,
  secretKey: SecretKey,
  publicKey: PublicKey,
): Promise<Uint8Array>
```

**Parameters**:

- `ciphertext`: The encapsulated ciphertext
- `secretKey`: Recipient's secret key
- `publicKey`: Recipient's public key (for FO verification)

**Returns**: 32-byte shared secret

---

## Signature Functions

### `signGenerateKeyPair(params?)`

Generate a signing key pair.

```typescript
async function signGenerateKeyPair(
  params?: MosaicParams,
): Promise<{ publicKey: SignPublicKey; secretKey: SignSecretKey }>
```

---

### `sign(message, secretKey, publicKey)`

Sign a message.

```typescript
async function sign(
  message: Uint8Array,
  secretKey: SignSecretKey,
  publicKey: SignPublicKey,
): Promise<Uint8Array>
```

**Returns**: Signature bytes

---

### `verify(message, signature, publicKey)`

Verify a signature.

```typescript
async function verify(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: SignPublicKey,
): Promise<boolean>
```

**Returns**: `true` if valid, `false` otherwise

---

## Utility Functions

### `constantTimeEqual(a, b)`

Compare two byte arrays in constant time.

```typescript
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean
```

---

### `secureRandomBytes(length)`

Generate cryptographically secure random bytes.

```typescript
function secureRandomBytes(length: number): Uint8Array
```

---

### `zeroize(buffer)`

Securely zero a buffer.

```typescript
function zeroize(buffer: Uint8Array): void
```

---

# Appendix D: FAQ

## General Questions

**Q: Is kMOSAIC ready for production use?**

A: kMOSAIC is in **beta**. While the cryptographic design is sound, it has not completed a third-party security audit. For production systems requiring compliance, consider NIST-standardized algorithms.

**Q: Why use kMOSAIC instead of NIST algorithms?**

A: kMOSAIC provides **defense-in-depth** — security even if one of its three underlying problems is broken. NIST algorithms are faster and standardized, but rely on a single assumption.

**Q: Is kMOSAIC patented?**

A: No. kMOSAIC is open source under the MIT license. The underlying mathematical techniques are public domain.

## Technical Questions

**Q: Why are keys so large?**

A: Post-quantum algorithms fundamentally require larger keys. kMOSAIC uses three components (each with its own keys), so sizes are approximately 3× a single-component scheme.

**Q: Why is signing slower than verification?**

A: Signing involves rejection sampling — some attempts are discarded. Verification always succeeds in one pass.

**Q: Can I use kMOSAIC in the browser?**

A: Yes! kMOSAIC is pure TypeScript and works in all modern browsers with Web Crypto API support.

**Q: Is there a C/Rust implementation?**

A: Not yet, but it's planned. The TypeScript reference implementation is the source of truth.

## Security Questions

**Q: What if one component is broken?**

A: kMOSAIC remains secure! The secret sharing ensures that breaking one or two components reveals nothing about the shared secret.

**Q: Is quantum randomness used?**

A: No. "Entanglement" refers to cryptographic binding, not quantum mechanics. kMOSAIC runs on classical computers.

**Q: How do I report security issues?**

A: Please email security issues privately to the maintainers. Do NOT open public GitHub issues for vulnerabilities.

## Compatibility Questions

**Q: Does kMOSAIC work with TLS?**

A: Not directly. kMOSAIC is a library, not a protocol. It could be integrated into TLS implementations, but this isn't done yet.

**Q: Can I use kMOSAIC with existing PKI?**

A: You would need to run parallel PKI infrastructure for kMOSAIC keys alongside existing X.509 certificates.

---

# Conclusion

You've reached the end of The kMOSAIC Book. You now understand:

1. **Why** post-quantum cryptography matters
2. **How** kMOSAIC's three-pillar architecture provides defense-in-depth
3. **What** makes each component (lattices, tensors, graphs) secure
4. **How to** use kMOSAIC in your applications

The quantum threat is real but not imminent. The time to prepare is now — not when quantum computers are breaking cryptography. kMOSAIC offers a unique approach: bet on three horses instead of one.

Welcome to the post-quantum era.

---

# References

[^shor1994]: Shor, P.W. (1994). "Algorithms for quantum computation: Discrete logarithms and factoring". _Proceedings 35th Annual Symposium on Foundations of Computer Science_, pp. 124–134. [doi:10.1109/sfcs.1994.365700](https://doi.org/10.1109/sfcs.1994.365700)

[^grover1996]: Grover, L.K. (1996). "A fast quantum mechanical algorithm for database search" _Proceedings of the 28th Annual ACM Symposium on Theory of Computing_, pp. 212–219. [arXiv:quant-ph/9605043](https://arxiv.org/abs/quant-ph/9605043)

[^diffie1976]: Diffie, W. & Hellman, M. (1976). "New Directions in Cryptography". _IEEE Transactions on Information Theory_, 22(6), pp. 644–654. [doi:10.1109/TIT.1976.1055638](https://doi.org/10.1109/TIT.1976.1055638)

[^castryck2022]: Castryck, W. & Decru, T. (2022). "An efficient key recovery attack on SIDH (preliminary version)". _Cryptology ePrint Archive_, Paper 2022/975. [eprint.iacr.org/2022/975](https://eprint.iacr.org/2022/975)

[^beullens2022]: Beullens, W. (2022). "Breaking Rainbow Takes a Weekend on a Laptop". _Advances in Cryptology – CRYPTO 2022_. [eprint.iacr.org/2022/214](https://eprint.iacr.org/2022/214)

[^lll1982]: Lenstra, A.K., Lenstra, H.W., & Lovász, L. (1982). "Factoring polynomials with rational coefficients". _Mathematische Annalen_, 261, pp. 515–534. [doi:10.1007/BF01457454](https://doi.org/10.1007/BF01457454)

[^hillar2013]: Hillar, C.J. & Lim, L.H. (2013). "Most Tensor Problems are NP-Hard". _Journal of the ACM_, 60(6), Article 45. [doi:10.1145/2512329](https://doi.org/10.1145/2512329)

[^fips203]: NIST (2024). "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)". [csrc.nist.gov/pubs/fips/203/final](https://csrc.nist.gov/pubs/fips/203/final)

[^fips204]: NIST (2024). "FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)". [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)

[^fips205]: NIST (2024). "FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)". [csrc.nist.gov/pubs/fips/205/final](https://csrc.nist.gov/pubs/fips/205/final)

[^sha1collision]: Stevens, M. et al. (2017). "The first collision for full SHA-1". _Advances in Cryptology – CRYPTO 2017_. [shattered.io](https://shattered.io/)

[^fo1999]: Fujisaki, E. & Okamoto, T. (1999). "Secure Integration of Asymmetric and Symmetric Encryption Schemes". _Advances in Cryptology – CRYPTO '99_, LNCS 1666, pp. 537–554. [doi:10.1007/3-540-48405-1_34](https://doi.org/10.1007/3-540-48405-1_34)

[^regev2005]: Regev, O. (2005). "On lattices, learning with errors, random linear codes, and cryptography". _Proceedings of the 37th Annual ACM Symposium on Theory of Computing_, pp. 84–93. [doi:10.1145/1060590.1060603](https://doi.org/10.1145/1060590.1060603)

[^nielsen2010]: Nielsen, M.A. & Chuang, I.L. (2010). _Quantum Computation and Quantum Information_ (10th Anniversary Edition). Cambridge University Press. ISBN 978-1-107-00217-3

---

_The kMOSAIC Book, Version 1.0_
_December 2025_
