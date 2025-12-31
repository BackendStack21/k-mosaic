# k-mosaic-cli Installation Guide

The `k-mosaic-cli` is a command-line interface for the kMOSAIC post-quantum cryptographic library. It provides terminal-based access to key encapsulation, encryption/decryption, and digital signature operations.

## TL;DR

```bash
# Install globally with Bun
bun install -g k-mosaic

# Or install locally and use via npx
npm install k-mosaic

# Generate keys, encrypt, decrypt
k-mosaic-cli kem keygen -l 128 -o keys.json
k-mosaic-cli kem encrypt -p keys.json -m "Secret message" -o enc.json
k-mosaic-cli kem decrypt -s keys.json -p keys.json -c enc.json

# Generate keys, sign, verify
k-mosaic-cli sign keygen -l 128 -o sign.json
k-mosaic-cli sign sign -s sign.json -p sign.json -m "Document" -o sig.json
k-mosaic-cli sign verify -p sign.json -g sig.json
```

## Quick Reference (Cheat Sheet)

| Task                  | Command                                                                     |
| --------------------- | --------------------------------------------------------------------------- |
| Check version         | `k-mosaic-cli version`                                                      |
| Generate KEM keys     | `k-mosaic-cli kem keygen -l 128 -o keys.json`                               |
| Encrypt message       | `k-mosaic-cli kem encrypt -p keys.json -m "text" -o enc.json`               |
| Encrypt file          | `k-mosaic-cli kem encrypt -p keys.json -i file.txt -o enc.json`             |
| Decrypt message       | `k-mosaic-cli kem decrypt -s keys.json -p keys.json -c enc.json -o out.txt` |
| Generate signing keys | `k-mosaic-cli sign keygen -l 128 -o sign.json`                              |
| Sign message          | `k-mosaic-cli sign sign -s sign.json -p sign.json -m "text" -o sig.json`    |
| Sign file             | `k-mosaic-cli sign sign -s sign.json -p sign.json -i file.txt -o sig.json`  |
| Verify signature      | `k-mosaic-cli sign verify -p sign.json -g sig.json`                         |
| Run benchmark         | `k-mosaic-cli benchmark -l 128 -n 10`                                       |
| Extract public key    | `jq '{public_key, security_level}' keys.json > pub.json`                    |

## Table of Contents

- [Requirements](#requirements)
- [Installation Methods](#installation-methods)
  - [Install with Bun](#install-with-bun)
  - [Install with npm](#install-with-npm)
  - [Run from Source](#run-from-source)
- [Quick Start](#quick-start)
- [Commands Reference](#commands-reference)
  - [KEM Operations](#kem-operations)
  - [Signature Operations](#signature-operations)
  - [Benchmarking](#benchmarking)
- [Usage Examples](#usage-examples)
- [File Formats](#file-formats)
- [Security Considerations](#security-considerations)

## Requirements

- **Bun 1.0 or later** - Required runtime (the CLI is written for Bun)
- **Operating Systems**: macOS, Linux, Windows (with Bun support)
- **Optional**: Node.js 18+ (if you want to use the library directly, though CLI requires Bun)

## Installation Methods

### Install with Bun

The recommended and fastest installation method:

```bash
# Install globally (recommended)
bun install -g k-mosaic

# Verify installation
k-mosaic-cli version
```

Make sure Bun is installed. If not:

```bash
# Install Bun (macOS/Linux)
curl -fsSL https://bun.sh/install | bash

# Or with npm
npm install -g bun
```

### Install with npm

You can also install via npm, but you'll need Bun to run the CLI:

```bash
# Install the package
npm install -g k-mosaic

# Or install locally
npm install k-mosaic

# Run via npx (if installed locally)
npx k-mosaic-cli version
```

### Run from Source

1. **Clone the repository:**

```bash
git clone https://github.com/BackendStack21/k-mosaic.git
cd k-mosaic/k-mosaic-node
```

2. **Install dependencies:**

```bash
bun install
```

3. **Run the CLI directly:**

```bash
bun src/k-mosaic-cli.ts version

# Or make it executable
chmod +x k-mosaic-cli.ts
./src/k-mosaic-cli.ts version
```

4. **Create a symlink (optional):**

```bash
# Create symlink to run from anywhere
ln -s $(pwd)/src/k-mosaic-cli.ts /usr/local/bin/k-mosaic-cli
```

### Uninstall

```bash
# If installed via bun globally
bun pm remove -g k-mosaic

# If installed via npm globally
npm uninstall -g k-mosaic

# If installed locally
cd /path/to/project
npm uninstall k-mosaic

# If symlinked
rm /usr/local/bin/k-mosaic-cli
```

## Quick Start

### Verify Installation

```bash
# Check the installed version
k-mosaic-cli version
# Output: kMOSAIC CLI version 1.0.1
```

### Understanding Keys in kMOSAIC

**Important Concepts:**

- A **key pair** contains BOTH a public key and a secret (private) key
- The **public key** can be shared with anyone - use it to encrypt or verify signatures
- The **secret key** must be kept private - use it to decrypt or sign messages
- When you generate keys with `keygen`, you get ONE file containing BOTH keys
- For real-world use, you'll need to split and distribute keys appropriately

### Generate Keys and Encrypt a Message

```bash
# 1. Generate a KEM key pair (this creates ONE file with BOTH keys)
k-mosaic-cli kem keygen --level 128 --output my-keypair.json

# IMPORTANT: my-keypair.json now contains BOTH your public_key AND secret_key
# For security, you should extract the public key to share with others (see "Working with Keys" below)

# 2. Encrypt a message using the keypair file
# Note: Encryption only uses the public key, but the CLI accepts the full keypair file
k-mosaic-cli kem encrypt --public-key my-keypair.json --message "Hello, quantum-safe world!" --output encrypted.json

# 3. Decrypt the message using the same keypair file
# Note: Decryption requires BOTH the secret key and public key
k-mosaic-cli kem decrypt --secret-key my-keypair.json --public-key my-keypair.json --ciphertext encrypted.json
```

### Sign and Verify a Document

```bash
# 1. Generate a signature key pair (ONE file with BOTH keys)
k-mosaic-cli sign keygen --level 128 --output my-signkeys.json

# 2. Sign a message (requires the secret key from the keypair)
k-mosaic-cli sign sign --secret-key my-signkeys.json --public-key my-signkeys.json --message "Important document" --output signature.json

# 3. Verify the signature (only needs the public key)
k-mosaic-cli sign verify --public-key my-signkeys.json --signature signature.json
```

## Commands Reference

### Understanding Key Files

**Key Pair File Structure:**
When you generate keys with `keygen`, you get a JSON file containing:

- `public_key`: Safe to share - used for encryption and signature verification
- `secret_key`: Keep private - used for decryption and signing
- `security_level`: The security level used (MOS-128 or MOS-256)
- `created_at`: Timestamp of key generation

**Using Keys in Commands:**

- When a command needs `--public-key`, you can pass the full keypair file (it will extract the public key)
- When a command needs `--secret-key`, you can pass the full keypair file (it will extract the secret key)
- For better security practices, see "Working with Keys" section below

### Global Options

| Option     | Short | Description                        |
| ---------- | ----- | ---------------------------------- |
| `--level`  | `-l`  | Security level: 128 or 256 (default: 128) |
| `--output` | `-o`  | Output file path (default: stdout) |

### KEM Operations

#### Generate Key Pair

```bash
k-mosaic-cli kem keygen [OPTIONS]
```

Generates a new KEM (Key Encapsulation Mechanism) key pair.

**What it does:**

- Creates ONE JSON file containing BOTH your public and secret keys
- The public key can be shared with others who want to send you encrypted messages
- The secret key must be kept private - it's needed to decrypt messages

**Security Levels:**

- `--level 128`: Provides 128-bit post-quantum security (faster, smaller keys)
- `--level 256`: Provides 256-bit post-quantum security (slower, larger keys)

**Example:**

```bash
# Generate a keypair with 128-bit security
k-mosaic-cli kem keygen --level 128 --output my-kem-keypair.json

# The output file contains:
# {
#   "security_level": "MOS-128",
#   "public_key": "base64-encoded-data...",
#   "secret_key": "base64-encoded-data...",
#   "created_at": "2025-12-30T10:30:00Z"
# }
```

**Next Steps After Key Generation:**

- Keep the keypair file secure with `chmod 600 my-kem-keypair.json`
- To share your public key, see "Working with Keys" section below
- Back up your keypair file in a secure location

#### Encrypt

```bash
k-mosaic-cli kem encrypt --public-key <file> [--message <text> | --input <file>] [OPTIONS]
```

Encrypts a message using hybrid encryption (KEM + symmetric encryption).

**What it does:**

- Takes a message and the recipient's public key
- Produces encrypted data that ONLY the recipient can decrypt (using their secret key)
- Uses quantum-resistant encryption

**Who needs what:**

- **You need:** The recipient's public key
- **Recipient needs:** Their own secret key to decrypt

**Options:**

- `--public-key`, `-p`: Path to recipient's public key (can be full keypair file or just public key)
- `--message`, `-m`: Text message to encrypt
- `--input`, `-i`: File to encrypt (for larger data)

**Examples:**

```bash
# Encrypt a text message for someone
k-mosaic-cli kem encrypt --public-key recipient-keypair.json --message "Secret message" --output encrypted.json

# Encrypt a file
k-mosaic-cli kem encrypt --public-key recipient-keypair.json --input document.txt --output encrypted.json

# Encrypt from stdin (pipe data)
echo "Secret data" | k-mosaic-cli kem encrypt --public-key recipient-keypair.json --output encrypted.json
```

**Real-world scenario:**

```bash
# Alice wants to send an encrypted message to Bob
# 1. Bob shares his public key (bob-keypair.json) with Alice
# 2. Alice encrypts her message using Bob's public key
k-mosaic-cli kem encrypt --public-key bob-keypair.json --message "Hi Bob!" --output for-bob.json
# 3. Alice sends for-bob.json to Bob
# 4. Only Bob can decrypt it using his secret key
```

#### Decrypt

```bash
k-mosaic-cli kem decrypt --secret-key <file> --public-key <file> --ciphertext <file> [OPTIONS]
```

Decrypts an encrypted message.

**What it does:**

- Takes encrypted data and your secret key
- Recovers the original message
- Only works if you have the correct secret key

**Who needs what:**

- **You need:** Your own secret key AND public key, plus the encrypted message
- **Note:** You can use your keypair file for both `--secret-key` and `--public-key`

**Options:**

- `--secret-key`, `-s`: Your secret key (can be full keypair file)
- `--public-key`, `-p`: Your public key (can be same keypair file)
- `--ciphertext`, `-c`: The encrypted message file

**Example:**

```bash
# Decrypt a message sent to you
k-mosaic-cli kem decrypt \
  --secret-key my-keypair.json \
  --public-key my-keypair.json \
  --ciphertext encrypted.json \
  --output decrypted.txt

# If you receive encrypted.json, you need YOUR keypair to decrypt it
```

**Real-world scenario:**

```bash
# Bob receives an encrypted file (for-bob.json) from Alice
# Bob uses his own keypair to decrypt it
k-mosaic-cli kem decrypt \
  --secret-key bob-keypair.json \
  --public-key bob-keypair.json \
  --ciphertext for-bob.json
# Output: "Hi Bob!" (the original message from Alice)
```

### Signature Operations

#### Generate Signature Key Pair

```bash
k-mosaic-cli sign keygen [OPTIONS]
```

Generates a new signature key pair.

**What it does:**

- Creates ONE JSON file containing BOTH your public and secret signing keys
- The secret key is used to sign documents/messages (proves it came from you)
- The public key is used by others to verify your signatures

**Security Levels:**

- `--level 128`: Provides 128-bit post-quantum security
- `--level 256`: Provides 256-bit post-quantum security

**Example:**

```bash
# Generate signing keys
k-mosaic-cli sign keygen --level 128 --output my-sign-keypair.json

# Output structure:
# {
#   "security_level": "MOS-128",
#   "public_key": "base64-encoded-data...",
#   "secret_key": "base64-encoded-data...",
#   "created_at": "2025-12-30T10:30:00Z"
# }
```

**Next Steps:**

- Keep the keypair file secure: `chmod 600 my-sign-keypair.json`
- Share only the public key portion with people who need to verify your signatures
- Never share the secret key - it's like your digital signature pen!

#### Sign

```bash
k-mosaic-cli sign sign --secret-key <file> --public-key <file> [--message <text> | --input <file>] [OPTIONS]
```

Signs a message to prove it came from you.

**What it does:**

- Takes your message and your secret key
- Creates a digital signature that proves YOU wrote/approved the message
- Others can verify the signature using your public key

**Who needs what:**

- **You need:** Your secret key to create the signature
- **Others need:** Your public key to verify the signature

**Options:**

- `--secret-key`, `-s`: Your secret key (can be full keypair file)
- `--public-key`, `-p`: Your public key (can be same keypair file)
- `--message`, `-m`: Text message to sign
- `--input`, `-i`: File to sign

**Examples:**

```bash
# Sign a text message
k-mosaic-cli sign sign \
  --secret-key my-sign-keypair.json \
  --public-key my-sign-keypair.json \
  --message "I approve this transaction" \
  --output my-signature.json

# Sign a document file
k-mosaic-cli sign sign \
  --secret-key my-sign-keypair.json \
  --public-key my-sign-keypair.json \
  --input contract.pdf \
  --output contract-signature.json
```

**Real-world scenario:**

```bash
# Alice wants to sign a document so Bob knows it's authentic
# 1. Alice signs the document with her secret key
k-mosaic-cli sign sign \
  --secret-key alice-keypair.json \
  --public-key alice-keypair.json \
  --input document.txt \
  --output document-signature.json
# 2. Alice sends both document.txt and document-signature.json to Bob
# 3. Alice also shares her public key with Bob (alice-public.json)
# 4. Bob can verify it's really from Alice (see "Verify" below)
```

#### Verify

```bash
k-mosaic-cli sign verify --public-key <file> --signature <file> [--message <text> | --input <file>] [OPTIONS]
```

Verifies that a signature is authentic.

**What it does:**

- Checks if a signature was created by the person who owns the public key
- Confirms the message hasn't been tampered with
- Returns success (exit code 0) if valid, failure (exit code 1) if invalid

**Who needs what:**

- **You need:** The signer's public key, the signature file, and the original message
- **Note:** You DON'T need the signer's secret key (that's the point!)

**Options:**

- `--public-key`, `-p`: The signer's public key (can be full keypair file)
- `--signature`, `-g`: The signature file to verify
- `--message`, `-m`: Original message (if not in signature file)
- `--input`, `-i`: Original file that was signed

**Examples:**

```bash
# Verify a signature (message included in signature file)
k-mosaic-cli sign verify \
  --public-key alice-keypair.json \
  --signature document-signature.json

# Verify with explicit message
k-mosaic-cli sign verify \
  --public-key alice-keypair.json \
  --message "I approve this transaction" \
  --signature my-signature.json

# Verify a signed file
k-mosaic-cli sign verify \
  --public-key alice-keypair.json \
  --input document.txt \
  --signature document-signature.json
```

**Exit Codes:**

- `0`: Signature is valid ✓
- `1`: Signature is invalid or error occurred ✗

**Real-world scenario:**

```bash
# Bob receives a document and signature from Alice
# Bob uses Alice's public key to verify the signature
k-mosaic-cli sign verify \
  --public-key alice-public.json \
  --input document.txt \
  --signature document-signature.json

# If valid, Bob knows:
# 1. The document really came from Alice (authentication)
# 2. The document hasn't been modified (integrity)
```

### Benchmarking

```bash
k-mosaic-cli benchmark [OPTIONS]
```

Runs performance benchmarks for all cryptographic operations.

**Options:**

- `--iterations`, `-n`: Number of iterations (default: 10)
- `--level`, `-l`: Security level (default: 128)

**Example:**

```bash
k-mosaic-cli benchmark --level 128 --iterations 20
```

**Sample Output:**

```
╔══════════════════════════════════════════════════════════════════════════╗
║              kMOSAIC vs Node.js Crypto Benchmark                          ║
║  Post-Quantum (kMOSAIC) vs Classical (X25519/Ed25519)                     ║
╚══════════════════════════════════════════════════════════════════════════╝

📊 KEM Key Generation
────────────────────────────────────────────────────────
  kMOSAIC:      19.289 ms/op |     51.8 ops/sec
  X25519:       0.016 ms/op |  63441.7 ops/sec
  Comparison: Node.js is 1223.7x faster

📊 KEM Encapsulation
────────────────────────────────────────────────────────
  kMOSAIC:       0.538 ms/op |   1860.0 ops/sec
  X25519:       0.043 ms/op |  23529.4 ops/sec
  Comparison: Node.js is 12.7x faster

📊 KEM Decapsulation
────────────────────────────────────────────────────────
  kMOSAIC:       4.220 ms/op |    237.0 ops/sec
  X25519:       0.030 ms/op |  32811.1 ops/sec
  Comparison: Node.js is 138.5x faster

📊 Signature Key Generation
────────────────────────────────────────────────────────
  kMOSAIC:       19.204 ms/op |     52.1 ops/sec
  Ed25519:       0.012 ms/op |  80971.7 ops/sec
  Comparison: Node.js is 1555.0x faster

📊 Signing
────────────────────────────────────────────────────────
  kMOSAIC:        0.040 ms/op |  25049.6 ops/sec
  Ed25519:       0.011 ms/op |  87190.3 ops/sec
  Comparison: Node.js is 3.5x faster

📊 Verification
────────────────────────────────────────────────────────
  kMOSAIC:        1.417 ms/op |    705.9 ops/sec
  Ed25519:       0.033 ms/op |  30607.6 ops/sec
  Comparison: Node.js is 43.4x faster

════════════════════════════════════════════════════════════════════════════

📦 KEY & SIGNATURE SIZES

┌─────────────────────┬─────────────┬─────────────┐
│ Component           │ kMOSAIC      │ Classical   │
├─────────────────────┼─────────────┼─────────────┤
│ KEM Public Key      │ ~  7500 B │       44 B │
│ KEM Ciphertext      │ ~  7800 B │       76 B │
│ Signature           │ ~  7400 B │       64 B │
└─────────────────────┴─────────────┴─────────────┘

💡 NOTES:
  • kMOSAIC provides post-quantum security (resistant to quantum attacks)
  • X25519/Ed25519 are classical algorithms (vulnerable to quantum computers)
  • kMOSAIC combines 3 independent hard problems for defense-in-depth
  • Size/speed tradeoff is typical for post-quantum cryptography

🛡️  SECURITY MITIGATIONS (kMOSAIC):
  • Native timingSafeEqual for constant-time comparisons
  • Native SHAKE256/SHA3-256 via Node.js crypto
  • Timing attack padding (25-50ms minimum for signatures)
  • Entropy validation for seed generation
  • Implicit rejection in KEM decapsulation
```

## Usage Examples

### Working with Keys (For Beginners)

#### Understanding Key Management

When you generate keys, you get ONE file with BOTH keys. Here's how to manage them properly:

**Step 1: Generate Your Keypair**

```bash
# Generate your keypair (contains both public and secret keys)
k-mosaic-cli kem keygen --level 128 --output my-full-keypair.json

# Secure it immediately!
chmod 600 my-full-keypair.json
```

**Step 2: Extract Public Key to Share with Others**

The CLI doesn't have a built-in key extraction command, but you can manually create public-only files:

```bash
# Using jq (install with: brew install jq on macOS, apt install jq on Linux)
jq '{public_key: .public_key, security_level: .security_level}' my-full-keypair.json > my-public-key.json

# Or manually: copy the JSON and remove the "secret_key" field
```

**Example: Creating a public key file**

```json
// my-public-key.json (SAFE to share)
{
  "security_level": "MOS-128",
  "public_key": "base64-encoded-data..."
}

// my-full-keypair.json (NEVER share - contains secret_key!)
{
  "security_level": "MOS-128",
  "public_key": "base64-encoded-data...",
  "secret_key": "PRIVATE-base64-data...",
  "created_at": "2025-12-30T10:30:00Z"
}
```

**Step 3: Share Your Public Key**

```bash
# You can now safely share my-public-key.json via:
# - Email
# - File sharing service
# - Public key server
# - Your website

# NEVER share my-full-keypair.json (it contains your secret key!)
```

#### Quick Reference: Which Key Do I Use?

| You Want To...                    | You Need...                  | They Need...     |
| --------------------------------- | ---------------------------- | ---------------- |
| Receive encrypted messages        | Share your public key        | Your public key  |
| Decrypt messages sent to you      | Your secret key + public key | -                |
| Send encrypted message to someone | Their public key             | Their secret key |
| Sign a document                   | Your secret key + public key | -                |
| Prove a document is yours         | Share your public key        | Your public key  |
| Verify someone else's signature   | Their public key             | -                |

#### Practical Key Workflow

```bash
# === ALICE'S SIDE ===
# 1. Alice generates her keypair
k-mosaic-cli kem keygen --level 128 --output alice-keypair.json

# 2. Alice extracts her public key to share
jq '{public_key: .public_key, security_level: .security_level}' alice-keypair.json > alice-public.json

# 3. Alice shares alice-public.json with Bob (via email, etc.)

# === BOB'S SIDE ===
# 4. Bob receives alice-public.json and wants to send her an encrypted message
k-mosaic-cli kem encrypt \
  --public-key alice-public.json \
  --message "Hi Alice! This is private." \
  --output message-for-alice.json

# 5. Bob sends message-for-alice.json back to Alice

# === ALICE'S SIDE AGAIN ===
# 6. Alice receives the encrypted message and decrypts it
k-mosaic-cli kem decrypt \
  --secret-key alice-keypair.json \
  --public-key alice-keypair.json \
  --ciphertext message-for-alice.json

# Output: "Hi Alice! This is private."
```

### Complete Encryption Workflow

```bash
#!/usr/bin/env bash
# Real-world encryption scenario

# === RECIPIENT (Bob) ===
# Bob generates his keypair
k-mosaic-cli kem keygen --level 128 --output bob-keypair.json
chmod 600 bob-keypair.json

# Bob creates a public key file to share
jq '{public_key: .public_key, security_level: .security_level}' bob-keypair.json > bob-public.json

# Bob shares bob-public.json with potential senders

# === SENDER (Alice) ===
# Alice receives bob-public.json and encrypts a message for Bob
k-mosaic-cli kem encrypt \
  --public-key bob-public.json \
  --message "This is a secret message for Bob!" \
  --output encrypted-for-bob.json

# Alice sends encrypted-for-bob.json to Bob

# === RECIPIENT (Bob) ===
# Bob receives and decrypts the message using his full keypair
k-mosaic-cli kem decrypt \
  --secret-key bob-keypair.json \
  --public-key bob-keypair.json \
  --ciphertext encrypted-for-bob.json

# Output: "This is a secret message for Bob!"
```

### Complete Signature Workflow

```bash
#!/usr/bin/env bash
# Real-world signature scenario

# === SIGNER (Alice) ===
# Alice generates her signing keypair
k-mosaic-cli sign keygen --level 128 --output alice-sign-keypair.json
chmod 600 alice-sign-keypair.json

# Alice creates a public key file to share (for verification)
jq '{public_key: .public_key, security_level: .security_level}' alice-sign-keypair.json > alice-sign-public.json

# Alice signs an important document
k-mosaic-cli sign sign \
  --secret-key alice-sign-keypair.json \
  --public-key alice-sign-keypair.json \
  --input important-contract.txt \
  --output contract-signature.json

# Alice sends THREE files to Bob:
# 1. important-contract.txt (the document)
# 2. contract-signature.json (the signature)
# 3. alice-sign-public.json (her public key for verification)

# === VERIFIER (Bob) ===
# Bob receives all three files and verifies the signature
k-mosaic-cli sign verify \
  --public-key alice-sign-public.json \
  --input important-contract.txt \
  --signature contract-signature.json

# Check the result
if [ $? -eq 0 ]; then
  echo "✓ SUCCESS: Signature is valid!"
  echo "  - Document is authentic (really from Alice)"
  echo "  - Document hasn't been modified"
else
  echo "✗ FAILURE: Signature is INVALID!"
  echo "  - Document may be fake or tampered with"
  echo "  - DO NOT trust this document"
fi
```


## File Formats

### Key Pair File (JSON)

```json
{
  "security_level": "MOS-128",
  "public_key": "base64-encoded-public-key...",
  "secret_key": "base64-encoded-secret-key...",
  "created_at": "2024-12-30T10:30:00Z"
}
```

### Encrypted Message File (JSON)

```json
{
  "ciphertext": "base64-encoded-ciphertext..."
}
```

### Signature File (JSON)

```json
{
  "message": "base64-encoded-message...",
  "signature": "base64-encoded-signature..."
}
```

## Security Considerations

> ⚠️ **WARNING**: kMOSAIC is an experimental cryptographic construction that has NOT been formally verified by academic peer review. DO NOT use in production systems protecting sensitive data.

### Best Practices

#### 1. Secure Key Storage

**Protect Your Keypair Files:**

```bash
# Set restrictive permissions (owner read/write only)
chmod 600 my-keypair.json

# Store in a secure location
mkdir -p ~/.kmosaic/keys
mv my-keypair.json ~/.kmosaic/keys/
chmod 700 ~/.kmosaic/keys
```

**What to protect:**

- ✗ **NEVER share** files containing `secret_key`
- ✓ **Safe to share** files with only `public_key`
- ✗ **NEVER commit** keypair files to Git/version control
- ✓ **DO backup** keypair files securely (encrypted backups)

#### 2. Key Distribution

**Sharing Public Keys (SAFE):**

```bash
# Create public-only file from full keypair
jq '{public_key: .public_key, security_level: .security_level}' my-keypair.json > my-public.json

# Now my-public.json is safe to share via:
# - Email
# - Public website
# - Cloud storage
# - Key servers
```

**Protecting Secret Keys (CRITICAL):**

- Store offline or in encrypted storage
- Use hardware security modules (HSM) for high-value keys
- Never send via unencrypted channels
- Create encrypted backups: `gpg -c my-keypair.json`

#### 3. Key Backup and Recovery

```bash
# Create encrypted backup
gpg --symmetric --cipher-algo AES256 my-keypair.json
# This creates: my-keypair.json.gpg (encrypted backup)

# Store encrypted backup in multiple locations:
# - External encrypted drive
# - Encrypted cloud storage
# - Safe deposit box (on USB drive)

# To restore from backup:
gpg --decrypt my-keypair.json.gpg > my-keypair.json
chmod 600 my-keypair.json
```

#### 4. Security Levels

**Choose the right security level:**

- **MOS-128** (128-bit post-quantum security)

  - Recommended for most uses
  - Faster operations
  - Smaller key sizes (~2-3 KB)
  - Good for: Email encryption, file encryption, routine signatures

- **MOS-256** (256-bit post-quantum security)
  - For higher security requirements
  - Slower operations
  - Larger key sizes (~4-6 KB)
  - Good for: Long-term secrets, high-value transactions, critical infrastructure

```bash
# Generate keys with appropriate security level
k-mosaic-cli kem keygen --level 128 --output standard-keypair.json
k-mosaic-cli kem keygen --level 256 --output high-security-keypair.json
```

**Approximate Key and Data Sizes:**

| Level   | Public Key | Secret Key | Ciphertext | Signature |
| ------- | ---------- | ---------- | ---------- | --------- |
| MOS-128 | ~2.5 KB    | ~3.0 KB    | ~2.5 KB    | ~2.5 KB   |
| MOS-256 | ~5.0 KB    | ~6.0 KB    | ~5.0 KB    | ~5.0 KB   |

_Note: Actual sizes may vary slightly. Use `stat -f%z filename.json` (macOS) or `stat -c%s filename.json` (Linux) to check exact file sizes._

#### 5. Key Rotation

Regularly rotate keys, especially for long-lived systems:

```bash
# Rotation schedule recommendations:
# - Encryption keys: Every 1-2 years
# - Signing keys: Every 2-3 years
# - Compromised keys: IMMEDIATELY

# Generate new keypair
k-mosaic-cli kem keygen --level 128 --output new-keypair-2026.json

# Notify correspondents of new public key
# Securely delete old keypair after transition period
shred -u old-keypair.json  # Linux
srm old-keypair.json       # macOS (if installed)
```

#### 6. Verification Best Practices

**Always verify signatures:**

```bash
# Before trusting a signed document, verify it
k-mosaic-cli sign verify \
  --public-key sender-public.json \
  --input document.txt \
  --signature document-sig.json

# Only trust if exit code is 0 (valid)
if [ $? -eq 0 ]; then
  echo "Document verified - safe to trust"
else
  echo "Verification FAILED - do not trust"
  exit 1
fi
```

#### 7. Common Security Mistakes to Avoid

❌ **DON'T:**

- Share your full keypair file (contains secret key)
- Store secret keys in version control (Git, SVN, etc.)
- Send secret keys via unencrypted email
- Use weak file permissions (644, 755) on keypair files
- Reuse keys across different security levels
- Store unencrypted backups in cloud storage

✅ **DO:**

- Extract and share only public keys
- Use strong file permissions (600 for keypairs)
- Create encrypted backups
- Rotate keys periodically
- Verify signatures before trusting content
- Store secret keys offline when possible

### Threat Model

kMOSAIC provides security against:

- Classical computing attacks
- Quantum computing attacks (post-quantum security)
- Single point-of-failure through defense-in-depth (three independent hard problems)

### JavaScript/TypeScript Security Limitations

**Important considerations for the JavaScript implementation:**

- **No constant-time guarantees**: JavaScript engines use JIT compilation and garbage collection, making it impossible to guarantee constant-time execution
- **Memory zeroization is best-effort**: The garbage collector may leave copies of sensitive data in memory
- **Timing side-channels**: JIT optimization and GC pauses can leak timing information
- **Use in server environments**: Best suited for server-side applications where timing attacks are harder to mount

For maximum security in production environments, consider using the Go implementation which provides better control over memory and timing.

## Troubleshooting

### Common Issues

1. **"command not found" or "bun: command not found"**

   - Ensure Bun is installed: `curl -fsSL https://bun.sh/install | bash`
   - Verify installation: `bun --version`
   - Ensure the CLI is installed: `bun install -g k-mosaic`

2. **"Permission denied" when running the CLI**

   - Make the script executable: `chmod +x src/k-mosaic-cli.ts`
   - Or run with: `bun src/k-mosaic-cli.ts`

3. **"invalid key format"**

   - Ensure you're using the correct file format (JSON with base64-encoded keys)
   - Verify the file wasn't corrupted during transfer
   - Check that the file contains both `public_key` and `security_level` fields

4. **"signature invalid"**
   - Verify you're using the correct public key
   - Ensure the message hasn't been modified
   - Check that the signature file format is correct

### Frequently Asked Questions (FAQ)

#### Q: How do I know which file is my public key vs secret key?

**A:** When you run `keygen`, you get ONE file with BOTH keys. Look inside:

```json
{
  "public_key": "...", // Safe to share
  "secret_key": "...", // NEVER share
  "security_level": "MOS-128"
}
```

To create a public-only file: `jq '{public_key: .public_key, security_level: .security_level}' keypair.json > public.json`

#### Q: Can I use the same keypair for both encryption and signing?

**A:** No. You need separate keypairs:

- Use `kem keygen` for encryption/decryption keys
- Use `sign keygen` for signing/verification keys
- They serve different cryptographic purposes

#### Q: How do I send my public key to someone?

**A:**

1. Extract public key: `jq '{public_key: .public_key, security_level: .security_level}' my-keypair.json > my-public.json`
2. Send `my-public.json` via email, file sharing, etc.
3. NEVER send the original keypair file (it contains your secret key)

#### Q: Someone sent me their keypair file. What should I do?

**A:** Tell them to STOP! They should never send their full keypair (it contains their secret key).
Ask them to:

1. Extract public key: `jq '{public_key: .public_key}' keypair.json > public.json`
2. Send only `public.json`
3. Immediately generate a NEW keypair (the old one is compromised)

#### Q: Can I extract my secret key separately?

**A:** Yes, but there's usually no need. If you must:

```bash
jq '{secret_key: .secret_key, security_level: .security_level}' keypair.json > secret.json
chmod 600 secret.json  # Protect it!
```

#### Q: I lost my secret key. Can I recover it from my public key?

**A:** No. That's the whole point of public-key cryptography! The secret key cannot be derived from the public key.

- If you lose your secret key, you cannot decrypt messages sent to you
- You'll need to generate a new keypair and distribute the new public key
- This is why backups are critical

#### Q: How do I split a keypair file into separate public and secret files?

**A:**

```bash
# Extract public key (safe to share)
jq '{public_key: .public_key, security_level: .security_level}' keypair.json > public.json

# Extract secret key (keep private)
jq '{secret_key: .secret_key, security_level: .security_level}' keypair.json > secret.json
chmod 600 secret.json

# Original keypair.json can be kept as backup
```

#### Q: Why do decrypt and sign need BOTH --public-key and --secret-key?

**A:** The kMOSAIC algorithm requires both keys for these operations:

- **Decrypt**: Uses secret key + public key together
- **Sign**: Uses secret key + public key together
- Tip: You can pass the same keypair file to both parameters: `--secret-key keypair.json --public-key keypair.json`

#### Q: Can quantum computers break kMOSAIC?

**A:** kMOSAIC is designed to be quantum-resistant. It uses three independent hard problems:

- Even if quantum computers break one, the others provide protection
- However, kMOSAIC is experimental and not formally verified
- Don't use it for real secrets yet!

#### Q: What happens if I use the wrong security level?

**A:** Keys from different security levels are incompatible:

- A message encrypted with MOS-128 keys cannot be decrypted with MOS-256 keys
- Always use matching security levels
- Choose one level and stick with it for a given communication channel

#### Q: How do I know if a file is encrypted or just a public key?

**A:** Look at the JSON structure:

```json
// Encrypted message
{"ciphertext": "..."}

// Public key
{"public_key": "...", "security_level": "..."}

// Full keypair
{"public_key": "...", "secret_key": "...", "security_level": "..."}
```

#### Q: Can I use this CLI with Node.js instead of Bun?

**A:** The CLI script uses the Bun shebang (`#!/usr/bin/env bun`) and is optimized for Bun. While the library itself works with Node.js, the CLI requires Bun to run. To use with Node.js:

```bash
# Install the package
npm install k-mosaic

# Use the library programmatically in Node.js
# (see the main README.md for API examples)
```

#### Q: Why is the signature flag `-g` instead of `-s`?

**A:** The `-s` flag is reserved for `--secret-key`, so the signature verification command uses `-g` (for siGnature). Both `--signature` (long form) and `-g` (short form) work.

### Getting Help

```bash
# General help
k-mosaic-cli --help

# Command-specific help
k-mosaic-cli kem --help
k-mosaic-cli sign --help

# Specific subcommand help
k-mosaic-cli kem keygen --help
k-mosaic-cli sign verify --help
```

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Support

For issues and feature requests, please visit: https://github.com/BackendStack21/k-mosaic/issues

## See Also

- [Main README](README.md) - Library overview and JavaScript/TypeScript API
- [Developer Guide](DEVELOPER_GUIDE.md) - The kMOSAIC Book with implementation details
- [White Paper](kMOSAIC_WHITE_PAPER.md) - Theoretical foundations and security analysis
- [Security Report](SECURITY_REPORT.md) - Security audit results
- [Go Implementation](https://github.com/BackendStack21/k-mosaic-go) - Faster Go-based version
