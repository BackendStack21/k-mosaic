# K-MOSAIC Size Quick Reference

Quick lookup table for kMOSAIC cryptographic component sizes.

## At a Glance

```
MOS-128:  823 KB key  |  5.7 KB ciphertext  |  140 B signature
MOS-256:  3.3 MB key  | 10.5 KB ciphertext  |  140 B signature
```

## Complete Size Table

### MOS-128 (128-bit Security)

| Component | Size | Range | Typical Use |
|-----------|------|-------|------------|
| **Public Key** | 823.6 KB | 820-830 KB | Public key exchange, certificate storage |
| **Secret Key** | ~100 KB | - | Local storage only |
| **Ciphertext** | 5.7 KB | 5.6-6.0 KB | Encrypted messages, key encapsulation |
| **Signature** | 140 B | Always 140 B | Digital signatures, authentication |
| **Binding Hash** | 32 B | Always 32 B | Internal (part of public key) |

### MOS-256 (256-bit Security)

| Component | Size | Range | Typical Use |
|-----------|------|-------|------------|
| **Public Key** | 3.33 MB | 3.3-3.4 MB | Public key exchange, certificate storage |
| **Secret Key** | ~400 KB | - | Local storage only |
| **Ciphertext** | 10.5 KB | 10.0-11.0 KB | Encrypted messages, key encapsulation |
| **Signature** | 140 B | Always 140 B | Digital signatures, authentication |
| **Binding Hash** | 32 B | Always 32 B | Internal (part of public key) |

### Classical Cryptography (Reference)

| Algorithm | Public Key | Ciphertext | Signature | Notes |
|-----------|------------|-----------|-----------|-------|
| X25519 | 32 B | 32 B | - | ECDH key exchange |
| Ed25519 | 32 B | - | 64 B | Digital signatures |
| kMOSAIC (MOS-128) | **25,738x** | **178x** | **2.2x** | Larger due to post-quantum security |

## Size Formula

### MOS-128

```
Public Key ≈ (384 × 512 × 4) + 55,000 ≈ 823 KB
           = SLSS(786 KB) + TDD(55 KB) + overhead(~10 KB)

Ciphertext ≈ 1,500 + 1,500 + 2,300 ≈ 5.7 KB
           = SLSS(c1) + TDD(c2) + EGRW(c3) + NIZK proof

Signature = 32 + 32 + 64 + 12 = 140 B
          = commitment + challenge + response + headers
```

### MOS-256

```
Public Key ≈ (768 × 1024 × 4) + 186,000 ≈ 3.33 MB
           = SLSS(3.1 MB) + TDD(186 KB) + overhead(~20 KB)

Ciphertext ≈ 2,500 + 3,500 + 4,500 ≈ 10.5 KB
           = SLSS(c1) + TDD(c2) + EGRW(c3) + NIZK proof

Signature = 32 + 32 + 64 + 12 = 140 B
          = commitment + challenge + response + headers (same as MOS-128)
```

## Storage Requirements

### Per User

| Security Level | Public Key | Secret Key | Total |
|---|---|---|---|
| MOS-128 | 824 KB | 100 KB | ~1 MB |
| MOS-256 | 3.3 MB | 400 KB | ~3.7 MB |
| Classical | 32 B | 32 B | ~64 B |

### For 1 Million Users

| Security Level | Public Keys | Total |
|---|---|---|
| MOS-128 | 824 GB | ~825 GB |
| MOS-256 | 3.3 TB | ~3.3 TB |
| Classical | 32 GB | ~32 GB |

## Network Transmission

Typical packet sizes for different operations:

### Key Exchange

| Operation | Size | Notes |
|-----------|------|-------|
| Send public key (MOS-128) | 824 KB | One-time per peer |
| Send public key (MOS-256) | 3.3 MB | One-time per peer |
| TLS certificate chain | 2-10 KB | Typical modern certificate |

### Message Authentication

| Operation | Size | Notes |
|-----------|------|-------|
| Sign + Signature | Original + 140 B | Attached to messages |
| Verify operation | 140 B input | Constant time |

### Encryption

| Operation | Size | Notes |
|-----------|------|-------|
| Encapsulate (MOS-128) | 5.7 KB | Ephemeral ciphertext |
| Encapsulate (MOS-256) | 10.5 KB | Ephemeral ciphertext |
| Typical AES message | 1-100 KB | Application dependent |

## Bandwidth Impact

### For Public Key Infrastructure

| Scenario | MOS-128 | MOS-256 | Classical | Impact |
|----------|---------|---------|-----------|--------|
| Upload new public key | 824 KB | 3.3 MB | 32 B | +25,000x |
| Download peer's key | 824 KB | 3.3 MB | 32 B | +25,000x |
| Sync key directory (1M keys) | 825 GB | 3.3 TB | 32 GB | +25,000x |

### For Message Signing

| Scenario | MOS-128 | MOS-256 | Classical | Impact |
|----------|---------|---------|-----------|--------|
| Sign message | Negligible | Negligible | Negligible | 1x |
| Send signed message | Msg + 140 B | Msg + 140 B | Msg + 64 B | +2.2x |
| Verify signature | Negligible | Negligible | Negligible | 1x |

## Performance Characteristics

### Generation Speed

| Operation | Time | Security Level |
|-----------|------|---|
| Generate public key | 1-10 ms | MOS-128 |
| Generate public key | 10-50 ms | MOS-256 |
| Generate signature | 1-5 ms | Both |

### Validation Speed

| Operation | Time | Security Level |
|-----------|------|---|
| Verify signature | 0.5-2 ms | Both |
| Verify ciphertext | 5-20 ms | Both |

## Practical Implications

### When Size Matters

✓ **Use Cases Favoring Classical:**
- IoT devices with limited storage
- Resource-constrained embedded systems
- High-frequency transaction systems
- Bandwidth-limited networks

✓ **Use Cases Favoring kMOSAIC:**
- Long-term data protection (harvest-now-decrypt-later attacks)
- Government/military communications
- Financial systems with long-term security requirements
- Systems expecting quantum computing threats

### Optimization Strategies

1. **Compress public keys** in transit (gzip: ~30% reduction)
2. **Store secret keys** encrypted on disk
3. **Use key derivation** to avoid storing multiple keys
4. **Batch signatures** for multiple messages
5. **Pair with classical** cryptography for hybrid security

## Implementation Notes

### Serialization Overhead

- Length prefixes: 4 bytes per component
- Domain separators: Included in hash values
- Alignment padding: None (efficient variable-length encoding)

### Determinism

✓ All size values are **deterministic** for a given security level
✓ Same key material always serializes to same size
✓ No random padding or variable-length components

### Validation

Run `bun test test/validate-sizes.test.ts` to verify actual sizes match expectations.

---

**Last Updated:** December 31, 2025
**Test Coverage:** All components validated
**Status:** All tests passing ✓
