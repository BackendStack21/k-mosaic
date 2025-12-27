/**
 * kMOSAIC Type Definitions
 * Post-Quantum Cryptographic Algorithm with Heterogeneous Hardness
 */

// =============================================================================
// Security Levels
// =============================================================================

export enum SecurityLevel {
  MOS_128 = 'MOS-128',
  MOS_256 = 'MOS-256',
}

// =============================================================================
// Parameter Sets
// =============================================================================

export interface SLSSParams {
  n: number // Lattice dimension
  m: number // Number of equations
  q: number // Prime modulus
  w: number // Sparsity weight
  sigma: number // Error standard deviation
}

export interface TDDParams {
  n: number // Tensor dimension
  r: number // Tensor rank
  q: number // Modulus
  sigma: number // Noise standard deviation
}

export interface EGRWParams {
  p: number // Prime for SL(2, Z_p)
  k: number // Walk length
}

export interface MOSAICParams {
  level: SecurityLevel
  slss: SLSSParams
  tdd: TDDParams
  egrw: EGRWParams
}

// =============================================================================
// Key Types
// =============================================================================

export interface SLSSPublicKey {
  A: Int32Array // m x n matrix (flattened)
  t: Int32Array // m-vector
}

export interface SLSSSecretKey {
  s: Int8Array // Sparse n-vector in {-1, 0, 1}
}

export interface TDDPublicKey {
  T: Int32Array // n x n x n tensor (flattened)
}

export interface TDDSecretKey {
  factors: {
    a: Int32Array[] // r vectors of dimension n
    b: Int32Array[]
    c: Int32Array[]
  }
}

export interface EGRWPublicKey {
  vStart: SL2Element
  vEnd: SL2Element
}

export interface EGRWSecretKey {
  walk: number[] // Sequence of generator indices
}

export interface SL2Element {
  a: number
  b: number
  c: number
  d: number
}

// =============================================================================
// Composite Keys
// =============================================================================

export interface MOSAICPublicKey {
  slss: SLSSPublicKey
  tdd: TDDPublicKey
  egrw: EGRWPublicKey
  binding: Uint8Array // 32-byte binding hash
  params: MOSAICParams
}

export interface MOSAICSecretKey {
  slss: SLSSSecretKey
  tdd: TDDSecretKey
  egrw: EGRWSecretKey
  seed: Uint8Array // Original seed for implicit rejection
  publicKeyHash: Uint8Array
}

export interface MOSAICKeyPair {
  publicKey: MOSAICPublicKey
  secretKey: MOSAICSecretKey
}

// =============================================================================
// KEM Types
// =============================================================================

export interface SLSSCiphertext {
  u: Int32Array
  v: Int32Array
}

export interface TDDCiphertext {
  data: Int32Array
}

export interface EGRWCiphertext {
  vertex: SL2Element
  commitment: Uint8Array
}

export interface MOSAICCiphertext {
  c1: SLSSCiphertext
  c2: TDDCiphertext
  c3: EGRWCiphertext
  proof: Uint8Array
}

export interface EncapsulationResult {
  sharedSecret: Uint8Array
  ciphertext: MOSAICCiphertext
}

// =============================================================================
// Signature Types
// =============================================================================

export interface SLSSCommitment {
  w: Int32Array
}

export interface TDDCommitment {
  w: Int32Array
}

export interface EGRWCommitment {
  vertex: SL2Element
}

export interface SLSSResponse {
  z: Int32Array
  commitment?: Uint8Array // w1 commitment for verification
}

export interface TDDResponse {
  z: Int32Array
  commitment?: Uint8Array // w2 commitment for verification
}

export interface EGRWResponse {
  combined: number[]
  hints: Uint8Array
}

export interface MOSAICSignature {
  challenge: Uint8Array
  z1: SLSSResponse
  z2: TDDResponse
  z3: EGRWResponse
}

// =============================================================================
// Serialization
// =============================================================================

export interface SerializedPublicKey {
  format: 'raw' | 'pem' | 'der'
  data: Uint8Array
}

export interface SerializedSecretKey {
  format: 'raw' | 'pem' | 'der'
  data: Uint8Array
}

// =============================================================================
// Analysis Types
// =============================================================================

export interface SecurityAnalysis {
  slss: {
    dimension: number
    sparsity: number
    estimatedSecurity: number
  }
  tdd: {
    tensorDim: number
    rank: number
    estimatedSecurity: number
  }
  egrw: {
    graphSize: number
    walkLength: number
    estimatedSecurity: number
  }
  combined: {
    estimatedSecurity: number
    quantumSecurity: number
  }
}
