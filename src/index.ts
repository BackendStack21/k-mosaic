/**
 * kMOSAIC (Multi-Oracle Structured Algebraic Intractability Composition)
 *
 * A novel post-quantum cryptographic library combining three heterogeneous
 * computational hard problems with cryptographic entanglement for defense-in-depth.
 *
 * Core Design Principles:
 * 1. Heterogeneity: Combines Lattice (SLSS), Tensor (TDD), and Graph (EGRW) problems.
 * 2. Entanglement: Components are cryptographically bound; breaking one is insufficient.
 * 3. Defense-in-Depth: Security holds if at least one underlying problem remains hard.
 * 4. Constant-Time: Implementation resists timing and cache side-channel attacks.
 *
 * Modules:
 * - KEM: Key Encapsulation Mechanism (IND-CCA2 secure)
 * - Sign: Digital Signature Scheme (EUF-CMA secure)
 * - Core: Parameter management and type definitions
 * - Utils: Secure randomness, hashing, and constant-time primitives
 *
 * @author k-mosaic
 * @license MIT
 * @version 0.1.0
 */

import { SecurityLevel } from './types.js'

// =============================================================================
// Core Types
// =============================================================================

export { SecurityLevel } from './types.js'
export type {
  MOSAICParams,
  SLSSParams,
  TDDParams,
  EGRWParams,
  MOSAICPublicKey,
  MOSAICSecretKey,
  MOSAICKeyPair,
  MOSAICCiphertext,
  MOSAICSignature,
  EncapsulationResult,
  SLSSPublicKey,
  SLSSSecretKey,
  TDDPublicKey,
  TDDSecretKey,
  EGRWPublicKey,
  EGRWSecretKey,
  SL2Element,
} from './types.js'

// =============================================================================
// Core Parameters
// =============================================================================

export { getParams, validateParams, MOS_128, MOS_256 } from './core/params.js'

// =============================================================================
// KEM (Key Encapsulation Mechanism)
// =============================================================================

export {
  generateKeyPair as kemGenerateKeyPair,
  generateKeyPairFromSeed as kemGenerateKeyPairFromSeed,
  encapsulate,
  encapsulateDeterministic,
  decapsulate,
  encrypt,
  decrypt,
  serializePublicKey,
  serializeCiphertext,
  deserializeCiphertext,
  analyzePublicKey,
} from './kem/index.js'

// =============================================================================
// Digital Signatures
// =============================================================================

export {
  generateKeyPair as signGenerateKeyPair,
  generateKeyPairFromSeed as signGenerateKeyPairFromSeed,
  sign,
  verify,
  serializeSignature,
  deserializeSignature,
} from './sign/index.js'

// =============================================================================
// Utilities
// =============================================================================

export {
  secureRandomBytes,
  sampleGaussianVector,
  randomSparseVector,
  randomVectorZq,
} from './utils/random.js'

export {
  shake256,
  sha3_256,
  hashConcat,
  hashWithDomain,
} from './utils/shake.js'

export {
  constantTimeEqual,
  constantTimeSelect,
  zeroize,
  SecureBuffer,
} from './utils/constant-time.js'

// =============================================================================
// Entanglement & Proofs
// =============================================================================

export {
  secretShare,
  secretReconstruct,
  computeBinding,
  createCommitment,
  verifyCommitment,
  generateNIZKProof,
  verifyNIZKProof,
} from './entanglement/index.js'

// =============================================================================
// Individual Problem Implementations (Advanced Usage)
// =============================================================================

export {
  slssKeyGen,
  slssEncrypt,
  slssDecrypt,
  slssSerializePublicKey,
  slssDeserializePublicKey,
} from './problems/slss/index.js'

export {
  tddKeyGen,
  tddEncrypt,
  tddDecrypt,
  tddSerializePublicKey,
  tddDeserializePublicKey,
} from './problems/tdd/index.js'

export {
  egrwKeyGen,
  egrwEncrypt,
  egrwDecrypt,
  egrwSerializePublicKey,
  egrwDeserializePublicKey,
  bytesToSl2,
  sl2ToBytes,
} from './problems/egrw/index.js'

// =============================================================================
// Convenience API
// =============================================================================

/**
 * kMOSAIC cryptographic library
 *
 * A novel post-quantum scheme combining:
 * - SLSS: Sparse Lattice Subset Sum (combines subset sum with lattice hardness)
 * - TDD: Tensor Decomposition Distinguishing (multilinear algebra hard problem)
 * - EGRW: Expander Graph Random Walk (number-theoretic path problem)
 *
 * These problems are entangled cryptographically, requiring an attacker to
 * break ALL THREE simultaneously to compromise the system.
 */
const crypto = {
  // KEM operations
  kem: {
    generateKeyPair: () =>
      import('./kem/index.js').then((m) => m.generateKeyPair()),
    encapsulate: (pk: import('./types.js').MOSAICPublicKey) =>
      import('./kem/index.js').then((m) => m.encapsulate(pk)),
    decapsulate: (
      ct: import('./types.js').MOSAICCiphertext,
      sk: import('./types.js').MOSAICSecretKey,
      pk: import('./types.js').MOSAICPublicKey,
    ) => import('./kem/index.js').then((m) => m.decapsulate(ct, sk, pk)),
    encrypt: (message: Uint8Array, pk: import('./types.js').MOSAICPublicKey) =>
      import('./kem/index.js').then((m) => m.encrypt(message, pk)),
    decrypt: (
      ciphertext: Uint8Array,
      sk: import('./types.js').MOSAICSecretKey,
      pk: import('./types.js').MOSAICPublicKey,
    ) => import('./kem/index.js').then((m) => m.decrypt(ciphertext, sk, pk)),
  },

  // Signature operations
  sign: {
    generateKeyPair: () =>
      import('./sign/index.js').then((m) => m.generateKeyPair()),
    sign: (
      message: Uint8Array,
      sk: import('./types.js').MOSAICSecretKey,
      pk: import('./types.js').MOSAICPublicKey,
    ) => import('./sign/index.js').then((m) => m.sign(message, sk, pk)),
    verify: (
      message: Uint8Array,
      sig: import('./types.js').MOSAICSignature,
      pk: import('./types.js').MOSAICPublicKey,
    ) => import('./sign/index.js').then((m) => m.verify(message, sig, pk)),
  },

  // Parameter sets
  params: {
    [SecurityLevel.MOS_128]: () =>
      import('./core/params.js').then((m) => m.MOS_128),
    [SecurityLevel.MOS_256]: () =>
      import('./core/params.js').then((m) => m.MOS_256),
  },
}

export default crypto

// =============================================================================
// Version Information
// =============================================================================

export const CLI_VERSION = '1.0.0'
export const ALGORITHM_NAME = 'kMOSAIC'
export const ALGORITHM_VERSION = '1.0'

/**
 * Algorithm description for documentation purposes
 */
export const ALGORITHM_INFO = {
  name: 'kMOSAIC',
  fullName: 'Multi-Oracle Structured Algebraic Intractability Composition',
  version: '1.0',
  securityLevels: [SecurityLevel.MOS_128, SecurityLevel.MOS_256],
  hardProblems: [
    {
      name: 'SLSS',
      fullName: 'Sparse Lattice Subset Sum',
      description:
        'Combines subset sum with lattice-based cryptography using sparse secrets',
      complexity: 'NP-hard (subset sum) + worst-case lattice hardness',
    },
    {
      name: 'TDD',
      fullName: 'Tensor Decomposition Distinguishing',
      description: 'Distinguishing random tensors from low-rank decompositions',
      complexity: 'NP-hard for rank determination over finite fields',
    },
    {
      name: 'EGRW',
      fullName: 'Expander Graph Random Walk',
      description: 'Finding paths in Cayley graphs of SL(2, Z_p)',
      complexity: 'Related to discrete log and group-theoretic problems',
    },
  ],
  entanglement: {
    description:
      'Secrets split using XOR 3-of-3 sharing, bound by hash commitment',
    benefit: 'Attacker must break ALL three problems simultaneously',
  },
  features: {
    kem: 'IND-CCA2 secure via Fujisaki-Okamoto transform',
    signatures: 'Multi-witness Fiat-Shamir with three parallel proofs',
    hybridReady: 'Can combine with classical algorithms',
  },
}
