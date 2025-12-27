/**
 * Constant-time operations to prevent timing attacks
 *
 * Security Properties:
 * - All operations execute in time independent of input values
 * - No secret-dependent branches or memory accesses
 * - Uses Node.js crypto.timingSafeEqual for comparisons
 * - Zeroization uses memory barriers to prevent optimization
 *
 * WARNING: JavaScript JIT compilation can introduce timing variations.
 * These implementations provide best-effort constant-time behavior.
 * For production cryptographic use, consider WebAssembly or native code.
 */

import { timingSafeEqual, randomBytes } from 'crypto'

// =============================================================================
// Equality Comparisons
// =============================================================================

/**
 * Constant-time equality comparison using Node.js crypto
 *
 * Security: Uses timingSafeEqual which is implemented in C++ with
 * constant-time guarantees. Length comparison is NOT constant-time
 * but length is typically not secret.
 *
 * @param a - First buffer to compare
 * @param b - Second buffer to compare
 * @returns true if buffers are equal, false otherwise
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Check if lengths are different; this is not constant time but length is usually public
  if (a.length !== b.length) return false

  // Handle empty arrays case
  if (a.length === 0) return true

  // Use Node.js built-in constant-time comparison
  return timingSafeEqual(a, b)
}

// =============================================================================
// Conditional Selection
// =============================================================================

/**
 * Constant-time conditional select for Uint8Array
 *
 * Returns a if condition is 1, b if condition is 0.
 * Executes both branches and uses bitmasking to select result.
 *
 * Security: No branches dependent on condition value.
 *
 * @param condition - Must be 0 or 1 (other values produce undefined behavior)
 * @param a - Value to return if condition is 1
 * @param b - Value to return if condition is 0
 * @returns Selected array (new allocation)
 */
export function constantTimeSelect(
  condition: number,
  a: Uint8Array,
  b: Uint8Array,
): Uint8Array {
  // Ensure arrays have the same length to prevent length leaks
  if (a.length !== b.length) {
    throw new Error('Arrays must have same length')
  }

  // Get the length of the arrays
  const len = a.length

  // Allocate a new array for the result
  const result = new Uint8Array(len)

  // Convert condition to full mask: 0 -> 0x00, 1 -> 0xFF
  // If condition is 1, -condition is -1 (0xFFFFFFFF...), & 0xff gives 0xFF
  // If condition is 0, -condition is 0, & 0xff gives 0x00
  const mask = -condition & 0xff

  // Create the inverse mask: 0 -> 0xFF, 1 -> 0x00
  const notMask = ~mask & 0xff

  // Iterate through each byte
  for (let i = 0; i < len; i++) {
    // Select byte from 'a' using mask and 'b' using notMask
    // If mask is 0xFF, we get a[i] | 0 = a[i]
    // If mask is 0x00, we get 0 | b[i] = b[i]
    result[i] = (a[i] & mask) | (b[i] & notMask)
  }

  // Return the selected array
  return result
}

/**
 * Constant-time conditional select for Int32Array
 *
 * @param condition - Must be 0 or 1
 * @param a - Value to return if condition is 1
 * @param b - Value to return if condition is 0
 * @returns Selected array (new allocation)
 */
export function constantTimeSelectInt32(
  condition: number,
  a: Int32Array,
  b: Int32Array,
): Int32Array {
  // Ensure arrays have the same length
  if (a.length !== b.length) {
    throw new Error('Arrays must have same length')
  }

  // Get the length of the arrays
  const len = a.length

  // Allocate a new array for the result
  const result = new Int32Array(len)

  // Create full 32-bit mask from condition
  // If condition is 1, -condition is -1 (0xFFFFFFFF)
  // If condition is 0, -condition is 0 (0x00000000)
  const mask = -condition

  // Iterate through each integer
  for (let i = 0; i < len; i++) {
    // Select integer from 'a' using mask and 'b' using ~mask
    // If mask is 0xFFFFFFFF, we get a[i] | 0 = a[i]
    // If mask is 0x00000000, we get 0 | b[i] = b[i]
    result[i] = (a[i] & mask) | (b[i] & ~mask)
  }

  // Return the selected array
  return result
}

// =============================================================================
// Arithmetic Operations
// =============================================================================

/**
 * Constant-time less than comparison
 *
 * @param a - First operand
 * @param b - Second operand
 * @returns 1 if a < b, 0 otherwise
 */
export function constantTimeLessThan(a: number, b: number): number {
  // Subtract b from a and check the sign bit
  // If a < b, a - b is negative, so sign bit (bit 31) is 1
  // If a >= b, a - b is positive or zero, so sign bit is 0
  return ((a - b) >>> 31) & 1
}

/**
 * Constant-time absolute value
 *
 * @param x - Input value
 * @returns |x|
 */
export function constantTimeAbs(x: number): number {
  // Get the sign mask: 0xFFFFFFFF if x < 0, 0x00000000 if x >= 0
  const mask = x >> 31

  // If x is negative: (x + (-1)) ^ (-1) = (x - 1) ^ 0xFFFFFFFF = ~(x - 1) = -x
  // If x is positive: (x + 0) ^ 0 = x
  return (x + mask) ^ mask
}

/**
 * Constant-time modular reduction (for positive modulus)
 *
 * @param x - Value to reduce
 * @param q - Modulus (must be positive)
 * @returns x mod q in range [0, q)
 */
export function constantTimeMod(x: number, q: number): number {
  // Check if x is negative
  const negative = x >> 31

  // If x is negative, add q to make it potentially positive (approximation)
  // This helps with simple cases but isn't a full Euclidean mod
  const adjusted = x + (q & negative)

  // Perform standard JS modulo and handle remaining negative results
  // ((adjusted % q) + q) % q ensures result is in [0, q)
  const result = ((adjusted % q) + q) % q

  // Return the result
  return result
}

// =============================================================================
// Memory Security
// =============================================================================

/**
 * Zeroize (securely clear) a buffer
 *
 * Security: Uses multiple techniques to prevent compiler/JIT optimization:
 * 1. First pass: overwrite with random data (prevents frozen memory pattern attacks)
 * 2. Second pass: fill with zeros
 * 3. Third pass: volatile-like read to create dependency
 * 4. Memory barrier via Atomics where supported
 *
 * Note: JavaScript cannot fully guarantee zeroization like C's memset_s.
 * Secrets may still persist in GC-based runtimes.
 *
 * @param buffer - Buffer to zeroize (modified in place)
 */
export function zeroize(buffer: Uint8Array | Int8Array | Int32Array): void {
  // Get buffer length
  const len = buffer.length

  // If empty, nothing to do
  if (len === 0) return

  // First pass: overwrite with random data using native crypto
  // Calculate byte length for random data generation
  const byteLen = buffer instanceof Int32Array ? len * 4 : len

  // Generate random bytes, capped at 4KB to avoid performance hit on large buffers
  const randomData = randomBytes(Math.min(byteLen, 4096))

  // Overwrite buffer with random data
  for (let i = 0; i < len; i++) {
    if (buffer instanceof Int32Array) {
      // For Int32Array, construct 32-bit integers from random bytes
      const offset = (i * 4) % randomData.length
      buffer[i] =
        randomData[offset] |
        (randomData[(offset + 1) % randomData.length] << 8) |
        (randomData[(offset + 2) % randomData.length] << 16) |
        (randomData[(offset + 3) % randomData.length] << 24)
    } else {
      // For byte arrays, just copy random bytes
      ;(buffer as Uint8Array)[i] = randomData[i % randomData.length]
    }
  }

  // Second pass: fill with zeros
  buffer.fill(0)

  // Third pass: read all values to create dependency
  // This prevents the compiler from optimizing away the zero fill
  let dummy = 0
  for (let i = 0; i < len; i++) {
    dummy |= buffer[i]
  }

  // Memory barrier where supported
  try {
    if (
      typeof Atomics !== 'undefined' &&
      typeof SharedArrayBuffer !== 'undefined'
    ) {
      // Use Atomics.store to force a memory fence
      Atomics.store(new Int32Array(new SharedArrayBuffer(4)), 0, dummy)
    }
  } catch {
    // Atomics not available, proceed without explicit barrier
  }

  // Prevent dead code elimination by using the dummy value
  if (dummy === Number.MIN_SAFE_INTEGER - 1) {
    console.log('zeroize')
  }
}

/**
 * Secure buffer wrapper that auto-zeroizes on disposal
 *
 * Usage with explicit dispose:
 * ```typescript
 * const secret = new SecureBuffer(32);
 * try {
 *   // use secret.buffer
 * } finally {
 *   secret.dispose();
 * }
 * ```
 *
 * Usage with using statement (TypeScript 5.2+):
 * ```typescript
 * using secret = new SecureBuffer(32);
 * // use secret.buffer
 * // automatically disposed at end of block
 * ```
 */
export class SecureBuffer {
  private data: Uint8Array
  private disposed = false

  /**
   * Create a new SecureBuffer
   * @param lengthOrData - Length in bytes or existing Uint8Array to copy
   */
  constructor(lengthOrData: number | Uint8Array) {
    if (typeof lengthOrData === 'number') {
      // Validate length
      if (lengthOrData < 0) {
        throw new Error('Buffer length must be non-negative')
      }
      // Allocate new zero-filled buffer
      this.data = new Uint8Array(lengthOrData)
    } else {
      // Copy existing data to new buffer
      this.data = new Uint8Array(lengthOrData)
    }
  }

  /**
   * Access the underlying buffer
   * Throws if disposed
   */
  get buffer(): Uint8Array {
    if (this.disposed) {
      throw new Error('Buffer has been disposed')
    }
    return this.data
  }

  /**
   * Get buffer length
   */
  get length(): number {
    return this.data.length
  }

  /**
   * Check if buffer is disposed
   */
  get isDisposed(): boolean {
    return this.disposed
  }

  /**
   * Securely wipe the buffer
   */
  dispose(): void {
    if (!this.disposed) {
      // Zeroize the data
      zeroize(this.data)
      // Mark as disposed
      this.disposed = true
    }
  }

  /**
   * Support for 'using' keyword
   */
  [Symbol.dispose](): void {
    this.dispose()
  }

  /**
   * Create a copy of the secure buffer
   */
  clone(): SecureBuffer {
    if (this.disposed) {
      throw new Error('Buffer has been disposed')
    }
    return new SecureBuffer(this.data)
  }

  /**
   * Fill buffer with random data
   */
  randomize(): void {
    if (this.disposed) {
      throw new Error('Buffer has been disposed')
    }
    // Generate random bytes
    const random = randomBytes(this.data.length)
    // Copy to buffer
    this.data.set(random)
  }
}
