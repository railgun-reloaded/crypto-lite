import { bn254 } from '@noble/curves/bn254'
import { randomBytes } from '@noble/curves/utils'

/**
 * Represents input types that can be converted to a field element.
 */
type FieldInput = bigint | number | string

/**
 * Represents a point in the field as an array of bigints (double precision).
 */
type FieldPointDouble = bigint[]

/**
 * Represents a point in the field as an array of bigints (single precision).
 */
type FieldPointSingle = bigint[]

const NobleFr = bn254.fields.Fr

/**
 * Converts a field input value to an internal field representation using Noble's Fr field implementation for BN254.
 * @param f - The field input value to convert, can be a string, number, or bigint
 * @returns The internal field element representation as a Noble Fr field element
 * @throws {Error} When the input cannot be converted to a valid field element
 * @example
 * ```typescript
 * const fieldElement = toIField(42);
 * const fieldFromString = toIField("123456789");
 * const fieldFromBigInt = toIField(123456789n);
 * ```
 */
function toIField (f: FieldInput): bigint {
  return NobleFr.create(BigInt(f))
}

/**
 * Interface for finite field arithmetic operations over the scalar field Fr of the BN254 elliptic curve.
 * This interface provides a comprehensive set of operations for working with field elements,
 * including basic arithmetic, modular operations, serialization, and utility functions.
 * The field has a prime modulus p and supports both regular and Montgomery form representations.
 */
interface FrInterface {
  /** The bit length of field elements (254 bits for BN254 Fr field) */
  readonly bitLength: number
  /** The zero element of the field */
  readonly zero: bigint
  /** The multiplicative identity element of the field */
  readonly one: bigint
  /** The prime modulus of the field */
  readonly p: bigint

  add: (a: FieldInput, b: FieldInput) => bigint
  sub: (a: FieldInput, b: FieldInput) => bigint
  mul: (a: FieldInput, b: FieldInput) => bigint
  square: (a: FieldInput) => bigint
  eq: (a: FieldInput, b: FieldInput) => boolean
  div: (a: FieldInput, b: FieldInput) => bigint
  inv: (a: FieldInput) => bigint
  neg: (a: FieldInput) => bigint
  pow: (base: FieldInput, exp: FieldInput) => bigint
  isZero: (a: FieldInput) => boolean
  toObject: (a: FieldInput) => bigint
  toString: (a: FieldInput, base?: number) => string
  e: (a: FieldInput | Uint8Array) => bigint
  toRprLE: (buffer: Uint8Array, offset: number, value: FieldInput | Uint8Array) => void
  fromRprLE: (buffer: Uint8Array, offset?: number, length?: number) => bigint
  toBytes: (value: FieldInput) => Uint8Array
  fromBytes: (bytes: Uint8Array) => bigint
  toMontgomery: (a: FieldInput | Uint8Array) => Uint8Array
  fromMontgomery: (a: FieldInput | Uint8Array) => Uint8Array
  isValid: (value: bigint) => boolean
  random: () => bigint
  toHex: (value: bigint) => string
  fromHex: (hex: string) => bigint
  mod: (a: FieldInput, b: FieldInput) => bigint
  shr: (a: FieldInput, bits: number) => bigint
}

/**
 * BN254 scalar field (Fr) implementation providing arithmetic operations over the finite field.
 * This implementation wraps the Noble BN254 Fr field operations with additional utility methods.
 * The BN254 scalar field Fr has the following properties:
 * - Order: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 * - Bit length: 254 bits
 * - Used for scalar multiplication in BN254 elliptic curve cryptography
 * - Commonly used in zero-knowledge proof systems like zk-SNARKs
 * @example
 * Basic arithmetic operations:
 * ```typescript
 * const a = Fr.e(123n);
 * const b = Fr.e(456n);
 * const sum = Fr.add(a, b);
 * const product = Fr.mul(a, b);
 * const inverse = Fr.inv(a);
 * const isZero = Fr.isZero(Fr.sub(a, a)); // true
 * ```
 * @example
 * Working with bytes and serialization:
 * ```typescript
 * // Convert to/from bytes
 * const value = Fr.e(42n);
 * const bytes = Fr.toBytes(value);
 * const restored = Fr.fromBytes(bytes);
 * // Little-endian buffer operations
 * const buffer = new Uint8Array(32);
 * Fr.toRprLE(buffer, 0, value);
 * const fromBuffer = Fr.fromRprLE(buffer, 0, 32);
 * ```
 * @example
 * Random generation and validation:
 * ```typescript
 * // Generate random field element
 * const random = Fr.random();
 * const isValid = Fr.isValid(random); // true
 * // Hexadecimal representation
 * const hex = Fr.toHex(random);
 * const fromHex = Fr.fromHex(hex);
 * console.log(Fr.eq(random, fromHex)); // true
 * ```
 * @example
 * Montgomery form operations (for optimized arithmetic):
 * ```typescript
 * const value = Fr.e(123n);
 * const montgomery = Fr.toMontgomery(value);
 * const restored = Fr.fromMontgomery(montgomery);
 * ```
 */
const Fr: FrInterface = {

  bitLength: 254,
  zero: NobleFr.ZERO,
  one: NobleFr.ONE,
  p: NobleFr.ORDER,

  /**
   * Adds two field elements.
   * @param a - First operand
   * @param b - Second operand
   * @returns The sum (a + b) mod p
   */
  add: (a: FieldInput, b: FieldInput) => NobleFr.add(toIField(a), toIField(b)),

  /**
   * Subtracts two field elements.
   * @param a - Minuend
   * @param b - Subtrahend
   * @returns The difference (a - b) mod p
   */
  sub: (a: FieldInput, b: FieldInput) => NobleFr.sub(toIField(a), toIField(b)),

  /**
   * Multiplies two field elements.
   * @param a - First factor
   * @param b - Second factor
   * @returns The product (a * b) mod p
   */
  mul: (a: FieldInput, b: FieldInput) => NobleFr.mul(toIField(a), toIField(b)),

  /**
   * Squares a field element.
   * @param a - The element to square
   * @returns The square (a²) mod p
   */
  square: (a: FieldInput) => NobleFr.sqr(toIField(a)),

  /**
   * Tests equality of two field elements.
   * @param a - First element
   * @param b - Second element
   * @returns True if a equals b in the field
   */
  eq: (a: FieldInput, b: FieldInput) => NobleFr.eql(toIField(a), toIField(b)),

  /**
   * Divides two field elements.
   * @param a - Dividend
   * @param b - Divisor (must be non-zero)
   * @returns The quotient (a / b) mod p
   * @throws When b is zero
   */
  div: (a: FieldInput, b: FieldInput) => NobleFr.div(toIField(a), toIField(b)),

  /**
   * Computes the modular inverse of a field element.
   * @param a - The element to invert (must be non-zero)
   * @returns The inverse element such that a * inv(a) = 1 mod p
   * @throws When a is zero
   */
  inv: (a: FieldInput) => NobleFr.inv(toIField(a)),

  /**
   * Computes the additive inverse (negation) of a field element.
   * @param a - The element to negate
   * @returns The negation (-a) mod p
   */
  neg: (a: FieldInput) => NobleFr.neg(toIField(a)),

  /**
   * Computes base raised to the power of exp in the field.
   * @param base - The base element
   * @param exp - The exponent
   * @returns The result (base^exp) mod p
   */
  pow: (base: FieldInput, exp: FieldInput) => NobleFr.pow(toIField(base), BigInt(exp)),

  /**
   * Tests if a field element is zero.
   * @param a - The element to test
   * @returns True if the element is zero
   */
  isZero: (a: FieldInput) => {
    const value = toIField(a)
    return NobleFr.eql(value, NobleFr.ZERO)
  },

  /**
   * Converts a field input to its internal bigint representation.
   * @param a - The input to convert
   * @returns The internal representation
   */
  toObject: (a: FieldInput) => toIField(a),

  /**
   * Converts a field element to its string representation.
   * @param a - The element to convert
   * @param base - The numeric base for the string representation
   * @returns The string representation of the element
   */
  toString: (a: FieldInput, base: number = 10) => toIField(a).toString(base),

  /**
   * Creates a field element from input or bytes.
   * @param a - The input value or byte array
   * @returns The field element
   */
  e: (a: FieldInput | Uint8Array) => {
    if (a instanceof Uint8Array) {
      return NobleFr.fromBytes(a, true)
    }
    return toIField(a)
  },

  /**
   * Writes a field element to a buffer in little-endian format.
   * @param buffer - The target buffer
   * @param offset - The offset in the buffer to start writing
   * @param value - The value to write
   */
  toRprLE: (buffer, offset, value) => {
    const bytes = value instanceof Uint8Array
      ? value
      : NobleFr.toBytes(toIField(value))
    const le = new Uint8Array(32)
    le.set(bytes)
    le.reverse()
    const copyLen = Math.min(32, buffer.length - offset)
    buffer.set(le.subarray(0, copyLen), offset)
  },

  /**
   * Reads a field element from a buffer in little-endian format.
   * @param buffer - The source buffer
   * @param offset - The offset in the buffer to start reading
   * @param length - The number of bytes to read
   * @returns The field element
   */
  fromRprLE: (buffer, offset = 0, length = 32) => {
    const end = Math.min(buffer.length, offset + length)
    const slice = buffer.subarray(offset, end)
    const padded = new Uint8Array(32)
    padded.set(slice)
    padded.reverse()
    return NobleFr.fromBytes(padded)
  },

  /**
   * Converts a field element to its byte representation.
   * @param value - The field element to convert
   * @returns The byte representation (32 bytes, big-endian)
   */
  toBytes: (value: FieldInput) => NobleFr.toBytes(toIField(value)),

  /**
   * Creates a field element from its byte representation.
   * @param bytes - The byte array to convert
   * @returns The field element
   */
  fromBytes: (bytes: Uint8Array) => NobleFr.fromBytes(bytes),

  /**
   * Converts a field element to Montgomery form.
   * @param a - The element to convert
   * @returns The Montgomery form representation
   */
  toMontgomery: (a: FieldInput | Uint8Array) => {
    if (a instanceof Uint8Array) {
      return NobleFr.toBytes(NobleFr.fromBytes(a))
    }
    return NobleFr.toBytes(toIField(a))
  },

  /**
   * Converts a field element from Montgomery form.
   * @param a - The Montgomery form element
   * @returns The standard form representation
   */
  fromMontgomery: (a: FieldInput | Uint8Array) => {
    if (a instanceof Uint8Array) {
      return NobleFr.toBytes(NobleFr.fromBytes(a))
    }
    return NobleFr.toBytes(toIField(a))
  },

  /**
   * Validates if a bigint value is a valid field element.
   * @param value - The value to validate
   * @returns True if the value is valid in this field
   */
  isValid: (value: bigint) => value >= 0n && value < NobleFr.ORDER,

  /**
   * Generates a random field element.
   * @returns A uniformly random field element
   */
  random: () => {
    while (true) {
      const bytes = randomBytes(32)
      try {
        return NobleFr.fromBytes(bytes)
      } catch { /* reject if ≥ ORDER */ }
    }
  },

  /**
   * Converts a field element to its hexadecimal representation.
   * @param value - The field element
   * @returns The hexadecimal string with '0x' prefix (64 hex digits)
   */
  toHex: (value: bigint) => '0x' + NobleFr.create(value).toString(16).padStart(64, '0'),

  /**
   * Creates a field element from a hexadecimal string.
   * @param hex - The hexadecimal string (with or without '0x' prefix)
   * @returns The field element
   */
  fromHex: (hex: string) => {
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex
    return toIField('0x' + cleanHex)
  },

  /**
   * Computes the modulo operation.
   * @param a - The dividend
   * @param b - The modulus
   * @returns The result (a mod b)
   */
  mod: (a, b) => {
    const aVal = BigInt(a)
    const bVal = BigInt(b)
    let r = aVal % bVal
    if (r < 0n) r += bVal
    return r
  },

  /**
   * Performs a right bit shift operation.
   * @param a - The value to shift
   * @param bits - The number of bits to shift right
   * @returns The shifted result as a valid field element
   */
  shr: (a: FieldInput, bits: number) => {
    const aVal = BigInt(a)
    return NobleFr.create(aVal >> BigInt(bits))
  },

} as const

export type { FieldPointDouble, FieldPointSingle, FieldInput, FrInterface }
export { NobleFr, toIField, Fr }
