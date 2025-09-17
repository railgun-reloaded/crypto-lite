import type { EdwardsOpts } from '@noble/curves/abstract/edwards'
import { edwards } from '@noble/curves/abstract/edwards'
import { blake512 } from '@noble/hashes/blake1'
import { poseidon5 } from 'poseidon-lite'

// import buildPoseidon from './poseidon_opt'
// import { poseidon } from './poseidon-lite-wrapper'

// initializePoseidonFuncs()

// const poseidon = buildPoseidon()

const babyjubjubCURVE: EdwardsOpts = {
  p: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n,
  n: 0x30644e72e131a029b85045b68181585d59f76dc1c90770533b94bee1c9093788n,
  h: 8n,
  a: 168700n,
  d: 168696n,
  Gx: 0x023343e3445b673d38bcba38f25645adb494b1255b1162bb40f41a59f4d4b45en,
  Gy: 0x0c19139cb84c680a6e14116da06056174a0cfa121e6e5c2450f87d64fc000001n,
}

const BabyJubPoint = edwards(babyjubjubCURVE)

type Affine = { x: bigint; y: bigint }

/**
 * Clamps and prunes a 32-byte array according to EdDSA scalar requirements by clearing the lowest 3 bits, clearing the highest bit, and setting the second-highest bit.
 * @param b - The 32-byte input array to clamp and prune
 * @returns A new Uint8Array with the clamped and pruned values
 * @example
 * ```typescript
 * const key = new Uint8Array(32);
 * key.fill(0xff); // Fill with all 1s
 * const clamped = clampPrune32(key);
 * console.log(clamped[0] & 0x07); // 0 - lowest 3 bits cleared
 * console.log(clamped[31] & 0x80); // 0 - highest bit cleared
 * console.log(clamped[31] & 0x40); // 64 - second-highest bit set
 * ```
 */
function clampPrune32 (b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b)
  out[0]! &= 0xf8
  out[31]! &= 0x7f
  out[31]! |= 0x40
  return out
}

/**
 * Converts a little-endian byte array to a BigInt value.
 * @param u8 - The Uint8Array containing bytes in little-endian format
 * @returns The BigInt representation of the byte array
 * @example
 * ```typescript
 * const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
 * const result = leBytesToBigint(bytes); // Returns 0x04030201n
 * ```
 * @example
 * ```typescript
 * const emptyBytes = new Uint8Array([]);
 * const result = leBytesToBigint(emptyBytes); // Returns 0n
 * ```
 */
function leBytesToBigint (u8: Uint8Array): bigint {
  let n = 0n
  for (let i = u8.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u8[i]!)
  return n
}

/**
 * EdDSA implementation using Poseidon hash function for cryptographic signatures on Baby Jubjub curve.
 * Provides key generation, signing, and verification functionality with Poseidon hash integration.
 * @example
 * ```typescript
 * const eddsa = new EddsaPoseidon();
 * const privateKey = new Uint8Array(32);
 * crypto.getRandomValues(privateKey);
 * const publicKey = eddsa.prv2pub(privateKey);
 * const message = new TextEncoder().encode("Hello World");
 * const signature = eddsa.signPoseidon(privateKey, message);
 * const isValid = eddsa.verifyPoseidon(message, signature, { x: publicKey[0], y: publicKey[1] });
 * ```
 */
class EddsaPoseidon {
  /**
   * The Point constructor from the noble-curves library for Baby Jubjub elliptic curve operations.
   * @example const point = new this.Point(x, y);
   */
  private readonly Point = BabyJubPoint                 // noble Point constructor
  /**
   * The order of the elliptic curve subgroup, representing the number of points in the prime-order subgroup.
   * This value is used in scalar arithmetic operations and key generation to ensure all operations
   * stay within the valid range of the curve's cyclic group.
   * @example
   * ```typescript
   * // Using the subgroup order for scalar validation
   * const scalar = BigInt("123456789");
   * const validScalar = scalar % this.n;
   * ```
   * @example
   * ```typescript
   * // Key generation using subgroup order
   * const privateKey = randomBytes(32);
   * const privateKeyScalar = mod(bytesToNumberBE(privateKey), this.n);
   * ```
   */
  private readonly n = this.Point.CURVE().n             // subgroup order
  /**
   * Precomputed point representing 8 times the generator point G in affine coordinates.
   * This precomputed value is used to optimize scalar multiplication operations in EdDSA.
   * @example
   * ```typescript
   * // The Base8 point is automatically precomputed during initialization
   * const eddsaInstance = new EdDSA();
   * // Base8 is used internally for efficient point operations
   * ```
   */
  private readonly Base8: Affine                        // 8*G (affine)
  /**
   * The base field (Fp) used by the elliptic curve points.
   * This field defines the mathematical operations and properties for the prime field
   * over which the elliptic curve is defined.
   * @example
   * ```typescript
   * const curve = new EdDSACurve();
   * const fieldElement = curve.Fp.create(42n);
   * const isValid = curve.Fp.isValid(fieldElement);
   * ```
   */
  public readonly Fp = this.Point.Fp                    // base field
  /**
   * The scalar field (base field) for EdDSA operations, representing the finite field
   * over which scalar arithmetic is performed. This field is used for private keys,
   * signatures, and other scalar values in the EdDSA cryptographic operations.
   * @example
   * ```typescript
   * // Generate a random scalar in the base field
   * const randomScalar = eddsa.Fr.random();
   * // Perform scalar arithmetic
   * const a = eddsa.Fr.from(123n);
   * const b = eddsa.Fr.from(456n);
   * const sum = eddsa.Fr.add(a, b);
   * const product = eddsa.Fr.mul(a, b);
   * ```
   * @example
   * ```typescript
   * // Convert between different scalar representations
   * const scalar = eddsa.Fr.from("0x1a2b3c4d5e6f");
   * const bytes = eddsa.Fr.toBytes(scalar);
   * const restored = eddsa.Fr.fromBytes(bytes);
   * ```
   */
  public readonly Fr = this.Point.Fn                    // base field
  // /**
  //  * Poseidon hash function instance used for cryptographic operations in EdDSA signatures.
  //  * This is typically used for hashing data before signing or for generating deterministic values.
  //  * @example
  //  * ```typescript
  //  * const hash = this.poseidon([1, 2, 3, 4]);
  //  * console.log(hash); // Returns poseidon hash output
  //  * ```
  //  * @example
  //  * ```typescript
  //  * // Hash message before signing
  //  * const message = [BigInt(123), BigInt(456)];
  //  * const hashedMessage = this.poseidon(message);
  //  * const signature = this.sign(hashedMessage, privateKey);
  //  * ```
  //  */
  // public readonly poseidon: any

  /**
   * Creates a new instance of the EdDSA-Poseidon-Babyjubjub class.
   * Initializes the Base8 point by multiplying the base point by 8 and converting to affine coordinates,
   * and sets up the Poseidon hash function.
   * @example
   * ```typescript
   * const eddsa = new EdDSA();
   * ```
   */
  constructor () {
    this.Base8 = this.Point.BASE.multiplyUnsafe(8n).toAffine() as Affine
    // this.poseidon = poseidon
  }

  /**
   * Converts a bigint value to its byte representation using the field's byte conversion.
   * @param a - The bigint value to convert to bytes
   * @returns The byte array representation of the input value
   * @example
   * ```typescript
   * const value = 12345n;
   * const bytes = instance.toBytes(value);
   * console.log(bytes); // Uint8Array representation
   * ```
   * @example
   * ```typescript
   * // Converting a field element to bytes for serialization
   * const fieldElement = 0x1234567890abcdefn;
   * const serialized = instance.toBytes(fieldElement);
   * ```
   */
  toBytes (a: bigint) {
    return this.Fr.toBytes(a)
  }

  /**
   * Converts a byte array to a field element.
   * @param a - The byte array to convert
   * @returns The field element representation of the input bytes
   * @example
   * ```typescript
   * const bytes = new Uint8Array([1, 2, 3, 4]);
   * const fieldElement = instance.fromBytes(bytes);
   * ```
   */
  fromBytes (a: Uint8Array) {
    return this.Fr.fromBytes(a, true)
  }

  /**
   * Converts a value to Montgomery form representation.
   * @param a - The value to convert, either as a bigint or Uint8Array
   * @returns The value converted to Montgomery form as a Uint8Array
   * @example
   * ```typescript
   * // Convert from bigint
   * const result1 = toMontgomery(123n);
   * // Convert from Uint8Array
   * const bytes = new Uint8Array([1, 2, 3, 4]);
   * const result2 = toMontgomery(bytes);
   * ```
   */
  toMontgomery (a: bigint | Uint8Array) {
    if (a instanceof Uint8Array) {
      return this.Fr.toBytes(this.Fr.fromBytes(a, true))
    }
    return this.Fr.toBytes(this.Fr.create(BigInt(a)))
  }

  /**
   * Converts a value from Montgomery form to standard form and returns it as bytes.
   * @param a - The value to convert, either as a bigint or Uint8Array
   * @returns The converted value as a Uint8Array in standard form
   * @example
   * ```typescript
   * // Convert from Uint8Array
   * const bytes = new Uint8Array([1, 2, 3, 4]);
   * const result = fromMontgomery(bytes);
   * // Convert from bigint
   * const bigintValue = 12345n;
   * const result = fromMontgomery(bigintValue);
   * ```
   */
  fromMontgomery (a: bigint | Uint8Array) {
    if (a instanceof Uint8Array) {
      return this.Fr.toBytes(this.Fr.fromBytes(a, true))
    }
    return this.Fr.toBytes(this.Fr.create(BigInt(a)))
  }

  /**
   * Prunes and clamps a buffer to ensure it meets EdDSA key requirements.
   * @param buff - The input buffer to be pruned and clamped
   * @returns The pruned and clamped 32-byte buffer
   * @example
   * ```typescript
   * const rawKey = new Uint8Array(32);
   * const prunedKey = pruneBuffer(rawKey);
   * ```
   */
  pruneBuffer (buff: Uint8Array) {
    return clampPrune32(buff)
  }

  /**
   * Converts a private key to its corresponding public key point.
   * @param prv - The private key as a Uint8Array
   * @returns A tuple containing the x and y coordinates of the public key point as bigints
   * @example
   * ```typescript
   * const privateKey = new Uint8Array(32).fill(1);
   * const [x, y] = prv2pub(privateKey);
   * console.log(`Public key: (${x}, ${y})`);
   * ```
   */
  prv2pub (prv: Uint8Array): [bigint, bigint] {
    const sBuff = this.pruneBuffer(blake512(prv)) // 64 bytes
    const s = leBytesToBigint(sBuff.subarray(0, 32))
    const sShr3 = s >> 3n
    const point = this.Point.fromAffine(this.Base8).multiplyUnsafe(sShr3).toAffine() as Affine
    return [point.x, point.y]
  }

  /**
   * Signs a message using the Poseidon hash function in the EdDSA signature scheme.
   * @param prv - The private key as a 32-byte Uint8Array
   * @param msg - The message to sign as a Uint8Array
   * @returns An object containing the signature components R8 (point) and S (scalar)
   * @example
   * ```typescript
   * const privateKey = new Uint8Array(32).fill(1);
   * const message = new TextEncoder().encode("hello world");
   * const signature = signPoseidon(privateKey, message);
   * console.log(signature.R8); // Point coordinates
   * console.log(signature.S); // Scalar value
   * ```
   */
  signPoseidon (prv: Uint8Array, msg: Uint8Array) {
    const sBuff = this.pruneBuffer(blake512(prv)) // 64 bytes
    const s = leBytesToBigint(sBuff.subarray(0, 32))
    const A = (this.Point.fromAffine(this.Base8) as any).multiplyUnsafe(s >> 3n).toAffine() as Affine

    const compose = new Uint8Array(32 + msg.length)
    compose.set(sBuff.subarray(32, 64), 0)
    compose.set(msg, 32)

    const r = leBytesToBigint(blake512(compose)) % this.n
    const R8 = (this.Point.fromAffine(this.Base8) as any).multiplyUnsafe(r).toAffine() as Affine
    const msgField = this.Fr.create(leBytesToBigint(msg))

    const hm = poseidon5([R8.x, R8.y, A.x, A.y, msgField]) % this.n
    const hms = this.Fr.create(hm)
    const subOrder = this.Fr.ORDER >> 3n
    const mul = hms * s
    const add = r + mul
    const S = add % subOrder
    return { R8, S }
  }

  /**
   * Verifies a Poseidon-based EdDSA signature against a message and public key.
   * @param msg - The message bytes to verify as Uint8Array
   * @param sig - The signature object containing R8 point and S scalar
   * @param sig.R8 - The R8 point component of the signature as Affine coordinates
   * @param sig.S - The S scalar component of the signature as bigint
   * @param A - The public key as Affine point coordinates
   * @returns True if the signature is valid, false otherwise
   * @example
   * ```typescript
   * const message = new Uint8Array([1, 2, 3, 4]);
   * const signature = {
   *   R8: { x: 123n, y: 456n },
   *   S: 789n
   * };
   * const publicKey = { x: 111n, y: 222n };
   * const isValid = verifyPoseidon(message, signature, publicKey);
   * ```
   */
  verifyPoseidon (msg: Uint8Array, sig: { R8: Affine, S: bigint }, A: Affine) {
    const { R8, S } = sig
    const subOrder = this.Fr.ORDER >> 3n

    if (S >= subOrder) return false
    const R = this.Point.fromAffine(R8)
    const Ap = this.Point.fromAffine(A)

    if (!R.multiplyUnsafe(subOrder).equals(this.Point.ZERO)) return false
    if (!Ap.multiplyUnsafe(subOrder).equals(this.Point.ZERO)) return false
    const msgField = this.Fr.create(leBytesToBigint(msg))
    const hm = poseidon5([R8.x, R8.y, A.x, A.y, msgField]) % this.n
    const hms = this.Fr.create(hm)

    const left = this.Point.fromAffine(this.Base8)
      .multiplyUnsafe(S % subOrder)
      .toAffine() as Affine

    const k = (hms * 8n) % this.n
    const right = R.add(Ap.multiplyUnsafe(k)).toAffine() as Affine

    return left.x === right.x && left.y === right.y
  }
}

/**
 * Creates a new instance of EddsaPoseidon for EdDSA signature operations using Poseidon hash.
 * @returns A new EddsaPoseidon instance configured for cryptographic operations
 * @example
 * ```typescript
 * const eddsa = buildEddsaPoseidon();
 * const keyPair = eddsa.generateKeyPair();
 * const signature = eddsa.sign(message, keyPair.privateKey);
 * ```
 */
export default function buildEddsaPoseidon () {
  return new EddsaPoseidon()
}

export { EddsaPoseidon, BabyJubPoint }
