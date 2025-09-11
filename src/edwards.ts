/* eslint-disable jsdoc/require-jsdoc */
import { createKeygen } from '@noble/curves/abstract/curve'
import type { EdDSA, EdDSAOpts, EdwardsPointCons } from '@noble/curves/abstract/edwards'
import type { FHash, Signer } from '@noble/curves/utils'
import { abool, abytes, bytesToNumberLE, concatBytes, isBytes, validateObject, randomBytes as wcRandomBytes } from '@noble/curves/utils'

// const _0n = BigInt(0)
const _1n = BigInt(1)
// const _2n = BigInt(2)
// const _8n = BigInt(8)

export type PHash = (message: bigint[]) => Uint8Array

export function eddsa (Point: EdwardsPointCons, cHash: FHash, pHash: PHash, eddsaOpts: EdDSAOpts = {}): EdDSA {
  if (typeof cHash !== 'function') throw new Error('"hash" function param is required')
  validateObject(
    eddsaOpts,
    {},
    {
      adjustScalarBytes: 'function',
      randomBytes: 'function',
      domain: 'function',
      prehash: 'function',
      mapToCurve: 'function',
    }
  )

  const { prehash } = eddsaOpts
  const { BASE, Fp, Fn } = Point

  const randomBytes = eddsaOpts.randomBytes || wcRandomBytes
  const adjustScalarBytes = eddsaOpts.adjustScalarBytes || ((bytes: Uint8Array) => bytes)
  const domain =
    eddsaOpts.domain ||
    ((data: Uint8Array, ctx: Uint8Array, phflag: boolean) => {
      abool(phflag, 'phflag')
      if (ctx.length || phflag) throw new Error('Contexts/pre-hash are not supported')
      return data
    }) // NOOP

  // Little-endian SHA512 with modulo n
  // eslint-disable-next-line camelcase
  function modN_LE (hash: Uint8Array): bigint {
    return Fn.create(bytesToNumberLE(hash)) // Not Fn.fromBytes: it has length limit
  }

  // Get the hashed private scalar per RFC8032 5.1.5
  function getPrivateScalar (key: Uint8Array) {
    const len = lengths.secretKey
    abytes(key, lengths.secretKey, 'secretKey')
    // Hash private key with curve's hash function to produce uniformingly random input
    // Check byte lengths: ensure(64, h(ensure(32, key)))
    const hashed = abytes(cHash(key), 2 * len, 'hashedSecretKey')
    const head = adjustScalarBytes(hashed.slice(0, len)) // clear first half bits, produce FE
    const prefix = hashed.slice(len, 2 * len) // second half is called key prefix (5.1.6)
    const scalar = modN_LE(head) // The actual private scalar
    return { head, prefix, scalar }
  }

  /**
   * Convenience method that creates public key from scalar. RFC8032 5.1.5
   * @param secretKey -
   * @returns -
   */
  function getExtendedPublicKey (secretKey: Uint8Array) {
    const { head, prefix, scalar } = getPrivateScalar(secretKey)
    const point = BASE.multiply(scalar) // Point on Edwards curve aka public key
    const pointBytes = point.toBytes()
    return { head, prefix, scalar, point, pointBytes }
  }

  /**
   * Calculates EdDSA pub key. RFC8032 5.1.5.
   * @param secretKey -
   * @returns -
   */
  function getPublicKey (secretKey: Uint8Array): Uint8Array {
    return getExtendedPublicKey(secretKey).pointBytes
  }

  // int('LE', SHA512(dom2(F, C) || msgs)) mod N
  function hashDomainToScalar (context: Uint8Array = Uint8Array.of(), ...msgs: Uint8Array[]) {
    const msg = concatBytes(...msgs)
    return modN_LE(cHash(domain(msg, abytes(context, undefined, 'context'), !!prehash)))
  }

  function pHashDomainToScalar (...msgs: Uint8Array[]) {
    // const msg = concatBytes(...msgs)
    // console.log("CONTEXT", context)
    // console.log("CONTEXT", msgs)
    const input = [
      // Fn.fromBytes(context),
      ...msgs.map(a => Fn.fromBytes(a, true))
    ]
    return modN_LE(pHash(input))
  }

  /**
   * Signs message with secret key. RFC8032 5.1.6
   * @param msg -
   * @param secretKey -
   * @param options -
   * @param options.context -
   * @returns -
   */
  function sign (
    msg: Uint8Array,
    secretKey: Uint8Array,
    options: { context?: Uint8Array } = {}
  ): Uint8Array {
    msg = abytes(msg, undefined, 'message')
    if (prehash) msg = prehash(msg) // for ed25519ph etc.
    const { prefix, scalar, pointBytes } = getExtendedPublicKey(secretKey)
    const r = hashDomainToScalar(options.context, prefix, msg) // r = dom2(F, C) || prefix || PH(M)
    const Rb = BASE.multiply(r).toBytes()// R = rG
    const R = Point.fromBytes(BASE.multiply(r).toBytes()).toAffine()// R = rG
    const k = pHashDomainToScalar(Rb, pointBytes, msg) // R || A || PH(M)
    const s = Fn.create(r + k * scalar) // S = (r + k * s) mod L
    if (!Fn.isValid(s)) throw new Error('sign failed: invalid s') // 0 <= s < L
    console.log(R, s)
    const rs = concatBytes(Rb, Fn.toBytes(s))
    return abytes(rs, lengths.signature, 'result')
  }

  // verification rule is either zip215 or rfc8032 / nist186-5. Consult fromHex:
  const verifyOpts: { context?: Uint8Array; zip215?: boolean } = { zip215: true }

  /**
   * Verifies EdDSA signature against message and public key. RFC8032 5.1.7.
   * An extended group equation is checked.
   * @param sig -
   * @param msg -
   * @param publicKey -
   * @param options -
   * @returns -
   */
  function verify (
    sig: Uint8Array,
    msg: Uint8Array,
    publicKey: Uint8Array,
    options = verifyOpts
  ): boolean {
    const { zip215 } = options
    const len = lengths.signature
    sig = abytes(sig, len, 'signature')
    msg = abytes(msg, undefined, 'message')
    publicKey = abytes(publicKey, lengths.publicKey, 'publicKey')
    if (zip215 !== undefined) abool(zip215, 'zip215')
    if (prehash) msg = prehash(msg) // for ed25519ph, etc

    const mid = len / 2
    const r = sig.subarray(0, mid)
    const s = bytesToNumberLE(sig.subarray(mid, len))
    let A, R, SB
    try {
      // zip215=true is good for consensus-critical apps. =false follows RFC8032 / NIST186-5.
      // zip215=true:  0 <= y < MASK (2^256 for ed25519)
      // zip215=false: 0 <= y < P (2^255-19 for ed25519)
      A = Point.fromBytes(publicKey, zip215)
      R = Point.fromBytes(r, zip215)
      SB = BASE.multiplyUnsafe(s) // 0 <= s < l is done inside
    } catch (error) {
      return false
    }
    if (!zip215 && A.isSmallOrder()) return false // zip215 allows public keys of small order

    const k = pHashDomainToScalar(R.toBytes(), A.toBytes(), msg)
    const RkA = R.add(A.multiplyUnsafe(k))
    // Extended group equation
    // [8][S]B = [8]R + [8][k]A'
    return RkA.subtract(SB).clearCofactor().is0()
  }

  const _size = Fp.BYTES // 32 for ed25519, 57 for ed448
  const lengths = {
    secretKey: _size,
    publicKey: _size,
    signature: 2 * _size,
    seed: _size,
  }
  function randomSecretKey (seed = randomBytes(lengths.seed)): Uint8Array {
    return abytes(seed, lengths.seed, 'seed')
  }

  function isValidSecretKey (key: Uint8Array): boolean {
    return isBytes(key) && key.length === Fn.BYTES
  }

  function isValidPublicKey (key: Uint8Array, zip215?: boolean): boolean {
    try {
      return !!Point.fromBytes(key, zip215)
    } catch (error) {
      return false
    }
  }

  const utils = {
    getExtendedPublicKey,
    randomSecretKey,
    isValidSecretKey,
    isValidPublicKey,
    /**
     * Converts ed public key to x public key. Uses formula:
     * - ed25519:
     *   - `(u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)`
     *   - `(x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))`
     * - ed448:
     *   - `(u, v) = ((y-1)/(y+1), sqrt(156324)*u/x)`
     *   - `(x, y) = (sqrt(156324)*u/v, (1+u)/(1-u))`
     * @param publicKey -
     * @returns -
     */
    toMontgomery (publicKey: Uint8Array): Uint8Array {
      const { y } = Point.fromBytes(publicKey)
      const size = lengths.publicKey
      const is25519 = size === 32
      if (!is25519 && size !== 57) throw new Error('only defined for 25519 and 448')
      const u = is25519 ? Fp.div(_1n + y, _1n - y) : Fp.div(y - _1n, y + _1n)
      return Fp.toBytes(u)
    },
    toMontgomerySecret (secretKey: Uint8Array): Uint8Array {
      const size = lengths.secretKey
      abytes(secretKey, size)
      const hashed = cHash(secretKey.subarray(0, size))
      return adjustScalarBytes(hashed).subarray(0, size)
    },
  }

  return Object.freeze({
    keygen: createKeygen(randomSecretKey, getPublicKey),
    getPublicKey,
    sign,
    verify,
    utils,
    Point,
    lengths,
  }) satisfies Signer
}
