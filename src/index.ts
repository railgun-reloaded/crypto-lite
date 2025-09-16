/* eslint-disable import-x/first */
/* eslint-disable import-x/order */
import {
  etc,
  getPublicKey,
  hashes,
} from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha2'

// import { initializePoseidonFuncs } from './poseidon-lite-wrapper'
// initializePoseidonFuncs()
import buildEddsa from './eddsa-noble'
import { bigIntToUint8Array, uint8ArrayToBigInt } from './utils'

// Set the SHA-512 implementation
// https://github.com/paulmillr/noble-ed25519/blob/main/README.md#enabling-synchronous-methods
// Sync methods can be used now:
// ed25519.getPublicKey(privKey);
// ed25519.sign(msg, privKey);
// ed25519.verify(signature, msg, pubKey);
/**
 *1
 * @param m a
 * @returns a
 */
hashes.sha512 = (...m) => sha512(etc.concatBytes(...m))
/**
 * Represents a cryptographic signature in the format used by Circomlib.
 * @example
 * ```typescript
 * const signature: CircomlibSignature = {
 *   R8: [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])],
 *   S: 123456789012345678901234567890n
 * };
 * ```
 * @example
 * ```typescript
 * function verifySignature(sig: CircomlibSignature, message: string): boolean {
 *   // Verification logic using sig.R8 and sig.S
 *   return true;
 * }
 * ```
 */
interface CircomlibSignature {
  R8: [Uint8Array, Uint8Array];
  S: bigint;
}

const eddsaBuild = buildEddsa()

const poseidonBuild = eddsaBuild.poseidon

const wrapperModule = {
  eddsaBuild,
  poseidonBuild
}

/**
 * Computes the Poseidon hash for an array of byte arrays.
 * @param inputs - Array of Uint8Array inputs to be hashed
 * @returns The Poseidon hash result as a reversed Uint8Array
 * @example
 * ```typescript
 * const input1 = new Uint8Array([1, 2, 3]);
 * const input2 = new Uint8Array([4, 5, 6]);
 * const hash = poseidon([input1, input2]);
 * console.log(hash); // Uint8Array containing the hash
 * ```
 */
const poseidon = (inputs: Uint8Array[]) => {
  // TODO: wasm import
  const result = poseidonBuild(inputs.map(a => a.reverse()))
  // const result = poseidonBuild.F.fromMontgomery(
  //   poseidonBuild(inputs.map((input) => poseidonBuild.F.toMontgomery(new Uint8Array(input).reverse())))
  // )
  return bigIntToUint8Array(result).reverse()
}

/**
 * Computes a Poseidon hash of the input strings and returns the result as a BigInt or hex string.
 * @param inputs - Array of string inputs to be hashed
 * @param toHex - Optional flag to return the result as a hex string instead of BigInt (default: false)
 * @returns The Poseidon hash as a BigInt or hex string
 * @example
 * ```typescript
 * const hash = poseidonHex(['123', '456']);
 * console.log(hash); // Returns BigInt
 * ```
 * @example
 * ```typescript
 * const hexHash = poseidonHex(['123', '456'], true);
 * console.log(hexHash); // Returns hex string
 * ```
 */
const poseidonHex = (inputs: string[], toHex = false) => {
  // TODO: sanitize inputs 32 bytes
  const result = poseidon(inputs.map(BigInt).map(bigIntToUint8Array))
  const output = uint8ArrayToBigInt(result)
  return toHex ? output.toString(16) : output
}

/**
 * Signs a message using Poseidon hash and EdDSA signature scheme.
 * @param key - The private key as a Uint8Array used for signing
 * @param message - The message to be signed as a Uint8Array
 * @returns A tuple containing three Uint8Arrays: [R8.x, R8.y, S] representing the signature components
 * @throws {Error} Throws "Invalid" error if eddsaBuild is undefined
 * @example
 * ```typescript
 * const privateKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
 * const message = new TextEncoder().encode("Hello World");
 * const [r8x, r8y, s] = signPoseidon(privateKey, message);
 * console.log("Signature components:", { r8x, r8y, s });
 * ```
 */
const signPoseidon = (
  key: Uint8Array,
  message: Uint8Array
): [Uint8Array, Uint8Array, Uint8Array] => {
  // TODO: these checks are unecessary, the initialization is no longer async
  // if (typeof eddsaBuild === 'undefined') {
  //   throw new Error('Invalid')
  // }
  const montgomery = eddsaBuild.toMontgomery(
    new Uint8Array(message).reverse()
  )
  const sig = eddsaBuild.signPoseidon(key, montgomery)
  const r8 = sig.R8
  // TODO: output S as bigint?
  return [bigIntToUint8Array(r8.x).reverse(), bigIntToUint8Array(r8.y).reverse(), bigIntToUint8Array(sig.S as any as bigint)]
}

/**
 * Verifies an EdDSA signature using Poseidon hash function and circomlib
 * @param message - The message that was signed as a Uint8Array
 * @param signature - The EdDSA signature containing R8 point and S scalar
 * @param pubkey - The public key as a tuple of two Uint8Array elements representing x and y coordinates
 * @returns True if the signature is valid, false otherwise
 * @throws Error when eddsaBuild is undefined
 * @example
 * ```typescript
 * const message = new Uint8Array([1, 2, 3, 4]);
 * const signature = { R8: [new Uint8Array([...]), new Uint8Array([...])], S: new Uint8Array([...]) };
 * const pubkey: [Uint8Array, Uint8Array] = [new Uint8Array([...]), new Uint8Array([...])];
 * const isValid = verifyEDDSA(message, signature, pubkey);
 * ```
 */
const verifyEDDSA = (message: Uint8Array, signature: CircomlibSignature, pubkey: [Uint8Array, Uint8Array]) => {
  // TODO: these checks are unecessary, the initialization is no longer async
  // if (typeof eddsaBuild === 'undefined') {
  //   throw new Error('Invalid')
  // }
  const montgomery = eddsaBuild.fromMontgomery(
    new Uint8Array(message).reverse()
  )
  const r8 = signature.R8.map((element: any) => uint8ArrayToBigInt(element.reverse()))
  const newSig = {
    R8: { x: r8[0]!, y: r8[1]! },
    S: uint8ArrayToBigInt(signature.S as any as Uint8Array),
  }
  const newPubKey = pubkey.map((element: any) => uint8ArrayToBigInt(element.reverse()))

  return eddsaBuild.verifyPoseidon(montgomery, newSig, { x: newPubKey[0]!, y: newPubKey[1]! })
}

/**
 * Converts a private key to its corresponding public key pair using EdDSA cryptography.
 * @param privateKey - The private key as a Uint8Array to convert
 * @returns A tuple containing two Uint8Array elements representing the public key components, or any on error
 * @example
 * ```typescript
 * const privateKey = new Uint8Array([1, 2, 3, 4, 5]);
 * const [pubKeyX, pubKeyY] = privateKeyToPublicKey(privateKey);
 * ```
 */
const privateKeyToPublicKey = (
  privateKey: Uint8Array
): [Uint8Array, Uint8Array] | any => {
  const key = eddsaBuild
    .prv2pub(privateKey)
    .map((element: any) => eddsaBuild.fromMontgomery(element).reverse()) as [Uint8Array, Uint8Array]
  return key
}

/**
 * Derives the public spending key pair from a private key.
 * @param privateKey - A 32-byte private key as Uint8Array
 * @returns A tuple containing two Uint8Array elements representing the public key pair
 * @throws Error when private key length is not 32 bytes
 * @example
 * ```typescript
 * const privateKey = new Uint8Array(32).fill(1);
 * const [pubKey1, pubKey2] = getPublicSpendingKey(privateKey);
 * ```
 */
const getPublicSpendingKey = (privateKey: Uint8Array): [Uint8Array, Uint8Array] => {
  if (privateKey.length !== 32) throw Error('Invalid private key length')
  return privateKeyToPublicKey(privateKey)
}

/**
 * Derives a public viewing key from a private viewing key.
 * @param privateViewingKey - The private viewing key as a Uint8Array
 * @returns The corresponding public viewing key as a Uint8Array
 * @example
 * ```typescript
 * const privateKey = new Uint8Array([1, 2, 3, 4, 5]);
 * const publicKey = getPublicViewingKey(privateKey);
 * console.log(publicKey); // Uint8Array containing the public key
 * ```
 */
const getPublicViewingKey = (
  privateViewingKey: Uint8Array
): Uint8Array => {
  return getPublicKey(privateViewingKey)
}

export {
  bigIntToUint8Array,
  uint8ArrayToBigInt,
  getPublicKey,
  getPublicSpendingKey,
  getPublicViewingKey,
  privateKeyToPublicKey,
  signPoseidon,
  verifyEDDSA,
  poseidon,
  poseidonHex,
  eddsaBuild,
  poseidonBuild,
  wrapperModule
}
