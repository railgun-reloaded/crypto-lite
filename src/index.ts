/* eslint-disable import-x/group-exports */
/* eslint-disable jsdoc/require-jsdoc */

// @ts-ignore TODO: typefix
// export { randomBytes } from '@noble/curves/utils.js';
import {
  //  ExtendedPoint as Point,
  getPublicKey
} from '@noble/ed25519'
// import * as ed from '@noble/ed25519'
// import { blake512 } from '@noble/hashes/blake1'
// console.log(blake512)

import buildEddsa from './eddsa-noble'
// @ts-ignore TODO: typefix
import { bigIntToUint8Array, uint8ArrayToBigInt } from './math'

// import { ShieldNoteERC20 } from './notes/shield-note-erc20.js';

// export * from './notes'

// maybe this is no longer needed?
// ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m))

// const poseidonPromise = buildPoseidonOpt();

interface CircomlibSignature {
  R8: [Uint8Array, Uint8Array];
  S: bigint;
}

export const SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n
export const eddsaBuild = buildEddsa()

export const poseidonBuild = eddsaBuild.poseidon
export const wrapperModule = {
  eddsaBuild,
  poseidonBuild
}
// initialize sha512 sync

export const poseidon = (inputs: Uint8Array[]) => {
  // prefer wasm, (dev) must be manually initialized as such.
  // eddsaBuild = eddsaPromise;
  // console.log(eddsaBuild.babyjubjub)
  // const _poseidon = poseidonBuild; // typeof typeof poseidonBuild.wasm === 'undefined' ? poseidonBuild.pure : poseidonBuild.wasm
  // if (typeof _poseidon === 'undefined') {
  //   throw new Error('Poseidon has not been loaded.');
  // }
  // // poseidon expect input of bigint
  // const _inputs = inputs.map((input) =>
  //   _poseidon.F.toMontgomery(new Uint8Array(input).reverse()),
  // );
  // const result =
  //   _poseidon.F.fromMontgomery(
  //     _poseidon(
  //       _inputs,
  //     ),
  //   );
  // console.log('result', result)
  const result = poseidonBuild(inputs)
  return bigIntToUint8Array(result).reverse()
}

export const poseidonHex = (inputs: string[], toHex = false) => {
  // TODO: sanitize inputs 32 bytes
  const result = poseidon(inputs.map(BigInt).map(bigIntToUint8Array))
  const output = uint8ArrayToBigInt(result)
  return toHex ? output.toString(16) : output
}

export const signPoseidon = (
  key: Uint8Array,
  message: Uint8Array
): [Uint8Array, Uint8Array, Uint8Array] => {
  if (typeof eddsaBuild === 'undefined') {
    throw new Error('Invalid')
  }
  // Get montgomery representation
  const montgomery = eddsaBuild.toMontgomery(
    new Uint8Array(message).reverse()
  )
  // Sign
  const sig = eddsaBuild.signPoseidon(key, montgomery)
  // console.log('SIGNED', sig)
  // Convert R8 elements from montgomery and to BE
  const r8 = sig.R8
  // .map((element: any) =>
  //   eddsaBuild.F.fromMontgomery(element).reverse()
  // )
  // 32 byte inputs only right now
  return [bigIntToUint8Array(r8.x).reverse(), bigIntToUint8Array(r8.y).reverse(), bigIntToUint8Array(sig.S as any as bigint)]
  // reversing matches output from railgun-reloaded/cryptography
  // still ned to confirm thatis valid. does not currently pass /verify/ function
  // return [r8[0], r8[1], bigIntToUint8Array(sig.S).reverse()]
}

export const verifyEDDSA = (message: Uint8Array, signature: CircomlibSignature, pubkey: [Uint8Array, Uint8Array]) => {
  if (typeof eddsaBuild === 'undefined') {
    throw new Error('Invalid')
  }
  const montgomery = eddsaBuild.fromMontgomery(
    new Uint8Array(message).reverse()
  )
  // console.log('SIGGGGGG', signature)
  //  use raw values
  const r8 = signature.R8.map((element: any) => uint8ArrayToBigInt(element.reverse()))
  const newSig = {
    R8: { x: r8[0]!, y: r8[1]! },
    S: uint8ArrayToBigInt(signature.S as any as Uint8Array),
  }
  const newPubKey = pubkey.map((element: any) => uint8ArrayToBigInt(element.reverse()))

  return eddsaBuild.verifyPoseidon(montgomery, newSig, { x: newPubKey[0]!, y: newPubKey[1]! })
}

// used for getPublicSpendingKey
export const privateKeyToPublicKey = (
  privateKey: Uint8Array
): [Uint8Array, Uint8Array] | any => {
  const key = eddsaBuild
    .prv2pub(privateKey)
    .map((element: any) => eddsaBuild.fromMontgomery(element).reverse()) as [Uint8Array, Uint8Array]
  return key
}

export const getPublicSpendingKey = (privateKey: Uint8Array): [Uint8Array, Uint8Array] => {
  // convert this from
  if (privateKey.length !== 32) throw Error('Invalid private key length')
  return privateKeyToPublicKey(privateKey)
}

export const getPublicViewingKey = (
  privateViewingKey: Uint8Array
): Uint8Array => {
  return getPublicKey(privateViewingKey)
}

// add in aes operations
// recheck bn254
