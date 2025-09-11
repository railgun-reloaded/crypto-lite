/* eslint-disable import-x/group-exports */
/* eslint-disable jsdoc/require-jsdoc */

// @ts-ignore TODO: typefix
import {
  getPublicKey
} from '@noble/ed25519'

import buildEddsa from './eddsa-noble'
import { bigIntToUint8Array, uint8ArrayToBigInt } from './math'

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

export const poseidon = (inputs: Uint8Array[]) => {
  // TODO: wasm import
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
  const montgomery = eddsaBuild.toMontgomery(
    new Uint8Array(message).reverse()
  )
  const sig = eddsaBuild.signPoseidon(key, montgomery)
  const r8 = sig.R8
  return [bigIntToUint8Array(r8.x).reverse(), bigIntToUint8Array(r8.y).reverse(), bigIntToUint8Array(sig.S as any as bigint)]
}

export const verifyEDDSA = (message: Uint8Array, signature: CircomlibSignature, pubkey: [Uint8Array, Uint8Array]) => {
  if (typeof eddsaBuild === 'undefined') {
    throw new Error('Invalid')
  }
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

export const privateKeyToPublicKey = (
  privateKey: Uint8Array
): [Uint8Array, Uint8Array] | any => {
  const key = eddsaBuild
    .prv2pub(privateKey)
    .map((element: any) => eddsaBuild.fromMontgomery(element).reverse()) as [Uint8Array, Uint8Array]
  return key
}

export const getPublicSpendingKey = (privateKey: Uint8Array): [Uint8Array, Uint8Array] => {
  if (privateKey.length !== 32) throw Error('Invalid private key length')
  return privateKeyToPublicKey(privateKey)
}

export const getPublicViewingKey = (
  privateViewingKey: Uint8Array
): Uint8Array => {
  return getPublicKey(privateViewingKey)
}
