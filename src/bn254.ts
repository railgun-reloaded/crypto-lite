/* eslint-disable import-x/group-exports */
// TODO: remove this
/* eslint-disable jsdoc/require-jsdoc */

import { bn254 } from '@noble/curves/bn254'
import { randomBytes } from '@noble/curves/utils'

type FieldInput = bigint | number | string
type FieldPointDouble = bigint[]
type FieldPointSingle = bigint[]

export const NobleFr = bn254.fields.Fr
export function toIField (f:FieldInput) {
  return NobleFr.create(BigInt(f))
}

export type { FieldPointDouble, FieldPointSingle, FieldInput }
export const Fr = {

  bitLength: 254,
  zero: NobleFr.ZERO,
  one: NobleFr.ONE,
  p: NobleFr.ORDER,

  add: (a: FieldInput, b: FieldInput) => NobleFr.add(toIField(a), toIField(b)),
  sub: (a: FieldInput, b: FieldInput) => NobleFr.sub(toIField(a), toIField(b)),
  mul: (a: FieldInput, b: FieldInput) => NobleFr.mul(toIField(a), toIField(b)),

  square: (a: FieldInput) => NobleFr.sqr(toIField(a)),
  eq: (a: FieldInput, b: FieldInput) => NobleFr.eql(toIField(a), toIField(b)),

  div: (a: FieldInput, b: FieldInput) => NobleFr.div(toIField(a), toIField(b)),
  inv: (a: FieldInput) => NobleFr.inv(toIField(a)),
  neg: (a: FieldInput) => NobleFr.neg(toIField(a)),
  pow: (base: FieldInput, exp: FieldInput) => NobleFr.pow(toIField(base), BigInt(exp)),

  isZero: (a: FieldInput) => {
    const value = toIField(a)
    return NobleFr.eql(value, NobleFr.ZERO)
  },

  toObject: (a: FieldInput) => toIField(a),
  toString: (a: FieldInput, base: number = 10) => toIField(a).toString(base),
  e: (a: FieldInput | Uint8Array) => {
    if (a instanceof Uint8Array) {
      return NobleFr.fromBytes(a, true)
    }
    return toIField(a)
  },

  // little-endian support (Noble doesn't have this)
  toRprLE: (buffer: Uint8Array, offset: number, value: FieldInput | Uint8Array) => {
    let bytes: Uint8Array
    if (value instanceof Uint8Array) {
      bytes = value
    } else {
      bytes = NobleFr.toBytes(toIField(value))
    }
    // convert big-endian to little-endian
    const leBytes = new Uint8Array(bytes).reverse()
    const copyLength = Math.min(leBytes.length, buffer.length - offset)
    buffer.set(leBytes.slice(0, copyLength), offset)
  },

  fromRprLE: (buffer: Uint8Array, offset: number = 0, length: number = 32) => {
    const bytes = buffer.slice(offset, offset + length)
    // Pad or trim to 32 bytes
    const paddedBytes = new Uint8Array(32)
    paddedBytes.set(bytes.slice(0, Math.min(bytes.length, 32)))
    // Convert little-endian to big-endian for Noble
    const beBytes = paddedBytes.reverse()
    return NobleFr.fromBytes(beBytes)
  },

  // Big-endian (direct Noble usage)
  toBytes: (value: FieldInput) => NobleFr.toBytes(toIField(value)),
  fromBytes: (bytes: Uint8Array) => NobleFr.fromBytes(bytes),

  // Montgomery form - Noble handles internally
  toMontgomery: (a: FieldInput | Uint8Array) => {
    if (a instanceof Uint8Array) {
      return NobleFr.toBytes(NobleFr.fromBytes(a))
    }
    return NobleFr.toBytes(toIField(a))
  },

  fromMontgomery: (a: FieldInput | Uint8Array) => {
    if (a instanceof Uint8Array) {
      return NobleFr.toBytes(NobleFr.fromBytes(a))
    }
    return NobleFr.toBytes(toIField(a))
  },

  isValid: (value: bigint) => {
    try {
      NobleFr.create(value)
      return true
    } catch {
      return false
    }
  },

  random: () => {
    const bytes = randomBytes(32)
    return NobleFr.fromBytes(bytes)
  },

  toHex: (value: bigint) => '0x' + NobleFr.create(value).toString(16).padStart(64, '0'),
  fromHex: (hex: string) => {
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex
    return toIField('0x' + cleanHex)
  },

  mod: (a: FieldInput, b: FieldInput) => {
    // Noble handles modular reduction automatically, but for compatibility:
    const aVal = toIField(a)
    const bVal = BigInt(b)
    return aVal % bVal
  },

  shr: (a: FieldInput, bits: number) => {
    const aVal = BigInt(a)
    return NobleFr.create(aVal >> BigInt(bits))
  },

} as const
