/* eslint-disable import-x/exports-last */
/* eslint-disable import-x/group-exports */
/* eslint-disable jsdoc/require-jsdoc */
// import type { EdDSA } from '@noble/curves/abstract/edwards'
import { edwards } from '@noble/curves/abstract/edwards'
import type { EdwardsOpts } from '@noble/ed25519'
import { blake512 } from '@noble/hashes/blake1'

// import type { FieldInput } from './bn254.js'
import { eddsa } from './edwards.js'
import buildPoseidon from './poseidon_opt.js'

const poseidon = buildPoseidon()

const babyjubjubCURVE: EdwardsOpts = {
  p: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n,
  n: 0x30644e72e131a029b85045b68181585d59f76dc1c90770533b94bee1c9093788n,
  h: 8n,
  a: 168700n,
  d: 168696n,
  Gx: 0x023343e3445b673d38bcba38f25645adb494b1255b1162bb40f41a59f4d4b45en,
  Gy: 0x0c19139cb84c680a6e14116da06056174a0cfa121e6e5c2450f87d64fc000001n,
}

export const BabyJubPoint = edwards(babyjubjubCURVE)

function poseidonHash (inputs: bigint[]): Uint8Array {
  // convert output into uint8array
  console.log('INPUTS', inputs)
  const hash = poseidon(inputs, [], 1)
  return BabyJubPoint.Fn.toBytes(hash)
}

export const babyjubjub = eddsa(BabyJubPoint, blake512, poseidonHash)

type Affine = { x: bigint; y: bigint }

function clampPrune32 (b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b)
  out[0]! &= 0xf8
  out[31]! &= 0x7f
  out[31]! |= 0x40
  return out
}
function leBytesToBigint (u8: Uint8Array): bigint {
  let n = 0n
  for (let i = u8.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u8[i]!)
  return n
}

export class EddsaPoseidon {
  private readonly Point = BabyJubPoint                 // noble Point constructor
  public readonly Fp = this.Point.Fp                   // base field
  public readonly Fr = this.Point.Fn                   // base field
  private readonly n = this.Point.CURVE().n             // subgroup order
  private readonly Base8: Affine                        // 8*G (affine)
  public readonly poseidon: any

  constructor () {
    // Base8 = 8 * BASE, stored as affine
    this.Base8 = this.Point.BASE.multiplyUnsafe(8n).toAffine() as Affine
    this.poseidon = poseidon
  }

  toBytes (a: bigint) {
    return this.Fr.toBytes(a)
  }

  fromBytes (a: Uint8Array) {
    return this.Fr.fromBytes(a, true)
  }

  toMontgomery (a: bigint | Uint8Array) {
    if (a instanceof Uint8Array) {
      return this.Fr.toBytes(this.Fr.fromBytes(a, true))
    }
    return this.Fr.toBytes(this.Fr.create(BigInt(a)))
  }

  fromMontgomery (a: bigint | Uint8Array) {
    if (a instanceof Uint8Array) {
      return this.Fr.toBytes(this.Fr.fromBytes(a, true))
    }
    return this.Fr.toBytes(this.Fr.create(BigInt(a)))
  }

  pruneBuffer (buff: Uint8Array) {
    return clampPrune32(buff)
  }

  // A = Base8 * (s >> 3), s from pruned blake512(prv)[0..31] LE
  prv2pub (prv: Uint8Array): [bigint, bigint] {
    const sBuff = this.pruneBuffer(blake512(prv)) // 64 bytes
    const s = leBytesToBigint(sBuff.subarray(0, 32))
    const sShr3 = s >> 3n
    const point = this.Point.fromAffine(this.Base8).multiplyUnsafe(sShr3).toAffine() as Affine
    return [point.x, point.y]
  }

  // Circom-compatible Poseidon EDDSA:
  // r = blake512(sBuff[32..64) || msg) mod n
  // R8 = Base8 * r
  // hm = Poseidon(R8x, R8y, Ax, Ay, msgField), msgField reduced into Fp
  // S = (r + hm*s) mod n
  signPoseidon (prv: Uint8Array, msg: Uint8Array) {
    const sBuff = this.pruneBuffer(blake512(prv)) // 64 bytes
    const s = leBytesToBigint(sBuff.subarray(0, 32))
    const A = (this.Point.fromAffine(this.Base8) as any).multiplyUnsafe(s >> 3n).toAffine() as Affine
    // console.log("A, new", A)

    const compose = new Uint8Array(32 + msg.length)
    // console.log("composeBuff new", compose)
    compose.set(sBuff.subarray(32, 64), 0)
    // console.log("composeBuff new", compose)
    compose.set(msg, 32)
    // console.log("composeBuff new", compose)

    const r = leBytesToBigint(blake512(compose)) % this.n

    // console.log('rbuff new', r)
    const R8 = (this.Point.fromAffine(this.Base8) as any).multiplyUnsafe(r).toAffine() as Affine

    // Reduce msg into Fp (BN254) via Fp.create

    const msgField = this.Fr.create(leBytesToBigint(msg))

    const hm = this.poseidon([R8.x, R8.y, A.x, A.y, msgField]) % this.n
    // console.log("hm new", hm)
    const hms = this.Fr.create(hm)
    // console.log('hms new', hms)

    // const S = (r + hm * s) % this.Fp.ORDER
    const subOrder = this.Fr.ORDER >> 3n
    // console.log('subOrder', subOrder, this.Point.CURVE())
    // console.log('this.fp.order', this.Fp.ORDER, this.Fr.ORDER, subOrder)
    const mul = hms * s
    const add = r + mul
    const S = add % subOrder // % this.Point.Fn.ORDER
    // reorder inputs
    // msg.reverse()
    return { R8, S }
    // return [R8.x, R8.y, S]
  }

  // Check: Base8*S == R8 + A*(hm*8)
  verifyPoseidon (msg: Uint8Array, sig: { R8: Affine, S: bigint }, A: Affine) {
    const { R8, S } = sig
    // const { x: Rx, y: Ry } = R8
    const subOrder = this.Fr.ORDER >> 3n

    if (S >= subOrder) return false

    // const R8 = { x: Rx, y: Ry } as Affine
    const R = this.Point.fromAffine(R8)
    const Ap = this.Point.fromAffine(A)

    // subgroup checks
    if (!R.multiplyUnsafe(subOrder).equals(this.Point.ZERO)) return false
    if (!Ap.multiplyUnsafe(subOrder).equals(this.Point.ZERO)) return false
    // console.log("PASSES SUBGROUP CHECKS")
    // requires the msg.reverse
    const msgField = this.Fr.create(leBytesToBigint(msg))
    // msg.reverse()
    const hm = this.poseidon([R8.x, R8.y, A.x, A.y, msgField]) % this.n
    const hms = this.Fr.create(hm)

    const left = this.Point.fromAffine(this.Base8)
      .multiplyUnsafe(S % subOrder)
      .toAffine() as Affine
    // console.log("Pleft new", left)

    const k = (hms * 8n) % this.n
    const right = R.add(Ap.multiplyUnsafe(k)).toAffine() as Affine
    // console.log("pRight new", right)

    return left.x === right.x && left.y === right.y
  }
}

// Factory
export default function buildEddsaPoseidon2 () {
  return new EddsaPoseidon()
}
