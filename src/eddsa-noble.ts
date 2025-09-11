/* eslint-disable jsdoc/require-jsdoc */
import type { EdwardsOpts } from '@noble/curves/abstract/edwards'
import { edwards } from '@noble/curves/abstract/edwards'
import { blake512 } from '@noble/hashes/blake1'

// import { eddsa } from './edwards.js'
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

const BabyJubPoint = edwards(babyjubjubCURVE)

// function poseidonHash (inputs: bigint[]): Uint8Array {
//   const hash = poseidon(inputs, [], 1)
//   return BabyJubPoint.Fn.toBytes(hash)
// }

// const babyjubjub = eddsa(BabyJubPoint, blake512, poseidonHash)

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

class EddsaPoseidon {
  private readonly Point = BabyJubPoint                 // noble Point constructor
  private readonly n = this.Point.CURVE().n             // subgroup order
  private readonly Base8: Affine                        // 8*G (affine)
  public readonly Fp = this.Point.Fp                    // base field
  public readonly Fr = this.Point.Fn                    // base field
  public readonly poseidon: any

  constructor () {
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

  prv2pub (prv: Uint8Array): [bigint, bigint] {
    const sBuff = this.pruneBuffer(blake512(prv)) // 64 bytes
    const s = leBytesToBigint(sBuff.subarray(0, 32))
    const sShr3 = s >> 3n
    const point = this.Point.fromAffine(this.Base8).multiplyUnsafe(sShr3).toAffine() as Affine
    return [point.x, point.y]
  }

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

    const hm = this.poseidon([R8.x, R8.y, A.x, A.y, msgField]) % this.n
    const hms = this.Fr.create(hm)
    const subOrder = this.Fr.ORDER >> 3n
    const mul = hms * s
    const add = r + mul
    const S = add % subOrder
    return { R8, S }
  }

  verifyPoseidon (msg: Uint8Array, sig: { R8: Affine, S: bigint }, A: Affine) {
    const { R8, S } = sig
    const subOrder = this.Fr.ORDER >> 3n

    if (S >= subOrder) return false
    const R = this.Point.fromAffine(R8)
    const Ap = this.Point.fromAffine(A)

    if (!R.multiplyUnsafe(subOrder).equals(this.Point.ZERO)) return false
    if (!Ap.multiplyUnsafe(subOrder).equals(this.Point.ZERO)) return false
    const msgField = this.Fr.create(leBytesToBigint(msg))
    const hm = this.poseidon([R8.x, R8.y, A.x, A.y, msgField]) % this.n
    const hms = this.Fr.create(hm)

    const left = this.Point.fromAffine(this.Base8)
      .multiplyUnsafe(S % subOrder)
      .toAffine() as Affine

    const k = (hms * 8n) % this.n
    const right = R.add(Ap.multiplyUnsafe(k)).toAffine() as Affine

    return left.x === right.x && left.y === right.y
  }
}

export default function buildEddsaPoseidon () {
  return new EddsaPoseidon()
}

export { EddsaPoseidon, BabyJubPoint }
