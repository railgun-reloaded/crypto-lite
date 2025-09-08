/* eslint-disable import-x/exports-last */
/* eslint-disable import-x/group-exports */
/* eslint-disable jsdoc/require-jsdoc */
import type { EdDSA } from '@noble/curves/abstract/edwards'
import { eddsa, edwards } from '@noble/curves/abstract/edwards'
import type { EdwardsOpts } from '@noble/ed25519'
import { blake512 } from '@noble/hashes/blake1'

import buildPoseidon from './poseidon_opt.js'
import type { FieldInput } from './bn254.js'

// -------- Curve --------
const babyjubjubCURVE: EdwardsOpts = {
  p: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n,
  n: 0x30644e72e131a029b85045b68181585d59f76dc1c90770533b94bee1c9093788n,
  h: 8n,
  a: 168700n,
  d: 168696n,
  Gx: 0x023343e3445b673d38bcba38f25645adb494b1255b1162bb40f41a59f4d4b45en,
  Gy: 0x0c19139cb84c680a6e14116da06056174a0cfa121e6e5c2450f87d64fc000001n,
}

export const BabyJubPoint = edwards(babyjubjubCURVE) // <-- THIS IS THE POINT CLASS
export const babyjubjub: EdDSA = eddsa(BabyJubPoint, blake512)

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
  private readonly Fp = this.Point.Fp                   // base field
  public readonly Fr = this.Point.Fn                   // base field
  private readonly n = this.Point.CURVE().n             // subgroup order
  private readonly Base8: Affine                        // 8*G (affine)
  private readonly poseidon: (inputs: bigint[]) => bigint

  constructor (poseidon: (inputs: bigint[]) => bigint) {
    // Base8 = 8 * BASE, stored as affine
    this.Base8 = this.Point.BASE.multiplyUnsafe(8n).toAffine() as Affine
    this.poseidon = poseidon
  }

  toMontgomery (a: FieldInput | Uint8Array) {
    if (a instanceof Uint8Array) {
      return this.Fr.toBytes(this.Fr.fromBytes(a))
    }
    return this.Fr.toBytes(this.Fr.create(BigInt(a)))
  }

  fromMontgomery (a: FieldInput | Uint8Array) {
    if (a instanceof Uint8Array) {
      return this.Fr.toBytes(this.Fr.fromBytes(a))
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

    const A = this.Point.fromAffine(this.Base8)
      .multiplyUnsafe(s >> 3n)
      .toAffine() as Affine

    const compose = new Uint8Array(32 + msg.length)
    compose.set(sBuff.subarray(32, 64), 0)
    compose.set(msg, 32)

    const r = leBytesToBigint(blake512(compose)) % this.n
    const R8 = this.Point.fromAffine(this.Base8).multiplyUnsafe(r).toAffine() as Affine

    const msgField = this.Fp.create(leBytesToBigint(msg)) // reduce into Fp
    const hm = this.poseidon([R8.x, R8.y, A.x, A.y, msgField]) // % this.n

    const S = (r + hm * s) % this.n
    const output = [R8.x, R8.y, S]
    return output
    // return { R8: [R8.x, R8.y], S, A: [A.x, A.y] }
  }

  // Check: Base8*S == R8 + A*(hm*8)
  verifyPoseidon (msg: Uint8Array, sig: { R8: Affine; S: bigint }, A: Affine): boolean {
    if (!sig?.R8 || typeof sig.S !== 'bigint') return false
    if (sig.S >= this.n) return false

    const R = this.Point.fromAffine(sig.R8)
    const Ap = this.Point.fromAffine(A)

    // optional subgroup checks
    if (!R.multiplyUnsafe(this.n).equals(this.Point.ZERO)) return false
    if (!Ap.multiplyUnsafe(this.n).equals(this.Point.ZERO)) return false

    const msgField = this.Fp.create(leBytesToBigint(msg))
    const hm = this.poseidon([sig.R8.x, sig.R8.y, A.x, A.y, msgField]) % this.n

    const left = this.Point.fromAffine(this.Base8).multiplyUnsafe(sig.S).toAffine() as Affine
    const right = R.add(Ap.multiplyUnsafe(hm * 8n)).toAffine() as Affine

    return left.x === right.x && left.y === right.y
  }
}

// Factory
export default function buildEddsaPoseidon2 () {
  return new EddsaPoseidon(buildPoseidon() as any)
}
