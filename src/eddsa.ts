/* eslint-disable jsdoc/require-jsdoc */
// @ts-ignore: type-error
import createBlakeHash from 'blake-hash'
// @ts-ignore: type-error
import { Scalar } from 'ffjavascript'

import buildBabyJub from './babyjub.js'
import buildPoseidon from './poseidon_opt.js'

class Eddsa {
  babyJub: any
  poseidon: any
  F: any
  constructor (babyJub: any, poseidon: any) {
    this.babyJub = babyJub
    this.poseidon = poseidon
    this.F = babyJub.F
  }

  pruneBuffer (buff: Uint8Array) {
    buff[0] = buff[0]! & 0xf8
    buff[31] = buff[31]! & 0x7f
    buff[31] = buff[31] | 0x40
    return buff
  }

  prv2pub (prv: Uint8Array) {
    // uneeded
    // const F = this.babyJub.F;
    const sBuff = this.pruneBuffer(
      createBlakeHash('blake512').update(Buffer.from(prv)).digest()
    )
    const s = Scalar.fromRprLE(sBuff, 0, 32)
    const A = this.babyJub.mulPointEscalar(
      this.babyJub.Base8,
      Scalar.shr(s, 3)
    )
    return A
  }

  signPoseidon (prv: Uint8Array, msg: Uint8Array) {
    const F = this.babyJub.F
    const sBuff = this.pruneBuffer(
      createBlakeHash('blake512').update(Buffer.from(prv)).digest()
    )
    const s = Scalar.fromRprLE(sBuff, 0, 32)
    const A = this.babyJub.mulPointEscalar(
      this.babyJub.Base8,
      Scalar.shr(s, 3)
    )
    // console.log("A, old", A)
    const composeBuff = new Uint8Array(32 + msg.length)
    // console.log("composeBuff", composeBuff)
    composeBuff.set(sBuff.slice(32), 0)
    // console.log("composeBuff", composeBuff)
    F.toRprLE(composeBuff, 32, msg)
    const rBuff = createBlakeHash('blake512')
      .update(Buffer.from(composeBuff))
      .digest()
    // console.log("rBuff", uint8ArrayToBigInt(rBuff))

    // console.log("composeBuff", composeBuff)
    const r = Scalar.mod(Scalar.fromRprLE(rBuff, 0, 64), this.babyJub.subOrder)
    const R8 = this.babyJub.mulPointEscalar(this.babyJub.Base8, r)

    const hm = this.poseidon([R8[0], R8[1], A[0], A[1], msg])
    // console.log("hm old", hm)
    const hms = Scalar.e(this.babyJub.F.toObject(hm))
    // console.log('hms old', hms)
    // const aa = Scalar.mul(hms, s)
    // console.log('aa', aa)
    // const bb = Scalar.add(r, aa)
    // console.log('bb', bb)
    // console.log('suborder', this.babyJub.subOrder)
    // console.log('order', this.babyJub.order)
    const S = Scalar.mod(
      Scalar.add(r, Scalar.mul(hms, s)),
      this.babyJub.subOrder
    )
    // console.log('S', S)
    return {
      R8,
      S,
    }
  }

  verifyPoseidon (msg: Uint8Array, sig: any, A: any) {
    if (typeof sig !== 'object') return false
    if (!Array.isArray(sig.R8)) return false
    if (sig.R8.length !== 2) return false
    if (!this.babyJub.inCurve(sig.R8)) return false
    if (!Array.isArray(A)) return false
    if (A.length !== 2) return false
    if (!this.babyJub.inCurve(A)) return false
    if (sig.S >= this.babyJub.subOrder) return false

    const hm = this.poseidon([sig.R8[0], sig.R8[1], A[0], A[1], msg])
    const hms = Scalar.e(this.babyJub.F.toObject(hm))

    const Pleft = this.babyJub.mulPointEscalar(this.babyJub.Base8, sig.S)
    // console.log("Pleft", Pleft)
    let Pright = this.babyJub.mulPointEscalar(A, Scalar.mul(hms, 8))
    // console.log("pRight", Pright)
    Pright = this.babyJub.addPoint(sig.R8, Pright)

    // console.log("pRight", Pright)

    if (!this.babyJub.F.eq(Pleft[0], Pright[0])) return false
    if (!this.babyJub.F.eq(Pleft[1], Pright[1])) return false
    return true
  }
}

// export default new Eddsa(buildBabyJub(), buildPoseidon())
export default function buildEddsaPoseidon () {
  const babyJub = buildBabyJub()
  const poseidon = buildPoseidon()
  return new Eddsa(babyJub, poseidon)
}
