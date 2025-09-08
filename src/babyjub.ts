/* eslint-disable jsdoc/require-jsdoc */
// @ts-ignore -typefix
import { Scalar } from 'ffjavascript'

import { Fr } from './bn254'
// https://github.com/paulmillr/noble-curves/issues/168
// TODO maybe reimplement with twistedEdwards noble

class BabyJub {
  F: typeof Fr
  p: any
  pm1d2: any
  Generator: bigint[]
  Base8: bigint[]
  order: any
  subOrder: any
  A: bigint
  D: bigint
  constructor (F: typeof Fr) {
    this.F = F
    this.p = Scalar.fromString(
      '21888242871839275222246405745257275088548364400416034343698204186575808495617'
    )
    this.pm1d2 = Scalar.div(Scalar.sub(this.p, Scalar.e(1)), Scalar.e(2))

    this.Generator = [
      F.e(
        '995203441582195749578291179787384436505546430278305826713579947235728471134'
      ),
      F.e(
        '5472060717959818805561601436314318772137091100104008585924551046643952123905'
      ),
    ]
    this.Base8 = [
      F.e(
        '5299619240641551281634865583518297030282874472190772894086521144482721001553'
      ),
      F.e(
        '16950150798460657717958625567821834550301663161624707787222815936182638968203'
      ),
    ]
    this.order = Scalar.fromString(
      '21888242871839275222246405745257275088614511777268538073601725287587578984328'
    )
    this.subOrder = Scalar.shiftRight(this.order, 3)
    this.A = F.e('168700')
    this.D = F.e('168696')
  }

  addPoint (a: bigint[], b: bigint[]): bigint[] {
    const F = this.F

    const res = []

    const [aX, aY] = a as [bigint, bigint]
    const [bX, bY] = b as [bigint, bigint]

    const beta = F.mul(aX, bY)
    const gamma = F.mul(aY, bX)
    const delta = F.mul(F.sub(aY, F.mul(this.A, aX)), F.add(bX, bY))
    const tau = F.mul(beta, gamma)
    const dtau = F.mul(this.D, tau)

    res[0] = F.div(F.add(beta, gamma), F.add(F.one, dtau))

    res[1] = F.div(
      F.add(delta, F.sub(F.mul(this.A, beta), gamma)),
      F.sub(F.one, dtau)
    )

    return res
  }

  mulPointEscalar (base: bigint[], e: bigint): bigint[] {
    const F = this.F
    let res = [F.e('0'), F.e('1')]
    let rem = e
    let exp = base

    while (!Scalar.isZero(rem)) {
      if (Scalar.isOdd(rem)) {
        res = this.addPoint(res, exp)
      }
      exp = this.addPoint(exp, exp)
      rem = Scalar.shiftRight(rem, 1)
    }

    return res
  }

  inSubgroup (P: bigint[]) {
    const F = this.F
    if (!this.inCurve(P)) return false
    const res = this.mulPointEscalar(P, this.subOrder) as [bigint, bigint]
    return F.isZero(res[0]) && F.eq(res[1], F.one)
  }

  inCurve (P: bigint[]) {
    const F = this.F
    const x2 = F.square(P[0]!)
    const y2 = F.square(P[1]!)

    if (
      !F.eq(
        F.add(F.mul(this.A, x2), y2),
        F.add(F.one, F.mul(F.mul(x2, y2), this.D))
      )
    ) { return false }

    return true
  }
}

export default function buildBabyJub () {
  return new BabyJub(Fr)
}
