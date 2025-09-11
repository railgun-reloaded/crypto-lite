/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable import-x/group-exports */
/* eslint-disable jsdoc/require-jsdoc */
// import type { IField } from '@noble/curves/abstract/modular'

import type { IField } from '@noble/curves/abstract/modular'

import poseidonConstants from '../src/poseidon_constants_opt'
// const scalar = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const N_ROUNDS_F = 8
const N_ROUNDS_P = [
  56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
]

export function unsringifyConstants (F: any, o: typeof poseidonConstants): any {
  if (typeof o === 'string' && /^[0-9]+$/.test(o)) {
    return F.create(BigInt('0x' + o))// % F.ORDER
  } else if (typeof o === 'string' && /^0x[0-9a-fA-F]+$/.test(o)) {
    return F.create(BigInt(o))// % F.ORDER
  } else if (Array.isArray(o)) {
    return o.map(unsringifyConstants.bind(null, F))
  } else if (typeof o === 'object') {
    if (o === null) return null
    const res: any = {}
    const keys = Object.keys(o)
    keys.forEach((k) => {
      // @ts-ignore - TODO: typefix
      res[k] = unsringifyConstants(F, o[k])
    })
    return res
  } else {
    return o
  }
}

export function createPoseidon (opts: {
  Fp: IField<bigint>;
  // t: number;                // state size
  // rate: number;             // rate
  // capacity: number;         // capacity
}) {
  const {
    Fp,
    // t,
  } = opts
  // console.log(Fp.ORDER, t)
  const nRoundsF = N_ROUNDS_F

  const constants = unsringifyConstants(Fp, poseidonConstants)
  // console.log(nRoundsF, nRoundsP)
  const { C, S, M, P } = constants

  // console.log(C, S, M, P, nRoundsF, nRoundsP)

  // const halfFull = Math.floor(nRoundsF / 2)
  const pow5 = (a: bigint) => Fp.pow(Fp.create(a), 5n)
  // console.log(pow5(10n))

  // function e (input: any) {
  //   if (input instanceof Uint8Array) {
  //     return Fp.fromBytes(input, true)
  //   }
  //   return Fp.create(BigInt(input))
  // }

  function getConstants (t: number) {
    const c = C[t - 2]!
    const s = S[t - 2]!
    const m = M[t - 2]!
    const p = P[t - 2]!
    return { c, s, m, p }
  }

  
  function initializeState (inputs: bigint[]) {
    const initState = Fp.ZERO
    const t = inputs.length + 1
    const { c } = getConstants(t)
    let state = [initState, ...inputs.map((a) => Fp.create(Fp.fromBytes(Fp.toBytes(a).reverse()))), ...new Array(t - 2).fill(0n)]
    state = state.map((a, i) => Fp.add(a, ((c[i]!))))
    return state
  }
  function addRoundConstants (state: bigint[], round: number, c: bigint[]): bigint[] {
    return state.map((a, i) => Fp.add(a, ((c[round + i]!))))
  }

  function sBox (_state: bigint[]) {
    return _state.map((a) => pow5(a))
  }

  function reduceConstant (_state: bigint[], c: bigint[][]) {
    let state = _state
    state = state.map((_, i) =>
      state.reduce((acc, a, j) => Fp.add(acc, Fp.mul(c[j]![i]!, a)), Fp.ZERO)
    )
    return state
  }

  function permute (_state: bigint[]): bigint[] {
    const t = _state.length
    const nRoundsP = N_ROUNDS_P[t - 2]

    const { c, m, p, s } = getConstants(t)
    let state = _state
    for (let r = 0; r < nRoundsF / 2 - 1; r++) {
      state = sBox(state)
      state = addRoundConstants(state, t * (r + 1), c)
      state = reduceConstant(state, m)
    }

    state = sBox(state)
    state = addRoundConstants(state, t * (nRoundsF / 2 - 1 + 1), c)
    state = reduceConstant(state, p)
    // compute main hash
    for (let r = 0; r < nRoundsP!; r++) {
      state[0] = pow5(state[0]!)
      state[0] = Fp.add(state[0], c[(nRoundsF / 2 + 1) * t + r])
      const s0 = state.reduce((acc, a, j) => {
        return Fp.add(acc, Fp.mul(s[(t * 2 - 1) * r + j], a))
      }, Fp.ZERO)
      for (let k = 1; k < t; k++) {
        state[k] = Fp.add(
          state[k]!,
          Fp.mul(state[0], s[(t * 2 - 1) * r + t + k - 1])
        )
      }
      state[0] = s0
    }
    // final round
    for (let r = 0; r < nRoundsF / 2 - 1; r++) {
      state = sBox(state)
      state = addRoundConstants(state, ((nRoundsF / 2 + 1) * t + nRoundsP! + r * t), c)
      // state = state.map((a, i) =>
      //   Fp.add(a, c[(nRoundsF / 2 + 1) * t + nRoundsP! + r * t + i])
      // )
      state = reduceConstant(state, m)
    }

    state = sBox(state)
    state = reduceConstant(state, m)

    return state
  }

  // Circom convention: hash(inputs) fills rate slots, last slot = 0
  function hash (inputs: bigint[]): bigint {
    if (inputs.length === 0) {
      throw new Error(`Poseidon: invalid inputs got ${inputs.length}`)
    }
    let state = initializeState(inputs)
    state = permute(state)
    return state[0]
  }

  return { hash, permute }
}
