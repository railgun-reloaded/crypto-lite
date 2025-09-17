/* eslint-disable jsdoc/require-jsdoc */
import * as poseidonLib from 'poseidon-lite'

import { bigIntToUint8Array, uint8ArrayToBigInt } from './utils'

type PoseidonFunc = (input: (bigint | number | string)[], nOuts?: number) => bigint
const poseidonFuncs: PoseidonFunc[] = [
  poseidonLib.poseidon1,
  poseidonLib.poseidon2,
  poseidonLib.poseidon3,
  poseidonLib.poseidon4,
  poseidonLib.poseidon5,
  poseidonLib.poseidon6,
  poseidonLib.poseidon7,
  poseidonLib.poseidon8,
  poseidonLib.poseidon9,
  poseidonLib.poseidon10,
  poseidonLib.poseidon11,
  poseidonLib.poseidon12,
  poseidonLib.poseidon13,
  poseidonLib.poseidon14,
  poseidonLib.poseidon15,
  poseidonLib.poseidon16,
]

type PoseidonInput = bigint | number | string

// async function buildPoseidon () {

function poseidon (inputs: (PoseidonInput)[], returnBigInt = true, nOuts?: number) {
  const inputLen = inputs.length
  if (nOuts === undefined) {
    nOuts = 1 // Default to 1 output if not specified
  }

  if (inputLen < 1 || inputLen > 14) {
    throw new Error('Poseidon function index must be between 1 and 16')
  }

  // check if the inputs are uint8arrays, if they are convert to bigint
  for (let i = 0; i < inputs.length; i++) {
    const input: any = inputs[i]
    if (input === undefined || input === null) {
      throw new Error(`Input at index ${i} is undefined or null`)
    }
    if (typeof input === 'string') {
      inputs[i] = BigInt(input)
    } else if (typeof input === 'number') {
      inputs[i] = BigInt(input)
    } else if (input instanceof Uint8Array) {
      inputs[i] = uint8ArrayToBigInt(input) // Ensure the input is a valid Uint8Array
    } else if (typeof inputs[i] !== 'bigint') {
      throw new Error(`Invalid input type: ${typeof input}`)
    }
  }

  const func = poseidonFuncs[inputLen - 1]!
  // ignore this because it gets modified.
  const output = func(inputs as PoseidonInput[], nOuts)
  // convert this back into uint8array if nOuts is 1
  if (returnBigInt) {
    if (nOuts === 1) {
      // If nOuts is 1, return a single bigint
      if (typeof output !== 'bigint') {
        throw new Error(`Expected output to be a bigint, got ${typeof output}`)
      }
      return output
    } else {
      // If nOuts > 1, return an array of bigints
      if (!Array.isArray(output) || output.length !== nOuts) {
        throw new Error(`Expected output to be an array of length ${nOuts}`)
      }
      return output.map((out: bigint) => {
        if (typeof out !== 'bigint') {
          throw new Error(`Expected output to be a bigint, got ${typeof out}`)
        }
        return out
      })
    }
  } else {
    if (nOuts === 1) {
      return bigIntToUint8Array(output as bigint)
    } else {
      // If nOuts > 1, return an array of uint8arrays
      if (!Array.isArray(output) || output.length !== nOuts) {
        throw new Error(`Expected output to be an array of length ${nOuts}`)
      }
      return output.map((out: bigint) => {
        return bigIntToUint8Array(out as bigint)
      })
    }
  }
}

export { poseidon }
