// import assert from 'node:assert/strict'

import { before, describe, it } from 'node:test'

import { expect } from 'chai'

import { poseidon, poseidonHex, privateKeyToPublicKey, signPoseidon, verifyEDDSA } from '../src'
import { uint8ArrayToBigInt } from '../src/math'

describe('Crypto-Lite module', () => {
  before(async () => {
    // before setup
  })
  it('computes nullifier', () => {
    const input = new Uint8Array([
      213, 240, 248, 140, 111, 244, 23, 235,
      61, 48, 29, 92, 187, 133, 59, 226,
      69, 42, 2, 146, 162, 37, 2, 192,
      139, 19, 97, 86, 239, 35, 80, 129
    ])
    const expected = new Uint8Array([
      22, 70, 157, 162, 69, 227, 233, 160,
      41, 212, 29, 163, 49, 10, 67, 11,
      62, 254, 124, 144, 87, 178, 140, 93,
      173, 35, 189, 183, 164, 200, 32, 209
    ])
    // const hinput = poseidon([input]);
    // console.log('hinput', hinput);
    expect(poseidon([input])).to.deep.equal(expected)
  })

  it('computes hex nullifier', () => {
    const input = new Uint8Array([
      213, 240, 248, 140, 111, 244, 23, 235,
      61, 48, 29, 92, 187, 133, 59, 226,
      69, 42, 2, 146, 162, 37, 2, 192,
      139, 19, 97, 86, 239, 35, 80, 129
    ])
    const expected = new Uint8Array([
      22, 70, 157, 162, 69, 227, 233, 160,
      41, 212, 29, 163, 49, 10, 67, 11,
      62, 254, 124, 144, 87, 178, 140, 93,
      173, 35, 189, 183, 164, 200, 32, 209
    ])
    const hexInput = uint8ArrayToBigInt(input).toString(16);
    const hexExpected = uint8ArrayToBigInt(expected)
    expect(poseidonHex(['0x' + hexInput])).to.deep.equal(hexExpected)
    expect(poseidonHex(['0x' + hexInput], true)).to.deep.equal(hexExpected.toString(16))
  })

  it('Should sign poseidon', async () => {
    const privateKey = new Uint8Array([
      213, 240, 248, 140, 111, 244, 23, 235,
      61, 48, 29, 92, 187, 133, 59, 226,
      69, 42, 2, 146, 162, 37, 2, 192,
      139, 19, 97, 86, 239, 35, 80, 129
    ])
    // const pubKey = privateKeyToPublicKey(privateKey)
    const message = new Uint8Array([
      22, 70, 157, 162, 69, 227, 233, 160,
      41, 212, 29, 163, 49, 10, 67, 11,
      62, 254, 124, 144, 87, 178, 140, 93,
      173, 35, 189, 183, 164, 200, 32, 209
    ])
    const signature = signPoseidon(privateKey, message)
    // const verified = eddsa.verifyEDDSA(message, {
    //   R8: [signature[0], signature[1]],
    //   S: BigInt('0x' + bytesToHex(signature[2]))
    // }, pubKey)
    expect(signature, 'Signature not generated.')
    // expect(verified, 'Signature not verified.')
  })

  it('Should sign & verify poseidon', async () => {
    const privateKey = new Uint8Array([
      213, 240, 248, 140, 111, 244, 23, 235,
      61, 48, 29, 92, 187, 133, 59, 226,
      69, 42, 2, 146, 162, 37, 2, 192,
      139, 19, 97, 86, 239, 35, 80, 129
    ])
    const pubKey = privateKeyToPublicKey(privateKey)
    const message = new Uint8Array([
      22, 70, 157, 162, 69, 227, 233, 160,
      41, 212, 29, 163, 49, 10, 67, 11,
      62, 254, 124, 144, 87, 178, 140, 93,
      173, 35, 189, 183, 164, 200, 32, 209
    ])
    // const convert = (arr: any) => {
    //   return BigInt('0x' + uint8ArrayToBigInt(arr).toString(16));
    // }

    const expected = [
      new Uint8Array([
        39, 189, 32, 168, 242, 83, 145, 186,
        218, 211, 193, 6, 165, 189, 41, 156,
        58, 161, 55, 72, 45, 157, 124, 232,
        188, 88, 106, 105, 191, 37, 113, 62
      ]),
      new Uint8Array([
        0, 18, 216, 188, 251, 179, 0, 93,
        10, 95, 124, 157, 37, 170, 112, 233,
        47, 106, 169, 129, 48, 112, 151, 91,
        227, 194, 15, 56, 6, 96, 86, 143
      ]),
      new Uint8Array([
        221, 193, 178, 218, 65, 42, 58, 45,
        58, 34, 24, 85, 14, 16, 30, 88,
        160, 174, 191, 220, 36, 35, 130, 208,
        111, 67, 150, 8, 188, 174, 13, 5
      ])
    ]
    const signature = signPoseidon(privateKey, message)
    // REMEMBER REVERSE MODIFIES THE ACTUAL OBJ
    expect(signature).to.deep.equal(expected)
    expect(signature, 'Signature not generated.')

    const verified = verifyEDDSA(message, {
      R8: [signature[0], signature[1]],
      // @ts-ignore
      S: signature[2],
    }, pubKey)

    expect(verified, 'Signature not verified.').to.eq(true)
  })
})
