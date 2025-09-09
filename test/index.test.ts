// import assert from 'node:assert/strict'

import { before, describe, it } from 'node:test'

import { grainGenConstants, poseidon as ppp } from '@noble/curves/abstract/poseidon'
import {
  // grainGenConstants,
  poseidonSponge,
  // poseidon as ppp
} from '@noble/curves/abstract/poseidon.js'
import { expect } from 'chai'

import { poseidon, poseidonHex, privateKeyToPublicKey, signPoseidon, verifyEDDSA } from '../src'
import { NobleFr } from '../src/bn254'
import buildEddsaPoseidon2 from '../src/eddsa-noble'
import { bigIntToUint8Array, uint8ArrayToBigInt } from '../src/math'
import opts from '../src/poseidon_constants_opt'
import { createPoseidon } from '../src/poseidon-noble'

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

  it.only('poseidon hashes new ', () => {
    // const input = new Uint8Array([
    //   213, 240, 248, 140, 111, 244, 23, 235,
    //   61, 48, 29, 92, 187, 133, 59, 226,
    //   69, 42, 2, 146, 162, 37, 2, 192,
    //   139, 19, 97, 86, 239, 35, 80, 129
    // ])
    // const expected = new Uint8Array([
    //   22, 70, 157, 162, 69, 227, 233, 160,
    //   41, 212, 29, 163, 49, 10, 67, 11,
    //   62, 254, 124, 144, 87, 178, 140, 93,
    //   173, 35, 189, 183, 164, 200, 32, 209
    // ])
    const rate = 2
    const capacity = 1
    const roundsFull = 8
    const roundsPartial = 57
    // const mds1 = opts.M[2]!.map(row => row.map(BigInt)) // t=3
    // const roundConstants1 = opts.C[2]!.map(BigInt)
    const eddsa = buildEddsaPoseidon2()
    const { mds, roundConstants } = grainGenConstants({
      Fp: NobleFr,
      t: rate + capacity,
      roundsFull,
      roundsPartial,
    })
    console.log(roundConstants.length)
    // const roundConstants = opts.C.map(a => {
    //   return a.map(BigInt)
    // })

    const _opts = {
      Fp: eddsa.Fp,
      rate,
      capacity,
      t: rate + capacity,
      sboxPower: 5,
      mds,
      roundConstants,
      roundsFull,
      roundsPartial,
    }

    const opts2 = {
      Fp: eddsa.Fp,
      // rate,
      // capacity,
      // t: rate + capacity,
      // sboxPower: 5n,
      // mds: mds1,
      // roundConstants: roundConstants1,
      // roundsFull,
      // roundsPartial,
    }
    // console.log(opts2)
    const pos3 = createPoseidon(opts2)

    const permutation = ppp(_opts)
    const sponge = poseidonSponge(_opts)() // use carefully, not specced

    // console.log(permutation, sponge)
    const p = permutation([1n, 0n, 0n])
    // const output = sponge.hash([1n, 0n, 0n])
    sponge.absorb(p)
    // console.log('output', output)
    // const a = sponge.squeeze(1)
    console.log('new poseidon', p)
    const newpos = pos3.hash([1n])
    console.log('newpos', newpos)
    const ppa = poseidon([bigIntToUint8Array(1n),
      // bigIntToUint8Array(0n), bigIntToUint8Array(0n)
    ])
    console.log('normal poseidon', uint8ArrayToBigInt(ppa))
    // console.log('sponge a', a)
    // console.log('p', p)
  })

  it('computes nullifier noble/ciphers', () => {
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
    // const roundsPartial = 8

    const mds = opts.M[1]!.map(a => {
      return a.map(BigInt)
    })
    console.log(mds)

    // const roundConstants = opts.C.map(a => {
    //   return a.slice(0, 3).map(BigInt)
    // })
    // const roundConstants = opts.C[0]!.map(BigInt)
    // // .map(a => {
    // //   return a.map(BigInt)
    // // })
    // const { mds, roundConstants } = grainGenConstants({
    //   Fp: NobleFr,
    //   t: 1,
    //   roundsFull: 8,
    //   roundsPartial
    // })
    // const genPoseidon = ppp({
    //   Fp: NobleFr,
    //   t: 3,
    //   roundsFull: 8,
    //   roundsPartial,
    //   roundConstants,
    //   sboxPower: 5,
    //   mds
    // })
    // const inputz = uint8ArrayToBigInt(input)
    // const hash = poseidonHash3(inputz, 0n, 0n)
    // const h2 = poseidon([input, new Uint8Array(32)])
    // console.log('hash', hash, uint8ArrayToBigInt(h2))
    const ehash = uint8ArrayToBigInt(expected)
    const output = poseidon([input])
    console.log(ehash, uint8ArrayToBigInt(output))
    expect(output).to.deep.equal(expected)
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
    const hexInput = uint8ArrayToBigInt(input).toString(16)
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
    console.log('og', pubKey)

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
    console.log('old sig', signature)
    const verified = verifyEDDSA(message, {
      R8: [signature[0], signature[1]],
      // @ts-ignore
      S: signature[2],
    }, pubKey)

    expect(verified, 'Signature not verified.').to.eq(true)
  })

  it('Should sign & verify poseidon new', async () => {
    const privateKey = new Uint8Array([
      213, 240, 248, 140, 111, 244, 23, 235,
      61, 48, 29, 92, 187, 133, 59, 226,
      69, 42, 2, 146, 162, 37, 2, 192,
      139, 19, 97, 86, 239, 35, 80, 129
    ])
    const eddsa = buildEddsaPoseidon2()
    const pkey = eddsa.prv2pub(privateKey)
    const key = pkey.map((element: any) => {
      return bigIntToUint8Array(element) // .reverse()
    }
    ) as [Uint8Array, Uint8Array]
    // const pubKey = privateKeyToPublicKey(privateKey)
    // console.log('og', pubKey)
    console.log('prv2pub', pkey)
    console.log('new', key)

    const message = new Uint8Array([
      22, 70, 157, 162, 69, 227, 233, 160,
      41, 212, 29, 163, 49, 10, 67, 11,
      62, 254, 124, 144, 87, 178, 140, 93,
      173, 35, 189, 183, 164, 200, 32, 209
    ])
    // const convert = (arr: any) => {
    //   return BigInt('0x' + uint8ArrayToBigInt(arr).toString(16));
    // }
    // const expected = [
    //   new Uint8Array([
    //     39, 189, 32, 168, 242, 83, 145, 186,
    //     218, 211, 193, 6, 165, 189, 41, 156,
    //     58, 161, 55, 72, 45, 157, 124, 232,
    //     188, 88, 106, 105, 191, 37, 113, 62
    //   ]),
    //   new Uint8Array([
    //     0, 18, 216, 188, 251, 179, 0, 93,
    //     10, 95, 124, 157, 37, 170, 112, 233,
    //     47, 106, 169, 129, 48, 112, 151, 91,
    //     227, 194, 15, 56, 6, 96, 86, 143
    //   ]),
    //   new Uint8Array([
    //     221, 193, 178, 218, 65, 42, 58, 45,
    //     58, 34, 24, 85, 14, 16, 30, 88,
    //     160, 174, 191, 220, 36, 35, 130, 208,
    //     111, 67, 150, 8, 188, 174, 13, 5
    //   ])
    // ]
    // const signature = signPoseidon(privateKey, message)
    // // REMEMBER REVERSE MODIFIES THE ACTUAL OBJ
    // expect(signature).to.deep.equal(expected)
    // expect(signature, 'Signature not generated.')

    // // new signature
    // const verified = verifyEDDSA(message, {
    //   R8: [signature[0], signature[1]],
    //   // @ts-ignore
    //   S: signature[2],
    // }, pubKey)

    // expect(verified, 'Signature not verified.').to.eq(true)
    // console.log('msg', message)
    const newsignature = eddsa.signPoseidon(privateKey, message)
    // console.log('msg', message)
    // console.log('signature', signature)
    // const formatted = newsignature.map(bigIntToUint8Array)
    // const formatted = [
    //   bigIntToUint8Array(newsignature[0]!).reverse(),
    //   bigIntToUint8Array(newsignature[1]!).reverse(),
    //   bigIntToUint8Array(newsignature[2]!)
    // ]
    // console.log('newsignature', formatted)
    // console.log('newsignature', formatted)
    const a = { x: uint8ArrayToBigInt(key[0]), y: uint8ArrayToBigInt(key[1]) }
    // console.log('a', a)
    const newVerified = eddsa.verifyPoseidon(message, newsignature as [bigint, bigint, bigint], a)

    expect(newVerified, 'New Signature not verified.').to.eq(true)
  })
})
