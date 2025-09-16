import assert from 'node:assert/strict'
import { PerformanceObserver, performance } from 'node:perf_hooks'
import { before, describe, it } from 'node:test'

import {
  bigIntToUint8Array,
  getPublicKey,
  getPublicSpendingKey,
  getPublicViewingKey,
  poseidon,
  poseidonHex,
  privateKeyToPublicKey,
  signPoseidon,
  uint8ArrayToBigInt,
  verifyEDDSA,
} from '../src/index'

describe('Crypto-Lite module (production tests)', () => {
  before(() => {
    const obs = new PerformanceObserver((items) => {
      items.getEntries().forEach((entry) => {
        console.log(`${entry.name}: ${entry.duration}ms`)
      })
    })
    obs.observe({ entryTypes: ['measure'] })
  })

  const input = new Uint8Array([
    213, 240, 248, 140, 111, 244, 23, 235,
    61, 48, 29, 92, 187, 133, 59, 226,
    69, 42, 2, 146, 162, 37, 2, 192,
    139, 19, 97, 86, 239, 35, 80, 129
  ])

  const expectedNullifier = new Uint8Array([
    22, 70, 157, 162, 69, 227, 233, 160,
    41, 212, 29, 163, 49, 10, 67, 11,
    62, 254, 124, 144, 87, 178, 140, 93,
    173, 35, 189, 183, 164, 200, 32, 209
  ])

  const ogPoseidonOutBig = 67770771820894602869173624865523212694969471050530985054131446787965899093267n

  const privKey = new Uint8Array([
    213, 240, 248, 140, 111, 244, 23, 235,
    61, 48, 29, 92, 187, 133, 59, 226,
    69, 42, 2, 146, 162, 37, 2, 192,
    139, 19, 97, 86, 239, 35, 80, 129
  ])

  const message = new Uint8Array([
    22, 70, 157, 162, 69, 227, 233, 160,
    41, 212, 29, 163, 49, 10, 67, 11,
    62, 254, 124, 144, 87, 178, 140, 93,
    173, 35, 189, 183, 164, 200, 32, 209
  ])

  const expectedSignature: [Uint8Array, Uint8Array, Uint8Array] = [
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

  describe('Converters', () => {
    it('bigIntToUint8Array / uint8ArrayToBigInt are inverses (roundtrip)', () => {
      const nums = [
        0n,
        1n,
        255n,
        256n,
        2n ** 128n - 1n,
        2n ** 255n,                    // edge-ish
        ogPoseidonOutBig
      ]
      for (const n of nums) {
        const bytes = bigIntToUint8Array(n)
        const back = uint8ArrayToBigInt(bytes)
        assert.equal(back, n)
      }
    })
  })

  describe('Poseidon hashing', () => {
    it('computes nullifier (bytes input => bytes out)', () => {
      const out = poseidon([input])
      assert.deepStrictEqual(out, expectedNullifier)
    })

    it('poseidon hashes OG (benchmarked)', () => {
      performance.mark('start')
      const hash = poseidon([bigIntToUint8Array(1n)])
      performance.mark('end')
      performance.measure('poseidon hash duration', 'start', 'end')
      assert.deepStrictEqual(hash, bigIntToUint8Array(ogPoseidonOutBig))
    })

    it('computes hex nullifier (string inputs => bigint or hex)', () => {
      const hexInput = uint8ArrayToBigInt(input).toString(16)
      const hexExpectedBig = uint8ArrayToBigInt(expectedNullifier)
      const hashBig = poseidonHex(['0x' + hexInput])
      const hashHex = poseidonHex(['0x' + hexInput], true)
      assert.strictEqual(hashBig, hexExpectedBig)
      assert.strictEqual(hashHex, hexExpectedBig.toString(16))
    })

    it('poseidonHex returns bigint and hex', () => {
      const inputs = ['1', '2', '3']
      const asBigint = poseidonHex(inputs)
      assert.equal(typeof asBigint, 'bigint') // covers default branch

      const asHex = poseidonHex(inputs, true)
      assert.match(asHex as string, /^[0-9a-f]+$/) // covers toHex branch
    })
  })

  describe('EDDSA (Poseidon wrapper)', () => {
    it('signPoseidon returns a signature tuple', () => {
      const sig = signPoseidon(privKey, message)
      assert.ok(sig && Array.isArray(sig) && sig.length === 3)
      sig.forEach((part) => assert.ok(part instanceof Uint8Array))
    })

    it('signPoseidon returns expected deterministic signature for example vector', () => {
      const sig = signPoseidon(privKey, message)
      assert.deepStrictEqual(sig, expectedSignature)
    })

    it('verifyEDDSA returns true for valid (msg, sig, pubKey)', () => {
      const pubKey = privateKeyToPublicKey(privKey) as [Uint8Array, Uint8Array]
      const sig = signPoseidon(privKey, message)
      const ok = verifyEDDSA(message, { R8: [sig[0], sig[1]], S: sig[2] as any }, pubKey)
      assert.equal(ok, true)
    })

    it('verifyEDDSA returns false for wrong message', () => {
      const pubKey = privateKeyToPublicKey(privKey) as [Uint8Array, Uint8Array]
      const sig = signPoseidon(privKey, message)
      const tampered = new Uint8Array(message)
      tampered[0] = (tampered[0]! ^ 0xff) & 0xff
      const ok = verifyEDDSA(tampered, { R8: [sig[0], sig[1]], S: sig[2] as any }, pubKey)
      assert.equal(ok, false)
    })

    it('verifyEDDSA returns false for wrong public key', () => {
      const wrongPriv = new Uint8Array(32).fill(7)
      const wrongPub = privateKeyToPublicKey(wrongPriv) as [Uint8Array, Uint8Array]
      const sig = signPoseidon(privKey, message)
      const ok = verifyEDDSA(message, { R8: [sig[0], sig[1]], S: sig[2] as any }, wrongPub)
      assert.equal(ok, false)
    })

    it('privateKeyToPublicKey returns two Uint8Array components', () => {
      const pubKey = privateKeyToPublicKey(privKey)
      assert.ok(Array.isArray(pubKey) && pubKey.length === 2)
      assert.ok(pubKey[0] instanceof Uint8Array)
      assert.ok(pubKey[1] instanceof Uint8Array)
    })
  })

  describe('Viewing & Spending keys', () => {
    it('getPublicSpendingKey mirrors privateKeyToPublicKey', () => {
      const a = privateKeyToPublicKey(privKey)
      const b = getPublicSpendingKey(privKey)
      assert.deepStrictEqual(a, b)
    })

    it('getPublicSpendingKey throws for invalid length', () => {
      const bad = new Uint8Array(31).fill(1)
      assert.throws(() => getPublicSpendingKey(bad), /Invalid private key length/)
    })

    it('getPublicViewingKey returns Uint8Array (ed25519) and is 32 bytes', async () => {
      // Using the same 32-byte private key; ed25519 getPublicKey expects 32 bytes
      const vk = await getPublicViewingKey(privKey)
      assert.ok(vk instanceof Uint8Array)
      assert.equal(vk.length, 32)
    })

    it('getPublicKey (re-export) matches getPublicViewingKey for the same key', async () => {
      const a = await getPublicViewingKey(privKey)
      const b = await getPublicKey(privKey)
      assert.deepStrictEqual(a, b)
    })
  })
})
