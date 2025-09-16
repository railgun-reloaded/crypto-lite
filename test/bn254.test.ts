/* eslint-disable jsdoc/require-jsdoc */
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { randomBytes } from '@noble/curves/utils'

import { Fr, NobleFr, toIField } from '../src/bn254'

const P = Fr.p
const ITER = 200

function randFr (): bigint {
  const b = BigInt('0x' + Buffer.from(randomBytes(32)).toString('hex'))
  return b % P
}
function randNonZeroFr (): bigint {
  let x = 0n
  while (x === 0n) x = randFr()
  return x
}
function modP (x: bigint) {
  const r = x % P
  return r >= 0n ? r : r + P
}

describe('Fr (BN254 scalar field)', () => {
  it('exposes correct constants', () => {
    assert.equal(Fr.bitLength, 254)
    assert.equal(Fr.zero, 0n)
    assert.equal(Fr.one, 1n)
    assert.equal(NobleFr.ORDER, P)
  })

  describe('coercion & validation', () => {
    it('toIField coerces and reduces mod p', () => {
      assert.equal(toIField('42'), 42n)
      assert.equal(toIField(42), 42n)
      assert.equal(toIField(P + 7n), 7n)
      assert.equal(toIField(-1n), modP(-1n))
    })

    it('isValid accepts [0,p) and rejects >= p', () => {
      assert.ok(Fr.isValid(0n))
      assert.ok(Fr.isValid(P - 1n))
      assert.ok(!Fr.isValid(P))
    })
  })

  describe('arithmetic', () => {
    it('add/sub/neg are consistent', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr()
        const b = randFr()
        assert.equal(Fr.add(a, b), (a + b) % P)
        assert.equal(Fr.sub(a, b), (a - b + P) % P)
        assert.equal(Fr.add(a, Fr.neg(a)), 0n)
      }
    })

    it('mul/square consistent', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr()
        const b = randFr()
        assert.equal(Fr.mul(a, b), (a * b) % P)
        assert.equal(Fr.square(a), (a * a) % P)
      }
    })

    it('inv/div laws', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randNonZeroFr()
        const b = randNonZeroFr()
        assert.equal(Fr.mul(a, Fr.inv(a)), Fr.one)
        assert.equal(Fr.div(a, b), Fr.mul(a, Fr.inv(b)))
      }
    })

    it('inv(0n) should throw', () => {
      assert.throws(() => Fr.inv(0n))
    })

    it('pow laws', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr()
        const x = BigInt(i % 20)
        const y = BigInt((i * 7) % 20)
        assert.equal(Fr.pow(a, 0n), Fr.one)
        assert.equal(Fr.pow(a, x + y), Fr.mul(Fr.pow(a, x), Fr.pow(a, y)))
      }
    })

    it('eq and isZero behave correctly', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr()
        assert.ok(Fr.eq(a, a))
        assert.equal(Fr.isZero(a), a === 0n)
      }
    })
  })

  describe('serialization', () => {
    it('toBytes/fromBytes roundtrip', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr()
        assert.equal(Fr.fromBytes(Fr.toBytes(a)), a)
      }
    })

    it('toRprLE/fromRprLE roundtrip (full buffer)', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr()
        const buf = new Uint8Array(32)
        Fr.toRprLE(buf, 0, a)
        assert.equal(Fr.fromRprLE(buf, 0, 32), a)
      }
    })

    it('toHex/fromHex roundtrip', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr()
        const hex = Fr.toHex(a)
        assert.equal(Fr.fromHex(hex), a)
        assert.equal(Fr.fromHex(hex.slice(2)), a)
      }
    })

    it('Fr.toObject covers toIField path', () => {
      // direct coverage trigger
      const v = Fr.toObject(0)
      assert.equal(typeof v, 'bigint')
    })

    it('Fr.toString covers default and explicit base', () => {
      assert.equal(Fr.toString(0n), '0')  // default base
      assert.equal(Fr.toString(15n, 16), 'f')  // explicit base path
    })

    it('Fr.e(Uint8Array) matches bigint input', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr()
        assert.equal(Fr.e(Fr.toBytes(a)), a)
      }
    })
  })

  describe('utility', () => {
    it('mod always yields canonical result', () => {
      for (let i = -10; i < 10; i++) {
        const a = BigInt(i)
        const b = 7n
        const r = Fr.mod(a, b)
        assert.ok(r >= 0n && r < b)
        assert.equal(r, ((a % b) + b) % b)
      }
    })

    it('shr behaves like >> then mod p', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr(); const bits = i % 128
        assert.equal(Fr.shr(a, bits), modP(a >> BigInt(bits)))
      }
    })

    it('random always in [0,p)', () => {
      for (let i = 0; i < 50; i++) {
        const r = Fr.random()
        assert.ok(r >= 0n && r < P)
      }
    })
  })

  describe('cross-check with NobleFr', () => {
    it('add/sub/mul/sqr match NobleFr', () => {
      for (let i = 0; i < ITER; i++) {
        const a = randFr(); const b = randFr()
        assert.equal(Fr.add(a, b), NobleFr.add(NobleFr.create(a), NobleFr.create(b)))
        assert.equal(Fr.sub(a, b), NobleFr.sub(NobleFr.create(a), NobleFr.create(b)))
        assert.equal(Fr.mul(a, b), NobleFr.mul(NobleFr.create(a), NobleFr.create(b)))
        assert.equal(Fr.square(a), NobleFr.sqr(NobleFr.create(a)))
      }
    })
  })
})
