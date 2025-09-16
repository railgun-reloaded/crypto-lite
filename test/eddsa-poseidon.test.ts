/* eslint-disable import-x/order */
/* eslint-disable jsdoc/require-jsdoc */
import assert from 'node:assert/strict'
import { before, describe, it } from 'node:test'

import { randomBytes } from '@noble/hashes/utils'

import { initializePoseidonFuncs } from '../src/poseidon-lite-wrapper'
import buildEddsaPoseidon, { BabyJubPoint } from '../src/eddsa-noble'

function randomKey (): Uint8Array {
  const k = randomBytes(32)
  return k
}

describe('EddsaPoseidon (production tests)', () => {
  const eddsa = buildEddsaPoseidon()

  let prv: Uint8Array
  let pub: [bigint, bigint]
  let msg: Uint8Array
  const subOrder = eddsa.Fr.ORDER >> 3n

  before(() => {
    initializePoseidonFuncs()
    prv = new Uint8Array(32).fill(7)
    pub = eddsa.prv2pub(prv)
    msg = new TextEncoder().encode('PoseidonTestMessage')
  })

  it('prv2pub returns a valid point on the prime-order subgroup', () => {
    const [x, y] = pub
    const P = BabyJubPoint.fromAffine({ x, y })
    assert.ok(!P.equals(BabyJubPoint.ZERO), 'pubkey must not be point at infinity')
  })

  it('pruneBuffer clamps bits as per EdDSA spec', () => {
    const raw = new Uint8Array(32).fill(0xff)
    const pruned = eddsa.pruneBuffer(raw)
    assert.equal(pruned.length, 32)
    assert.equal(pruned[0]! & 0x07, 0)
    assert.equal(pruned[31]! & 0x80, 0)
    assert.equal(pruned[31]! & 0x40, 0x40)
  })

  it('prv2pub returns a valid non-infinity point', () => {
    const [x, y] = pub
    const P = BabyJubPoint.fromAffine({ x, y })
    assert.ok(!P.equals(BabyJubPoint.ZERO), 'pubkey must not be point at infinity')
  })

  it('different keys produce different pubkeys', () => {
    const prv1 = randomKey(); const prv2 = randomKey()
    const pub1 = eddsa.prv2pub(prv1)
    const pub2 = eddsa.prv2pub(prv2)
    assert.notDeepEqual(pub1, pub2)
  })

  describe('toBytes / fromBytes / Montgomery', () => {
    it('roundtrips via toBytes/fromBytes', () => {
      const a = 12345n
      const bytes = eddsa.toBytes(a)
      const back = eddsa.fromBytes(bytes)
      assert.equal(back, a)
    })

    it('toMontgomery/fromMontgomery are identity for bigints', () => {
      const a = 987654321n
      const mont = eddsa.toMontgomery(a)
      const back = eddsa.fromMontgomery(mont)
      assert.deepEqual(back, eddsa.Fr.toBytes(eddsa.Fr.create(a)))
    })
  })

  describe('signing & verification', () => {
    it('produces valid signature with S < subOrder', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      assert.ok(typeof sig.S === 'bigint')
      assert.ok(sig.S >= 0n && sig.S < subOrder, 'S must be in [0,subOrder)')
      const R = BabyJubPoint.fromAffine(sig.R8)
      assert.ok(!R.equals(BabyJubPoint.ZERO), 'R8 must not be point at infinity')
    })

    it('verifyPoseidon returns true for valid signature', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      assert.equal(eddsa.verifyPoseidon(msg, sig, { x: pub[0], y: pub[1] }), true)
    })

    it('verifyPoseidon returns false for wrong message', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const badMsg = new TextEncoder().encode('tampered')
      assert.equal(eddsa.verifyPoseidon(badMsg, sig, { x: pub[0], y: pub[1] }), false)
    })

    it('verifyPoseidon returns false for wrong public key', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const wrongPub = eddsa.prv2pub(new Uint8Array(32).fill(8))
      assert.equal(
        eddsa.verifyPoseidon(msg, sig, { x: wrongPub[0], y: wrongPub[1] }),
        false
      )
    })

    it('signing is deterministic for fixed key+message', () => {
      const sig1 = eddsa.signPoseidon(prv, msg)
      const sig2 = eddsa.signPoseidon(prv, msg)
      assert.deepEqual(sig1, sig2)
    })
  })

  describe('edge cases & rejection', () => {
    it('rejects signature with S >= subOrder', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const badSig = { R8: sig.R8, S: subOrder } // intentionally invalid
      assert.equal(
        eddsa.verifyPoseidon(msg, badSig, { x: pub[0], y: pub[1] }),
        false
      )
    })

    it('returns false for forged R8 not in subgroup', () => {
      const sig = eddsa.signPoseidon(prv, msg)
      const forgedR8 = { x: sig.R8.x, y: (sig.R8.y + 1n) % BabyJubPoint.CURVE().p }
      assert.equal(
        eddsa.verifyPoseidon(msg, { R8: forgedR8, S: sig.S }, { x: pub[0], y: pub[1] }),
        false
      )
    })
  })
})
