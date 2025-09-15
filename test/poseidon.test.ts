/* eslint-disable jsdoc/require-jsdoc */
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { Fr } from '../src/bn254'
import poseidonConstants from '../src/poseidon_constants_opt'
import buildPoseidon, { unsringifyConstants } from '../src/poseidon_opt'

const P = Fr.p
// supported t = 2..17 per your N_ROUNDS_P array (length 16)
const N_ROUNDS_P = [
  56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
]

function isField (x: bigint): boolean {
  return x >= 0n && x < P
}

describe('Poseidon constants - unstringify & shape', () => {
  it('unsringifyConstants converts numeric & hex strings to Fr elements and preserves shapes', () => {
    const opt = unsringifyConstants(Fr as any, poseidonConstants as any)

    // core groups should exist for each t in 2..17
    for (let tIdx = 0; tIdx < N_ROUNDS_P.length; tIdx++) {
      const t = tIdx + 2

      // C: round constants length == nRoundsF + nRoundsP + nRoundsF (with per-step layout used in code)
      // we don't assert exact counts, but we do verify it's an array of multiples of t with field elements
      const C = opt.C[tIdx]
      assert.ok(Array.isArray(C), `C[t=${t}] should be array`)
      assert.ok(C.length > 0, `C[t=${t}] non-empty`)
      C.forEach((c: bigint, i: number) => {
        assert.ok(typeof c === 'bigint', `C[t=${t}][${i}] type`)
        assert.ok(isField(c), `C[t=${t}][${i}] in field`)
      })

      // S: sparse MDS factors per partial rounds; length is (t*2-1) * nRoundsP
      const S = opt.S[tIdx]
      assert.ok(Array.isArray(S), `S[t=${t}] should be array`)
      assert.ok(S.length === (t * 2 - 1) * N_ROUNDS_P[tIdx]!, `S[t=${t}] length`)
      S.forEach((s: bigint, i: number) => {
        assert.ok(typeof s === 'bigint', `S[t=${t}][${i}] type`)
        assert.ok(isField(s), `S[t=${t}][${i}] in field`)
      })

      // M, P: MDS / optimized matrices should be t×t of field elements
      const M = opt.M[tIdx]
      const Pm = opt.P[tIdx];
      [M, Pm].forEach((mat: any, mi: number) => {
        const name = mi === 0 ? 'M' : 'P'
        assert.ok(Array.isArray(mat), `${name}[t=${t}] outer array`)
        assert.equal(mat.length, t, `${name}[t=${t}] rows = t`)
        for (let r = 0; r < t; r++) {
          assert.ok(Array.isArray(mat[r]), `${name}[t=${t}][${r}] is row`)
          assert.equal(mat[r].length, t, `${name}[t=${t}][${r}] cols = t`)
          for (let c = 0; c < t; c++) {
            const v = mat[r][c]
            assert.ok(typeof v === 'bigint', `${name}[t=${t}][${r}][${c}] type`)
            assert.ok(isField(v), `${name}[t=${t}][${r}][${c}] in field`)
          }
        }
      })
    }
  })

  it('unsringifyConstants handles nested structures and leaves non-matching entries intact', () => {
    const input = {
      a: '123',
      b: '0x2a',
      c: ['7', '0x10', { d: '999' }, null],
      e: true,
    } as any
    const out = unsringifyConstants(Fr as any, input) as any

    assert.equal(out.a, Fr.e('123'))
    assert.equal(out.b, Fr.e('0x2a'))
    assert.deepEqual(out.c[0], Fr.e('7'))
    assert.deepEqual(out.c[1], Fr.e('0x10'))
    assert.deepEqual(out.c[2].d, Fr.e('999'))
    assert.equal(out.c[3], null)
    assert.equal(out.e, true)
  })
})

describe('Poseidon permutation & hash - production tests', () => {
  const poseidon = buildPoseidon()

  it('basic API: returns bigint for nOut=1 and array for nOut>1', () => {
    const h1 = poseidon([1n], undefined, 1)
    assert.ok(typeof h1 === 'bigint')
    const h2 = poseidon([1n], undefined, 2)
    assert.ok(Array.isArray(h2))
    assert.equal(h2.length, Math.min(2, /* t */ 2)) // state length = t = inputs+1
  })

  it('rejects invalid arities and zero inputs', () => {
    assert.throws(() => poseidon([], undefined, 1)) // must have >0 inputs
    // > N_ROUNDS_P.length => unsupported arity
    const tooMany = new Array(N_ROUNDS_P.length + 1).fill(1n)
    assert.throws(() => poseidon(tooMany, undefined, 1))
  })

  it('all outputs are valid field elements (< p)', () => {
    for (let t = 2; t <= 6; t++) {
      const inputs = Array.from({ length: t - 1 }, (_, i) => BigInt(i + 1))
      const out1 = poseidon(inputs, undefined, 1) as bigint
      assert.ok(isField(out1))
      const k = Math.min(t, 3) // request up to 3 outputs but cannot exceed t
      const outs = poseidon(inputs, undefined, k) as bigint[]
      assert.ok(Array.isArray(outs))
      assert.equal(outs.length, Math.min(k, t))
      outs.forEach((v) => assert.ok(isField(v)))
    }
  })

  it('deterministic: same inputs/initState/nOut give same result', () => {
    const inputs = [1n, 2n, 3n]
    const a = poseidon(inputs, 0n, 2)
    const b = poseidon(inputs, 0n, 2)
    assert.deepEqual(a, b)
  })

  it('initState affects the output', () => {
    const inputs = [1n, 2n]
    const h0 = poseidon(inputs, 0n, 1) as bigint
    const h5 = poseidon(inputs, 5n, 1) as bigint
    assert.notEqual(h0, h5)
  })

  it('different arities produce different states (domain separation by t)', () => {
    // Same first two inputs but different arity should (with overwhelming probability) differ
    const h2 = poseidon([1n], undefined, 1) as bigint      // t=2
    const h3 = poseidon([1n, 2n], undefined, 1) as bigint  // t=3
    assert.notEqual(h2, h3)
  })

  it('small input perturbations change the output', () => {
    const base = poseidon([1n, 2n, 3n], undefined, 1) as bigint
    const d1 = poseidon([2n, 2n, 3n], undefined, 1) as bigint
    const d2 = poseidon([1n, 3n, 3n], undefined, 1) as bigint
    const d3 = poseidon([1n, 2n, 4n], undefined, 1) as bigint
    assert.notEqual(base, d1)
    assert.notEqual(base, d2)
    assert.notEqual(base, d3)
  })

  it('accepts mixed input types via Fr.e (bigint, number, decimal/hex strings, bytes)', () => {
    const b = 123n
    const n = 123
    const ds = '123'
    const hs = '0x7b'
    const bytes = Fr.toBytes(123n)
    const outA = poseidon([b, n, ds], undefined, 1) as bigint
    const outB = poseidon([hs, bytes], undefined, 1) as bigint
    // No specific equality required, but should be valid field elements
    assert.ok(isField(outA))
    assert.ok(isField(outB))
  })

  it('nOut clamps to state size (t)', () => {
    // t = inputs+1
    const inputs = [1n, 2n, 3n] // t=4
    const out = poseidon(inputs, undefined, 8) as bigint[] // request > t
    assert.ok(Array.isArray(out))
    assert.equal(out.length, 4)
  })

  it('full-vs-partial rounds structure is actually exercised for multiple t', () => {
    // We can’t peek internals here, but we can sanity-check distinctness across rounds by sampling a few t
    const sets: Array<bigint[]> = []
    for (const t of [2, 3, 4, 5, 6]) {
      const inputs = Array.from({ length: t - 1 }, (_, i) => BigInt(i + 1))
      const outs = poseidon(inputs, undefined, Math.min(3, t)) as bigint[]
      sets.push(outs)
      outs.forEach((o) => assert.ok(isField(o)))
    }
    // pairwise ensure at least one output differs per t (extremely likely, acts as a tripwire)
    for (let i = 0; i < sets.length; i++) {
      for (let j = i + 1; j < sets.length; j++) {
        assert.notDeepEqual(sets[i], sets[j], `outputs for different t should differ (t[i]=${i + 2}, t[j]=${j + 2})`)
      }
    }
  })

  it('does not mutate input arrays', () => {
    const arr = [1n, 2n, 3n]
    const copy = arr.slice()
    // eslint-disable-next-line no-void
    void poseidon(arr, undefined, 2)
    assert.deepEqual(arr, copy)
  })
})
