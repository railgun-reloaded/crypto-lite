import type { EdDSA } from '@noble/curves/abstract/edwards'
import {
  eddsa,
  edwards
  // type EdDSA,
  // type EdwardsOpts,
  // type EdwardsPoint,
} from '@noble/curves/abstract/edwards'
import type { EdwardsOpts } from '@noble/ed25519'
import { blake512 } from '@noble/hashes/blake1'

// babyjubjub p = bn254 n, verify in bn254.ts
const babyjubjubCURVE: EdwardsOpts = {
  p: BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001'),
  n: BigInt('0x30644e72e131a029b85045b68181585d59f76dc1c90770533b94bee1c9093788'),
  h: BigInt(8),
  a: BigInt('168700'),
  d: BigInt('168696'),
  Gx: BigInt('0x23343e3445b673d38bcba38f25645adb494b1255b1162bb40f41a59f4d4b45e'),
  Gy: BigInt('0xc19139cb84c680a6e14116da06056174a0cfa121e6e5c2450f87d64fc000001'),
}

export const babyjubjub: EdDSA = /* @__PURE__ */ eddsa(edwards(babyjubjubCURVE), blake512)

// twistedEdwards babyjubjub -blake512 implementation?
// need to modify prv2pub sign/verify or write new ones?
