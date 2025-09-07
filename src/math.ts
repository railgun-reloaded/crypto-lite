/* eslint-disable jsdoc/require-jsdoc */

// Modular exponentiation
function modPow (base: bigint, exp: bigint, mod: bigint) {
  if (mod === 1n) return 0n
  let result = 1n
  base = base % mod
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod
    }
    exp = exp >> 1n
    base = (base * base) % mod
  }
  return result
}
// Extended Euclidean Algorithm for modular inverse
function extendedGcd (a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (a === 0n) return [b, 0n, 1n]
  const [gcd, x1, y1] = extendedGcd(b % a, a)
  const x = y1 - (b / a) * x1
  const y = x1
  return [gcd, x, y]
}

function modInverse (a: bigint, m: bigint) {
  if (a < 0n) a = ((a % m) + m) % m
  const [g, x] = extendedGcd(a, m)
  if (g !== 1n) throw new Error('Modular inverse does not exist')
  return ((x % m) + m) % m
}

// Convert BigInt to Uint8Array (32 bytes, little-endian)
function bigIntToUint8Array (num: bigint) {
  const hex = num.toString(16).padStart(64, '0')
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    bytes[31 - i] = parseInt(hex.substr(i * 2, 2), 16)
  }
  return bytes
}

// Convert Uint8Array to BigInt (little-endian)
function uint8ArrayToBigInt (buf: Uint8Array) {
  let result = 0n
  for (let i = buf.length - 1; i >= 0; i--) {
    result = (result << 8n) + BigInt(buf[i]!)
  }
  return result
}

export {
  modPow,
  modInverse,
  extendedGcd,
  bigIntToUint8Array,
  uint8ArrayToBigInt
}
