/* eslint-disable import-x/group-exports */
import { eddsaBuild } from '.'

/**
 * Converts a BigInt to a Uint8Array representation.
 * @param num - The BigInt number to convert
 * @returns A Uint8Array containing the byte representation of the BigInt
 * @example
 * ```typescript
 * const bigNum = 123456789n;
 * const bytes = bigIntToUint8Array(bigNum);
 * console.log(bytes); // Uint8Array representation
 * ```
 */
export function bigIntToUint8Array (num: bigint) {
  return eddsaBuild.toBytes(num)
}
/**
 * Converts a Uint8Array buffer to a BigInt using the eddsa build from bytes method.
 * @param buf - The Uint8Array buffer to convert to BigInt
 * @returns The BigInt representation of the input buffer
 * @example
 * ```typescript
 * const buffer = new Uint8Array([1, 2, 3, 4]);
 * const bigIntValue = uint8ArrayToBigInt(buffer);
 * console.log(bigIntValue); // BigInt representation of the buffer
 * ```
 */
export function uint8ArrayToBigInt (buf: Uint8Array) {
  return eddsaBuild.fromBytes(buf)
}
