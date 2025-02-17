import crypto from "crypto";
import * as bcu from "bigint-crypto-utils";

/**
 * Returns a random value relatively prime to n.
 */
export function getRand(n: bigint): bigint {
  let r: bigint;
  do {
    r = bcu.randBetween(n);
  } while (bcu.gcd(r, n) !== 1n);
  return r;
}

/**
 * Converts bytes (Uint8Array) to bigint.
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return BigInt("0x" + hex);
}

/**
 * Computes a SHA-256 hash over several bigints.
 */
export function sha256BigInts(...nums: bigint[]): bigint {
  const bytesArrays = nums.map((x) => bigIntToBytes(x));
  const totalLength = bytesArrays.reduce((acc, cur) => acc + cur.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of bytesArrays) {
    combined.set(arr, offset);
    offset += arr.length;
  }
  const hash = crypto.createHash("sha256").update(combined).digest();
  return bytesToBigInt(new Uint8Array(hash));
}

/**
 * Converts bigint to Uint8Array.
 */
function bigIntToBytes(bigint: bigint): Uint8Array {
  let hex = bigint.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i] = parseInt(hex.substring(i, i + 1), 16);
  }
  return bytes;
}