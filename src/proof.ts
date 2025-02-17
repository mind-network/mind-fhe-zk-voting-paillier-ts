/**
 * Type for a zero-knowledge proof.
 */
export interface Proof {
  a0: bigint;
  a1: bigint;
  e0: bigint;
  e1: bigint;
  z0: bigint;
  z1: bigint;
  c: bigint;
  ts: bigint;
}