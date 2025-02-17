import { PublicKey } from "paillier-bigint";
import * as bcu from "bigint-crypto-utils";
import { Proof } from "./proof";
import { sha256BigInts } from "./util";

const Two256 = 2n ** 256n;

/**
 * A class that verifies zero-knowledge proofs for each bit.
 */
export class Verifier {
  public publicKey: PublicKey;
  public n2: bigint;

  /**
   * Constructs a new instance.
   * @param publicKey The Paillier public key to use for encryption.
   */
  constructor(publicKey: PublicKey) {
    this.publicKey = publicKey;
    this.n2 = this.publicKey.n * this.publicKey.n;
  }

  /**
   * Verifies a single proof for a bit.
   */
  private verifyBit(
    proof: Proof,
    proofValidTimeInMinutes: number
  ): boolean {
    const { a0, a1, e0, e1, z0, z1, c, ts } = proof;

    // Check timestamp (e.g. proof must be generated in the last 60 minutes)
    if (proofValidTimeInMinutes && ts < BigInt(Date.now()) - 60000n * BigInt(proofValidTimeInMinutes)) {
      return false;
    }

    // Verify that the challenge equals e0 + e1
    const e = sha256BigInts(a0, a1, c, ts);
    const e_v = bcu.modAdd([e0, e1], Two256);
    if (e !== e_v) return false;

    // Verify Branch 0
    const l0 = bcu.modPow(z0, this.publicKey.n, this.n2);
    const r0 = bcu.modMultiply(
      [a0, bcu.modPow(c, e0, this.n2)],
      this.n2
    );
    if (l0 !== r0) return false;

    // Verify Branch 1
    const l1 = bcu.modPow(z1, this.publicKey.n, this.n2);
    const r1 = bcu.modMultiply(
      [
        a1,
        bcu.modPow(
          bcu.modMultiply([c, bcu.modInv(this.publicKey.g, this.n2)], this.n2),
          e1,
          this.n2
        ),
      ],
      this.n2
    );
    if (l1 !== r1) return false;

    return true;
  }

  /**
   * Verifies an array of proofs (one per bit).
   */
  public verifyNumber(
    proofs: Proof[],
    proofValidTimeInMinutes: number
  ): boolean {
    for (const proof of proofs) {
      if (!(this.verifyBit(proof, proofValidTimeInMinutes))) {
        return false;
      }
    }
    return true;
  }
}