import { PublicKey } from "paillier-bigint";
import crypto from "crypto";
import * as bcu from "bigint-crypto-utils";
import { Proof } from "./proof";
import { getRand, bytesToBigInt, sha256BigInts } from "./util";

const Two256 = 2n ** 256n;

/**
 * A class that handles encryption of numbers (bitwise) using the Paillier cryptosystem,
 * along with generating zero-knowledge proofs for each bit.
 */
export class Voter {
  public bits: number;
  public publicKey: PublicKey;
  public n2: bigint;

  /**
   * Constructs a new instance.
   * @param bits The number of bits that will be used (e.g. 7 bits for values 0-127)
   * @param publicKey The Paillier public key to use for encryption.
   */
  constructor(bits: number, publicKey: PublicKey) {
    this.bits = bits;
    this.publicKey = publicKey;
    this.n2 = this.publicKey.n * this.publicKey.n;
  }

  /**
   * Encrypts a number (bitwise) using a provided bit length.
   * Returns an array of proofs for each bit (LSB first).
   *
   * @param value The number to encrypt.
   * @param bits The number of bits to support.
   */
  public encryptNumber(
    value: number
  ): Proof[] {
    if (value < 0 || value >= 2 ** this.bits) {
      throw new Error(`Value must be between 0 and ${2 ** this.bits - 1}`);
    }
    // Convert the number to a binary string and pad to the required bit-length.
    const bin = value.toString(2).padStart(this.bits, "0");
    // Encrypt each bit (we choose LSB first so that reconstruction is easier).
    const proofs: Proof[] = [];
    for (let i = bin.length - 1; i >= 0; i--) {
      const bit = Number(bin[i]) as 0 | 1;
      proofs.push(this.encryptBit(bit));
    }
    return proofs;
  }

  /**
   * Generates a zero-knowledge proof and encryption for bit 1.
   */
  private proofB1(): Proof {
    const v = 1n;
    const r = getRand(this.publicKey.n);
    const c = this.publicKey.encrypt(v, r);

    // Honest Branch
    const s = getRand(this.publicKey.n);
    const a1 = bcu.modPow(s, this.publicKey.n, this.n2);

    // Simulation Branch
    const e0 = bytesToBigInt(crypto.randomBytes(32));
    const z0 = getRand(this.publicKey.n);
    const a0 = bcu.modMultiply(
      [
        bcu.modPow(z0, this.publicKey.n, this.n2),
        bcu.modInv(bcu.modPow(c, e0, this.n2), this.n2),
      ],
      this.n2
    );

    // Challenge
    const ts = BigInt(Date.now());
    const e = sha256BigInts(a0, a1, c, ts);
    const e1 = bcu.modAdd([e, -e0], Two256);

    // Reply
    const z1 = bcu.modMultiply(
      [s, bcu.modPow(r, e1, this.publicKey.n)],
      this.publicKey.n
    );

    return { a0, a1, e0, e1, z0, z1, c, ts };
  }

  /**
   * Generates a zero-knowledge proof and encryption for bit 0.
   */
  private proofB0(): Proof {
    const v = 0n;
    const r = getRand(this.publicKey.n);
    const c = this.publicKey.encrypt(v, r);

    // Honest Branch
    const s = getRand(this.publicKey.n);
    const a0 = bcu.modPow(s, this.publicKey.n, this.n2);

    // Simulation Branch
    const e1 = bytesToBigInt(crypto.randomBytes(32));
    const z1 = getRand(this.publicKey.n);
    const a1 = bcu.modMultiply(
      [
        bcu.modPow(z1, this.publicKey.n, this.n2),
        bcu.modInv(
          bcu.modPow(
            bcu.modMultiply(
              [c, bcu.modInv(this.publicKey.g, this.n2)],
              this.n2
            ),
            e1,
            this.n2
          ),
          this.n2
        ),
      ],
      this.n2
    );

    // Challenge
    const ts = BigInt(Date.now());
    const e = sha256BigInts(a0, a1, c, ts);
    const e0 = bcu.modAdd([e, -e1], Two256);

    // Reply
    const z0 = bcu.modMultiply(
      [s, bcu.modPow(r, e0, this.publicKey.n)],
      this.publicKey.n
    );

    return { a0, a1, e0, e1, z0, z1, c, ts };
  }

  /**
   * Encrypts a single bit (0 or 1) along with its zero-knowledge proof.
   */
  private encryptBit(
    bit: 0 | 1
  ): Proof {
    if (bit === 0) {
      return this.proofB0();
    } else {
      return this.proofB1();
    }
  }
}