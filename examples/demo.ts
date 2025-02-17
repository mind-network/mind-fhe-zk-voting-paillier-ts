import {
  generateKeyPair,
  serializePublicKey,
  deserializePublicKey,
  serializePrivateKey,
  deserializePrivateKey,
  Voter,
  Verifier,
  Proof
} from '../dist/index';
import { PublicKey, PrivateKey } from "paillier-bigint";

async function demo(): Promise<void> {
  // 1. Generate a new key pair
  let { publicKey, privateKey }: { publicKey: PublicKey; privateKey: PrivateKey } =
    await generateKeyPair(2048);
  console.log('✅ Generated new key pair.');

  // 2. (Optional) Serialize & deserialize keys for storage/transmission
  const serializedPub = serializePublicKey(publicKey);
  console.log('🔑 Serialized Public Key:', serializedPub);

  const serializedPriv = serializePrivateKey(privateKey);
  console.log('🔒 Serialized Private Key:', serializedPriv);

  // Restore objects from strings
  publicKey = deserializePublicKey(serializedPub);
  privateKey = deserializePrivateKey(serializedPriv, publicKey);
  console.log('🔄 Deserialized keys back into objects.');

  // 3. Prepare Voter & Verifier
  const bits = 7; // supports values in [0, 2^7)
  const voter = new Voter(bits, publicKey);
  const verifier = new Verifier(publicKey);

  // 4. Encrypt a number and generate zero‑knowledge proofs
  const value = 30;
  console.log('🎯 Original value:', value);

  console.time('⏱️ Encrypt + Prove');
  const proofs: Proof[] = voter.encryptNumber(value);
  console.timeEnd('⏱️ Encrypt + Prove');

  // 5. Verify the proofs
  console.time('⏱️ Verify proofs');
  const proofValidTimeInMinutes = 15;
  const ok: boolean = verifier.verifyNumber(proofs, proofValidTimeInMinutes);
  console.timeEnd('⏱️ Verify proofs');
  console.log('✅ Proofs valid?', ok);

  // 6. Homomorphically reconstruct the ciphertext of `value`
  //    by summing each bit‐encryption multiplied by its weight.
  //    Note: Ciphertext is a bigint under the hood.
  let aggregate: bigint = publicKey.encrypt(BigInt(0));
  proofs.forEach((p, i) => {
    const weight = 2 ** i;
    const term: bigint = publicKey.multiply(p.c, weight);
    aggregate = publicKey.addition(aggregate, term);
  });

  // 7. Decrypt the aggregated ciphertext
  const decrypted: bigint = privateKey.decrypt(aggregate);
  console.log('🔓 Decrypted aggregate:', decrypted.toString());
}

demo().catch((err) => {
  console.error('❌ Demo failed:', err);
  process.exit(1);
});
