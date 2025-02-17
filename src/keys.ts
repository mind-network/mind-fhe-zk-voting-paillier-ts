import { PublicKey, PrivateKey, generateRandomKeys } from "paillier-bigint";

/**
 * Generates a Paillier key pair.
 *
 * @param bitLength The bit length for the keys
 */
export async function generateKeyPair(
  bitLength: number
): Promise<{
  publicKey: PublicKey;
  privateKey: PrivateKey;
}> {
  return generateRandomKeys(bitLength);
}

export function serializePublicKey(key: PublicKey) {
  return JSON.stringify({ n: key.n.toString(), g: key.g.toString() });
}

export function deserializePublicKey(keyStr: string) {
  const { n, g } = JSON.parse(keyStr);
  return new PublicKey(BigInt(n), BigInt(g));
}

export function serializePrivateKey(key: PrivateKey) {
  return JSON.stringify({ lambda: key.lambda.toString(), mu: key.mu.toString() });
}

export function deserializePrivateKey(keyStr: string, publicKey: PublicKey) {
  const { lambda, mu } = JSON.parse(keyStr);
  return new PrivateKey(BigInt(lambda), BigInt(mu), publicKey);
}