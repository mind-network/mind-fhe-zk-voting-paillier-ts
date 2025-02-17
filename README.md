# mind-paillier-voting-sdk

**mind-paillier-voting-sdk** is a TypeScript library designed for secure and privacy-preserving voting systems. The package leverages Fully Homomorphic Encryption (FHE) and Zero-Knowledge (ZK) proofs to generate keys, encrypt votes, and verify proofs, ensuring the confidentiality and integrity of the voting process.

## Features

- **Key Generation:** Easily generate public and private FHE keys.
- **Serialization Utilities:** Serialize and deserialize keys for storage or transmission.
- **Encryption & Decryption:** Encrypt numbers (votes) and decrypt aggregated results.
- **Zero-Knowledge Proofs:** Create and verify ZK proofs to ensure vote validity.

## Installation

Install the package via npm:

```bash
npm install mind-paillier-voting-sdk
```

## API Overview

### Key Generation
- **generateKeyPair(bitLength)**: Asynchronously generates a pair of FHE keys (public and private).

### Key Serialization
- **serializePublicKey(publicKey)**: Serializes the public key to a string.
- **deserializePublicKey(serializedKey)**: Converts a serialized public key string back to its object form.
- **serializePrivateKey(privateKey)**: Serializes the private key.
- **deserializePrivateKey(serializedKey, publicKey)**: Deserializes the private key with reference to the public key.

### Voting Operations
- **Voter(bits, publicKey)**: Creates a new voter instance. The `bits` parameter defines the number range.
- **encryptNumber(number)**: Encrypts a vote and returns a set of proofs.
- **Verifier(publicKey)**: Creates a new verifier instance.
- **verifyNumber(proofs, proofValidTimeInMinutes)**: Verifies the ZK proofs to ensure the vote's validity.

## Usage

For sample usage and example code, please refer to the [`examples/demo.ts`](examples/demo.ts) file in this repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.