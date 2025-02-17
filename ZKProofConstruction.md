# Zero-Knowledge Proof Construction for Paillier Bit Encryption

This repository contains a practical implementation in JavaScript of a non‑interactive zero‑knowledge proof (ZKP) for demonstrating that a Paillier ciphertext encrypts a bit (i.e. either `0` or `1`). The construction is based on a disjunctive (OR) proof built from sigma protocols. This document describes the goal, building blocks, and details of the construction as implemented in the code.

---

## 1. Goal

The main objective of this project is to generate a proof that a given Paillier ciphertext encrypts a bit (i.e., a value in the set {0, 1}) **without revealing which one**. More specifically, the proof shows that the ciphertext is well‑formed by proving that it either:
- Encrypts `0` (i.e., it is an encryption of the form `r^n mod n^2`), or
- Encrypts `1` (i.e., it is of the form `g * r^n mod n^2`, which is equivalent to saying `(c / g)` is an `n`th residue).

This ZK proof can be used, for example, in privacy-preserving voting or secure computation systems, where it is critical to verify that encrypted votes or values are valid without disclosing the actual value.

---

## 2. Building Blocks: Sigma Protocols

A sigma protocol is a three‑move interactive proof system that is particularly well suited for proving statements about knowledge (e.g., knowing a secret witness). The typical structure includes:

1. **Commitment:**  
   The prover generates a random commitment `a` using a randomly chosen value `s`. In our context, for a statement “_X is an n-th residue_,” the commitment is computed as:  
   ```math
   a = s^n \mod n^2
   ```
2. **Challenge:**  
   The verifier (or, in the non‑interactive version, a hash function via the Fiat–Shamir heuristic) provides a challenge `e`.
3. **Response:**  
   The prover computes the response `z` based on the commitment randomness and the witness:  
   ```math
   z = s \cdot r^e \mod n
   ```
4. **Verification:**  
   The verifier checks the equation:  
   ```math
   z^n \stackrel{?}{\equiv} a \cdot (X)^e \mod n^2
   ```

In our implementation, these sigma protocols are used as the fundamental building block for both branches of the OR‑proof.

---

## 3. The OR‑Proof Construction (Non‑Interactive Version)

The goal of the OR‑proof is to convince a verifier that **either** one of two statements is true without revealing which one is correct. In our case, the two statements are:
- **Statement S₀:** “The ciphertext `c` is an encryption of `0`.”  
  That is, there exists an `r` such that:
  ```math
  c = r^n \mod n^2
  ```
- **Statement S₁:** “The ciphertext `c` is an encryption of `1`.”  
  Equivalently, this means that:
  ```math
  c / g = r^n \mod n^2
  ```

### Construction Details

- **Non‑Interactive Proof Using Fiat–Shamir:**  
  Instead of an interactive challenge, the proof uses a hash function (`SHA‑256`) to derive the overall challenge `e` from the public values. In our code, the overall challenge is computed by hashing the two sigma protocol commitments `a₀` and `a₁`, the ciphertext `c`, and a timestamp.

- **Splitting the Challenge:**  
  The overall challenge `e` is split into two parts:
  - For the branch corresponding to the actual plaintext (the "honest" branch), the challenge is computed in the usual manner.
  - For the branch where the prover does not have a witness (the "simulation" branch), the challenge is randomly chosen, and the commitment is computed by back-solving the verification equation.

- **Transcript Components:**  
  For each branch, the proof includes:
  - The commitment `a` (computed as `s^n mod n^2` for the honest branch or simulated for the simulation branch).
  - The challenge value (`e₀` for one branch and `e₁` for the other) such that:
    ```math
    e₀ + e₁ = e \quad (\mod 2^{256})
    ```
  - The response `z` computed as:
    ```math
    z = s \cdot r^{e} \mod n
    ```
    (with appropriate adjustments depending on the branch).

The final proof transmitted consists of all these values (commitments, challenges, responses, ciphertext, and timestamp).