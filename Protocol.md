# NTT-based Key Exchange and Digital Signature Protocol

## Introduction

This document explains the protocol used in the NTT-based cryptosystem. The protocol adapts the classic Diffie-Hellman key exchange to operate on sequences rather than single numbers, leveraging the Number Theoretic Transform (NTT) for efficient convolution operations. It covers key generation, key exchange, message encryption/decryption, and a Schnorr-like digital signature scheme.

## Public Parameters

The protocol relies on several shared system parameters:
- **Prime Modulus (p):**  
  A large prime number defining the finite field GF(p). p is chosen such that (p - 1) is divisible by the sequence length, ensuring the existence of an n-th root of unity.
  
- **Sequence Length (n):**  
  The length of the sequences used for operations. It must be a power of 2 for efficient NTT computations.
  
- **Primitive n-th Root of Unity (w):**  
  An element in GF(p) that satisfies:
  - w^n ≡ 1 (mod p)
  - For any 1 ≤ k < n, w^k ≠ 1 (mod p)

- **Public Sequence (G):**  
  A random sequence of n elements from GF(p), analogous to a generator in traditional Diffie-Hellman. It serves as the basis for convolution operations in the cryptosystem.

## Number Theoretic Transform (NTT)

The NTT is a finite-field version of the discrete Fourier transform. Its role is to:
- **Transform Sequences:**  
  Convert a sequence from the time domain into a frequency-like domain.
- **Convolution Efficiency:**  
  In the NTT domain, circular convolution (a relatively heavy operation in the time domain) becomes simple pointwise multiplication.
- **Inverse Transform (INTT):**  
  Convert the result of the pointwise operations back to the time domain.

## Circular Convolution and Sequence Exponentiation

The core operation in the protocol is the circular convolution:
- **Circular Convolution (⊗):**  
  For two sequences A and B of length n, the circular convolution results in a sequence C where each element is computed from a sum over shifted products modulo p.

- **Sequence Exponentiation (G^{*a}):**  
  Instead of a conventional power, we "exponentiate" a sequence by convolving it with itself a times. This is done efficiently by:
  1. Converting G into its NTT representation.
  2. Raising each element of the NTT representation to the power a.
  3. Applying the inverse NTT (INTT) to obtain the result.

## Key Generation

Each user (for example, Alice or Bob) creates a keypair in the following way:
1. **Private Key (a):**  
   Select a random integer from 1 to (p - 1).
   
2. **Public Key (P):**  
   Compute the public key as G^{*a} (meaning G convolved with itself a times). In the NTT domain, this corresponds to raising each element of NTT(G) to the power a and then applying INTT.

## Key Exchange Process

The key exchange process ensures that both parties derive the same shared secret:
1. **Generate Keypairs:**
   - Alice computes Pₐ = G^{*a}.
   - Bob computes Pᵦ = G^{*b}.
   
2. **Exchange:**  
   Alice and Bob exchange their public keys.

3. **Compute Shared Key:**
   - Alice computes K = (Pᵦ)^{*a}.
   - Bob computes K = (Pₐ)^{*b}.
    
   **Why They Match:**  
   Due to the associativity of convolution,  
   (G^{*b})^{*a} equals G^{*(a*b)} and  
   (G^{*a})^{*b} also equals G^{*(a*b)}.  
   Thus, both parties derive the identical shared secret.

## Encryption and Decryption

The shared key can be used to encrypt and decrypt messages:
- **Encryption:**
  - Represent the message M as a sequence of length n.
  - Compute the ciphertext C using a circular convolution: C = M ⊗ K.
  
- **Decryption:**
  - Recover M from C by performing deconvolution (which in practice involves switching to the NTT domain, performing pointwise division, and then applying the INTT).

## Digital Signature Scheme

The protocol includes a Schnorr-like signature mechanism adapted to the NTT domain.

### Signing Process

1. **Hash the Message:**  
   Compute a fixed-length digest from the message to handle messages of any length.

2. **Generate an Ephemeral Key (k):**  
   Choose a random key that is relatively prime to (p - 1) to ensure invertibility.

3. **Compute Commitment (r):**  
   Calculate r = G^{*k}. This acts as a commitment similar to g^k in standard signature schemes.

4. **Compute Challenge (e):**  
   Combine the message digest and r, and then hash this combined sequence to obtain e. This ties the message and commitment together.

5. **Compute Response (s):**  
   Calculate s = (k + e*a) mod (p - 1), where a is the signer's private key.

6. **Signature Output:**  
   The signature is the pair (r, s).

### Verification Process

To verify a signature, one checks the following:
1. **Recompute Challenge (e):**  
   Using the same method as in the signing process, derive e from the message digest and r.

2. **Verify the Equation:**  
   Validate that G^{*s} equals r convolved with (P^{*e}), where P is the signer's public key.  
   **Explanation:**  
   - Since s = k + e*a, then G^{*s} equals G^{*(k + e*a)}.  
   - This can be broken down into G^{*k} ⊗ G^{*e*a}.  
   - G^{*k} is the commitment r, and G^{*e*a} is the public key raised to e.  
   - Therefore, if the equation holds, the signature is valid.

## Proof of Correctness

### Shared Key Agreement

- **Alice's Computation:**  
  K = (G^{*b})^{*a} = G^{*(a*b)}.
  
- **Bob's Computation:**  
  K = (G^{*a})^{*b} = G^{*(a*b)}.
  
Since convolution is associative, both computed keys are identical.

### Signature Verification

- **Signature Generation:**  
  s is computed as s = k + e*a.
  
- **Verification Equation:**  
  When verifying, we compute G^{*s} which should equal r ⊗ (P^{*e}).  
  - Knowing that r = G^{*k} and P = G^{*a}, the right-hand side becomes G^{*k} ⊗ (G^{*a})^{*e}.  
  - This equals G^{*(k + e*a)} which is G^{*s}.
  
Thus, if the equation holds, the signature is valid and confirms that the signer knew the private key without exposing it.

## Security Considerations

- **Hard Math Problems:**  
  The security is based on the difficulty of the discrete logarithm and the computational Diffie-Hellman problems in the NTT domain.

- **Parameter Sizes:**  
  With a large prime (for instance, 2048 bits) and a reasonable sequence length (e.g., n = 64), it is computationally infeasible for an attacker to compute the private key, forge signatures, or decrypt messages without knowing the shared key.

- **Cryptographic Hash Functions:**  
  The use of secure hash functions (like SHA-256) ensures that the challenges in the signature process are unpredictable and tightly bound to the message.

## Conclusion

This protocol provides a proposal of a crypto system for:
- **Key Exchange:**  
  Both parties derive the same shared secret using the associativity of convolution.
  
- **Encryption/Decryption:**  
  Message confidentiality is achieved through circular convolution with the shared key.
  
- **Digital Signatures:**  
  The adapted Schnorr-like scheme ensures authenticity and integrity of messages without exposing the private key.

By leveraging the strengths of the Number Theoretic Transform, The detailed explanations provided here are intended to offer an accessible path to understanding both the high-level concepts and the underlying mathematics of the NTT-based cryptosystem.
