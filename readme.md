# Number Theoretic Transform (NTT)-Based Key Exchange Protocol

## Introduction

The Number Theoretic Transform (NTT)-based key exchange protocol is a cryptographic method that allows two parties, Alice and Bob, to securely agree on a shared secret key over an insecure channel. Unlike the traditional Diffie-Hellman key exchange, which uses single numbers, this protocol operates on sequences of elements in a finite field. The NTT enhances efficiency by speeding up convolution operations, making this a sequence-based alternative for key agreement.

This document explains the protocol in detail, including its mathematical basis, the key exchange steps, and a proof that both parties compute the same key.

## Public Parameters

The protocol relies on shared public parameters agreed upon by Alice and Bob:

- **Prime Modulus (p)**: A large prime number defining the finite field GF(p), where all arithmetic is performed.
- **Sequence Length (n)**: An integer that divides (p - 1), ensuring the existence of a primitive n-th root of unity in GF(p).
- **Primitive n-th Root of Unity (w)**: An element in GF(p) where raising w to the power n equals 1 modulo p, and raising w to any power k (where 1 ≤ k < n) does not equal 1 modulo p. This is critical for the NTT.
- **Public Sequence (G)**: A sequence of n elements from GF(p), serving as the base for convolution operations.

## Number Theoretic Transform (NTT)

The NTT is a finite-field adaptation of the discrete Fourier transform, used to efficiently compute convolutions of sequences. For a sequence A = [A[0], A[1], ..., A[n-1]] in GF(p), its NTT, denoted F = NTT(A), is computed as:

- For each k from 0 to n-1:
  - F[k] is the sum of A[j] times w raised to the power (j * k), over all j from 0 to n-1, taken modulo p.

The inverse NTT (INTT) reverses this process. For a sequence B, the INTT is:

- For each j from 0 to n-1:
  - A[j] is the sum of B[k] times w_inv raised to the power (j * k), over all k from 0 to n-1, multiplied by the modular inverse of n, all modulo p.

Here, w_inv is the modular inverse of w (where w * w_inv = 1 mod p), and inv_n is the modular inverse of n (where n * inv_n = 1 mod p).

## Convolution of Sequences

The convolution of two sequences A and B, each of length n, results in a sequence C where:

- C[k] = sum of (A[i] * B[(k - i) mod n]) over i from 0 to n-1, all modulo p.

In this protocol, we repeatedly convolve a sequence with itself. The notation G^{*a} denotes G convolved with itself a times, computed efficiently via:

1. Compute F = NTT(G).
2. Raise each element to the power a: F^a = [F[0]^a, F[1]^a, ..., F[n-1]^a] mod p.
3. Compute G^{*a} = INTT(F^a).

This works because the NTT transforms convolution into pointwise multiplication in the frequency domain.

## Key Exchange Protocol

The steps of the key exchange are as follows:

1. **Alice's Actions**:
   - Alice selects a secret integer a.
   - She computes G_a = G^{*a} using the NTT method.
   - She sends G_a to Bob.

2. **Bob's Actions**:
   - Bob selects a secret integer b.
   - He computes G_b = G^{*b} using the same method.
   - He sends G_b to Alice.

3. **Shared Key Computation**:
   - Alice receives G_b and computes K_alice = G_b^{*a}.
   - Bob receives G_a and computes K_bob = G_a^{*b}.

## Proof of Correctness

To confirm the protocol works, we prove K_alice equals K_bob:

- Define:
  - G_a = G^{*a}
  - G_b = G^{*b}

- Alice computes:
  - K_alice = G_b^{*a} = (G^{*b})^{*a}

- Since convolution is associative:
  - (G^{*b})^{*a} = G^{*(b*a)} = G^{*(a*b)}

- Bob computes:
  - K_bob = G_a^{*b} = (G^{*a})^{*b} = G^{*(a*b)}

- Therefore:
  - K_alice = G^{*(a*b)} = K_bob

Both parties compute the same key: G convolved with itself (a * b) times.

## Security Consideration

The protocol’s security resembles that of Diffie-Hellman. An eavesdropper seeing G_a and G_b must compute G^{*(a*b)} without knowing a or b, a problem believed to be computationally difficult, similar to the Computational Diffie-Hellman problem, given a large p and a well-chosen G.

## Conclusion

The NTT-based key exchange protocol uses sequence convolutions and the NTT to enable efficient, secure key agreement. Its correctness relies on convolution’s associativity, ensuring identical keys for both parties. This offers a sequence-based twist on the Diffie-Hellman concept.

## References

- [1] Diffie, W., & Hellman, M. (1976). New directions in cryptography. IEEE Transactions on Information Theory, 22(6), 644-654.
- [2] Nussbaumer, H. J. (1981). Fast Fourier Transform and Convolution Algorithms. Springer-Verlag.
- [3] McEliece, R. J. (1987). Finite Fields for Computer Scientists and Engineers. Kluwer Academic Publishers.
