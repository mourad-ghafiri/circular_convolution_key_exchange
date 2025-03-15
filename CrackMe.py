#!/usr/bin/env python3
"""
CrackMe.py - An NTT-Based Key Exchange Challenge

This file implements a cryptographic protocol based on Number Theoretic Transform (NTT)
convolution exponentiation. A secret exponent s is chosen and kept private; however, we publish
the following public parameters:

   p  : A large prime such that p = k*n + 1 (for some integer k) and with a desired bit length.
   n  : Sequence length (a power of 2).
   w  : A primitive n-th root of unity modulo p.
   G  : A random public sequence (with elements in GF(p)).
   H  : The convolution exponentiation of G with the secret s, computed as H = G^{*s}.

The convolution exponentiation is carried out as follows:
   1. Compute F = NTT(G, w, p), where
          F_j = Σ (G_i * w^(i*j)) mod p   for j = 0, ..., n-1.
   2. Raise each frequency component of F to the power s modulo p:
          F'_j = (F_j)^s mod p.
   3. Compute H = INTT(F', w, p), where the inverse transform is scaled by 1/n mod p.

Equations:
  (1) p = k*n + 1,  where p is prime.
  (2) w = g^((p-1)/n) mod p,  for some generator g of Z_p*.
  (3) NTT: F_j = Σ_(i=0)^(n-1) [G_i * w^(i*j)] mod p.
  (4) Convolution exponentiation: H = G^{*s} = INTT( [F_j^s mod p] )

Your challenge: Using the public info (p, n, w, G, and H), try to recover the secret exponent s.
Good luck cracking the protocol!
"""

import random
import secrets
import time

# Fast modular exponentiation: computes (base^exponent) mod modulus
def fast_pow_mod(base, exponent, modulus):
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result

# Miller-Rabin primality test
def is_prime(n, k=40):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    r, d = 0, n-1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n-2)
        x = fast_pow_mod(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = fast_pow_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Find a prime number of a given bit length such that (p - 1) is divisible by n.
def find_prime_congruent(bits, n):
    while True:
        k = secrets.randbits(bits - 1)
        p = k * n + 1
        if p.bit_length() != bits:
            continue
        if is_prime(p):
            return p

# Find a primitive n-th root of unity modulo p.
def find_primitive_root(p, n):
    if (p - 1) % n != 0:
        raise ValueError("n does not divide p-1")
    g = 2
    max_attempts = 100
    attempts = 0
    while attempts < max_attempts:
        if fast_pow_mod(g, (p - 1) // 2, p) != 1:
            break
        g += 1
        attempts += 1
    if attempts == max_attempts:
        raise ValueError("Failed to find a generator")
    # Compute w = g^((p-1) // n) mod p.
    w = fast_pow_mod(g, (p - 1) // n, p)
    if fast_pow_mod(w, n, p) != 1:
        raise ValueError("Failed to compute a primitive n-th root of unity")
    return w

# Number Theoretic Transform (NTT) - iterative implementation
def ntt(A, w, p):
    n = len(A)
    if n == 1:
        return A.copy()
    # Ensure n is a power of 2.
    if n & (n - 1) != 0:
        raise ValueError("NTT length must be a power of 2")
    
    A_copy = A.copy()
    # Bit-reversal permutation.
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j >= bit:
            j -= bit
            bit >>= 1
        j += bit
        if i < j:
            A_copy[i], A_copy[j] = A_copy[j], A_copy[i]
            
    # Cooley-Tukey iterative FFT (NTT) algorithm.
    s = 1
    while s < n:
        m = s << 1
        w_m = fast_pow_mod(w, (p - 1) // m, p)
        for k in range(0, n, m):
            omega = 1
            for j in range(s):
                t = (omega * A_copy[k + j + s]) % p
                u = A_copy[k + j]
                A_copy[k + j] = (u + t) % p
                A_copy[k + j + s] = (u - t) % p
                omega = (omega * w_m) % p
        s *= 2
    return A_copy

# Inverse Number Theoretic Transform (INTT)
def intt(A, w, p):
    n = len(A)
    # Compute inverse of w modulo p.
    w_inv = fast_pow_mod(w, p - 2, p)
    # Compute INTT via NTT using the inverse root.
    A_inv = ntt(A, w_inv, p)
    # Normalize by multiplying with modular inverse of n.
    n_inv = fast_pow_mod(n, p - 2, p)
    for i in range(n):
        A_inv[i] = (A_inv[i] * n_inv) % p
    return A_inv

# Convolution exponentiation: Computes H = G^{*s} by raising the NTT of G to the power s.
def convolve_power(G, s, w, p):
    # Compute the NTT of G.
    NTT_G = ntt(G, w, p)
    # Raise each component of the transformed sequence to the power s (mod p).
    NTT_G_s = [fast_pow_mod(x, s, p) for x in NTT_G]
    # Perform the inverse NTT to obtain H.
    H = intt(NTT_G_s, w, p)
    return H

# Generate a random sequence G of specified length with elements in GF(p).
def generate_random_sequence(length, p):
    return [random.randint(1, p - 1) for _ in range(length)]

def main():
    print("CrackMe Challenge: NTT-Based Cryptographic Protocol")
    print("----------------------------------------------------")
    # Parameters:
    # For strong security, bits should be 2048 or higher.
    # For demonstration purposes, we use 1024 bits here.
    bits = 1024  # Bit-length of prime modulus p.
    n = 16       # Sequence length (must be a power of 2 for NTT).
    
    # Step 1: Generate a prime p such that p = k*n + 1.
    print("\nStep 1: Generating prime p such that p = k*n + 1, with", bits, "bits.")
    start_time = time.time()
    p = find_prime_congruent(bits, n)
    print("Prime p =", p)
    print("Verification (p - 1) mod n =", (p - 1) % n)
    print("Time taken:", time.time() - start_time, "seconds")
    
    # Step 2: Compute a primitive n-th root of unity w modulo p.
    print("\nStep 2: Computing a primitive", n, "th root of unity w modulo p.")
    start_time = time.time()
    w = find_primitive_root(p, n)
    print("Primitive n-th root of unity, w =", w)
    print("Verification: w^n mod p =", fast_pow_mod(w, n, p))
    print("Time taken:", time.time() - start_time, "seconds")
    
    # Step 3: Generate a random public sequence G of length n.
    print("\nStep 3: Generating random public sequence G.")
    G = generate_random_sequence(n, p)
    print("Public sequence G =", G)
    
    # Step 4: Choose a secret exponent s (keep this private!)
    s = secrets.randbelow(p - 1) + 1
    # For demonstration or debugging you could print s:
    # print("Secret exponent s =", s)   # DO NOT print in a real challenge
    
    # Step 5: Compute convolution exponentiation H = G^{*s}.
    print("\nStep 4: Computing H = G^{*s} using convolution exponentiation.")
    start_time = time.time()
    H = convolve_power(G, s, w, p)
    print("Convolution exponentiation result H =", H)
    print("Time taken:", time.time() - start_time, "seconds")
    
    # Display public parameters and challenge description.
    print("\n--- Public Parameters for the Challenge ---")
    print("p      =", p)
    print("n      =", n)
    print("w      =", w)
    print("G      =", G)
    print("H      =", H)
    
    print("\nProtocol Equations and Steps:")
    print("1) p = k*n + 1, where p is prime and k is an integer.")
    print("2) w = g^((p-1)/n) mod p, with g a generator of Z_p*.")
    print("3) NTT: For G = [g0, g1, ..., g(n-1)],")
    print("       F_j = Σ_(i=0)^(n-1) (g_i * w^(i*j)) mod p, for j = 0,...,n-1.")
    print("4) Convolution Exponentiation:")
    print("       H = G^{*s} = INTT( [F_j^s mod p] ), where F = NTT(G, w, p).")
    
    print("\n-- YOUR CHALLENGE --")
    print("Using the public parameters above, determine the secret exponent s.")
    print("Best of luck to the reverse engineering and cryptography community!")

if __name__ == "__main__":
    main() 
