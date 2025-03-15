def ntt(A, w, p):
    """
    Number Theoretic Transform (NTT) of sequence A.
    
    Args:
        A (list): Input sequence of length n over GF(p)
        w (int): Primitive n-th root of unity modulo p
        p (int): Prime modulus
    
    Returns:
        list: NTT of A
    """
    n = len(A)
    F = [0] * n
    for k in range(n):
        for j in range(n):
            F[k] = (F[k] + A[j] * pow(w, j * k, p)) % p
    return F

def intt(B, w, p):
    """
    Inverse Number Theoretic Transform (INTT) of sequence B.
    
    Args:
        B (list): Input sequence in frequency domain
        w (int): Primitive n-th root of unity modulo p
        p (int): Prime modulus
    
    Returns:
        list: Inverse NTT of B
    """
    n = len(B)
    w_inv = pow(w, p - 2, p)  # Inverse of w modulo p
    inv_n = pow(n, p - 2, p)  # Inverse of n modulo p (Fermat's Little Theorem)
    A = [0] * n
    for j in range(n):
        for k in range(n):
            A[j] = (A[j] + B[k] * pow(w_inv, j * k, p)) % p
        A[j] = (A[j] * inv_n) % p
    return A

def convolve_power(G, a, w, p):
    """
    Compute G^{*a}, the sequence G convolved with itself a times.
    
    Args:
        G (list): Base sequence of length n
        a (int): Exponent (number of convolutions)
        w (int): Primitive n-th root of unity modulo p
        p (int): Prime modulus
    
    Returns:
        list: Result of G^{*a}
    """
    F_G = ntt(G, w, p)           # Transform G to frequency domain
    F_Ga = [pow(f, a, p) for f in F_G]  # Pointwise exponentiation
    Ga = intt(F_Ga, w, p)        # Transform back to time domain
    return Ga

# Public parameters
p = 17          # Small prime for demonstration (in practice, use a large prime)
n = 4           # Sequence length (must divide p-1; here, 4 divides 16)
w = 4           # Primitive 4-th root of unity in GF(17), since w^4 ≡ 1 mod 17
G = [1, 2, 3, 4]  # Public sequence over GF(17)

# Alice's part
a = 20122123           # Alice's secret key (small for demo; should be large in practice)
Ga = convolve_power(G, a, w, p)
print("Ga (Alice sends):", Ga)

# Bob's part
b = 31213121231           # Bob's secret key
Gb = convolve_power(G, b, w, p)
print("Gb (Bob sends):", Gb)

# Alice computes the shared key using Gb and her secret a
K_alice = convolve_power(Gb, a, w, p)
print("K_alice:", K_alice)

# Bob computes the shared key using Ga and his secret b
K_bob = convolve_power(Ga, b, w, p)
print("K_bob:", K_bob)

# Verify that Alice and Bob derived the same key
assert K_alice == K_bob, "Shared keys do not match!"
print("Shared key successfully established:", K_alice)

# Optional verification: compute G^{* (a*b)} directly
ab = a * b
K_direct = convolve_power(G, ab, w, p)
print("K_direct (G^{*6}):", K_direct)
assert K_alice == K_direct, "Direct computation does not match shared key!"
print("Verification passed: K_alice matches G^{*(a*b)}")
